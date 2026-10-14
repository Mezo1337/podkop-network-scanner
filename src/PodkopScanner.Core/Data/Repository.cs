using System.Globalization;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using PodkopScanner.Core.Analysis;
using PodkopScanner.Core.Model;
using PodkopScanner.Core.Net;

namespace PodkopScanner.Core.Data;

public sealed record RecordResult(int NewEntries, int UpdatedEntries, int Skipped, List<string> SkipReasons);

public sealed class Repository
{
    private readonly Database _db;
    private readonly object _writeLock = new();

    public Repository(Database db) => _db = db;
    public Database Database => _db;

    private static string T(DateTime d) => d.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture);
    private static DateTime P(string s) => DateTime.Parse(s, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);
    private static DateTime? PN(object o) => o is string s && s.Length > 0 ? P(s) : null;

    private static SqliteCommand Cmd(SqliteConnection c, string sql, SqliteTransaction? tx = null, params (string, object?)[] ps)
    {
        var cmd = c.CreateCommand();
        cmd.CommandText = sql; cmd.Transaction = tx;
        foreach (var (k, v) in ps) cmd.Parameters.AddWithValue(k, v ?? DBNull.Value);
        return cmd;
    }

    // ───────────── Проекты ─────────────

    public List<Project> GetProjects()
    {
        using var c = _db.Open();
        using var cmd = Cmd(c, "SELECT id,name,type,source,proxy_json,auto_include_ips,created,updated,last_refresh,notes FROM projects ORDER BY name COLLATE NOCASE");
        using var r = cmd.ExecuteReader();
        var list = new List<Project>();
        while (r.Read()) list.Add(ReadProject(r));
        return list;
    }

    public Project? GetProject(long id)
    {
        using var c = _db.Open();
        using var cmd = Cmd(c, "SELECT id,name,type,source,proxy_json,auto_include_ips,created,updated,last_refresh,notes FROM projects WHERE id=$id", null, ("$id", id));
        using var r = cmd.ExecuteReader();
        return r.Read() ? ReadProject(r) : null;
    }

    private static Project ReadProject(SqliteDataReader r) => new()
    {
        Id = r.GetInt64(0), Name = r.GetString(1), Type = (ProjectType)r.GetInt32(2), Source = r.GetString(3),
        ProxyJson = r.IsDBNull(4) ? null : r.GetString(4), AutoIncludeIps = r.GetInt32(5) != 0,
        Created = P(r.GetString(6)), Updated = P(r.GetString(7)), LastRefresh = r.IsDBNull(8) ? null : P(r.GetString(8)),
        Notes = r.GetString(9),
    };

    public Project CreateProject(string name, ProjectType type, string source)
    {
        var now = DateTime.UtcNow;
        lock (_writeLock)
        {
            using var c = _db.Open();
            using var cmd = Cmd(c, "INSERT INTO projects(name,type,source,auto_include_ips,created,updated) VALUES($n,$t,$s,$a,$c,$c) RETURNING id", null,
                ("$n", name), ("$t", (int)type), ("$s", source), ("$a", type == ProjectType.Program ? 1 : 0), ("$c", T(now)));
            var id = (long)cmd.ExecuteScalar()!;
            return GetProject(id)!;
        }
    }

    public void UpdateProject(Project p)
    {
        lock (_writeLock)
        {
            using var c = _db.Open();
            using var cmd = Cmd(c, "UPDATE projects SET name=$n,type=$t,source=$s,proxy_json=$p,auto_include_ips=$a,updated=$u,last_refresh=$lr,notes=$no WHERE id=$id", null,
                ("$n", p.Name), ("$t", (int)p.Type), ("$s", p.Source), ("$p", p.ProxyJson), ("$a", p.AutoIncludeIps ? 1 : 0),
                ("$u", T(DateTime.UtcNow)), ("$lr", p.LastRefresh is { } lr ? T(lr) : null), ("$no", p.Notes), ("$id", p.Id));
            cmd.ExecuteNonQuery();
        }
    }

    public void DeleteProject(long id)
    {
        lock (_writeLock)
        {
            using var c = _db.Open();
            using var cmd = Cmd(c, "DELETE FROM projects WHERE id=$id", null, ("$id", id));
            cmd.ExecuteNonQuery();
        }
    }

    // ───────────── Сканирования ─────────────

    public long StartScan(long projectId, string kind, string route)
    {
        lock (_writeLock)
        {
            using var c = _db.Open();
            using var cmd = Cmd(c, "INSERT INTO scans(project_id,kind,started,route) VALUES($p,$k,$s,$r) RETURNING id", null,
                ("$p", projectId), ("$k", kind), ("$s", T(DateTime.UtcNow)), ("$r", route));
            return (long)cmd.ExecuteScalar()!;
        }
    }

    public void FinishScan(long scanId, string summary)
    {
        lock (_writeLock)
        {
            using var c = _db.Open();
            using var cmd = Cmd(c, "UPDATE scans SET finished=$f, summary=$s WHERE id=$id", null, ("$f", T(DateTime.UtcNow)), ("$s", summary), ("$id", scanId));
            cmd.ExecuteNonQuery();
        }
        // Статус «текущее соединение / текущий DNS» зависит от последнего сканирования — пересчитываем весь проект.
        using var c2 = _db.Open();
        using var q = Cmd(c2, "SELECT project_id FROM scans WHERE id=$id", null, ("$id", scanId));
        if (q.ExecuteScalar() is long pid) RecomputeEntries(pid);
    }

    public List<Scan> GetScans(long projectId)
    {
        using var c = _db.Open();
        using var cmd = Cmd(c, "SELECT id,project_id,kind,started,finished,route,summary FROM scans WHERE project_id=$p ORDER BY id DESC", null, ("$p", projectId));
        using var r = cmd.ExecuteReader();
        var l = new List<Scan>();
        while (r.Read())
            l.Add(new Scan { Id = r.GetInt64(0), ProjectId = r.GetInt64(1), Kind = r.GetString(2), Started = P(r.GetString(3)), Finished = PN(r.GetValue(4)), Route = r.GetString(5), Summary = r.GetString(6) });
        return l;
    }

    // ───────────── Исключения ─────────────

    public List<Exclusion> GetExclusions(long? projectId)
    {
        using var c = _db.Open();
        using var cmd = Cmd(c, "SELECT id,project_id,pattern,whitelist FROM exclusions WHERE project_id IS NULL OR project_id=$p ORDER BY pattern", null, ("$p", projectId ?? -1));
        using var r = cmd.ExecuteReader();
        var l = new List<Exclusion>();
        while (r.Read()) l.Add(new Exclusion { Id = r.GetInt64(0), ProjectId = r.IsDBNull(1) ? null : r.GetInt64(1), Pattern = r.GetString(2), IsWhitelist = r.GetInt32(3) != 0 });
        return l;
    }

    public void AddExclusion(long? projectId, string pattern, bool whitelist)
    {
        lock (_writeLock)
        {
            using var c = _db.Open();
            using var cmd = Cmd(c, "INSERT INTO exclusions(project_id,pattern,whitelist) VALUES($p,$x,$w)", null, ("$p", projectId), ("$x", pattern.Trim().ToLowerInvariant()), ("$w", whitelist ? 1 : 0));
            cmd.ExecuteNonQuery();
        }
    }

    public void DeleteExclusion(long id)
    {
        lock (_writeLock)
        {
            using var c = _db.Open();
            using var cmd = Cmd(c, "DELETE FROM exclusions WHERE id=$id", null, ("$id", id));
            cmd.ExecuteNonQuery();
        }
    }

    // ───────────── Запись наблюдений ─────────────

    /// <summary>
    /// Сохраняет наблюдения: создаёт/обновляет записи, добавляет наблюдения и связи IP↔домен,
    /// затем детерминированно пересчитывает достоверность и статус затронутых записей.
    /// Записи из чёрного списка не сохраняются; локальные/служебные адреса отбрасываются.
    /// </summary>
    public RecordResult RecordFindings(long projectId, long scanId, IEnumerable<Finding> findings, bool keepSpecial = false)
    {
        var project = GetProject(projectId) ?? throw new InvalidOperationException("Проект не найден");
        var matcher = new ExclusionMatcher(GetExclusions(projectId));
        int created = 0, updated = 0, skipped = 0;
        var reasons = new List<string>();
        var touched = new HashSet<long>();
        lock (_writeLock)
        {
            using var c = _db.Open();
            using var tx = c.BeginTransaction();
            foreach (var f in findings)
            {
                if (f.Undetermined) { skipped++; continue; }
                var value = f.Value;
                var kind = f.Kind;
                if (kind == EntryKind.Domain)
                {
                    var n = DomainNormalizer.Normalize(value, rejectLocal: !matcher.IsWhitelisted(value));
                    if (!n.Ok) { skipped++; reasons.Add($"{value}: {DomainNormalizer.Describe(n.Reason)}"); continue; }
                    value = n.Domain!;
                }
                else
                {
                    if (!IpNetwork.TryParse(value, out var net)) { skipped++; reasons.Add($"{value}: не IP/CIDR"); continue; }
                    if (!keepSpecial && !matcher.IsWhitelisted(net.ToString()) && SpecialRanges.Match(net) is { } sp)
                    { skipped++; reasons.Add($"{value}: специальный диапазон ({sp.Description})"); continue; }
                    value = net.ToString();
                    kind = net.IsSingleHost ? (net.IsV6 ? EntryKind.IPv6 : EntryKind.IPv4) : (net.IsV6 ? EntryKind.Cidr6 : EntryKind.Cidr4);
                }
                if (matcher.IsBlacklisted(value)) { skipped++; reasons.Add($"{value}: в чёрном списке"); continue; }

                var t = T(f.Time);
                long id;
                using (var sel = Cmd(c, "SELECT id FROM entries WHERE project_id=$p AND value=$v", tx, ("$p", projectId), ("$v", value)))
                    id = sel.ExecuteScalar() is long l ? l : 0;
                if (id == 0)
                {
                    using var ins = Cmd(c, """
                        INSERT INTO entries(project_id,value,kind,first_seen,last_seen,category,category_reason,imported)
                        VALUES($p,$v,$k,$t,$t,$cat,$cr,$imp) RETURNING id
                        """, tx, ("$p", projectId), ("$v", value), ("$k", (int)kind), ("$t", t), ("$cat", (int)f.Category),
                        ("$cr", f.CategoryReason), ("$imp", f.Method == ObservationMethod.Import ? 1 : 0));
                    id = (long)ins.ExecuteScalar()!;
                    created++;
                }
                else
                {
                    // Категорию уточняем, только если новая классификация уверенней (есть обоснование и не «низкая»).
                    using var up = Cmd(c, """
                        UPDATE entries SET last_seen=MAX(last_seen,$t),
                          category=CASE WHEN $cat<>0 AND (category=0 OR ($cr NOT LIKE 'низкая%' AND category_reason LIKE 'низкая%')) THEN $cat ELSE category END,
                          category_reason=CASE WHEN $cat<>0 AND (category=0 OR ($cr NOT LIKE 'низкая%' AND category_reason LIKE 'низкая%')) THEN $cr ELSE category_reason END
                        WHERE id=$id
                        """, tx, ("$t", t), ("$cat", (int)f.Category), ("$cr", f.CategoryReason), ("$id", id));
                    up.ExecuteNonQuery();
                    if (!touched.Contains(id)) updated++;
                }
                touched.Add(id);
                if (matcher.IsWhitelisted(value))
                    using (var w = Cmd(c, "UPDATE entries SET include=1, include_set_by_user=1 WHERE id=$id AND include_set_by_user=0", tx, ("$id", id))) w.ExecuteNonQuery();

                using (var ob = Cmd(c, """
                    INSERT INTO observations(entry_id,scan_id,first_time,time,method,detail,process_name,pid,protocol,port,route)
                    VALUES($e,$s,$t,$t,$m,$d,$pn,$pid,$pr,$po,$r)
                    ON CONFLICT(entry_id,scan_id,method,detail,process_name,pid,protocol,port,route)
                    DO UPDATE SET time=MAX(time,excluded.time), hits=hits+1
                    """, tx, ("$e", id), ("$s", scanId), ("$t", t), ("$m", (int)f.Method), ("$d", f.Detail ?? ""),
                    ("$pn", f.ProcessName ?? ""), ("$pid", f.Pid ?? 0), ("$pr", f.Protocol ?? ""), ("$po", f.Port ?? 0), ("$r", f.Route)))
                    ob.ExecuteNonQuery();

                if (!string.IsNullOrEmpty(f.LinkedDomain) && kind != EntryKind.Domain)
                    using (var ln = Cmd(c, """
                        INSERT INTO ip_links(ip_entry_id,domain,method,time) VALUES($e,$d,$m,$t)
                        ON CONFLICT(ip_entry_id,domain,method) DO UPDATE SET time=MAX(time,excluded.time)
                        """, tx, ("$e", id), ("$d", f.LinkedDomain), ("$m", f.LinkMethod ?? "связь"), ("$t", t)))
                        ln.ExecuteNonQuery();
            }
            tx.Commit();
        }
        RecomputeEntries(projectId, touched, project.AutoIncludeIps);
        TouchProject(projectId);
        return new RecordResult(created, updated, skipped, reasons);
    }

    private void TouchProject(long id)
    {
        lock (_writeLock)
        {
            using var c = _db.Open();
            using var cmd = Cmd(c, "UPDATE projects SET updated=$u WHERE id=$id", null, ("$u", T(DateTime.UtcNow)), ("$id", id));
            cmd.ExecuteNonQuery();
        }
    }

    /// <summary>Пересчёт достоверности, статуса и включения по умолчанию (null = все записи проекта).</summary>
    public void RecomputeEntries(long projectId, IEnumerable<long>? entryIds = null, bool? autoIncludeIps = null)
    {
        var proj = GetProject(projectId);
        autoIncludeIps ??= proj?.AutoIncludeIps ?? false;
        var site = proj is { Type: not ProjectType.Program } ? SiteOwnership.SiteRegistrableFromSource(proj.Source) : null;
        var ids = entryIds?.ToHashSet();
        if (ids is { Count: 0 }) return;
        var now = DateTime.UtcNow;
        lock (_writeLock)
        {
            using var c = _db.Open();
            long latestCapture = 0, latestRefresh = 0, latestOfficial = 0;
            using (var q = Cmd(c, "SELECT COALESCE(MAX(id),0) FROM scans WHERE project_id=$p AND kind='official'", null, ("$p", projectId)))
                latestOfficial = (long)q.ExecuteScalar()!;
            using (var q = Cmd(c, "SELECT COALESCE(MAX(id),0) FROM scans WHERE project_id=$p AND kind IN ('web','process')", null, ("$p", projectId)))
                latestCapture = (long)q.ExecuteScalar()!;
            using (var q = Cmd(c, "SELECT COALESCE(MAX(id),0) FROM scans WHERE project_id=$p AND kind='refresh'", null, ("$p", projectId)))
                latestRefresh = (long)q.ExecuteScalar()!;

            var obs = new Dictionary<long, List<(ObservationMethod m, DateTime t, long scan, string detail)>>();
            using (var q = Cmd(c, "SELECT o.entry_id,o.method,o.time,o.scan_id,o.detail FROM observations o JOIN entries e ON e.id=o.entry_id WHERE e.project_id=$p", null, ("$p", projectId)))
            using (var r = q.ExecuteReader())
                while (r.Read())
                {
                    var eid = r.GetInt64(0);
                    if (ids != null && !ids.Contains(eid)) continue;
                    if (!obs.TryGetValue(eid, out var l)) obs[eid] = l = new();
                    l.Add(((ObservationMethod)r.GetInt32(1), P(r.GetString(2)), r.GetInt64(3), r.GetString(4)));
                }

            var entries = new List<(long id, EntryKind kind, bool manual, bool userSet, int cat, int miss, bool imported, string value)>();
            using (var q = Cmd(c, "SELECT id,kind,manual,include_set_by_user,category,dns_miss_streak,imported,value FROM entries WHERE project_id=$p", null, ("$p", projectId)))
            using (var r = q.ExecuteReader())
                while (r.Read())
                {
                    var eid = r.GetInt64(0);
                    if (ids != null && !ids.Contains(eid)) continue;
                    entries.Add((eid, (EntryKind)r.GetInt32(1), r.GetInt32(2) != 0, r.GetInt32(3) != 0, r.GetInt32(4), r.GetInt32(5), r.GetInt32(6) != 0, r.GetString(7)));
                }

            using var tx = c.BeginTransaction();
            foreach (var e in entries)
            {
                var list = obs.GetValueOrDefault(e.id) ?? new();
                var trust = TrustPolicy.Compute(list.Select(o => (o.m, o.t)), e.kind, e.manual, now);
                DateTime? lastConfirmed = list.Where(o => o.m != ObservationMethod.Import && !(o.m == ObservationMethod.DnsResolve && o.detail.StartsWith("ошибка")))
                    .Select(o => (DateTime?)o.t).DefaultIfEmpty(null).Max();
                var status = ComputeStatus(e.kind, list, latestCapture, latestRefresh, latestOfficial, e.miss, e.imported);
                var tmp = new Entry { Kind = e.kind, Trust = trust, Category = (ResourceCategory)e.cat };
                tmp.Value = e.value;
                var defInclude = TrustPolicy.DefaultInclude(tmp, autoIncludeIps.Value, site);
                using var up = Cmd(c, """
                    UPDATE entries SET trust=$tr, status=$st, last_confirmed=$lc,
                      include=CASE WHEN include_set_by_user=1 THEN include ELSE $inc END
                    WHERE id=$id
                    """, tx, ("$tr", (int)trust), ("$st", (int)status), ("$lc", lastConfirmed is { } lc ? T(lc) : null), ("$inc", defInclude ? 1 : 0), ("$id", e.id));
                up.ExecuteNonQuery();
            }
            tx.Commit();
        }
    }

    internal static EntryStatus ComputeStatus(EntryKind kind, List<(ObservationMethod m, DateTime t, long scan, string detail)> obs,
        long latestCapture, long latestRefresh, long latestOfficial, int missStreak, bool imported)
    {
        if (latestOfficial != 0 && obs.Any(o => o.m == ObservationMethod.OfficialRange && o.scan == latestOfficial))
            return EntryStatus.ConfirmedOfficial;
        // Для домена более свежая DNS-проверка с ошибкой (NXDOMAIN) важнее более раннего соединения.
        bool refreshIsNewer = latestRefresh > latestCapture;
        if (kind == EntryKind.Domain && refreshIsNewer && missStreak >= 2) return EntryStatus.NotReconfirmed;
        if (kind == EntryKind.Domain && refreshIsNewer && missStreak == 1) return EntryStatus.NeedsManualCheck;
        if (latestCapture != 0 && obs.Any(o => o.scan == latestCapture && TrustPolicy.IsConnectionEvidence(o.m)))
            return EntryStatus.ConfirmedConnection;
        if (latestRefresh != 0 && obs.Any(o => o.scan == latestRefresh && o.m == ObservationMethod.DnsResolve && !o.detail.StartsWith("ошибка")))
            return EntryStatus.FromCurrentDns;
        if (missStreak >= 2) return EntryStatus.NotReconfirmed;
        if (missStreak == 1 && kind == EntryKind.Domain) return EntryStatus.NeedsManualCheck;
        if (imported && obs.All(o => o.m == ObservationMethod.Import)) return EntryStatus.NeedsManualCheck;
        return EntryStatus.PreviouslySeen;
    }

    // ───────────── Чтение записей ─────────────

    public List<Entry> GetEntries(long projectId)
    {
        using var c = _db.Open();
        var list = new Dictionary<long, Entry>();
        using (var cmd = Cmd(c, """
            SELECT id,value,kind,first_seen,last_seen,last_confirmed,trust,status,category,category_reason,include,disabled,manual,imported,asn,provider,dns_miss_streak,note
            FROM entries WHERE project_id=$p
            """, null, ("$p", projectId)))
        using (var r = cmd.ExecuteReader())
            while (r.Read())
            {
                var e = new Entry
                {
                    Id = r.GetInt64(0), ProjectId = projectId, Value = r.GetString(1), Kind = (EntryKind)r.GetInt32(2),
                    FirstSeen = P(r.GetString(3)), LastSeen = P(r.GetString(4)), LastConfirmed = PN(r.GetValue(5)),
                    Trust = (Trust)r.GetInt32(6), Status = (EntryStatus)r.GetInt32(7), Category = (ResourceCategory)r.GetInt32(8),
                    CategoryReason = r.GetString(9), Include = r.GetInt32(10) != 0, Disabled = r.GetInt32(11) != 0,
                    ManualConfirmed = r.GetInt32(12) != 0, Imported = r.GetInt32(13) != 0, Asn = r.GetString(14),
                    Provider = r.GetString(15), DnsMissStreak = r.GetInt32(16), Note = r.GetString(17),
                };
                list[e.Id] = e;
            }

        var methods = new Dictionary<long, SortedSet<string>>();
        var procs = new Dictionary<long, SortedSet<string>>();
        var protos = new Dictionary<long, SortedSet<string>>();
        using (var cmd = Cmd(c, """
            SELECT o.entry_id, o.method, o.process_name, o.pid, o.protocol, o.port FROM observations o
            JOIN entries e ON e.id=o.entry_id WHERE e.project_id=$p
            GROUP BY o.entry_id, o.method, o.process_name, o.pid, o.protocol, o.port
            """, null, ("$p", projectId)))
        using (var r = cmd.ExecuteReader())
            while (r.Read())
            {
                var id = r.GetInt64(0);
                Add(methods, id, Ru.Of((ObservationMethod)r.GetInt32(1)));
                var pn = r.GetString(2); var pid = r.GetInt32(3);
                if (pn.Length > 0) Add(procs, id, pid > 0 ? $"{pn} ({pid})" : pn);
                var pr = r.GetString(4); var po = r.GetInt32(5);
                if (pr.Length > 0) Add(protos, id, po > 0 ? $"{pr}:{po}" : pr);
            }
        var links = new Dictionary<long, SortedSet<string>>();
        using (var cmd = Cmd(c, "SELECT l.ip_entry_id,l.domain,l.method FROM ip_links l JOIN entries e ON e.id=l.ip_entry_id WHERE e.project_id=$p", null, ("$p", projectId)))
        using (var r = cmd.ExecuteReader())
            while (r.Read()) Add(links, r.GetInt64(0), $"{r.GetString(1)} [{r.GetString(2)}]");

        foreach (var e in list.Values)
        {
            e.Sources = Join(methods, e.Id);
            e.ProcessInfo = Join(procs, e.Id, 4);
            e.Protocols = Join(protos, e.Id, 6);
            e.LinkedNames = Join(links, e.Id, 6);
        }
        return list.Values.OrderBy(e => e.Kind == EntryKind.Domain ? 0 : 1)
            .ThenBy(e => e.Value, Comparer<string>.Create((a, b) => DomainNormalizer.CompareByRegistrable(a, b))).ToList();

        static void Add(Dictionary<long, SortedSet<string>> d, long id, string v)
        {
            if (!d.TryGetValue(id, out var s)) d[id] = s = new SortedSet<string>();
            s.Add(v);
        }
        static string Join(Dictionary<long, SortedSet<string>> d, long id, int max = 20)
        {
            if (!d.TryGetValue(id, out var s)) return "";
            var parts = s.Take(max).ToList();
            return string.Join(", ", parts) + (s.Count > max ? $" … (+{s.Count - max})" : "");
        }
    }

    public List<Observation> GetObservations(long entryId)
    {
        using var c = _db.Open();
        using var cmd = Cmd(c, "SELECT id,entry_id,scan_id,time,method,detail,process_name,pid,protocol,port,route FROM observations WHERE entry_id=$e ORDER BY time DESC LIMIT 500", null, ("$e", entryId));
        using var r = cmd.ExecuteReader();
        var l = new List<Observation>();
        while (r.Read())
            l.Add(new Observation
            {
                Id = r.GetInt64(0), EntryId = r.GetInt64(1), ScanId = r.GetInt64(2), Time = P(r.GetString(3)), Method = (ObservationMethod)r.GetInt32(4),
                Detail = r.GetString(5), ProcessName = r.GetString(6), Pid = r.GetInt32(7), Protocol = r.GetString(8), Port = r.GetInt32(9), Route = r.GetString(10),
            });
        return l;
    }

    /// <summary>IP, полученные DNS-разрешением домена в указанном сканировании обновления.</summary>
    public Dictionary<string, HashSet<string>> GetDnsAnswersByScan(long projectId, long scanId)
    {
        using var c = _db.Open();
        using var cmd = Cmd(c, """
            SELECT e.value, l.domain FROM ip_links l JOIN entries e ON e.id=l.ip_entry_id
            JOIN observations o ON o.entry_id=e.id AND o.scan_id=$s AND o.method=$m
            WHERE e.project_id=$p AND l.method LIKE 'DNS%'
            """, null, ("$s", scanId), ("$m", (int)ObservationMethod.DnsResolve), ("$p", projectId));
        using var r = cmd.ExecuteReader();
        var d = new Dictionary<string, HashSet<string>>();
        while (r.Read())
        {
            var dom = r.GetString(1);
            if (!d.TryGetValue(dom, out var s)) d[dom] = s = new();
            s.Add(r.GetString(0));
        }
        return d;
    }

    // ───────────── Изменение записей пользователем ─────────────

    public void SetInclude(IEnumerable<long> ids, bool include) =>
        Update(ids, "UPDATE entries SET include=$v, include_set_by_user=1 WHERE id=$id", include ? 1 : 0);

    public void SetDisabled(IEnumerable<long> ids, bool disabled) =>
        Update(ids, "UPDATE entries SET disabled=$v WHERE id=$id", disabled ? 1 : 0);

    public void SetManualConfirmed(IEnumerable<long> ids, bool manual) =>
        Update(ids, "UPDATE entries SET manual=$v WHERE id=$id", manual ? 1 : 0);

    public void SetCategory(IEnumerable<long> ids, ResourceCategory cat) =>
        Update(ids, "UPDATE entries SET category=$v, category_reason='задано вручную' WHERE id=$id", (int)cat);

    public void ResetIncludeToDefault(IEnumerable<long> ids) =>
        Update(ids, "UPDATE entries SET include_set_by_user=0 WHERE id=$id", 0);

    public void SetNote(long id, string note) => Update(new[] { id }, "UPDATE entries SET note=$v WHERE id=$id", note);
    public void SetAsn(long id, string asn) => Update(new[] { id }, "UPDATE entries SET asn=$v WHERE id=$id", asn);
    public void SetProvider(long id, string provider) => Update(new[] { id }, "UPDATE entries SET provider=$v WHERE id=$id", provider);
    public void SetMissStreak(long id, int v) => Update(new[] { id }, "UPDATE entries SET dns_miss_streak=$v WHERE id=$id", v);

    public void DeleteEntries(IEnumerable<long> ids) => Update(ids, "DELETE FROM entries WHERE id=$id AND $v=$v", 0);

    private void Update(IEnumerable<long> ids, string sql, object v)
    {
        lock (_writeLock)
        {
            using var c = _db.Open();
            using var tx = c.BeginTransaction();
            foreach (var id in ids)
            {
                using var cmd = Cmd(c, sql, tx, ("$v", v), ("$id", id));
                cmd.ExecuteNonQuery();
            }
            tx.Commit();
        }
    }

    // ───────────── Версии списков и откат ─────────────

    private sealed record EntryState(string Value, bool Include, bool UserSet, bool Disabled, bool Manual);

    public long SaveVersion(long projectId, string reason, string domainsText, string subnetsText)
    {
        lock (_writeLock)
        {
            using var c = _db.Open();
            var states = new List<EntryState>();
            using (var q = Cmd(c, "SELECT value,include,include_set_by_user,disabled,manual FROM entries WHERE project_id=$p", null, ("$p", projectId)))
            using (var r = q.ExecuteReader())
                while (r.Read()) states.Add(new(r.GetString(0), r.GetInt32(1) != 0, r.GetInt32(2) != 0, r.GetInt32(3) != 0, r.GetInt32(4) != 0));
            // Не плодим одинаковые версии подряд.
            using (var last = Cmd(c, "SELECT domains_text, subnets_text FROM list_versions WHERE project_id=$p ORDER BY id DESC LIMIT 1", null, ("$p", projectId)))
            using (var r = last.ExecuteReader())
                if (r.Read() && r.GetString(0) == domainsText && r.GetString(1) == subnetsText) return -1;
            using var cmd = Cmd(c, "INSERT INTO list_versions(project_id,time,reason,domains_text,subnets_text,state_json) VALUES($p,$t,$r,$d,$s,$j) RETURNING id", null,
                ("$p", projectId), ("$t", T(DateTime.UtcNow)), ("$r", reason), ("$d", domainsText), ("$s", subnetsText), ("$j", JsonSerializer.Serialize(states)));
            return (long)cmd.ExecuteScalar()!;
        }
    }

    public List<ListVersion> GetVersions(long projectId)
    {
        using var c = _db.Open();
        using var cmd = Cmd(c, "SELECT id,project_id,time,reason,domains_text,subnets_text,state_json FROM list_versions WHERE project_id=$p ORDER BY id DESC", null, ("$p", projectId));
        using var r = cmd.ExecuteReader();
        var l = new List<ListVersion>();
        while (r.Read())
            l.Add(new ListVersion { Id = r.GetInt64(0), ProjectId = r.GetInt64(1), Time = P(r.GetString(2)), Reason = r.GetString(3), DomainsText = r.GetString(4), SubnetsText = r.GetString(5), StateJson = r.GetString(6) });
        return l;
    }

    /// <summary>
    /// Откат: восстанавливает флаги включения/отключения записей по сохранённой версии.
    /// Записи, появившиеся после версии, исключаются из экспорта (но не удаляются — история сохраняется).
    /// </summary>
    public void Rollback(ListVersion v)
    {
        var states = JsonSerializer.Deserialize<List<EntryState>>(v.StateJson) ?? new();
        var map = states.ToDictionary(s => s.Value);
        lock (_writeLock)
        {
            using var c = _db.Open();
            using var tx = c.BeginTransaction();
            var ids = new List<(long, string)>();
            using (var q = Cmd(c, "SELECT id,value FROM entries WHERE project_id=$p", tx, ("$p", v.ProjectId)))
            using (var r = q.ExecuteReader())
                while (r.Read()) ids.Add((r.GetInt64(0), r.GetString(1)));
            foreach (var (id, value) in ids)
            {
                using var cmd = map.TryGetValue(value, out var s)
                    ? Cmd(c, "UPDATE entries SET include=$i, include_set_by_user=$u, disabled=$d, manual=$m WHERE id=$id", tx,
                        ("$i", s.Include ? 1 : 0), ("$u", s.UserSet ? 1 : 0), ("$d", s.Disabled ? 1 : 0), ("$m", s.Manual ? 1 : 0), ("$id", id))
                    : Cmd(c, "UPDATE entries SET include=0, include_set_by_user=1 WHERE id=$id", tx, ("$id", id));
                cmd.ExecuteNonQuery();
            }
            tx.Commit();
        }
    }

    // ───────────── Снимки официальных диапазонов ─────────────

    public (DateTime time, List<IpNetwork> nets)? GetLatestProviderSnapshot(string provider)
    {
        using var c = _db.Open();
        using var cmd = Cmd(c, "SELECT time,cidrs FROM provider_snapshots WHERE provider=$p ORDER BY id DESC LIMIT 1", null, ("$p", provider));
        using var r = cmd.ExecuteReader();
        if (!r.Read()) return null;
        var nets = r.GetString(1).Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(IpNetwork.Parse).ToList();
        return (P(r.GetString(0)), nets);
    }

    /// <summary>Сохраняет снимок, если он изменился. Возвращает (добавленные, удалённые) относительно прошлого.</summary>
    public (List<IpNetwork> added, List<IpNetwork> removed, bool changed) SaveProviderSnapshot(string provider, List<IpNetwork> nets)
    {
        var prev = GetLatestProviderSnapshot(provider);
        var text = string.Join('\n', nets.OrderBy(n => n).Select(n => n.ToString(true)));
        var hash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(text)));
        var prevSet = prev?.nets.ToHashSet() ?? new HashSet<IpNetwork>();
        var curSet = nets.ToHashSet();
        var added = curSet.Except(prevSet).OrderBy(n => n).ToList();
        var removed = prevSet.Except(curSet).OrderBy(n => n).ToList();
        if (prev != null && added.Count == 0 && removed.Count == 0) return (added, removed, false);
        lock (_writeLock)
        {
            using var c = _db.Open();
            using var cmd = Cmd(c, "INSERT INTO provider_snapshots(provider,time,hash,cidrs) VALUES($p,$t,$h,$c)", null,
                ("$p", provider), ("$t", T(DateTime.UtcNow)), ("$h", hash), ("$c", text));
            cmd.ExecuteNonQuery();
        }
        return (added, removed, true);
    }
}

/// <summary>Белый/чёрный список: суффикс домена, маска с *, IP или подсеть (по вхождению).</summary>
public sealed class ExclusionMatcher
{
    private readonly List<Exclusion> _items;
    public ExclusionMatcher(IEnumerable<Exclusion> items) => _items = items.ToList();

    public bool IsWhitelisted(string value) => _items.Any(e => e.IsWhitelist && Matches(e.Pattern, value));
    public bool IsBlacklisted(string value) => !IsWhitelisted(value) && _items.Any(e => !e.IsWhitelist && Matches(e.Pattern, value));

    public static bool Matches(string pattern, string value)
    {
        pattern = pattern.Trim().ToLowerInvariant();
        value = value.Trim().ToLowerInvariant();
        if (pattern.Length == 0) return false;
        if (IpNetwork.TryParse(pattern, out var pn))
            return IpNetwork.TryParse(value, out var vn) && pn.Contains(vn);
        if (IpNetwork.TryParse(value, out _)) return false;
        if (pattern.Contains('*'))
        {
            var rx = "^" + System.Text.RegularExpressions.Regex.Escape(pattern).Replace("\\*", ".*") + "$";
            return System.Text.RegularExpressions.Regex.IsMatch(value, rx);
        }
        return DomainNormalizer.IsCoveredBySuffix(value, pattern.TrimStart('.'));
    }
}
