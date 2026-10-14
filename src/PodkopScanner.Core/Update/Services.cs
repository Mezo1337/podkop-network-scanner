using System.Collections.Concurrent;
using System.Net;
using System.Text;
using System.Threading.Channels;
using PodkopScanner.Core.Data;
using PodkopScanner.Core.Model;
using PodkopScanner.Core.Net;

namespace PodkopScanner.Core.Update;

/// <summary>
/// Сессия сканирования: принимает находки от анализаторов, пакетно пишет их в базу (не чаще раза в 0,5 с),
/// параллельно разрешает новые домены через выбранный DNS (с ограничением частоты).
/// </summary>
public sealed class ScanSession : IAsyncDisposable
{
    private readonly Repository _repo;
    private readonly Channel<Finding> _in = Channel.CreateUnbounded<Finding>();
    private readonly Channel<string> _dnsQueue = Channel.CreateUnbounded<string>();
    private readonly ConcurrentDictionary<string, byte> _resolved = new();
    private readonly DnsResolver? _resolver;
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _writer, _dnsWorker;
    private readonly int _dnsDelayMs;

    public long ProjectId { get; }
    public long ScanId { get; }
    public int Total { get; private set; }
    public event Action<RecordResult>? Flushed;
    public event Action<string>? Log;

    public ScanSession(Repository repo, long projectId, string kind, RouteSettings route, DnsSettings? dns, int dnsDelayMs = 150)
    {
        _repo = repo; ProjectId = projectId; _dnsDelayMs = dnsDelayMs;
        ScanId = repo.StartScan(projectId, kind, route.Describe());
        if (dns != null)
        {
            _resolver = new DnsResolver(dns, route);
        }
        _writer = Task.Run(WriterLoop);
        _dnsWorker = Task.Run(DnsLoop);
    }

    public string? DnsDescription => _resolver?.Describe();
    public string? DnsRouteWarning => _resolver?.RouteWarning();

    public void Add(Finding f)
    {
        _in.Writer.TryWrite(f);
        if (_resolver != null && f.Kind == EntryKind.Domain && _resolved.TryAdd(f.Value, 0)) _dnsQueue.Writer.TryWrite(f.Value);
    }

    private async Task WriterLoop()
    {
        var batch = new List<Finding>();
        while (await _in.Reader.WaitToReadAsync())
        {
            while (_in.Reader.TryRead(out var f)) batch.Add(f);
            if (batch.Count == 0) continue;
            try
            {
                var r = _repo.RecordFindings(ProjectId, ScanId, batch);
                Total += batch.Count;
                Flushed?.Invoke(r);
            }
            catch (Exception ex) { Log?.Invoke("Ошибка записи в базу: " + ex.Message); }
            batch.Clear();
            try { await Task.Delay(500, _cts.Token); } catch (OperationCanceledException) { }
        }
    }

    private async Task DnsLoop()
    {
        if (_resolver == null) return;
        try
        {
            await foreach (var d in _dnsQueue.Reader.ReadAllAsync(_cts.Token))
            {
                var r = await _resolver.ResolveAsync(d, _cts.Token);
                foreach (var ip in r.Addresses)
                    _in.Writer.TryWrite(new Finding
                    {
                        Value = ip.ToString(), Kind = ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? EntryKind.IPv6 : EntryKind.IPv4,
                        Method = ObservationMethod.DnsResolve, Detail = r.Method, LinkedDomain = d, LinkMethod = "DNS: " + r.Method,
                    });
                await Task.Delay(_dnsDelayMs, _cts.Token);
            }
        }
        catch (OperationCanceledException) { }
    }

    public async Task<string> FinishAsync(string summary)
    {
        _dnsQueue.Writer.TryComplete();
        try { await _dnsWorker.WaitAsync(TimeSpan.FromSeconds(30)); } catch { _cts.Cancel(); }
        _in.Writer.TryComplete();
        _cts.Cancel();
        await _writer;
        _repo.FinishScan(ScanId, summary);
        return summary;
    }

    public async ValueTask DisposeAsync()
    {
        _cts.Cancel();
        _in.Writer.TryComplete(); _dnsQueue.Writer.TryComplete();
        try { await _writer; } catch { }
        _resolver?.Dispose();
        _cts.Dispose();
    }
}

public sealed class RefreshReport
{
    public int DomainsChecked { get; set; }
    public int DomainsFailed { get; set; }
    public List<(string domain, List<string> added, List<string> missing, string? error)> Changes { get; } = new();
    public List<string> OfficialChanges { get; } = new();
    public string Resolver { get; set; } = "";
    public string? RouteWarning { get; set; }

    public string ToText()
    {
        var sb = new StringBuilder();
        sb.AppendLine($"Проверено доменов: {DomainsChecked}, с ошибками: {DomainsFailed}. Способ: {Resolver}.");
        if (RouteWarning != null) sb.AppendLine("⚠ " + RouteWarning);
        foreach (var c in Changes)
        {
            if (c.error != null) { sb.AppendLine($"• {c.domain}: {c.error}"); continue; }
            if (c.added.Count == 0 && c.missing.Count == 0) continue;
            sb.AppendLine($"• {c.domain}");
            foreach (var a in c.added) sb.AppendLine($"    + {a} (новый в DNS-ответе)");
            foreach (var m in c.missing) sb.AppendLine($"    − {m} (нет в текущем ответе — не удалён, помечен)");
        }
        if (OfficialChanges.Count > 0) { sb.AppendLine(); sb.AppendLine("Официальные списки провайдеров:"); foreach (var o in OfficialChanges) sb.AppendLine("• " + o); }
        if (Changes.All(c => c.error == null && c.added.Count == 0 && c.missing.Count == 0) && OfficialChanges.Count == 0)
            sb.AppendLine("Изменений в DNS-ответах нет.");
        return sb.ToString().TrimEnd();
    }
}

/// <summary>
/// «Обновить адреса»: повторное DNS-разрешение доменов проекта и сравнение с прошлым.
/// Ничего не удаляется автоматически. Отсутствие IP в одном ответе (ротация CDN, GeoDNS) лишь
/// увеличивает счётчик пропусков; статус «не подтверждён» — после 2 проверок подряд.
/// ICMP/ping не используется вовсе.
/// </summary>
public sealed class Refresher
{
    private readonly Repository _repo;
    public Refresher(Repository repo) => _repo = repo;

    public async Task<RefreshReport> RefreshAsync(long projectId, RouteSettings route, DnsSettings dns, int concurrency, int delayMs,
        IProgress<string>? progress, CancellationToken ct)
    {
        var report = new RefreshReport();
        var entries = _repo.GetEntries(projectId);
        var domains = entries.Where(e => e.IsDomain && !e.Disabled).ToList();
        var ipEntries = entries.Where(e => e.Kind is EntryKind.IPv4 or EntryKind.IPv6).ToDictionary(e => e.Value);

        // Предыдущие DNS-связи домен → IP.
        var prevLinks = new Dictionary<string, HashSet<string>>();
        foreach (var e in ipEntries.Values)
            foreach (var part in e.LinkedNames.Split(", ", StringSplitOptions.RemoveEmptyEntries))
            {
                var i = part.IndexOf(" [", StringComparison.Ordinal);
                if (i < 0 || !part[(i + 2)..].StartsWith("DNS")) continue;
                var dom = part[..i];
                if (!prevLinks.TryGetValue(dom, out var set)) prevLinks[dom] = set = new();
                set.Add(e.Value);
            }

        using var resolver = new DnsResolver(dns, route);
        report.Resolver = resolver.Describe();
        report.RouteWarning = resolver.RouteWarning();
        var scanId = _repo.StartScan(projectId, "refresh", route.Describe());
        var findings = new ConcurrentBag<Finding>();
        var seenNow = new ConcurrentDictionary<string, byte>();
        int done = 0;
        using var sem = new SemaphoreSlim(Math.Max(1, concurrency));
        var tasks = domains.Select(async e =>
        {
            await sem.WaitAsync(ct);
            try
            {
                var r = await resolver.ResolveAsync(e.Value, ct);
                Interlocked.Increment(ref done);
                progress?.Report($"DNS: {done}/{domains.Count} — {e.Value}");
                var ips = r.Addresses.Select(a => a.ToString()).ToHashSet();
                foreach (var ip in ips) seenNow.TryAdd(ip, 0);
                var prev = prevLinks.GetValueOrDefault(e.Value) ?? new HashSet<string>();
                lock (report)
                {
                    report.DomainsChecked++;
                    if (!r.Ok && r.Addresses.Count == 0) report.DomainsFailed++;
                    report.Changes.Add((e.Value, ips.Except(prev).OrderBy(x => x).ToList(), prev.Except(ips).OrderBy(x => x).ToList(),
                        r.Ok || r.Addresses.Count > 0 ? null : r.Error));
                }
                _repo.SetMissStreak(e.Id, r.NxDomain ? e.DnsMissStreak + 1 : (r.Addresses.Count > 0 ? 0 : e.DnsMissStreak));
                findings.Add(new Finding
                {
                    Value = e.Value, Kind = EntryKind.Domain, Method = ObservationMethod.DnsResolve, Route = route.Describe(),
                    Detail = r.Addresses.Count > 0 ? $"OK: {r.Addresses.Count} адрес(ов), {r.Method}" : $"ошибка: {r.Error ?? "нет A/AAAA-записей"}",
                });
                foreach (var ip in r.Addresses)
                    findings.Add(new Finding
                    {
                        Value = ip.ToString(), Kind = ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? EntryKind.IPv6 : EntryKind.IPv4,
                        Method = ObservationMethod.DnsResolve, Detail = r.Method, LinkedDomain = e.Value, LinkMethod = "DNS: " + r.Method, Route = route.Describe(),
                    });
                if (delayMs > 0) await Task.Delay(delayMs, ct);
            }
            finally { sem.Release(); }
        }).ToList();
        await Task.WhenAll(tasks);

        // IP, которые ранее приходили в DNS-ответах, но сейчас отсутствуют: увеличиваем счётчик пропусков.
        var everDns = prevLinks.Values.SelectMany(x => x).ToHashSet();
        foreach (var ip in everDns)
            if (ipEntries.TryGetValue(ip, out var e))
                _repo.SetMissStreak(e.Id, seenNow.ContainsKey(ip) ? 0 : e.DnsMissStreak + 1);

        _repo.RecordFindings(projectId, scanId, findings);
        _repo.RecomputeEntries(projectId);
        report.Changes.Sort((a, b) => string.CompareOrdinal(a.domain, b.domain));
        _repo.FinishScan(scanId, $"Проверено {report.DomainsChecked} доменов, ошибок {report.DomainsFailed}");
        var p = _repo.GetProject(projectId)!;
        p.LastRefresh = DateTime.UtcNow;
        _repo.UpdateProject(p);
        return report;
    }

    /// <summary>
    /// Загрузка официальных списков диапазонов, сохранение снимков и пометка IP проекта.
    /// Для «собственных» сетей сервиса (не общих CDN) создаются предложения-подсети с низким приоритетом:
    /// по умолчанию они НЕ включены в экспорт.
    /// </summary>
    public async Task<List<string>> CheckOfficialRangesAsync(long projectId, RouteSettings route, IProgress<string>? progress, CancellationToken ct)
    {
        var notes = new List<string>();
        using var http = route.CreateHttpClient(TimeSpan.FromSeconds(30));
        var all = new List<ProviderRange>();
        foreach (var prov in OfficialRanges.Providers)
        {
            progress?.Report("Загрузка официального списка: " + prov.Name);
            try
            {
                var nets = await OfficialRanges.FetchAsync(prov, http, ct);
                var (added, removed, changed) = _repo.SaveProviderSnapshot(prov.Id, nets);
                if (changed && (added.Count + removed.Count) > 0 && _repo.GetLatestProviderSnapshot(prov.Id) != null && !(added.Count == nets.Count))
                    notes.Add($"{prov.Name}: +{added.Count} / −{removed.Count} диапазонов" +
                              (added.Count > 0 ? $" (новые: {string.Join(", ", added.Take(5))}{(added.Count > 5 ? "…" : "")})" : "") +
                              (removed.Count > 0 ? $" (удалены: {string.Join(", ", removed.Take(5))}{(removed.Count > 5 ? "…" : "")})" : ""));
                all.AddRange(nets.Select(n => new ProviderRange(prov, n)));
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                notes.Add($"{prov.Name}: не удалось загрузить ({RouteChecker.Flatten(ex)}). Использую сохранённый снимок, если он есть.");
                var snap = _repo.GetLatestProviderSnapshot(prov.Id);
                if (snap != null) all.AddRange(snap.Value.nets.Select(n => new ProviderRange(prov, n)));
            }
        }

        var scanId = _repo.StartScan(projectId, "official", route.Describe());
        var findings = new List<Finding>();
        foreach (var e in _repo.GetEntries(projectId).Where(e => e.Kind is EntryKind.IPv4 or EntryKind.IPv6))
        {
            var net = IpNetwork.Parse(e.Value);
            var pr = OfficialRanges.FindContaining(net, all);
            var label = pr == null ? "" : pr.Provider.Shared ? $"{pr.Provider.Name} — общая сеть ({pr.Net})" : $"{pr.Provider.Name} ({pr.Net})";
            if (label != e.Provider) _repo.SetProvider(e.Id, label);
            if (pr != null && !pr.Provider.Shared && e.Trust >= Trust.Medium)
            {
                findings.Add(new Finding
                {
                    Value = pr.Net.ToString(true), Kind = pr.Net.IsV6 ? EntryKind.Cidr6 : EntryKind.Cidr4, Method = ObservationMethod.OfficialRange,
                    Detail = $"официальный список {pr.Provider.Name}; содержит наблюдавшийся IP {e.Value}", Route = route.Describe(),
                    Category = ResourceCategory.Unknown, CategoryReason = pr.Provider.Note,
                });
            }
        }
        // Уже имеющиеся в проекте подсети, подтверждённые текущим официальным списком.
        foreach (var e in _repo.GetEntries(projectId).Where(e => e.Kind is EntryKind.Cidr4 or EntryKind.Cidr6))
        {
            var net = IpNetwork.Parse(e.Value);
            var exact = all.FirstOrDefault(r => r.Net == net);
            if (exact != null)
                findings.Add(new Finding { Value = e.Value, Kind = e.Kind, Method = ObservationMethod.OfficialRange, Detail = $"есть в официальном списке {exact.Provider.Name}", Route = route.Describe() });
        }
        _repo.RecordFindings(projectId, scanId, findings);
        _repo.RecomputeEntries(projectId);
        _repo.FinishScan(scanId, $"Официальные списки: {findings.Count} совпадений");
        if (findings.Count > 0) notes.Add($"Найдено совпадений с официальными диапазонами: {findings.Count}. Подсети добавлены как предложения и не включены в экспорт без вашего решения.");
        return notes;
    }
}
