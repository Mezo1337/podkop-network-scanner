namespace PodkopScanner.Core.Monitoring;

public enum ProcessRelation { None, Selected, SameExe, Child, RelatedFolder, SharedService }

public sealed record TrackedProcess(int Pid, string Name, string? Path, DateTime? Created, ProcessRelation Relation, string Explanation);

/// <summary>
/// Определяет, относится ли PID к выбранной программе. Связь подтверждается только:
/// • совпадением PID с выбранным процессом;
/// • совпадением пути образа с выбранным EXE;
/// • происхождением от отслеживаемого процесса (родитель в дереве, родитель запущен раньше потомка — защита от повторного использования PID);
/// • (по желанию) расположением образа в папке программы — это помечается отдельно как «связанный».
/// Общие службы Windows (svchost, System и т.п.) помечаются как «неопределённые».
/// </summary>
public sealed class ProcessTracker
{
    private readonly string? _exePath;
    private readonly string? _folder;
    private readonly int? _rootPid;
    private readonly bool _includeChildren;
    private readonly bool _includeFolder;
    private readonly Dictionary<int, TrackedProcess> _tracked = new();
    private readonly Dictionary<int, (DateTime? created, ProcessRelation rel)> _negative = new();
    private Dictionary<int, ProcessInfo.Proc> _snapshot = new();
    private DateTime _snapshotTime;
    private readonly object _lock = new();

    public static readonly HashSet<string> SharedProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "System", "svchost.exe", "lsass.exe", "services.exe", "wininit.exe", "dllhost.exe", "smss.exe", "csrss.exe",
        "Registry", "MsMpEng.exe", "SearchHost.exe", "backgroundTaskHost.exe", "RuntimeBroker.exe", "taskhostw.exe",
        "WmiPrvSE.exe", "spoolsv.exe", "explorer.exe",
    };

    public event Action<TrackedProcess>? ProcessAdded;

    public ProcessTracker(string? exePath, int? rootPid, bool includeChildren, bool includeFolder)
    {
        _exePath = exePath is null ? null : System.IO.Path.GetFullPath(exePath);
        _folder = _exePath is null ? null : System.IO.Path.GetDirectoryName(_exePath)!.TrimEnd('\\') + "\\";
        _rootPid = rootPid;
        _includeChildren = includeChildren;
        _includeFolder = includeFolder;
        RefreshSnapshot(force: true);
        if (rootPid is int p)
        {
            var (path, created) = ProcessInfo.Details(p);
            Add(new TrackedProcess(p, NameOf(p, path), path, created, ProcessRelation.Selected, "выбранный процесс"));
        }
        // Уже запущенные экземпляры выбранного EXE и их потомки.
        ScanForNew();
    }

    public IReadOnlyCollection<TrackedProcess> Tracked { get { lock (_lock) return _tracked.Values.ToList(); } }

    private string NameOf(int pid, string? path) =>
        path != null ? System.IO.Path.GetFileName(path) : _snapshot.TryGetValue(pid, out var p) ? p.Name : $"PID {pid}";

    private void Add(TrackedProcess t)
    {
        lock (_lock) _tracked[t.Pid] = t;
        ProcessAdded?.Invoke(t);
    }

    public void RefreshSnapshot(bool force = false)
    {
        if (!force && DateTime.UtcNow - _snapshotTime < TimeSpan.FromMilliseconds(300)) return;
        var s = ProcessInfo.Snapshot();
        lock (_lock) { _snapshot = s; _snapshotTime = DateTime.UtcNow; }
    }

    /// <summary>Периодический поиск новых экземпляров и потомков (вызывается раз в секунду).</summary>
    public void ScanForNew()
    {
        RefreshSnapshot(force: true);
        Dictionary<int, ProcessInfo.Proc> snap;
        lock (_lock) snap = _snapshot;
        foreach (var p in snap.Values)
        {
            bool known; lock (_lock) known = _tracked.ContainsKey(p.Pid) || _negative.ContainsKey(p.Pid);
            if (known) continue;
            bool candidate = (_exePath != null && string.Equals(p.Name, System.IO.Path.GetFileName(_exePath), StringComparison.OrdinalIgnoreCase))
                             || (_includeChildren && IsTrackedPid(p.ParentPid));
            if (candidate) Resolve(p.Pid);
        }
    }

    private bool IsTrackedPid(int pid) { lock (_lock) return _tracked.ContainsKey(pid); }

    /// <summary>Классификация PID из сетевого события.</summary>
    public TrackedProcess? Resolve(int pid)
    {
        if (pid <= 0) return null;
        lock (_lock)
        {
            if (_tracked.TryGetValue(pid, out var t)) return t;
        }
        var (path, created) = ProcessInfo.Details(pid);
        lock (_lock)
        {
            if (_negative.TryGetValue(pid, out var neg) && neg.created == created)
                return neg.rel == ProcessRelation.SharedService ? new TrackedProcess(pid, NameOf(pid, path), path, created, neg.rel, "общая служба Windows") : null;
        }
        if (!_snapshot.ContainsKey(pid)) RefreshSnapshot();
        var name = NameOf(pid, path);

        if (_exePath != null && path != null && string.Equals(path, _exePath, StringComparison.OrdinalIgnoreCase))
            return AddNew(pid, name, path, created, ProcessRelation.SameExe, "тот же EXE");

        if (_includeChildren)
        {
            Dictionary<int, ProcessInfo.Proc> snap; lock (_lock) snap = _snapshot;
            int cur = pid; DateTime? childCreated = created;
            for (int depth = 0; depth < 12 && snap.TryGetValue(cur, out var info); depth++)
            {
                var parent = info.ParentPid;
                if (parent <= 0 || parent == cur) break;
                TrackedProcess? anc; lock (_lock) _tracked.TryGetValue(parent, out anc);
                if (anc != null && (anc.Created == null || childCreated == null || anc.Created <= childCreated))
                    return AddNew(pid, name, path, created, ProcessRelation.Child, depth == 0 ? $"дочерний процесс {anc.Name}" : $"потомок {anc.Name}");
                var (_, pc) = ProcessInfo.Details(parent);
                if (pc != null && childCreated != null && pc > childCreated) break; // PID родителя переиспользован
                cur = parent; childCreated = pc;
            }
        }

        if (_includeFolder && _folder != null && path != null && path.StartsWith(_folder, StringComparison.OrdinalIgnoreCase))
            return AddNew(pid, name, path, created, ProcessRelation.RelatedFolder, "процесс из папки программы");

        var rel = pid == 4 || SharedProcesses.Contains(name) ? ProcessRelation.SharedService : ProcessRelation.None;
        lock (_lock) _negative[pid] = (created, rel);
        return rel == ProcessRelation.SharedService ? new TrackedProcess(pid, name, path, created, rel, "общая служба Windows") : null;
    }

    private TrackedProcess AddNew(int pid, string name, string? path, DateTime? created, ProcessRelation rel, string why)
    {
        var t = new TrackedProcess(pid, name, path, created, rel, why);
        Add(t);
        return t;
    }
}
