using Microsoft.Data.Sqlite;

namespace PodkopScanner.Core.Data;

/// <summary>
/// Локальная база SQLite (WAL). При запуске проверяется целостность; повреждённый файл
/// переименовывается, а не удаляется, и создаётся новая база. Перед миграцией делается копия.
/// </summary>
public sealed class Database
{
    public const int SchemaVersion = 1;
    public string Path { get; }
    public string? RecoveryMessage { get; private set; }
    private readonly string _cs;

    public Database(string path)
    {
        Path = path;
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(path)!);
        _cs = new SqliteConnectionStringBuilder { DataSource = path, Mode = SqliteOpenMode.ReadWriteCreate, Cache = SqliteCacheMode.Private, Pooling = true }.ToString();
        Initialize();
    }

    public SqliteConnection Open()
    {
        var c = new SqliteConnection(_cs);
        c.Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;";
        cmd.ExecuteNonQuery();
        return c;
    }

    private void Initialize()
    {
        if (File.Exists(Path) && !IntegrityOk())
        {
            SqliteConnection.ClearAllPools();
            var bad = Path + $".corrupt-{DateTime.Now:yyyyMMdd-HHmmss}";
            File.Move(Path, bad);
            foreach (var ext in new[] { "-wal", "-shm" }) if (File.Exists(Path + ext)) File.Move(Path + ext, bad + ext);
            RecoveryMessage = $"База данных была повреждена и сохранена как {System.IO.Path.GetFileName(bad)}. Создана новая база.";
        }
        using var c = Open();
        Exec(c, "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;");
        var ver = Convert.ToInt32(Scalar(c, "PRAGMA user_version"));
        if (ver > SchemaVersion)
            throw new InvalidOperationException("База создана более новой версией программы. Обновите Podkop Network Scanner.");
        if (ver < SchemaVersion && ver > 0) Backup($"pre-migration-v{ver}");
        if (ver < 1) Migrate1(c);
    }

    private bool IntegrityOk()
    {
        try
        {
            using var c = Open();
            return (Scalar(c, "PRAGMA quick_check") as string) == "ok";
        }
        catch (SqliteException) { return false; }
    }

    private static void Migrate1(SqliteConnection c)
    {
        using var tx = c.BeginTransaction();
        Exec(c, tx, """
        CREATE TABLE IF NOT EXISTS projects(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            type INTEGER NOT NULL,
            source TEXT NOT NULL DEFAULT '',
            proxy_json TEXT,
            auto_include_ips INTEGER NOT NULL DEFAULT 0,
            created TEXT NOT NULL,
            updated TEXT NOT NULL,
            last_refresh TEXT,
            notes TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS scans(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            kind TEXT NOT NULL,
            started TEXT NOT NULL,
            finished TEXT,
            route TEXT NOT NULL DEFAULT '',
            summary TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS entries(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            value TEXT NOT NULL,
            kind INTEGER NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            last_confirmed TEXT,
            trust INTEGER NOT NULL DEFAULT 0,
            status INTEGER NOT NULL DEFAULT 3,
            category INTEGER NOT NULL DEFAULT 0,
            category_reason TEXT NOT NULL DEFAULT '',
            include INTEGER NOT NULL DEFAULT 0,
            include_set_by_user INTEGER NOT NULL DEFAULT 0,
            disabled INTEGER NOT NULL DEFAULT 0,
            manual INTEGER NOT NULL DEFAULT 0,
            imported INTEGER NOT NULL DEFAULT 0,
            asn TEXT NOT NULL DEFAULT '',
            provider TEXT NOT NULL DEFAULT '',
            dns_miss_streak INTEGER NOT NULL DEFAULT 0,
            note TEXT NOT NULL DEFAULT '',
            UNIQUE(project_id, value)
        );
        CREATE TABLE IF NOT EXISTS observations(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            entry_id INTEGER NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
            scan_id INTEGER NOT NULL DEFAULT 0,
            first_time TEXT NOT NULL,
            time TEXT NOT NULL,
            method INTEGER NOT NULL,
            detail TEXT NOT NULL DEFAULT '',
            process_name TEXT NOT NULL DEFAULT '',
            pid INTEGER NOT NULL DEFAULT 0,
            protocol TEXT NOT NULL DEFAULT '',
            port INTEGER NOT NULL DEFAULT 0,
            route TEXT NOT NULL DEFAULT '',
            hits INTEGER NOT NULL DEFAULT 1,
            UNIQUE(entry_id, scan_id, method, detail, process_name, pid, protocol, port, route)
        );
        CREATE INDEX IF NOT EXISTS ix_obs_entry ON observations(entry_id, time);
        CREATE TABLE IF NOT EXISTS ip_links(
            ip_entry_id INTEGER NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
            domain TEXT NOT NULL,
            method TEXT NOT NULL,
            time TEXT NOT NULL,
            UNIQUE(ip_entry_id, domain, method)
        );
        CREATE TABLE IF NOT EXISTS list_versions(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            time TEXT NOT NULL,
            reason TEXT NOT NULL,
            domains_text TEXT NOT NULL,
            subnets_text TEXT NOT NULL,
            state_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS exclusions(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER REFERENCES projects(id) ON DELETE CASCADE,
            pattern TEXT NOT NULL,
            whitelist INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS provider_snapshots(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            provider TEXT NOT NULL,
            time TEXT NOT NULL,
            hash TEXT NOT NULL,
            cidrs TEXT NOT NULL
        );
        PRAGMA user_version = 1;
        """);
        tx.Commit();
    }

    /// <summary>Горячая копия базы средствами SQLite (VACUUM INTO).</summary>
    public string Backup(string tag)
    {
        var dir = System.IO.Path.Combine(System.IO.Path.GetDirectoryName(Path)!, "backups");
        Directory.CreateDirectory(dir);
        var file = System.IO.Path.Combine(dir, $"podkop-scanner-{DateTime.Now:yyyyMMdd-HHmmss}-{tag}.db");
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "VACUUM INTO $f";
        cmd.Parameters.AddWithValue("$f", file);
        cmd.ExecuteNonQuery();
        // Храним не более 10 последних копий.
        foreach (var old in new DirectoryInfo(dir).GetFiles("*.db").OrderByDescending(f => f.CreationTimeUtc).Skip(10))
            try { old.Delete(); } catch { }
        return file;
    }

    internal static void Exec(SqliteConnection c, string sql) => Exec(c, null, sql);

    internal static void Exec(SqliteConnection c, SqliteTransaction? tx, string sql)
    {
        using var cmd = c.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = sql;
        cmd.ExecuteNonQuery();
    }

    internal static object? Scalar(SqliteConnection c, string sql)
    {
        using var cmd = c.CreateCommand();
        cmd.CommandText = sql;
        return cmd.ExecuteScalar();
    }
}
