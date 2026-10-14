using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using PodkopScanner.Core.Export;
using PodkopScanner.Core.Net;

namespace PodkopScanner.Core.Settings;

public enum BrowserChoice { BundledChromium = 0, Edge = 1, Chrome = 2 }

public sealed class AppSettings
{
    public RouteSettings Route { get; set; } = new();
    public DnsSettings Dns { get; set; } = new();
    public ExportOptions Export { get; set; } = new();

    public BrowserChoice Browser { get; set; } = BrowserChoice.BundledChromium;
    public int AutoCrawlMaxPages { get; set; } = 10;
    public int AutoCrawlDelaySeconds { get; set; } = 3;

    public bool IncludeRelatedFolderProcesses { get; set; }
    public bool FlushDnsCacheBeforeMonitoring { get; set; } = true;
    public bool ShowUndeterminedConnections { get; set; } = true;

    public bool AutoRefreshEnabled { get; set; }
    public int AutoRefreshHours { get; set; } = 24;
    public int RefreshConcurrency { get; set; } = 4;
    public int RefreshDelayMs { get; set; } = 150;

    public string[] ExternalIpServices { get; set; } = RouteChecker.DefaultIpServices;
    public string? SingBoxPath { get; set; }

    public int FreshDays { get; set; } = 60;

    [JsonIgnore] public string? FilePath { get; private set; }

    public static string DataDirectory
    {
        get
        {
            // Портативный режим: если рядом с exe есть файл portable.txt — данные хранятся рядом.
            var exeDir = AppContext.BaseDirectory;
            if (File.Exists(Path.Combine(exeDir, "portable.txt"))) return Path.Combine(exeDir, "data");
            return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PodkopNetworkScanner");
        }
    }

    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true, Converters = { new JsonStringEnumConverter() } };

    public static AppSettings Load(string? path = null)
    {
        path ??= Path.Combine(DataDirectory, "settings.json");
        AppSettings s;
        try
        {
            s = File.Exists(path) ? JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(path), Json) ?? new() : new();
        }
        catch (JsonException)
        {
            File.Copy(path, path + ".bad", true);
            s = new();
        }
        s.FilePath = path;
        s.Route.Password = Unprotect(s.Route.PasswordProtected);
        return s;
    }

    public void Save()
    {
        FilePath ??= Path.Combine(DataDirectory, "settings.json");
        Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
        Route.PasswordProtected = Protect(Route.Password);
        var tmp = FilePath + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(this, Json));
        File.Move(tmp, FilePath, true); // атомарная замена — файл не повреждается при сбое
    }

    /// <summary>Шифрование средствами Windows (DPAPI, область текущего пользователя).</summary>
    public static string? Protect(string? plain)
    {
        if (string.IsNullOrEmpty(plain)) return null;
        var data = ProtectedData.Protect(Encoding.UTF8.GetBytes(plain), Encoding.UTF8.GetBytes("PodkopScanner.Proxy"), DataProtectionScope.CurrentUser);
        return Convert.ToBase64String(data);
    }

    public static string? Unprotect(string? b64)
    {
        if (string.IsNullOrEmpty(b64)) return null;
        try
        {
            return Encoding.UTF8.GetString(ProtectedData.Unprotect(Convert.FromBase64String(b64), Encoding.UTF8.GetBytes("PodkopScanner.Proxy"), DataProtectionScope.CurrentUser));
        }
        catch (CryptographicException) { return null; }
    }

    /// <summary>Сериализация маршрута проекта (без пароля).</summary>
    public static string SerializeRoute(RouteSettings r) => JsonSerializer.Serialize(r, Json);
    public static RouteSettings? DeserializeRoute(string? json)
    {
        if (string.IsNullOrEmpty(json)) return null;
        try { var r = JsonSerializer.Deserialize<RouteSettings>(json, Json); if (r != null) r.Password = Unprotect(r.PasswordProtected); return r; }
        catch { return null; }
    }
}
