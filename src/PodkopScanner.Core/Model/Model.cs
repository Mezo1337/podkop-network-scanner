namespace PodkopScanner.Core.Model;

public enum ProjectType { Website = 0, Program = 1, Mixed = 2 }

public enum EntryKind { Domain = 0, IPv4 = 1, IPv6 = 2, Cidr4 = 3, Cidr6 = 4 }

/// <summary>Уровень достоверности. Вычисляется детерминированно из методов наблюдения (см. TrustPolicy).</summary>
public enum Trust { Low = 0, Medium = 1, High = 2 }

public enum EntryStatus
{
    ConfirmedConnection = 0,   // Подтверждён текущим соединением
    FromCurrentDns = 1,        // Получен из актуального DNS-ответа
    ConfirmedOfficial = 2,     // Подтверждён официальным источником
    PreviouslySeen = 3,        // Ранее наблюдался
    NotReconfirmed = 4,        // Не подтверждён повторной проверкой
    NeedsManualCheck = 5,      // Требует ручной проверки
}

/// <summary>Способ, которым адрес был обнаружен. Каждый метод имеет фиксированную базовую достоверность.</summary>
public enum ObservationMethod
{
    BrowserRequest = 0,     // хост из сетевого запроса контролируемого браузера
    BrowserServerAddr = 1,  // IP фактического соединения браузера (Response.ServerAddr, только без прокси)
    BrowserWebSocket = 2,
    BrowserRedirect = 3,
    FlowEstablished = 10,   // WinDivert FLOW: поток процесса (PID из ядра)
    SocketConnect = 11,     // WinDivert SOCKET: вызов connect() процесса
    IpHelperTable = 12,     // таблица TCP-соединений Windows с PID (опрос, без драйвера)
    TlsSni = 13,            // имя из TLS ClientHello потока процесса
    ProcessDnsEtw = 14,     // DNS-запрос процесса (ETW Microsoft-Windows-DNS-Client)
    ProcessDnsSniff = 15,   // DNS-ответ на сокет процесса (сниффинг UDP/53)
    RelatedProcessFlow = 16,// поток процесса из папки программы (связь по пути, не по дереву)
    ProxyRequest = 17,      // назначение из запроса процесса к локальному прокси (HTTP CONNECT / SOCKS)
    DnsResolve = 20,        // отдельное DNS-разрешение программой-сканером
    OfficialRange = 30,     // официальный опубликованный диапазон провайдера
    Import = 40,
    ProxyLog = 41,          // журнал sing-box / tcpdump / tshark / PCAPdroid
    Manual = 50,
}

public enum ResourceCategory
{
    Unknown = 0, MainSite, Api, Cdn, Auth, Media, WebSocket, ThirdParty, AdsAnalytics,
    GameServer, Voice, Update, Telemetry, Consent
}

public sealed class Project
{
    public long Id { get; set; }
    public string Name { get; set; } = "";
    public ProjectType Type { get; set; }
    public string Source { get; set; } = "";          // URL или путь к EXE
    public string? ProxyJson { get; set; }             // настройки маршрута проекта (без пароля)
    public bool AutoIncludeIps { get; set; }
    public DateTime Created { get; set; }
    public DateTime Updated { get; set; }
    public DateTime? LastRefresh { get; set; }
    public string Notes { get; set; } = "";
    public override string ToString() => Name;
}

public sealed class Entry
{
    public long Id { get; set; }
    public long ProjectId { get; set; }
    public string Value { get; set; } = "";
    public EntryKind Kind { get; set; }
    public DateTime FirstSeen { get; set; }
    public DateTime LastSeen { get; set; }
    public DateTime? LastConfirmed { get; set; }
    public Trust Trust { get; set; }
    public EntryStatus Status { get; set; }
    public ResourceCategory Category { get; set; }
    public string CategoryReason { get; set; } = "";
    public bool Include { get; set; }
    public bool Disabled { get; set; }
    public bool ManualConfirmed { get; set; }
    public bool Imported { get; set; }
    public string Sources { get; set; } = "";       // краткая сводка методов
    public string ProcessInfo { get; set; } = "";   // EXE/PID
    public string Protocols { get; set; } = "";     // TCP/UDP:порты
    public string LinkedNames { get; set; } = "";   // для IP: связанные домены и метод связи
    public string Asn { get; set; } = "";
    public string Provider { get; set; } = "";      // официальный провайдер-владелец диапазона
    public int DnsMissStreak { get; set; }
    public string Note { get; set; } = "";

    public bool IsDomain => Kind == EntryKind.Domain;
    public bool IsIp => Kind is EntryKind.IPv4 or EntryKind.IPv6 or EntryKind.Cidr4 or EntryKind.Cidr6;
}

/// <summary>Единичное наблюдение, поступающее из анализаторов в хранилище.</summary>
public sealed record Finding
{
    public required string Value { get; init; }
    public required EntryKind Kind { get; init; }
    public required ObservationMethod Method { get; init; }
    public DateTime Time { get; init; } = DateTime.UtcNow;
    public string Detail { get; init; } = "";        // тип ресурса, резолвер, комментарий
    public string? ProcessName { get; init; }
    public int? Pid { get; init; }
    public string? Protocol { get; init; }            // TCP / UDP / QUIC / WS
    public int? Port { get; init; }
    public string? LinkedDomain { get; init; }        // для IP — достоверно связанный домен
    public string? LinkMethod { get; init; }
    public string Route { get; init; } = "direct";
    public ResourceCategory Category { get; init; }
    public string CategoryReason { get; init; } = "";
    public bool Undetermined { get; init; }           // нельзя достоверно привязать к программе
}

public sealed class Observation
{
    public long Id { get; set; }
    public long EntryId { get; set; }
    public long? ScanId { get; set; }
    public DateTime Time { get; set; }
    public ObservationMethod Method { get; set; }
    public string Detail { get; set; } = "";
    public string? ProcessName { get; set; }
    public int? Pid { get; set; }
    public string? Protocol { get; set; }
    public int? Port { get; set; }
    public string Route { get; set; } = "";
}

public sealed class Scan
{
    public long Id { get; set; }
    public long ProjectId { get; set; }
    public string Kind { get; set; } = "";   // web / process / refresh / import
    public DateTime Started { get; set; }
    public DateTime? Finished { get; set; }
    public string Route { get; set; } = "";
    public string Summary { get; set; } = "";
}

public sealed class ListVersion
{
    public long Id { get; set; }
    public long ProjectId { get; set; }
    public DateTime Time { get; set; }
    public string Reason { get; set; } = "";
    public string DomainsText { get; set; } = "";
    public string SubnetsText { get; set; } = "";
    public string StateJson { get; set; } = "";
    public override string ToString() => $"{Time.ToLocalTime():dd.MM.yyyy HH:mm} — {Reason}";
}

public sealed class Exclusion
{
    public long Id { get; set; }
    public long? ProjectId { get; set; }   // null = глобальное
    public string Pattern { get; set; } = "";
    public bool IsWhitelist { get; set; }
}

public static class Ru
{
    public static string Of(Trust t) => t switch { Trust.High => "Высокая", Trust.Medium => "Средняя", _ => "Низкая" };

    public static string Of(EntryStatus s) => s switch
    {
        EntryStatus.ConfirmedConnection => "Подтверждён текущим соединением",
        EntryStatus.FromCurrentDns => "Получен из актуального DNS-ответа",
        EntryStatus.ConfirmedOfficial => "Подтверждён официальным источником",
        EntryStatus.PreviouslySeen => "Ранее наблюдался",
        EntryStatus.NotReconfirmed => "Не подтверждён повторной проверкой",
        _ => "Требует ручной проверки",
    };

    public static string Of(EntryKind k) => k switch
    {
        EntryKind.Domain => "Домен", EntryKind.IPv4 => "IPv4", EntryKind.IPv6 => "IPv6",
        EntryKind.Cidr4 => "CIDR v4", _ => "CIDR v6",
    };

    public static string Of(ProjectType t) => t switch
    {
        ProjectType.Website => "Сайт", ProjectType.Program => "Программа", _ => "Смешанный",
    };

    public static string Of(ResourceCategory c) => c switch
    {
        ResourceCategory.MainSite => "Основной сайт",
        ResourceCategory.Api => "API",
        ResourceCategory.Cdn => "CDN / статика",
        ResourceCategory.Auth => "Авторизация",
        ResourceCategory.Media => "Медиа / видео",
        ResourceCategory.WebSocket => "WebSocket",
        ResourceCategory.ThirdParty => "Сторонний сервис",
        ResourceCategory.AdsAnalytics => "Реклама / аналитика",
        ResourceCategory.GameServer => "Игровой сервер",
        ResourceCategory.Voice => "Голос / RTC",
        ResourceCategory.Update => "Обновления",
        ResourceCategory.Telemetry => "Телеметрия",
        ResourceCategory.Consent => "Cookie-баннер / согласие",
        _ => "Не определено",
    };

    public static string Of(ObservationMethod m) => m switch
    {
        ObservationMethod.BrowserRequest => "Browser: запрос",
        ObservationMethod.BrowserServerAddr => "Browser: IP соединения",
        ObservationMethod.BrowserWebSocket => "Browser: WebSocket",
        ObservationMethod.BrowserRedirect => "Browser: перенаправление",
        ObservationMethod.FlowEstablished => "Process: поток (WinDivert FLOW)",
        ObservationMethod.SocketConnect => "Process: connect (WinDivert SOCKET)",
        ObservationMethod.IpHelperTable => "Process: таблица TCP Windows",
        ObservationMethod.TlsSni => "Process: TLS SNI",
        ObservationMethod.ProcessDnsEtw => "Process: DNS (ETW)",
        ObservationMethod.ProcessDnsSniff => "Process: DNS-ответ (UDP/53)",
        ObservationMethod.RelatedProcessFlow => "Process: связанный процесс (папка)",
        ObservationMethod.ProxyRequest => "Process: запрос к локальному прокси",
        ObservationMethod.DnsResolve => "DNS",
        ObservationMethod.OfficialRange => "Официальный список",
        ObservationMethod.Import => "Import",
        ObservationMethod.ProxyLog => "Журнал прокси/роутера",
        _ => "Вручную",
    };
}
