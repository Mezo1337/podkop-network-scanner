using System.Diagnostics;
using System.Net;
using System.Text.Json;

namespace PodkopScanner.Core.Net;

public sealed record RouteCheckResult(bool Ok, string? ExternalIp, long LatencyMs, string Route, string? Error, string? ServiceUsed);

/// <summary>Проверка доступности маршрута и определение внешнего IP, под которым видны запросы.</summary>
public static class RouteChecker
{
    public static readonly string[] DefaultIpServices =
    {
        "https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com",
    };

    public static async Task<RouteCheckResult> CheckAsync(RouteSettings route, IEnumerable<string>? services, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        string? lastErr = null;
        if (route.UseProxy)
        {
            // Сначала — сам прокси: TCP + рукопожатие, чтобы дать понятную причину ошибки.
            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(TimeSpan.FromSeconds(10));
                await using var s = await ProxyTunnel.ConnectAsync(route, "api.ipify.org", 443, cts.Token);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                return new(false, null, sw.ElapsedMilliseconds, route.Describe(), "Прокси не ответил за 10 секунд", null);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                return new(false, null, sw.ElapsedMilliseconds, route.Describe(), ex.Message, null);
            }
        }
        using var http = route.CreateHttpClient(TimeSpan.FromSeconds(12));
        foreach (var svc in services ?? DefaultIpServices)
        {
            try
            {
                sw.Restart();
                var text = (await http.GetStringAsync(svc, ct)).Trim();
                if (IPAddress.TryParse(text, out var ip))
                    return new(true, ip.ToString(), sw.ElapsedMilliseconds, route.Describe(), null, svc);
                lastErr = $"{svc} вернул не IP-адрес";
            }
            catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
            {
                lastErr = $"{svc}: {Flatten(ex)}";
            }
        }
        return new(false, null, sw.ElapsedMilliseconds, route.Describe(), lastErr ?? "Нет ответа", null);
    }

    public static string Flatten(Exception ex)
    {
        var parts = new List<string>();
        for (var e = ex; e != null; e = e.InnerException) if (!parts.Contains(e.Message)) parts.Add(e.Message);
        return string.Join(" → ", parts);
    }
}

public sealed record AsnInfo(string Asn, string Prefix, string Country, string Name);

/// <summary>
/// ASN и оператор через DNS-сервис Team Cymru (origin.asn.cymru.com / asn.cymru.com, TXT).
/// Выполняется только по явному действию пользователя: адреса передаются этому сервису в DNS-запросах.
/// </summary>
public sealed class AsnLookup : IDisposable
{
    private readonly DnsResolver _dns;
    private readonly Dictionary<string, string> _names = new();

    public AsnLookup(DnsSettings dns, RouteSettings route)
    {
        // Системный резолвер Windows не умеет TXT-запросы — используем DoH по тому же маршруту.
        var s = dns.Mode is DnsMode.System ? new DnsSettings { Mode = DnsMode.DoH, DohUrl = dns.DohUrl } : dns;
        _dns = new DnsResolver(s, route);
    }

    public async Task<AsnInfo?> LookupAsync(IPAddress ip, CancellationToken ct)
    {
        ip = IpNetwork.Unmap(ip);
        string q;
        if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            q = string.Join('.', ip.GetAddressBytes().Reverse()) + ".origin.asn.cymru.com";
        else
        {
            var hex = Convert.ToHexString(ip.GetAddressBytes()).ToLowerInvariant();
            q = string.Join('.', hex.Reverse()) + ".origin6.asn.cymru.com";
        }
        var r = await _dns.QueryAsync(q, DnsType.TXT, ct);
        var txt = r.Answers.FirstOrDefault(a => a.Type == DnsType.TXT)?.Data;
        if (txt == null) return null;
        // "13335 | 104.16.0.0/13 | US | arin | 2014-03-28"
        var p = txt.Split('|').Select(x => x.Trim()).ToArray();
        if (p.Length < 3) return null;
        var asn = p[0].Split(' ')[0];
        if (!_names.TryGetValue(asn, out var name))
        {
            var nr = await _dns.QueryAsync($"AS{asn}.asn.cymru.com", DnsType.TXT, ct);
            var nt = nr.Answers.FirstOrDefault(a => a.Type == DnsType.TXT)?.Data;
            name = nt?.Split('|').LastOrDefault()?.Trim() ?? "";
            _names[asn] = name;
        }
        return new AsnInfo("AS" + asn, p[1], p[2], name);
    }

    public void Dispose() => _dns.Dispose();
}

/// <summary>Официально опубликованный провайдером список диапазонов.</summary>
public sealed record OfficialProvider(string Id, string Name, string[] Urls, bool Shared, string Note);

public sealed record ProviderRange(OfficialProvider Provider, IpNetwork Net);

/// <summary>
/// Загрузка официальных списков диапазонов. «Общие» провайдеры (CDN/облака) используются только для
/// пометки IP — их диапазоны НЕ предлагаются к добавлению, т.к. в них работают тысячи посторонних сайтов.
/// Диапазоны «собственных» сетей сервиса (Telegram, GitHub) предлагаются с подтверждением пользователя.
/// </summary>
public static class OfficialRanges
{
    public static readonly OfficialProvider[] Providers =
    {
        new("cloudflare", "Cloudflare", new[] { "https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6" }, true,
            "Общий CDN: за этими адресами работают миллионы сайтов"),
        new("google", "Google (сервисы и облако)", new[] { "https://www.gstatic.com/ipranges/goog.json" }, true,
            "Включает Google Cloud клиентов"),
        new("aws", "Amazon AWS / CloudFront", new[] { "https://ip-ranges.amazonaws.com/ip-ranges.json" }, true,
            "Общее облако"),
        new("fastly", "Fastly", new[] { "https://api.fastly.com/public-ip-list" }, true, "Общий CDN"),
        new("telegram", "Telegram", new[] { "https://core.telegram.org/resources/cidr.txt" }, false,
            "Собственная сеть Telegram"),
        new("github", "GitHub", new[] { "https://api.github.com/meta" }, false,
            "Собственные адреса GitHub (web, api, git, packages, pages)"),
    };

    public static async Task<List<IpNetwork>> FetchAsync(OfficialProvider p, HttpClient http, CancellationToken ct)
    {
        var result = new List<IpNetwork>();
        foreach (var url in p.Urls)
        {
            var text = await http.GetStringAsync(url, ct);
            result.AddRange(Parse(p.Id, text));
        }
        return result.Distinct().OrderBy(n => n).ToList();
    }

    public static IEnumerable<IpNetwork> Parse(string providerId, string text)
    {
        IEnumerable<string> raw;
        switch (providerId)
        {
            case "google":
            {
                using var d = JsonDocument.Parse(text);
                raw = d.RootElement.GetProperty("prefixes").EnumerateArray()
                    .Select(e => e.TryGetProperty("ipv4Prefix", out var v4) ? v4.GetString() : e.TryGetProperty("ipv6Prefix", out var v6) ? v6.GetString() : null)
                    .Where(s => s != null).ToList()!;
                break;
            }
            case "aws":
            {
                using var d = JsonDocument.Parse(text);
                var l = d.RootElement.GetProperty("prefixes").EnumerateArray().Select(e => e.GetProperty("ip_prefix").GetString()!).ToList();
                if (d.RootElement.TryGetProperty("ipv6_prefixes", out var v6))
                    l.AddRange(v6.EnumerateArray().Select(e => e.GetProperty("ipv6_prefix").GetString()!));
                raw = l;
                break;
            }
            case "fastly":
            {
                using var d = JsonDocument.Parse(text);
                var l = d.RootElement.GetProperty("addresses").EnumerateArray().Select(e => e.GetString()!).ToList();
                if (d.RootElement.TryGetProperty("ipv6_addresses", out var v6)) l.AddRange(v6.EnumerateArray().Select(e => e.GetString()!));
                raw = l;
                break;
            }
            case "github":
            {
                using var d = JsonDocument.Parse(text);
                var l = new List<string>();
                foreach (var key in new[] { "web", "api", "git", "packages", "pages" })
                    if (d.RootElement.TryGetProperty(key, out var arr) && arr.ValueKind == JsonValueKind.Array)
                        l.AddRange(arr.EnumerateArray().Select(e => e.GetString()!));
                raw = l;
                break;
            }
            default:
                raw = text.Split(new[] { '\n', '\r', ' ', ',' }, StringSplitOptions.RemoveEmptyEntries);
                break;
        }
        foreach (var s in raw)
            if (IpNetwork.TryParse(s, out var n)) yield return n;
    }

    public static ProviderRange? FindContaining(IpNetwork ip, IEnumerable<ProviderRange> ranges) =>
        ranges.Where(r => r.Net.Contains(ip)).OrderByDescending(r => r.Net.Prefix).FirstOrDefault();
}
