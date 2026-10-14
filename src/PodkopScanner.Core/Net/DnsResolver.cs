using System.Buffers.Binary;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;

namespace PodkopScanner.Core.Net;

public enum DnsMode
{
    System = 0,   // системный DNS Windows (всегда напрямую)
    Udp = 1,      // выбранный DNS-сервер по UDP/53 (всегда напрямую — UDP через SOCKS5 обычно не поддерживается)
    Tcp = 2,      // выбранный DNS-сервер по TCP/53 — через выбранный маршрут (SOCKS5/HTTP CONNECT)
    DoH = 3,      // DNS-over-HTTPS (RFC 8484) — через выбранный маршрут
}

public sealed class DnsSettings
{
    public DnsMode Mode { get; set; } = DnsMode.System;
    public string Server { get; set; } = "1.1.1.1";
    public string DohUrl { get; set; } = "https://cloudflare-dns.com/dns-query";
    public bool QueryIPv6 { get; set; } = true;
    public int TimeoutSeconds { get; set; } = 8;
}

public sealed record DnsResult(
    string Name, List<IPAddress> Addresses, List<string> Cnames, string Method, string? Error, int RCode, uint MinTtl)
{
    public bool NxDomain => RCode == 3;
    public bool Ok => Error == null;
}

/// <summary>
/// Разрешение имён с явным указанием способа и маршрута. Результат DNS никогда не выдаётся за
/// IP фактического соединения — он хранится с методом <c>DnsResolve</c> и описанием резолвера.
/// </summary>
public sealed class DnsResolver : IDisposable
{
    private readonly DnsSettings _s;
    private readonly RouteSettings _route;
    private readonly HttpClient? _http;
    private int _id = Random.Shared.Next(0, 65535);

    public DnsResolver(DnsSettings settings, RouteSettings route)
    {
        _s = settings; _route = route;
        if (_s.Mode == DnsMode.DoH) _http = route.CreateHttpClient(TimeSpan.FromSeconds(_s.TimeoutSeconds));
    }

    /// <summary>Человекочитаемое описание способа и маршрута разрешения.</summary>
    public string Describe() => _s.Mode switch
    {
        DnsMode.System => "системный DNS Windows, напрямую",
        DnsMode.Udp => $"DNS {_s.Server} по UDP, напрямую",
        DnsMode.Tcp => $"DNS {_s.Server} по TCP, маршрут: {_route.Describe()}",
        _ => $"DoH {_s.DohUrl}, маршрут: {_route.Describe()}",
    };

    /// <summary>Предупреждение, если выбранный способ DNS не идёт через прокси, хотя маршрут — прокси.</summary>
    public string? RouteWarning() => _route.UseProxy && _s.Mode is DnsMode.System or DnsMode.Udp
        ? "Выбран прокси, но DNS-проверка выполняется напрямую (системный DNS или UDP не проходят через прокси). " +
          "Для разрешения имён через прокси выберите DoH или DNS по TCP."
        : null;

    public async Task<DnsResult> ResolveAsync(string name, CancellationToken ct)
    {
        try
        {
            if (_s.Mode == DnsMode.System)
            {
                try
                {
                    using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    cts.CancelAfter(TimeSpan.FromSeconds(_s.TimeoutSeconds));
                    var family = _s.QueryIPv6 ? AddressFamily.Unspecified : AddressFamily.InterNetwork;
                    var addrs = await Dns.GetHostAddressesAsync(name, family, cts.Token);
                    return new DnsResult(name, addrs.Select(IpNetwork.Unmap).Distinct().ToList(), new(), Describe(), null, 0, 0);
                }
                catch (SocketException ex) when (ex.SocketErrorCode == SocketError.HostNotFound)
                {
                    return new DnsResult(name, new(), new(), Describe(), "Домен не найден (NXDOMAIN)", 3, 0);
                }
                catch (SocketException ex) when (ex.SocketErrorCode == SocketError.NoData)
                {
                    return new DnsResult(name, new(), new(), Describe(), null, 0, 0);
                }
            }

            var types = _s.QueryIPv6 ? new[] { DnsType.A, DnsType.AAAA } : new[] { DnsType.A };
            var all = new List<IPAddress>(); var cn = new List<string>(); int rcode = 0; uint minTtl = uint.MaxValue;
            foreach (var t in types)
            {
                var r = await QueryAsync(name, t, ct);
                if (r.RCode == 3) rcode = 3;
                else if (r.RCode != 0 && rcode == 0) rcode = r.RCode;
                foreach (var a in r.Answers)
                {
                    if (a.Address != null) { all.Add(a.Address); minTtl = Math.Min(minTtl, a.Ttl); }
                    else if (a.Type == DnsType.CNAME) cn.Add(a.Data);
                }
            }
            string? err = rcode switch { 0 => null, 3 => "Домен не найден (NXDOMAIN)", 2 => "Ошибка DNS-сервера (SERVFAIL)", 5 => "DNS-сервер отказал (REFUSED)", _ => $"DNS RCODE {rcode}" };
            return new DnsResult(name, all.Distinct().ToList(), cn.Distinct().ToList(), Describe(), all.Count > 0 ? null : err, rcode, minTtl == uint.MaxValue ? 0 : minTtl);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return new DnsResult(name, new(), new(), Describe(), "Таймаут DNS-запроса", -1, 0);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return new DnsResult(name, new(), new(), Describe(), ex.Message, -1, 0);
        }
    }

    public async Task<DnsResponse> QueryAsync(string name, DnsType type, CancellationToken ct)
    {
        var id = (ushort)Interlocked.Increment(ref _id);
        var q = DnsMessage.BuildQuery(name, type, id);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(TimeSpan.FromSeconds(_s.TimeoutSeconds));
        switch (_s.Mode)
        {
            case DnsMode.DoH:
            {
                using var content = new ByteArrayContent(q);
                content.Headers.ContentType = new MediaTypeHeaderValue("application/dns-message");
                using var req = new HttpRequestMessage(HttpMethod.Post, _s.DohUrl) { Content = content };
                req.Headers.Accept.ParseAdd("application/dns-message");
                using var resp = await _http!.SendAsync(req, cts.Token);
                resp.EnsureSuccessStatusCode();
                return DnsMessage.Parse(await resp.Content.ReadAsByteArrayAsync(cts.Token));
            }
            case DnsMode.Tcp:
                return await QueryTcpAsync(q, _route, _s.Server, cts.Token);
            default:
            {
                var r = await QueryUdpAsync(q, id, _s.Server, cts.Token);
                return r.Truncated ? await QueryTcpAsync(q, new RouteSettings(), _s.Server, cts.Token) : r;
            }
        }
    }

    private static async Task<DnsResponse> QueryUdpAsync(byte[] q, ushort id, string server, CancellationToken ct)
    {
        var ep = new IPEndPoint(IPAddress.Parse(server), 53);
        using var udp = new UdpClient(ep.AddressFamily);
        await udp.SendAsync(q, ep, ct);
        while (true)
        {
            var res = await udp.ReceiveAsync(ct);
            if (!res.RemoteEndPoint.Address.Equals(ep.Address)) continue;
            var r = DnsMessage.Parse(res.Buffer);
            if (r.Id == id && r.IsResponse) return r;
        }
    }

    private static async Task<DnsResponse> QueryTcpAsync(byte[] q, RouteSettings route, string server, CancellationToken ct)
    {
        await using var s = await ProxyTunnel.ConnectAsync(route, server, 53, ct);
        var framed = new byte[q.Length + 2];
        BinaryPrimitives.WriteUInt16BigEndian(framed, (ushort)q.Length);
        q.CopyTo(framed, 2);
        await s.WriteAsync(framed, ct);
        var lenBuf = await ProxyTunnel.ReadExactAsync(s, 2, ct);
        var body = await ProxyTunnel.ReadExactAsync(s, BinaryPrimitives.ReadUInt16BigEndian(lenBuf), ct);
        return DnsMessage.Parse(body);
    }

    public void Dispose() => _http?.Dispose();
}
