using System.Buffers.Binary;
using System.Net;
using System.Text;
using Microsoft.Win32;

namespace PodkopScanner.Core.Net;

/// <summary>Системный прокси Windows (Параметры → Сеть → Прокси), который используют браузеры и многие программы.</summary>
public static class SystemProxy
{
    public sealed record Endpoint(string Scheme, string Host, int Port);

    /// <summary>Читает HKCU\…\Internet Settings (ProxyEnable/ProxyServer). Ничего не изменяет.</summary>
    public static List<Endpoint> Get()
    {
        var list = new List<Endpoint>();
        try
        {
            using var k = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings");
            if (k?.GetValue("ProxyEnable") is not int en || en == 0) return list;
            if (k.GetValue("ProxyServer") is not string server || server.Length == 0) return list;
            list.AddRange(Parse(server));
        }
        catch { }
        return list;
    }

    /// <summary>Форматы: "127.0.0.1:10809" или "http=h:p;https=h:p;socks=h:p".</summary>
    public static IEnumerable<Endpoint> Parse(string server)
    {
        foreach (var part in server.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var scheme = "http"; var hp = part;
            var eq = part.IndexOf('=');
            if (eq > 0) { scheme = part[..eq].ToLowerInvariant(); hp = part[(eq + 1)..]; }
            if (hp.Contains("://")) hp = hp[(hp.IndexOf("://", StringComparison.Ordinal) + 3)..];
            var c = hp.LastIndexOf(':');
            if (c <= 0 || !int.TryParse(hp[(c + 1)..].TrimEnd('/'), out var port)) continue;
            yield return new Endpoint(scheme, hp[..c].Trim('[', ']'), port);
        }
    }

    /// <summary>Маршрут для браузера через системный прокси (HTTP или SOCKS).</summary>
    public static RouteSettings? ToRoute()
    {
        var eps = Get();
        var ep = eps.FirstOrDefault(e => e.Scheme is "http" or "https") ?? eps.FirstOrDefault(e => e.Scheme == "socks");
        if (ep == null) return null;
        return new RouteSettings { UseProxy = true, Kind = ep.Scheme == "socks" ? ProxyKind.Socks5 : ProxyKind.Http, Host = ep.Host, Port = ep.Port };
    }

    public static bool IsLocal(Endpoint e) => e.Host is "localhost" || (IPAddress.TryParse(e.Host, out var ip) && IPAddress.IsLoopback(ip));
}

/// <summary>
/// Разбор первого запроса клиента к прокси: HTTP CONNECT / абсолютный URI, SOCKS4/4a, SOCKS5.
/// Позволяет узнать исходное назначение программы, работающей через локальный прокси-клиент.
/// </summary>
public static class ProxyRequestParser
{
    public sealed record Target(string Host, int Port, string Kind);

    public static Target? TryParse(ReadOnlySpan<byte> p)
    {
        if (p.Length < 7) return null;
        // SOCKS5: запрос CONNECT/UDP ASSOCIATE: VER=5 CMD RSV=0 ATYP …
        if (p[0] == 5 && p[1] is 1 or 3 && p[2] == 0)
        {
            int atyp = p[3];
            if (atyp == 1 && p.Length >= 10) return new(new IPAddress(p.Slice(4, 4)).ToString(), BinaryPrimitives.ReadUInt16BigEndian(p[8..]), p[1] == 3 ? "SOCKS5 UDP" : "SOCKS5");
            if (atyp == 4 && p.Length >= 22) return new(new IPAddress(p.Slice(4, 16)).ToString(), BinaryPrimitives.ReadUInt16BigEndian(p[20..]), p[1] == 3 ? "SOCKS5 UDP" : "SOCKS5");
            if (atyp == 3)
            {
                int len = p[4];
                if (p.Length >= 5 + len + 2 && len > 0)
                    return new(Encoding.ASCII.GetString(p.Slice(5, len)), BinaryPrimitives.ReadUInt16BigEndian(p[(5 + len)..]), p[1] == 3 ? "SOCKS5 UDP" : "SOCKS5");
            }
            return null;
        }
        // SOCKS4 / SOCKS4a: VER=4 CMD=1 PORT(2) IP(4) USERID\0 [HOST\0]
        if (p[0] == 4 && p[1] == 1 && p.Length >= 9)
        {
            int port = BinaryPrimitives.ReadUInt16BigEndian(p[2..]);
            var ip = p.Slice(4, 4);
            int z = p[8..].IndexOf((byte)0);
            if (ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] != 0 && z >= 0)
            {
                var rest = p[(9 + z)..];
                int z2 = rest.IndexOf((byte)0);
                if (z2 > 0) return new(Encoding.ASCII.GetString(rest[..z2]), port, "SOCKS4a");
            }
            return new(new IPAddress(ip).ToString(), port, "SOCKS4");
        }
        // HTTP-прокси
        var lineEnd = p.IndexOf((byte)'\r');
        if (lineEnd < 0) lineEnd = Math.Min(p.Length, 2048);
        var line = Encoding.ASCII.GetString(p[..lineEnd]);
        var parts = line.Split(' ');
        if (parts.Length < 3 || !parts[2].StartsWith("HTTP/")) return null;
        if (parts[0] == "CONNECT")
        {
            var hp = parts[1];
            var c = hp.LastIndexOf(':');
            if (c > 0 && int.TryParse(hp[(c + 1)..], out var port)) return new(hp[..c].Trim('[', ']'), port, "HTTP CONNECT");
            return null;
        }
        if (Uri.TryCreate(parts[1], UriKind.Absolute, out var u) && u.Scheme is "http" or "https")
            return new(u.Host.Trim('[', ']'), u.Port, "HTTP-прокси");
        return null;
    }
}
