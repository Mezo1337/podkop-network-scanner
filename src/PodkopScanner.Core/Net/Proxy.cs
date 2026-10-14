using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace PodkopScanner.Core.Net;

public enum ProxyKind { Socks5 = 0, Http = 1, Https = 2 }

/// <summary>Источник подключения: напрямую или через пользовательский прокси.</summary>
public sealed class RouteSettings
{
    public bool UseProxy { get; set; }
    public ProxyKind Kind { get; set; } = ProxyKind.Socks5;
    public string Host { get; set; } = "127.0.0.1";
    public int Port { get; set; } = 1080;
    public string? User { get; set; }
    /// <summary>Пароль в памяти. На диск сохраняется только в зашифрованном виде (DPAPI).</summary>
    [System.Text.Json.Serialization.JsonIgnore] public string? Password { get; set; }
    public string? PasswordProtected { get; set; }

    public bool HasAuth => !string.IsNullOrEmpty(User);

    public string Scheme => Kind switch { ProxyKind.Socks5 => "socks5", ProxyKind.Http => "http", _ => "https" };

    /// <summary>Описание маршрута без пароля — сохраняется вместе с наблюдениями.</summary>
    public string Describe() => UseProxy ? $"{Scheme}://{(HasAuth ? User + "@" : "")}{HostForUri}:{Port}" : "direct";

    private string HostForUri => IPAddress.TryParse(Host, out var ip) && ip.AddressFamily == AddressFamily.InterNetworkV6 ? $"[{Host}]" : Host;

    public Uri ProxyUri => new($"{Scheme}://{HostForUri}:{Port}");

    /// <summary>Разбор ссылки вида socks5://user:pass@127.0.0.1:1080, http://host:3128, https://host:443.</summary>
    public static bool TryParseUrl(string text, out RouteSettings result, out string error)
    {
        result = new RouteSettings(); error = "";
        text = text.Trim();
        if (!text.Contains("://")) { error = "Ссылка должна начинаться с socks5://, http:// или https://"; return false; }
        if (!Uri.TryCreate(text, UriKind.Absolute, out var u)) { error = "Некорректная ссылка"; return false; }
        result.Kind = u.Scheme.ToLowerInvariant() switch
        {
            "socks5" or "socks5h" or "socks" => ProxyKind.Socks5,
            "http" => ProxyKind.Http,
            "https" => ProxyKind.Https,
            _ => (ProxyKind)(-1),
        };
        if ((int)result.Kind < 0) { error = $"Тип прокси «{u.Scheme}» не поддерживается (нужен SOCKS5, HTTP или HTTPS)"; return false; }
        result.Host = u.Host.Trim('[', ']');
        result.Port = u.IsDefaultPort || u.Port <= 0 ? (result.Kind == ProxyKind.Socks5 ? 1080 : result.Kind == ProxyKind.Http ? 8080 : 443) : u.Port;
        if (!string.IsNullOrEmpty(u.UserInfo))
        {
            var parts = u.UserInfo.Split(':', 2);
            result.User = Uri.UnescapeDataString(parts[0]);
            if (parts.Length > 1) result.Password = Uri.UnescapeDataString(parts[1]);
        }
        result.UseProxy = true;
        return true;
    }

    public RouteSettings Clone() => (RouteSettings)MemberwiseClone();

    /// <summary>HttpClient, который реально ходит через выбранный маршрут (или строго напрямую).</summary>
    public HttpClient CreateHttpClient(TimeSpan timeout)
    {
        var h = new SocketsHttpHandler
        {
            ConnectTimeout = TimeSpan.FromSeconds(Math.Min(15, timeout.TotalSeconds)),
            AutomaticDecompression = DecompressionMethods.All,
            PooledConnectionLifetime = TimeSpan.FromMinutes(2),
        };
        if (UseProxy)
        {
            var wp = new WebProxy(ProxyUri) { BypassProxyOnLocal = false };
            if (HasAuth) wp.Credentials = new NetworkCredential(User, Password ?? "");
            h.Proxy = wp; h.UseProxy = true;
        }
        else h.UseProxy = false; // «напрямую» — игнорируем и системный прокси Windows
        var c = new HttpClient(h) { Timeout = timeout };
        c.DefaultRequestHeaders.UserAgent.ParseAdd("PodkopNetworkScanner/1.0");
        return c;
    }
}

/// <summary>Установка TCP-туннеля к host:port через SOCKS5 (RFC 1928/1929) или HTTP CONNECT.</summary>
public static class ProxyTunnel
{
    public static async Task<Stream> ConnectAsync(RouteSettings route, string host, int port, CancellationToken ct)
    {
        if (!route.UseProxy)
        {
            var direct = new TcpClient();
            await direct.ConnectAsync(host, port, ct);
            return direct.GetStream();
        }
        var tcp = new TcpClient { NoDelay = true };
        try
        {
            await tcp.ConnectAsync(route.Host, route.Port, ct);
        }
        catch (SocketException ex)
        {
            tcp.Dispose();
            throw new ProxyException($"Прокси {route.Host}:{route.Port} недоступен: {ex.SocketErrorCode}", ex);
        }
        Stream s = tcp.GetStream();
        try
        {
            if (route.Kind == ProxyKind.Https)
            {
                var ssl = new System.Net.Security.SslStream(s, false);
                await ssl.AuthenticateAsClientAsync(new System.Net.Security.SslClientAuthenticationOptions { TargetHost = route.Host }, ct);
                s = ssl;
            }
            if (route.Kind == ProxyKind.Socks5) await Socks5HandshakeAsync(s, route.User, route.Password, host, port, ct);
            else await HttpConnectAsync(s, route, host, port, ct);
            return s;
        }
        catch
        {
            s.Dispose(); tcp.Dispose();
            throw;
        }
    }

    public static async Task Socks5HandshakeAsync(Stream s, string? user, string? pass, string host, int port, CancellationToken ct)
    {
        bool auth = !string.IsNullOrEmpty(user);
        await s.WriteAsync(auth ? new byte[] { 5, 2, 0, 2 } : new byte[] { 5, 1, 0 }, ct);
        var two = await ReadExactAsync(s, 2, ct);
        if (two[0] != 5) throw new ProxyException("Сервер не является SOCKS5-прокси");
        if (two[1] == 0xFF) throw new ProxyException("SOCKS5: ни один метод аутентификации не принят");
        if (two[1] == 2)
        {
            if (!auth) throw new ProxyException("SOCKS5-прокси требует логин и пароль");
            var u = Encoding.UTF8.GetBytes(user!); var p = Encoding.UTF8.GetBytes(pass ?? "");
            var req = new byte[3 + u.Length + p.Length];
            req[0] = 1; req[1] = (byte)u.Length; u.CopyTo(req, 2); req[2 + u.Length] = (byte)p.Length; p.CopyTo(req, 3 + u.Length);
            await s.WriteAsync(req, ct);
            var ar = await ReadExactAsync(s, 2, ct);
            if (ar[1] != 0) throw new ProxyException("SOCKS5: неверный логин или пароль");
        }
        var ms = new MemoryStream();
        ms.Write(new byte[] { 5, 1, 0 });
        if (IPAddress.TryParse(host, out var ip))
        {
            ms.WriteByte(ip.AddressFamily == AddressFamily.InterNetworkV6 ? (byte)4 : (byte)1);
            ms.Write(ip.GetAddressBytes());
        }
        else
        {
            var hb = Encoding.ASCII.GetBytes(host);
            ms.WriteByte(3); ms.WriteByte((byte)hb.Length); ms.Write(hb); // имя разрешается на стороне прокси
        }
        var pb = new byte[2]; BinaryPrimitives.WriteUInt16BigEndian(pb, (ushort)port); ms.Write(pb);
        await s.WriteAsync(ms.ToArray(), ct);
        var head = await ReadExactAsync(s, 4, ct);
        if (head[1] != 0) throw new ProxyException("SOCKS5: отказ в соединении — " + Socks5Error(head[1]));
        int skip = head[3] switch { 1 => 4, 4 => 16, 3 => (await ReadExactAsync(s, 1, ct))[0], _ => 0 };
        await ReadExactAsync(s, skip + 2, ct);
    }

    private static async Task HttpConnectAsync(Stream s, RouteSettings r, string host, int port, CancellationToken ct)
    {
        var target = IPAddress.TryParse(host, out var ip) && ip.AddressFamily == AddressFamily.InterNetworkV6 ? $"[{host}]:{port}" : $"{host}:{port}";
        var sb = new StringBuilder($"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
        if (r.HasAuth) sb.Append("Proxy-Authorization: Basic ").Append(Convert.ToBase64String(Encoding.UTF8.GetBytes($"{r.User}:{r.Password}"))).Append("\r\n");
        sb.Append("\r\n");
        await s.WriteAsync(Encoding.ASCII.GetBytes(sb.ToString()), ct);
        var resp = new StringBuilder();
        var one = new byte[1];
        while (!resp.ToString().EndsWith("\r\n\r\n"))
        {
            if (await s.ReadAsync(one, ct) == 0) throw new ProxyException("HTTP-прокси закрыл соединение");
            resp.Append((char)one[0]);
            if (resp.Length > 8192) throw new ProxyException("Слишком длинный ответ HTTP-прокси");
        }
        var status = resp.ToString().Split(' ', 3);
        if (status.Length < 2 || status[1] != "200")
            throw new ProxyException("HTTP-прокси отказал в CONNECT: " + resp.ToString().Split('\r')[0]);
    }

    public static async Task<byte[]> ReadExactAsync(Stream s, int n, CancellationToken ct)
    {
        var buf = new byte[n]; int got = 0;
        while (got < n)
        {
            int r = await s.ReadAsync(buf.AsMemory(got), ct);
            if (r == 0) throw new ProxyException("Соединение с прокси неожиданно закрыто");
            got += r;
        }
        return buf;
    }

    private static string Socks5Error(byte c) => c switch
    {
        1 => "общая ошибка сервера", 2 => "запрещено правилами", 3 => "сеть недоступна", 4 => "узел недоступен",
        5 => "соединение отклонено", 6 => "истёк TTL", 7 => "команда не поддерживается", 8 => "тип адреса не поддерживается",
        _ => "код " + c,
    };
}

public sealed class ProxyException(string message, Exception? inner = null) : Exception(message, inner);

/// <summary>
/// Локальный SOCKS5-мост без аутентификации → вышестоящий SOCKS5 с логином/паролем.
/// Нужен потому, что Chromium не поддерживает аутентификацию SOCKS5-прокси, а Playwright
/// передаёт ему прокси как есть. Слушает только 127.0.0.1 на случайном порту.
/// </summary>
public sealed class LocalSocksBridge : IAsyncDisposable
{
    private readonly RouteSettings _upstream;
    private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource _cts = new();
    private Task? _loop;

    public LocalSocksBridge(RouteSettings upstream) => _upstream = upstream;

    public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;

    public void Start()
    {
        _listener.Start();
        _loop = Task.Run(AcceptLoop);
    }

    private async Task AcceptLoop()
    {
        while (!_cts.IsCancellationRequested)
        {
            TcpClient c;
            try { c = await _listener.AcceptTcpClientAsync(_cts.Token); }
            catch { break; }
            _ = Task.Run(() => Handle(c));
        }
    }

    private async Task Handle(TcpClient client)
    {
        using var _ = client;
        var ct = _cts.Token;
        try
        {
            var s = client.GetStream();
            var h = await ProxyTunnel.ReadExactAsync(s, 2, ct);
            await ProxyTunnel.ReadExactAsync(s, h[1], ct);
            await s.WriteAsync(new byte[] { 5, 0 }, ct);
            var req = await ProxyTunnel.ReadExactAsync(s, 4, ct);
            if (req[1] != 1) { await s.WriteAsync(new byte[] { 5, 7, 0, 1, 0, 0, 0, 0, 0, 0 }, ct); return; }
            string host = req[3] switch
            {
                1 => new IPAddress(await ProxyTunnel.ReadExactAsync(s, 4, ct)).ToString(),
                4 => new IPAddress(await ProxyTunnel.ReadExactAsync(s, 16, ct)).ToString(),
                3 => Encoding.ASCII.GetString(await ProxyTunnel.ReadExactAsync(s, (await ProxyTunnel.ReadExactAsync(s, 1, ct))[0], ct)),
                _ => throw new ProxyException("bad atyp"),
            };
            int port = BinaryPrimitives.ReadUInt16BigEndian(await ProxyTunnel.ReadExactAsync(s, 2, ct));
            Stream up;
            try { up = await ProxyTunnel.ConnectAsync(_upstream, host, port, ct); }
            catch { await s.WriteAsync(new byte[] { 5, 5, 0, 1, 0, 0, 0, 0, 0, 0 }, ct); return; }
            await using var __ = up;
            await s.WriteAsync(new byte[] { 5, 0, 0, 1, 0, 0, 0, 0, 0, 0 }, ct);
            var a = s.CopyToAsync(up, ct);
            var b = up.CopyToAsync(s, ct);
            await Task.WhenAny(a, b);
        }
        catch { /* соединение браузера закрыто */ }
    }

    public async ValueTask DisposeAsync()
    {
        _cts.Cancel();
        _listener.Stop();
        if (_loop != null) try { await _loop; } catch { }
        _cts.Dispose();
    }
}
