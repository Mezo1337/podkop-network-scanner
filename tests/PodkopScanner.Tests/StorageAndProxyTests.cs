using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;
using PodkopScanner.Core.Data;
using PodkopScanner.Core.Export;
using PodkopScanner.Core.Model;
using PodkopScanner.Core.Net;
using PodkopScanner.Core.Settings;

namespace PodkopScanner.Tests;

public sealed class TempDb : IDisposable
{
    public string Dir { get; } = Path.Combine(Path.GetTempPath(), "pns-test-" + Guid.NewGuid().ToString("N"));
    public Database Db { get; }
    public Repository Repo { get; }
    public TempDb() { Db = new Database(Path.Combine(Dir, "t.db")); Repo = new Repository(Db); }
    public void Dispose() { Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools(); try { Directory.Delete(Dir, true); } catch { } }
}

public class RepositoryTests
{
    private static Finding F(string v, EntryKind k, ObservationMethod m, string? link = null, string? proc = null, int? pid = null) =>
        new() { Value = v, Kind = k, Method = m, LinkedDomain = link, LinkMethod = link != null ? "DNS: test" : null, ProcessName = proc, Pid = pid, Protocol = pid != null ? "UDP" : null, Port = pid != null ? 7777 : null };

    [Fact]
    public void RecordDeduplicatesAndFilters()
    {
        using var t = new TempDb();
        var p = t.Repo.CreateProject("Игра 1", ProjectType.Program, @"C:\Games\game.exe");
        var s = t.Repo.StartScan(p.Id, "process", "direct");
        var r = t.Repo.RecordFindings(p.Id, s, new[]
        {
            F("8.8.8.8", EntryKind.IPv4, ObservationMethod.FlowEstablished, proc: "game.exe", pid: 100),
            F("8.8.8.8", EntryKind.IPv4, ObservationMethod.FlowEstablished, proc: "game.exe", pid: 100),
            F("192.168.1.10", EntryKind.IPv4, ObservationMethod.FlowEstablished, proc: "game.exe", pid: 100),
            F("HTTPS://API.Game.COM/x", EntryKind.Domain, ObservationMethod.TlsSni),
            F("api.game.com", EntryKind.Domain, ObservationMethod.ProcessDnsEtw),
            F("printer.local", EntryKind.Domain, ObservationMethod.ProcessDnsEtw),
        });
        Assert.Equal(2, r.NewEntries);
        Assert.Equal(2, r.Skipped);
        var entries = t.Repo.GetEntries(p.Id);
        Assert.Equal(2, entries.Count);
        var ip = entries.Single(e => e.Value == "8.8.8.8");
        Assert.Equal(Trust.High, ip.Trust);
        Assert.Equal(EntryStatus.ConfirmedConnection, ip.Status);
        Assert.True(ip.Include); // для программ IP высокой достоверности включаются
        Assert.Contains("game.exe (100)", ip.ProcessInfo);
        Assert.Contains("UDP:7777", ip.Protocols);
        var obs = t.Repo.GetObservations(ip.Id);
        Assert.Single(obs);
    }

    [Fact]
    public void ImportedIsLowAndNotIncluded()
    {
        using var t = new TempDb();
        var p = t.Repo.CreateProject("Импорт", ProjectType.Website, "");
        var s = t.Repo.StartScan(p.Id, "import", "direct");
        t.Repo.RecordFindings(p.Id, s, new[] { F("discord.com", EntryKind.Domain, ObservationMethod.Import) });
        var e = t.Repo.GetEntries(p.Id).Single();
        Assert.Equal(Trust.Low, e.Trust);
        Assert.False(e.Include);
        Assert.True(e.Imported);
        Assert.Equal(EntryStatus.NeedsManualCheck, e.Status);
    }

    [Fact]
    public void BlacklistAndWhitelist()
    {
        using var t = new TempDb();
        var p = t.Repo.CreateProject("Сайт", ProjectType.Website, "https://example.com");
        t.Repo.AddExclusion(p.Id, "doubleclick.net", whitelist: false);
        t.Repo.AddExclusion(null, "10.0.0.0/8", whitelist: true);
        var s = t.Repo.StartScan(p.Id, "web", "direct");
        t.Repo.RecordFindings(p.Id, s, new[]
        {
            F("ad.doubleclick.net", EntryKind.Domain, ObservationMethod.BrowserRequest),
            F("10.1.2.3", EntryKind.IPv4, ObservationMethod.BrowserServerAddr),
        });
        var entries = t.Repo.GetEntries(p.Id);
        Assert.DoesNotContain(entries, e => e.Value.Contains("doubleclick"));
        Assert.Contains(entries, e => e.Value == "10.1.2.3" && e.Include);
    }

    [Fact]
    public void RefreshStatusesAndRollback()
    {
        using var t = new TempDb();
        var p = t.Repo.CreateProject("Сервис", ProjectType.Website, "https://example.com");
        var s1 = t.Repo.StartScan(p.Id, "refresh", "direct");
        t.Repo.RecordFindings(p.Id, s1, new[]
        {
            F("api.example.com", EntryKind.Domain, ObservationMethod.BrowserRequest),
            F("8.8.8.8", EntryKind.IPv4, ObservationMethod.DnsResolve, link: "api.example.com"),
        });
        var ip = t.Repo.GetEntries(p.Id).Single(e => e.Value == "8.8.8.8");
        Assert.Equal(EntryStatus.FromCurrentDns, ip.Status);
        Assert.Equal(Trust.Medium, ip.Trust);
        Assert.False(ip.Include); // DNS-IP сайта по умолчанию не включается

        var v1 = PodkopExporter.Build(t.Repo.GetEntries(p.Id), new ExportOptions());
        t.Repo.SaveVersion(p.Id, "v1", v1.DomainsText, v1.SubnetsText);

        // Второе обновление: IP пропал из ответа два раза подряд.
        t.Repo.SetMissStreak(ip.Id, 2);
        var s2 = t.Repo.StartScan(p.Id, "refresh", "direct");
        t.Repo.RecordFindings(p.Id, s2, new[] { F("8.8.4.4", EntryKind.IPv4, ObservationMethod.DnsResolve, link: "api.example.com") });
        t.Repo.RecomputeEntries(p.Id);
        var all = t.Repo.GetEntries(p.Id);
        Assert.Equal(EntryStatus.NotReconfirmed, all.Single(e => e.Value == "8.8.8.8").Status);
        Assert.Equal(EntryStatus.FromCurrentDns, all.Single(e => e.Value == "8.8.4.4").Status);
        // Запись не удалена автоматически.
        Assert.Contains(all, e => e.Value == "8.8.8.8");

        t.Repo.SetInclude(all.Where(e => e.IsIp).Select(e => e.Id), true);
        var v2 = PodkopExporter.Build(t.Repo.GetEntries(p.Id), new ExportOptions());
        Assert.Equal(2, v2.Subnets.Count);
        t.Repo.SaveVersion(p.Id, "v2", v2.DomainsText, v2.SubnetsText);
        var versions = t.Repo.GetVersions(p.Id);
        Assert.Equal(2, versions.Count);
        var diff = PodkopExporter.Diff(versions[1].DomainsText, versions[1].SubnetsText, versions[0].DomainsText, versions[0].SubnetsText);
        Assert.Equal(2, diff.AddedSubnets.Count);

        t.Repo.Rollback(versions.Single(v => v.Reason == "v1"));
        var back = PodkopExporter.Build(t.Repo.GetEntries(p.Id), new ExportOptions());
        Assert.Equal(v1.SubnetsText, back.SubnetsText);
        Assert.Equal(v1.DomainsText, back.DomainsText);
    }

    [Fact]
    public void MergedScansAccumulateEvidence()
    {
        using var t = new TempDb();
        var p = t.Repo.CreateProject("Игра", ProjectType.Program, "game.exe");
        for (int i = 0; i < 3; i++)
        {
            var s = t.Repo.StartScan(p.Id, "process", "direct");
            t.Repo.RecordFindings(p.Id, s, new[] { F($"9.9.9.{i + 1}", EntryKind.IPv4, ObservationMethod.FlowEstablished, proc: "game.exe", pid: 200 + i) });
            t.Repo.FinishScan(s, "ok");
        }
        var entries = t.Repo.GetEntries(p.Id);
        Assert.Equal(3, entries.Count);
        Assert.Equal(1, entries.Count(e => e.Status == EntryStatus.ConfirmedConnection)); // только последний скан «текущий»
        Assert.Equal(2, entries.Count(e => e.Status == EntryStatus.PreviouslySeen));
        Assert.All(entries, e => Assert.Equal(Trust.High, e.Trust));
        Assert.Equal(3, t.Repo.GetScans(p.Id).Count);
    }

    [Fact]
    public void PersistsAcrossReopen()
    {
        using var t = new TempDb();
        var p = t.Repo.CreateProject("Discord", ProjectType.Website, "https://discord.com");
        var repo2 = new Repository(new Database(t.Db.Path));
        Assert.Equal("Discord", repo2.GetProjects().Single().Name);
    }

    [Fact]
    public void CorruptDatabaseIsQuarantined()
    {
        var dir = Path.Combine(Path.GetTempPath(), "pns-corrupt-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, "x.db");
        File.WriteAllText(path, "это не база данных SQLite, а мусор ............................................");
        var db = new Database(path);
        Assert.NotNull(db.RecoveryMessage);
        Assert.Empty(new Repository(db).GetProjects());
        Assert.Single(Directory.GetFiles(dir, "x.db.corrupt-*"));
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        Directory.Delete(dir, true);
    }

    [Fact]
    public void ExclusionPatterns()
    {
        Assert.True(ExclusionMatcher.Matches("example.com", "a.example.com"));
        Assert.False(ExclusionMatcher.Matches("example.com", "notexample.com"));
        Assert.True(ExclusionMatcher.Matches("*.cdn.*", "x.cdn.net"));
        Assert.True(ExclusionMatcher.Matches("1.2.3.0/24", "1.2.3.4"));
        Assert.False(ExclusionMatcher.Matches("1.2.3.0/24", "1.2.4.4"));
    }

    [Fact]
    public void SettingsProtectPassword()
    {
        var path = Path.Combine(Path.GetTempPath(), "pns-settings-" + Guid.NewGuid().ToString("N") + ".json");
        var s = AppSettings.Load(path);
        s.Route = new RouteSettings { UseProxy = true, Host = "127.0.0.1", Port = 1080, User = "u", Password = "секрет-123" };
        s.Save();
        var raw = File.ReadAllText(path);
        Assert.DoesNotContain("секрет-123", raw);
        Assert.DoesNotContain("\"Password\"", raw);
        var s2 = AppSettings.Load(path);
        Assert.Equal("секрет-123", s2.Route.Password);
        File.Delete(path);
    }
}

/// <summary>Минимальный SOCKS5-сервер с логином/паролем для проверки, что трафик реально идёт через прокси.</summary>
public sealed class TestSocksServer : IDisposable
{
    private readonly TcpListener _l = new(IPAddress.Loopback, 0);
    private readonly IPEndPoint? _forwardTo;
    private readonly string _user, _pass;
    public List<string> Requested { get; } = new();
    public int Port => ((IPEndPoint)_l.LocalEndpoint).Port;

    /// <param name="forwardTo">null — настоящий прокси: соединяется с запрошенным адресом.</param>
    public TestSocksServer(IPEndPoint? forwardTo, string user, string pass)
    {
        _forwardTo = forwardTo; _user = user; _pass = pass;
        _l.Start();
        _ = Task.Run(async () =>
        {
            while (true)
            {
                TcpClient c;
                try { c = await _l.AcceptTcpClientAsync(); } catch { return; }
                _ = Task.Run(() => Handle(c));
            }
        });
    }

    private async Task Handle(TcpClient c)
    {
        using var _ = c;
        var s = c.GetStream();
        var h = await ProxyTunnel.ReadExactAsync(s, 2, default);
        var methods = await ProxyTunnel.ReadExactAsync(s, h[1], default);
        if (!methods.Contains((byte)2)) { await s.WriteAsync(new byte[] { 5, 0xFF }); return; }
        await s.WriteAsync(new byte[] { 5, 2 });
        var v = await ProxyTunnel.ReadExactAsync(s, 2, default);
        var u = Encoding.UTF8.GetString(await ProxyTunnel.ReadExactAsync(s, v[1], default));
        var pl = await ProxyTunnel.ReadExactAsync(s, 1, default);
        var p = Encoding.UTF8.GetString(await ProxyTunnel.ReadExactAsync(s, pl[0], default));
        if (u != _user || p != _pass) { await s.WriteAsync(new byte[] { 1, 1 }); return; }
        await s.WriteAsync(new byte[] { 1, 0 });
        var req = await ProxyTunnel.ReadExactAsync(s, 4, default);
        string host = req[3] switch
        {
            1 => new IPAddress(await ProxyTunnel.ReadExactAsync(s, 4, default)).ToString(),
            3 => Encoding.ASCII.GetString(await ProxyTunnel.ReadExactAsync(s, (await ProxyTunnel.ReadExactAsync(s, 1, default))[0], default)),
            _ => new IPAddress(await ProxyTunnel.ReadExactAsync(s, 16, default)).ToString(),
        };
        var port = BinaryPrimitives.ReadUInt16BigEndian(await ProxyTunnel.ReadExactAsync(s, 2, default));
        lock (Requested) Requested.Add($"{host}:{port}");
        using var up = new TcpClient();
        try
        {
            if (_forwardTo != null) await up.ConnectAsync(_forwardTo);
            else await up.ConnectAsync(host, port);
        }
        catch { await s.WriteAsync(new byte[] { 5, 4, 0, 1, 0, 0, 0, 0, 0, 0 }); return; }
        await s.WriteAsync(new byte[] { 5, 0, 0, 1, 0, 0, 0, 0, 0, 0 });
        var us = up.GetStream();
        await Task.WhenAny(s.CopyToAsync(us), us.CopyToAsync(s));
    }

    public void Dispose() => _l.Stop();
}

public class ProxyRoutingTests
{
    /// <summary>HTTP-сервер, отвечающий «внешним IP» — имитация api.ipify.org.</summary>
    private static (TcpListener, Task) FakeIpService(string answer)
    {
        var l = new TcpListener(IPAddress.Loopback, 0); l.Start();
        var t = Task.Run(async () =>
        {
            while (true)
            {
                TcpClient c;
                try { c = await l.AcceptTcpClientAsync(); } catch { return; }
                _ = Task.Run(async () =>
                {
                    using var _ = c; var s = c.GetStream();
                    var buf = new byte[4096]; await s.ReadAsync(buf);
                    var body = Encoding.ASCII.GetBytes(answer);
                    await s.WriteAsync(Encoding.ASCII.GetBytes($"HTTP/1.1 200 OK\r\nContent-Length: {body.Length}\r\nConnection: close\r\n\r\n"));
                    await s.WriteAsync(body);
                });
            }
        });
        return (l, t);
    }

    [Fact]
    public async Task HttpClientReallyUsesSocks5WithAuth()
    {
        var (svc, _) = FakeIpService("203.0.113.77");
        using var socks = new TestSocksServer((IPEndPoint)svc.LocalEndpoint, "user", "pa ss");
        var route = new RouteSettings { UseProxy = true, Kind = ProxyKind.Socks5, Host = "127.0.0.1", Port = socks.Port, User = "user", Password = "pa ss" };
        var r = await RouteChecker.CheckAsync(route, new[] { "http://ip-check.invalid-test/" }, default);
        Assert.True(r.Ok, r.Error);
        Assert.Equal("203.0.113.77", r.ExternalIp);
        Assert.Contains(socks.Requested, x => x.StartsWith("ip-check.invalid-test")); // имя разрешено на стороне прокси
        svc.Stop();
    }

    [Fact]
    public async Task WrongPasswordGivesClearError()
    {
        var (svc, _) = FakeIpService("1.1.1.1");
        using var socks = new TestSocksServer((IPEndPoint)svc.LocalEndpoint, "user", "right");
        var route = new RouteSettings { UseProxy = true, Kind = ProxyKind.Socks5, Host = "127.0.0.1", Port = socks.Port, User = "user", Password = "wrong" };
        var r = await RouteChecker.CheckAsync(route, new[] { "http://x.test/" }, default);
        Assert.False(r.Ok);
        Assert.Contains("неверный логин", r.Error);
        svc.Stop();
    }

    [Fact]
    public async Task UnreachableProxyGivesClearError()
    {
        var route = new RouteSettings { UseProxy = true, Kind = ProxyKind.Socks5, Host = "127.0.0.1", Port = 1 };
        var r = await RouteChecker.CheckAsync(route, new[] { "http://x.test/" }, default);
        Assert.False(r.Ok);
        Assert.Contains("недоступен", r.Error);
    }

    [Fact]
    public async Task LocalBridgeForwardsToAuthenticatedUpstream()
    {
        var (svc, _) = FakeIpService("198.51.100.5");
        using var socks = new TestSocksServer((IPEndPoint)svc.LocalEndpoint, "u", "p");
        var upstream = new RouteSettings { UseProxy = true, Kind = ProxyKind.Socks5, Host = "127.0.0.1", Port = socks.Port, User = "u", Password = "p" };
        await using var bridge = new LocalSocksBridge(upstream);
        bridge.Start();
        // Клиент без аутентификации (как Chromium) → мост → прокси с аутентификацией.
        var viaBridge = new RouteSettings { UseProxy = true, Kind = ProxyKind.Socks5, Host = "127.0.0.1", Port = bridge.Port };
        using var http = viaBridge.CreateHttpClient(TimeSpan.FromSeconds(10));
        var text = await http.GetStringAsync("http://site.example-test/");
        Assert.Equal("198.51.100.5", text);
        Assert.Contains(socks.Requested, x => x.StartsWith("site.example-test"));
        svc.Stop();
    }

    [Fact]
    public async Task DnsOverTcpThroughSocks()
    {
        // DNS-сервер на TCP, отвечающий на любой A-запрос адресом 192.0.2.55 (будет отфильтрован только в базе — здесь проверяем транспорт).
        var dns = new TcpListener(IPAddress.Loopback, 0); dns.Start();
        _ = Task.Run(async () =>
        {
            using var c = await dns.AcceptTcpClientAsync(); var s = c.GetStream();
            var len = BinaryPrimitives.ReadUInt16BigEndian(await ProxyTunnel.ReadExactAsync(s, 2, default));
            var q = await ProxyTunnel.ReadExactAsync(s, len, default);
            var resp = new List<byte>(q); resp[2] = 0x81; resp[3] = 0x80; resp[7] = 1;
            resp.AddRange(new byte[] { 0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 192, 0, 2, 55 });
            var framed = new byte[resp.Count + 2]; BinaryPrimitives.WriteUInt16BigEndian(framed, (ushort)resp.Count); resp.CopyTo(framed, 2);
            await s.WriteAsync(framed);
        });
        using var socks = new TestSocksServer((IPEndPoint)dns.LocalEndpoint, "a", "b");
        var route = new RouteSettings { UseProxy = true, Kind = ProxyKind.Socks5, Host = "127.0.0.1", Port = socks.Port, User = "a", Password = "b" };
        using var resolver = new DnsResolver(new DnsSettings { Mode = DnsMode.Tcp, Server = "9.9.9.9", QueryIPv6 = false }, route);
        var r = await resolver.ResolveAsync("game.example.com", default);
        Assert.Null(r.Error);
        Assert.Equal("192.0.2.55", r.Addresses.Single().ToString());
        Assert.Contains("9.9.9.9:53", socks.Requested);
        Assert.Contains("socks5://", r.Method);
        Assert.Null(resolver.RouteWarning());
        dns.Stop();
    }
}
