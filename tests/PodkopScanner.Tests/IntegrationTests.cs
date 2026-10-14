using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;
using PodkopScanner.Core.Export;
using PodkopScanner.Core.Model;
using PodkopScanner.Core.Monitoring;
using PodkopScanner.Core.Net;
using PodkopScanner.Core.Update;
using PodkopScanner.Core.Web;
using Xunit.Abstractions;

namespace PodkopScanner.Tests;

/// <summary>
/// Проверки на реальной сети и реальном Chromium. Запуск: dotnet test --filter Category=Integration
/// </summary>
[Trait("Category", "Integration")]
public class IntegrationTests
{
    private readonly ITestOutputHelper _out;
    public IntegrationTests(ITestOutputHelper o) => _out = o;

    private async Task<(List<Finding> findings, WebAnalyzer w, List<string> log)> RunWeb(string url, RouteSettings route, Func<Microsoft.Playwright.IPage, Task>? script)
    {
        var findings = new ConcurrentBag<Finding>();
        var log = new ConcurrentQueue<string>();
        var w = new WebAnalyzer(new WebAnalyzerOptions
        {
            Url = url, Route = route, Headless = true,
            AutomationScript = script ?? (async p => await p.WaitForTimeoutAsync(4000)),
        });
        w.Found += findings.Add;
        w.Log += log.Enqueue;
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(90));
        await w.RunAsync(cts.Token);
        await w.DisposeAsync();
        foreach (var l in log) _out.WriteLine("LOG " + l);
        return (findings.ToList(), w, log.ToList());
    }

    [Fact]
    public async Task Test1_SimpleSite_RealDomains_DedupAndExport()
    {
        using var t = new TempDb();
        var p = t.Repo.CreateProject("Wikipedia", ProjectType.Website, "https://www.wikipedia.org/");
        await using var session = new ScanSession(t.Repo, p.Id, "web", new RouteSettings(), new DnsSettings(), 50);
        session.Log += _out.WriteLine;
        session.Flushed += r => _out.WriteLine($"flush: new {r.NewEntries}, upd {r.UpdatedEntries}, skip {r.Skipped} {string.Join(";", r.SkipReasons)}");
        var (findings, w, _) = await RunWeb("https://www.wikipedia.org/", new RouteSettings(), null);
        foreach (var f in findings) session.Add(f);
        await session.FinishAsync("test");

        var domains = findings.Where(f => f.Kind == EntryKind.Domain).Select(f => f.Value).Distinct().ToList();
        _out.WriteLine($"Запросов: {w.RequestCount}; домены: {string.Join(", ", domains)}");
        Assert.Contains("www.wikipedia.org", domains);
        Assert.True(w.RequestCount >= 3);
        Assert.Contains(findings, f => f.Method == ObservationMethod.BrowserServerAddr && f.LinkedDomain == "www.wikipedia.org");

        var entries = t.Repo.GetEntries(p.Id);
        foreach (var e in entries) _out.WriteLine($"ENTRY {e.Value} {e.Kind} {e.Trust} {e.Status} [{e.Sources}] {e.LinkedNames}");
        Assert.Equal(entries.Count, entries.Select(e => e.Value).Distinct().Count()); // дедупликация
        var main = entries.Single(e => e.Value == "www.wikipedia.org");
        Assert.Equal(Trust.High, main.Trust);
        Assert.True(main.Include);
        Assert.Contains(entries, e => e.IsIp && e.Sources.Contains("DNS"));             // отдельное DNS-разрешение
        Assert.Contains(entries, e => e.IsIp && e.Sources.Contains("IP соединения"));    // фактический IP соединения

        var ex = PodkopExporter.Build(entries, new ExportOptions());
        Assert.Contains("www.wikipedia.org", ex.Domains);
        Assert.Empty(PodkopExporter.ValidateDomainsText(ex.DomainsText));
        Assert.Empty(PodkopExporter.ValidateSubnetsText(ex.SubnetsText));
        Assert.DoesNotContain("https://", ex.DomainsText);
        _out.WriteLine("Экспорт доменов:\n" + ex.DomainsText);
    }

    [Fact]
    public async Task Test2_InteractiveSite_RequestsAfterClickAreCaptured()
    {
        // Локальная страница: внешние запросы появляются ТОЛЬКО после нажатия кнопки.
        var html = """
            <html><body><h1>Тест</h1>
            <button id="b" onclick="fetch('https://api.github.com/zen').catch(()=>{}); var i=new Image(); i.src='https://upload.wikimedia.org/wikipedia/commons/6/63/Wikipedia-logo.png'; document.body.appendChild(i);">Загрузить</button>
            </body></html>
            """;
        var l = new TcpListener(IPAddress.Loopback, 0); l.Start();
        _ = Task.Run(async () =>
        {
            while (true)
            {
                TcpClient c; try { c = await l.AcceptTcpClientAsync(); } catch { return; }
                _ = Task.Run(async () =>
                {
                    using var _ = c; var s = c.GetStream(); var buf = new byte[4096]; await s.ReadAsync(buf);
                    var body = Encoding.UTF8.GetBytes(html);
                    await s.WriteAsync(Encoding.ASCII.GetBytes($"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {body.Length}\r\nConnection: close\r\n\r\n"));
                    await s.WriteAsync(body);
                });
            }
        });
        var port = ((IPEndPoint)l.LocalEndpoint).Port;
        DateTime clickTime = default;
        var (findings, _, _) = await RunWeb($"http://127.0.0.1:{port}/", new RouteSettings(), async page =>
        {
            await page.WaitForTimeoutAsync(1500);
            clickTime = DateTime.UtcNow;
            await page.ClickAsync("#b");
            await page.WaitForTimeoutAsync(4000);
        });
        l.Stop();
        var gh = findings.Where(f => f.Value == "api.github.com").ToList();
        var wm = findings.Where(f => f.Value == "upload.wikimedia.org").ToList();
        Assert.NotEmpty(gh);
        Assert.NotEmpty(wm);
        Assert.All(gh.Concat(wm), f => Assert.True(f.Time >= clickTime, "запрос должен появиться только после нажатия"));
        Assert.Equal(ResourceCategory.Api, gh.First().Category);
        _out.WriteLine(string.Join("\n", findings.Select(f => $"{f.Time:HH:mm:ss.fff} {f.Method} {f.Value} {f.Detail}")));
    }

    [Fact]
    public async Task Test4_DirectVsSocks5_BrowserTrafficReallyGoesThroughProxy()
    {
        using var socks = new TestSocksServer(null, "tester", "secret pass");
        var proxy = new RouteSettings { UseProxy = true, Kind = ProxyKind.Socks5, Host = "127.0.0.1", Port = socks.Port, User = "tester", Password = "secret pass" };

        var direct = await RouteChecker.CheckAsync(new RouteSettings(), null, default);
        var via = await RouteChecker.CheckAsync(proxy, null, default);
        _out.WriteLine($"Напрямую: {direct.ExternalIp} {direct.Error}; через SOCKS5: {via.ExternalIp} {via.Error}");
        Assert.True(direct.Ok, direct.Error);
        Assert.True(via.Ok, via.Error);
        Assert.Contains(socks.Requested, r => r.StartsWith("api.ipify.org") || r.StartsWith("ifconfig.me") || r.StartsWith("icanhazip.com"));

        var before = socks.Requested.Count;
        var (findings, _, log) = await RunWeb("https://example.com/", proxy, null);
        var seen = socks.Requested.Skip(before).ToList();
        _out.WriteLine("Прокси получил: " + string.Join(", ", seen));
        Assert.Contains(seen, r => r.StartsWith("example.com:443"));                       // браузер ходил через прокси (с авторизацией, через мост)
        Assert.Contains(findings, f => f.Value == "example.com");
        Assert.DoesNotContain(findings, f => f.Method == ObservationMethod.BrowserServerAddr); // IP прокси не выдаётся за IP сервера
        Assert.Contains(log, x => x.Contains("локальный мост"));
    }

    [Fact]
    public async Task Test3_ProcessMonitor_OnlyTargetProcessConnections()
    {
        var res = await SelfTest.RunProcessCaptureAsync(default);
        _out.WriteLine(res.Report);
        Assert.True(res.Passed, res.Report);
    }

    [Fact]
    public async Task Test5_RefreshComparesAndKeepsHistory()
    {
        using var t = new TempDb();
        var p = t.Repo.CreateProject("Сервис", ProjectType.Website, "");
        var s = t.Repo.StartScan(p.Id, "web", "direct");
        t.Repo.RecordFindings(p.Id, s, new[]
        {
            new Finding { Value = "example.com", Kind = EntryKind.Domain, Method = ObservationMethod.BrowserRequest },
            new Finding { Value = "www.wikipedia.org", Kind = EntryKind.Domain, Method = ObservationMethod.BrowserRequest },
            new Finding { Value = "this-domain-does-not-exist-pns-test.com", Kind = EntryKind.Domain, Method = ObservationMethod.BrowserRequest },
            // «Старый» IP, якобы полученный в прошлом DNS-ответе
            new Finding { Value = "8.8.8.8", Kind = EntryKind.IPv4, Method = ObservationMethod.DnsResolve, LinkedDomain = "example.com", LinkMethod = "DNS: прошлый" },
        });
        t.Repo.FinishScan(s, "seed");
        var r = new Refresher(t.Repo);
        var rep1 = await r.RefreshAsync(p.Id, new RouteSettings(), new DnsSettings { Mode = DnsMode.DoH }, 2, 50, null, default);
        _out.WriteLine(rep1.ToText());
        var rep2 = await r.RefreshAsync(p.Id, new RouteSettings(), new DnsSettings { Mode = DnsMode.DoH }, 2, 50, null, default);
        _out.WriteLine(rep2.ToText());

        var entries = t.Repo.GetEntries(p.Id);
        Assert.Contains(rep1.Changes, c => c.domain == "example.com" && c.added.Count > 0 && c.missing.Contains("8.8.8.8"));
        Assert.Contains(rep1.Changes, c => c.domain == "this-domain-does-not-exist-pns-test.com" && c.error != null);
        var old = entries.Single(e => e.Value == "8.8.8.8");
        Assert.Equal(EntryStatus.NotReconfirmed, old.Status);                  // пропал из 2 ответов подряд, но не удалён
        Assert.Contains(entries, e => e.IsIp && e.Status == EntryStatus.FromCurrentDns);
        Assert.Equal(EntryStatus.NotReconfirmed, entries.Single(e => e.Value.StartsWith("this-domain")).Status);
        Assert.Equal(3, t.Repo.GetScans(p.Id).Count);
        Assert.NotNull(t.Repo.GetProject(p.Id)!.LastRefresh);
    }

    [Fact]
    public async Task DnsTransportsReal()
    {
        foreach (var s in new[] { new DnsSettings { Mode = DnsMode.System }, new DnsSettings { Mode = DnsMode.Udp, Server = "1.1.1.1" },
                     new DnsSettings { Mode = DnsMode.Tcp, Server = "8.8.8.8" }, new DnsSettings { Mode = DnsMode.DoH } })
        {
            using var r = new DnsResolver(s, new RouteSettings());
            var res = await r.ResolveAsync("example.com", default);
            _out.WriteLine($"{r.Describe()}: {string.Join(", ", res.Addresses)} {res.Error}");
            Assert.True(res.Addresses.Count > 0, $"{s.Mode}: {res.Error}");
        }
        using var nx = new DnsResolver(new DnsSettings { Mode = DnsMode.DoH }, new RouteSettings());
        Assert.True((await nx.ResolveAsync("no-such-host-pns-12345.com", default)).NxDomain);
    }

    [Fact]
    public async Task OfficialRangesAndAsnReal()
    {
        using var http = new RouteSettings().CreateHttpClient(TimeSpan.FromSeconds(30));
        var cf = await OfficialRanges.FetchAsync(OfficialRanges.Providers.Single(p => p.Id == "cloudflare"), http, default);
        Assert.Contains(cf, n => n.Contains(IPAddress.Parse("104.16.0.1")));
        using var asn = new AsnLookup(new DnsSettings(), new RouteSettings());
        var info = await asn.LookupAsync(IPAddress.Parse("1.1.1.1"), default);
        _out.WriteLine($"{info?.Asn} {info?.Name} {info?.Prefix}");
        Assert.Equal("AS13335", info?.Asn);
    }
}
