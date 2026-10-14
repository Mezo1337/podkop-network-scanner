using System.Net;
using PodkopScanner.Core.Analysis;
using PodkopScanner.Core.Export;
using PodkopScanner.Core.Import;
using PodkopScanner.Core.Model;
using PodkopScanner.Core.Monitoring;
using PodkopScanner.Core.Net;

namespace PodkopScanner.Tests;

public class DomainNormalizationTests
{
    [Theory]
    [InlineData("https://api.example.com/v1/login", "api.example.com")]
    [InlineData("https://api.example.com/v1/users?x=1#y", "api.example.com")]
    [InlineData("HTTPS://CDN.Example.COM:8443/image.png", "cdn.example.com")]
    [InlineData("wss://gateway.discord.gg/?v=10", "gateway.discord.gg")]
    [InlineData("user:pass@login.example.org", "login.example.org")]
    [InlineData("*.example.net", "example.net")]
    [InlineData("example.com.", "example.com")]
    [InlineData("пример.рф", "xn--e1afmkfd.xn--p1ai")]
    [InlineData("https://почта.пример.рф/inbox", "xn--80a1acny.xn--e1afmkfd.xn--p1ai")]
    public void Normalizes(string input, string expected) =>
        Assert.Equal(expected, DomainNormalizer.Normalize(input).Domain);

    [Theory]
    [InlineData("192.168.1.1", DomainRejectReason.IpLiteral)]
    [InlineData("[2001:db8::1]:443", DomainRejectReason.IpLiteral)]
    [InlineData("localhost", DomainRejectReason.InvalidSyntax)]
    [InlineData("router.lan", DomainRejectReason.LocalOrSpecial)]
    [InlineData("printer.local", DomainRejectReason.LocalOrSpecial)]
    [InlineData("1.0.168.192.in-addr.arpa", DomainRejectReason.LocalOrSpecial)]
    [InlineData("bad_domain.com", DomainRejectReason.InvalidSyntax)]
    [InlineData("-bad.com", DomainRejectReason.InvalidSyntax)]
    [InlineData("co.uk", DomainRejectReason.PublicSuffixOnly)]
    [InlineData("", DomainRejectReason.Empty)]
    public void Rejects(string input, DomainRejectReason reason) =>
        Assert.Equal(reason, DomainNormalizer.Normalize(input).Reason);

    [Theory]
    [InlineData("api.example.com", "example.com")]
    [InlineData("a.b.example.co.uk", "example.co.uk")]
    [InlineData("d111111abcdef8.cloudfront.net", "d111111abcdef8.cloudfront.net")] // приватная секция PSL
    [InlineData("user.github.io", "user.github.io")]
    [InlineData("www.ck", "www.ck")] // исключение !www.ck
    public void RegistrableDomain(string host, string expected) =>
        Assert.Equal(expected, DomainNormalizer.RegistrableDomain(host));

    [Fact]
    public void RemoveRedundantKeepsCoverage()
    {
        var r = DomainNormalizer.RemoveRedundant(new[] { "api.example.com", "example.com", "cdn.example.com", "other.net", "a.b.other.net", "b.other.net" });
        Assert.Equal(new[] { "example.com", "other.net" }, r.OrderBy(x => x));
        // Не путаем «notexample.com» с поддоменом «example.com».
        var r2 = DomainNormalizer.RemoveRedundant(new[] { "example.com", "notexample.com" });
        Assert.Equal(2, r2.Count);
    }

    [Fact]
    public void PodkopValidatorParity()
    {
        Assert.True(DomainNormalizer.IsValidForPodkop("example.com"));
        Assert.True(DomainNormalizer.IsValidForPodkop("xn--e1afmkfd.xn--p1ai"));
        Assert.True(DomainNormalizer.IsValidForPodkop(".ru")); // форма .tld разрешена валидатором
        Assert.False(DomainNormalizer.IsValidForPodkop("example"));
        Assert.False(DomainNormalizer.IsValidForPodkop("https://example.com"));
        Assert.False(DomainNormalizer.IsValidForPodkop("Example.com")); // helpers.sh: только нижний регистр
    }
}

public class IpCidrTests
{
    [Theory]
    [InlineData("8.8.8.8", false, "8.8.8.8", 32)]
    [InlineData("8.8.8.0/24", false, "8.8.8.0", 24)]
    [InlineData("8.8.8.77/24", true, "8.8.8.0", 24)]
    [InlineData("2606:4700::1111", false, "2606:4700::1111", 128)]
    [InlineData("2606:4700::/32", false, "2606:4700::", 32)]
    [InlineData("::ffff:1.2.3.4", false, "1.2.3.4", 32)]
    public void Parses(string s, bool hostBits, string addr, int prefix)
    {
        Assert.True(IpNetwork.TryParse(s, out var n, out var hb));
        Assert.Equal(hostBits, hb);
        Assert.Equal(addr, n.Address.ToString());
        Assert.Equal(prefix, n.Prefix);
    }

    [Theory]
    [InlineData("1.2.3")]
    [InlineData("1.2.3.4/33")]
    [InlineData("256.1.1.1")]
    [InlineData("01.2.3.4")]
    [InlineData("example.com")]
    [InlineData("2001:db8::/129")]
    public void RejectsInvalid(string s) => Assert.False(IpNetwork.TryParse(s, out _));

    [Fact]
    public void AggregateMergesAdjacentWithoutExpansion()
    {
        var input = new[] { "10.0.0.0/25", "10.0.0.128/25", "10.0.1.5", "10.0.1.4", "10.0.1.6", "10.0.0.17" }.Select(IpNetwork.Parse);
        var r = Cidr.AggregateExact(input).Select(n => n.ToString(true)).ToList();
        Assert.Equal(new[] { "10.0.0.0/24", "10.0.1.4/31", "10.0.1.6/32" }, r);
    }

    [Fact]
    public void AggregateNeverAddsAddresses()
    {
        var rnd = new Random(42);
        for (int iter = 0; iter < 200; iter++)
        {
            var nets = Enumerable.Range(0, 30).Select(_ => new IpNetwork(false, (UInt128)(uint)rnd.Next(0, 4096) + 0x0A000000, rnd.Next(26, 33)))
                .Select(n => new IpNetwork(false, n.Network & ~IpNetwork.HostMask(false, n.Prefix), n.Prefix)).ToList();
            var agg = Cidr.AggregateExact(nets);
            // Каждый адрес результата входит хотя бы в одну исходную сеть и наоборот.
            for (uint a = 0x0A000000; a < 0x0A000000 + 4096 + 64; a++)
            {
                var ip = IpNetwork.ToAddress(false, a);
                Assert.Equal(nets.Any(n => n.Contains(ip)), agg.Any(n => n.Contains(ip)));
            }
            // Результат не содержит пересечений.
            for (int i = 1; i < agg.Count; i++) Assert.True(agg[i - 1].Last < agg[i].First);
        }
    }

    [Fact]
    public void AggregateIPv6()
    {
        var r = Cidr.AggregateExact(new[] { IpNetwork.Parse("2001:4860::/33"), IpNetwork.Parse("2001:4860:8000::/33") });
        Assert.Single(r);
        Assert.Equal("2001:4860::/32", r[0].ToString(true));
    }

    [Theory]
    [InlineData("10.1.2.3", true)]
    [InlineData("192.168.0.1", true)]
    [InlineData("172.20.0.1", true)]
    [InlineData("100.64.1.1", true)]
    [InlineData("127.0.0.1", true)]
    [InlineData("169.254.1.1", true)]
    [InlineData("198.18.0.5", true)]
    [InlineData("224.0.0.251", true)]
    [InlineData("fe80::1", true)]
    [InlineData("fd00::1", true)]
    [InlineData("::1", true)]
    [InlineData("8.8.8.8", false)]
    [InlineData("1.1.1.1", false)]
    [InlineData("172.32.0.1", false)]
    [InlineData("2a00:1450:4010::8a", false)]
    public void SpecialRangesDetected(string ip, bool special) =>
        Assert.Equal(special, SpecialRanges.IsSpecial(IpNetwork.Parse(ip)));

    [Fact]
    public void VeryLargeWarning()
    {
        Assert.True(Cidr.IsVeryLarge(IpNetwork.Parse("8.0.0.0/8")));
        Assert.True(Cidr.IsVeryLarge(IpNetwork.Parse("8.8.0.0/16")));
        Assert.False(Cidr.IsVeryLarge(IpNetwork.Parse("8.8.8.0/24")));
    }
}

public class ExportTests
{
    private static Entry E(string v, EntryKind k, Trust t = Trust.High, bool include = true, bool disabled = false) =>
        new() { Value = v, Kind = k, Trust = t, Include = include, Disabled = disabled };

    [Fact]
    public void ProducesPodkopCompatibleLists()
    {
        var entries = new[]
        {
            E("example.com", EntryKind.Domain), E("api.example.com", EntryKind.Domain), E("cdn.example.net", EntryKind.Domain),
            E("excluded.org", EntryKind.Domain, include: false), E("disabled.org", EntryKind.Domain, disabled: true),
            E("8.8.8.8", EntryKind.IPv4), E("8.8.4.4", EntryKind.IPv4), E("1.1.1.0/24", EntryKind.Cidr4),
            E("2606:4700::1111", EntryKind.IPv6),
        };
        var r = PodkopExporter.Build(entries, new ExportOptions());
        Assert.Equal(new[] { "example.com", "cdn.example.net" }, r.Domains);
        Assert.Equal(new[] { "1.1.1.0/24", "8.8.4.4/32", "8.8.8.8/32" }, r.Subnets);
        Assert.Empty(PodkopExporter.ValidateDomainsText(r.DomainsText));
        Assert.Empty(PodkopExporter.ValidateSubnetsText(r.SubnetsText));
        Assert.Single(r.SubnetsV6); // IPv6 не попадает в поле Podkop
        Assert.DoesNotContain(r.Subnets, s => s.Contains(':'));
        Assert.DoesNotContain("http", r.DomainsText);
        Assert.Contains(r.Warnings, w => w.Contains("IPv6"));
    }

    [Fact]
    public void PlainIpsWhenOptionOff()
    {
        var r = PodkopExporter.Build(new[] { E("8.8.8.8", EntryKind.IPv4) }, new ExportOptions { SingleAsCidr = false });
        Assert.Equal("8.8.8.8", r.SubnetsText);
    }

    [Fact]
    public void OnlyConfirmedFilters()
    {
        var r = PodkopExporter.Build(new[] { E("a.example.com", EntryKind.Domain, Trust.Medium), E("b.example.com", EntryKind.Domain) },
            new ExportOptions { OnlyConfirmed = true, RemoveRedundantDomains = false });
        Assert.Equal(new[] { "b.example.com" }, r.Domains);
    }

    [Theory]
    [InlineData("1.2.3.4", true)]
    [InlineData("1.2.3.0/24", true)]
    [InlineData("0.0.0.0", false)]
    [InlineData("1.2.3.4/33", false)]
    [InlineData("2001:db8::1", false)]
    [InlineData("256.0.0.1", false)]
    public void SubnetValidatorMatchesPodkop(string v, bool ok) => Assert.Equal(ok, PodkopExporter.IsValidPodkopSubnet(v));

    [Fact]
    public void ParseValueListMatchesPodkop()
    {
        var l = PodkopExporter.ParseValueList("example.com, sub.example.com\n// Social networks\ndomain.com test.com // personal");
        Assert.Equal(new[] { "example.com", "sub.example.com", "domain.com", "test.com" }, l);
    }

    [Fact]
    public void LargeNetworkWarning()
    {
        var r = PodkopExporter.Build(new[] { E("8.0.0.0/8", EntryKind.Cidr4) }, new ExportOptions());
        Assert.Contains(r.Warnings, w => w.Contains("очень большая сеть"));
    }

    [Fact]
    public void RulesetJsonFormat()
    {
        var j = PodkopExporter.BuildRulesetJson(new[] { "example.com" }, new[] { "1.2.3.4", "5.6.7.0/24" });
        using var d = System.Text.Json.JsonDocument.Parse(j);
        Assert.Equal(1, d.RootElement.GetProperty("version").GetInt32());
        var rule = d.RootElement.GetProperty("rules")[0];
        Assert.Equal("example.com", rule.GetProperty("domain_suffix")[0].GetString());
        Assert.Equal("1.2.3.4/32", rule.GetProperty("ip_cidr")[0].GetString());
    }

    [Fact]
    public void PlainListHasNoCommentsAndLf()
    {
        var path = Path.GetTempFileName();
        PodkopExporter.WritePlainList(path, new[] { "a.com", "b.com" });
        var bytes = File.ReadAllBytes(path);
        Assert.DoesNotContain((byte)'\r', bytes);
        Assert.NotEqual(0xEF, bytes[0]); // без BOM
        Assert.Equal("a.com\nb.com\n", System.Text.Encoding.UTF8.GetString(bytes));
        File.Delete(path);
    }

    [Fact]
    public void DiffBetweenVersions()
    {
        var d = PodkopExporter.Diff("a.com\nb.com", "1.1.1.1", "b.com\nc.com", "1.1.1.1\n2.2.2.2");
        Assert.Equal(new[] { "c.com" }, d.AddedDomains);
        Assert.Equal(new[] { "a.com" }, d.RemovedDomains);
        Assert.Equal(new[] { "2.2.2.2" }, d.AddedSubnets);
        Assert.Empty(d.RemovedSubnets);
        Assert.True(PodkopExporter.Diff("x", "", "x", "").Empty);
    }

    [Fact]
    public void GeneralizationNeverForSharedPlatforms()
    {
        var entries = new[] { "a.cloudfront.net", "b.cloudfront.net", "c.cloudfront.net", "x.amazonaws.com", "y.amazonaws.com", "z.amazonaws.com",
                              "api.game.com", "cdn.game.com", "auth.game.com" }.Select(d => E(d, EntryKind.Domain));
        var s = PodkopExporter.SuggestGeneralization(entries);
        Assert.Single(s);
        Assert.Equal("game.com", s[0].Parent);
    }
}

public class ImportTests
{
    [Fact]
    public void ParsesMixedFormats()
    {
        var text = """
            # comment
            example.com
            https://api.example.com/v1/login
            nftset=/discord.gg/4#inet#fw4#vpn_domains
            DOMAIN-SUFFIX,telegram.org
            0.0.0.0 ads.tracker.net
            149.154.160.0/20
            8.8.8.8, 1.1.1.1
            2001:67c:4e8::/48
            10.0.0.1
            file.png main.js
            example.com
            """;
        var r = ListImporter.ParseText(text, "test");
        Assert.Contains("example.com", r.Domains);
        Assert.Contains("api.example.com", r.Domains);
        Assert.Contains("discord.gg", r.Domains);
        Assert.Contains("telegram.org", r.Domains);
        Assert.Contains("ads.tracker.net", r.Domains);
        Assert.DoesNotContain("file.png", r.Domains);
        Assert.DoesNotContain("main.js", r.Domains);
        Assert.Contains("149.154.160.0/20", r.Networks);
        Assert.Contains("8.8.8.8", r.Networks);
        Assert.Contains("2001:67c:4e8::/48", r.Networks);
        Assert.DoesNotContain("10.0.0.1", r.Networks);
        Assert.True(r.Duplicates >= 1);
    }

    [Fact]
    public void ParsesSingBoxRuleset()
    {
        var json = """{"version":2,"rules":[{"domain_suffix":["youtube.com","googlevideo.com"],"domain_keyword":["yt"],"ip_cidr":["8.8.8.0/24"]}]}""";
        var r = ListImporter.ParseText(json, "rs");
        Assert.Equal(new[] { "googlevideo.com", "youtube.com" }, r.Domains.OrderBy(x => x));
        Assert.Equal(new[] { "8.8.8.0/24" }, r.Networks);
        Assert.Contains(r.Notes, n => n.Contains("domain_keyword"));
    }

    [Fact]
    public void ParsesTcpdumpAndTshark()
    {
        var log = """
            12:00:01.1 IP 192.168.50.63.53412 > 192.168.1.1.53: 1234+ A? play.googleapis.com. (37)
            12:00:01.2 IP 192.168.1.1.53 > 192.168.50.63.53412: 1234 1/0/0 A 142.250.74.10 (53)
            api.steampowered.com
            """;
        var r = ListImporter.ParseText(log, "tcpdump");
        Assert.Contains("play.googleapis.com", r.Domains);
        Assert.Contains("api.steampowered.com", r.Domains);
        Assert.Contains("142.250.74.10", r.Networks);
        Assert.DoesNotContain(r.Networks, n => n.StartsWith("192.168."));
    }

    [Theory]
    [InlineData("https://github.com/itdoginfo/allow-domains/blob/main/Services/discord.lst", "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Services/discord.lst")]
    [InlineData("https://gist.github.com/iamwildtuna/7772b7c84a11bf6e1385f23096a73a15", "https://gist.githubusercontent.com/iamwildtuna/7772b7c84a11bf6e1385f23096a73a15/raw")]
    [InlineData("https://example.com/list.txt", "https://example.com/list.txt")]
    public void GitHubRawUrls(string input, string expected) => Assert.Equal(expected, ListImporter.ToRawUrl(input));
}

public class ProtocolTests
{
    [Fact]
    public void DnsRoundTrip()
    {
        var q = DnsMessage.BuildQuery("example.com", DnsType.A, 0x1234);
        // Собираем ответ: копия запроса + флаги ответа + 1 запись A (со сжатым именем).
        var resp = new List<byte>(q);
        resp[2] = 0x81; resp[3] = 0x80; resp[7] = 1;
        resp.AddRange(new byte[] { 0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 215, 14 });
        var r = DnsMessage.Parse(resp.ToArray());
        Assert.True(r.IsResponse);
        Assert.Equal(0x1234, r.Id);
        Assert.Equal("example.com", r.Questions[0]);
        Assert.Equal("93.184.215.14", r.Answers.Single().Address!.ToString());
        Assert.Equal(60u, r.Answers[0].Ttl);
    }

    [Fact]
    public void SniExtraction()
    {
        var hello = BuildClientHello("game-api.example.com", 0);
        Assert.Equal(TlsSni.State.Found, TlsSni.TryGetSni(hello, out var sni, out var ech));
        Assert.Equal("game-api.example.com", sni);
        Assert.False(ech);
        // Неполная запись (ClientHello разбит на сегменты) — нужно больше данных.
        Assert.Equal(TlsSni.State.NeedMore, TlsSni.TryGetSni(hello.AsSpan(0, 20), out _));
        Assert.Equal(TlsSni.State.NotTls, TlsSni.TryGetSni("GET / HTTP/1.1\r\n"u8, out _));
        var withEch = BuildClientHello("public.example.com", 0xFE0D);
        Assert.Equal(TlsSni.State.Found, TlsSni.TryGetSni(withEch, out _, out var ech2));
        Assert.True(ech2);
    }

    internal static byte[] BuildClientHello(string host, int extraExt)
    {
        var name = System.Text.Encoding.ASCII.GetBytes(host);
        var sniExt = new List<byte> { 0, 0 };
        int listLen = 3 + name.Length;
        sniExt.AddRange(new[] { (byte)((listLen + 2) >> 8), (byte)(listLen + 2), (byte)(listLen >> 8), (byte)listLen, (byte)0, (byte)(name.Length >> 8), (byte)name.Length });
        sniExt.AddRange(name);
        var exts = new List<byte>();
        exts.AddRange(new byte[] { 0x00, 0x2b, 0, 3, 2, 3, 4 }); // supported_versions
        if (extraExt != 0) exts.AddRange(new byte[] { (byte)(extraExt >> 8), (byte)extraExt, 0, 2, 0, 0 });
        exts.AddRange(sniExt);
        var body = new List<byte> { 3, 3 };
        body.AddRange(new byte[32]);
        body.Add(0);
        body.AddRange(new byte[] { 0, 2, 0x13, 0x01 });
        body.AddRange(new byte[] { 1, 0 });
        body.AddRange(new[] { (byte)(exts.Count >> 8), (byte)exts.Count });
        body.AddRange(exts);
        var hs = new List<byte> { 1, 0, (byte)(body.Count >> 8), (byte)body.Count };
        hs.AddRange(body);
        var rec = new List<byte> { 0x16, 3, 1, (byte)(hs.Count >> 8), (byte)hs.Count };
        rec.AddRange(hs);
        return rec.ToArray();
    }

    [Fact]
    public void PacketParsingIPv4Tcp()
    {
        var payload = BuildClientHello("x.example.com", 0);
        var pkt = new byte[40 + payload.Length];
        pkt[0] = 0x45; pkt[2] = (byte)(pkt.Length >> 8); pkt[3] = (byte)pkt.Length; pkt[9] = 6;
        new byte[] { 192, 168, 1, 2 }.CopyTo(pkt, 12); new byte[] { 1, 2, 3, 4 }.CopyTo(pkt, 16);
        pkt[20] = 0xC3; pkt[21] = 0x50; pkt[22] = 1; pkt[23] = 0xBB; pkt[32] = 0x50;
        payload.CopyTo(pkt, 40);
        var p = PacketParsing.Parse(pkt)!.Value;
        Assert.Equal(50000, p.SrcPort); Assert.Equal(443, p.DstPort); Assert.Equal("1.2.3.4", p.Dst.ToString());
        Assert.Equal(TlsSni.State.Found, TlsSni.TryGetSni(pkt.AsSpan(p.PayloadOffset, p.PayloadLength), out var sni));
        Assert.Equal("x.example.com", sni);
    }

    [Theory]
    [InlineData("socks5://127.0.0.1:1080", ProxyKind.Socks5, "127.0.0.1", 1080, null)]
    [InlineData("socks5h://user:p%40ss@10.0.0.2:9050", ProxyKind.Socks5, "10.0.0.2", 9050, "user")]
    [InlineData("http://proxy.local:3128", ProxyKind.Http, "proxy.local", 3128, null)]
    [InlineData("https://p.example.com", ProxyKind.Https, "p.example.com", 443, null)]
    public void ProxyUrlParsing(string url, ProxyKind kind, string host, int port, string? user)
    {
        Assert.True(RouteSettings.TryParseUrl(url, out var r, out _));
        Assert.Equal(kind, r.Kind); Assert.Equal(host, r.Host); Assert.Equal(port, r.Port); Assert.Equal(user, r.User);
        if (user != null) Assert.Equal("p@ss", r.Password);
        Assert.DoesNotContain("p@ss", r.Describe());
    }

    [Fact]
    public void ProxyUrlRejectsUnknownScheme() => Assert.False(RouteSettings.TryParseUrl("vless://abc@host:443", out _, out _));
}

public class ClassificationAndTrustTests
{
    [Fact]
    public void WebClassification()
    {
        Assert.Equal(ResourceCategory.AdsAnalytics, Classifier.ClassifyWeb("www.google-analytics.com", "example.com", "script", "/", false, false).Item1);
        Assert.Equal(ResourceCategory.MainSite, Classifier.ClassifyWeb("example.com", "example.com", "document", "/", false, true).Item1);
        Assert.Equal(ResourceCategory.Auth, Classifier.ClassifyWeb("auth.example.com", "example.com", "document", "/", false, true).Item1);
        Assert.Equal(ResourceCategory.WebSocket, Classifier.ClassifyWeb("ws.example.com", "example.com", "websocket", "/", true, false).Item1);
        Assert.Equal(ResourceCategory.Api, Classifier.ClassifyWeb("api.example.com", "example.com", "fetch", "/v1/x", false, false).Item1);
        Assert.Equal(ResourceCategory.Media, Classifier.ClassifyWeb("rr3---sn-abc.googlevideo.com", "youtube.com", "media", "/videoplayback", false, false).Item1);
        Assert.Equal(ResourceCategory.Cdn, Classifier.ClassifyWeb("cdn.jsdelivr.net", "example.com", "script", "/npm/x.js", false, false).Item1);
        var (c, reason) = Classifier.ClassifyWeb("widgets.partner.io", "example.com", "document", "/", false, false);
        Assert.Equal(ResourceCategory.ThirdParty, c);
        Assert.StartsWith("низкая", reason);
    }

    [Fact]
    public void ProcessClassification()
    {
        Assert.Equal(ResourceCategory.Voice, Classifier.ClassifyProcess(null, "UDP", 3478).Item1);
        Assert.Equal(ResourceCategory.GameServer, Classifier.ClassifyProcess(null, "UDP", 7777).Item1);
        Assert.Equal(ResourceCategory.Auth, Classifier.ClassifyProcess("login.game.com", "TCP", 443).Item1);
    }

    [Fact]
    public void TrustIsDeterministic()
    {
        var now = DateTime.UtcNow;
        Assert.Equal(Trust.High, TrustPolicy.Compute(new[] { (ObservationMethod.FlowEstablished, now) }, EntryKind.IPv4, false, now));
        Assert.Equal(Trust.Medium, TrustPolicy.Compute(new[] { (ObservationMethod.DnsResolve, now) }, EntryKind.IPv4, false, now));
        Assert.Equal(Trust.Low, TrustPolicy.Compute(new[] { (ObservationMethod.Import, now) }, EntryKind.Domain, false, now));
        Assert.Equal(Trust.Low, TrustPolicy.Compute(new[] { (ObservationMethod.FlowEstablished, now.AddDays(-400)) }, EntryKind.IPv4, false, now));
        Assert.Equal(Trust.High, TrustPolicy.Compute(Array.Empty<(ObservationMethod, DateTime)>(), EntryKind.IPv4, true, now));
        Assert.False(TrustPolicy.DefaultInclude(new Entry { Kind = EntryKind.Domain, Trust = Trust.Low }, true));
        Assert.False(TrustPolicy.DefaultInclude(new Entry { Kind = EntryKind.Cidr4, Trust = Trust.High }, true));
    }
}

public class SystemProxyTests
{
    [Fact]
    public void ParsesWindowsProxyServerFormats()
    {
        var a = SystemProxy.Parse("127.0.0.1:10809").Single();
        Assert.Equal(("http", "127.0.0.1", 10809), (a.Scheme, a.Host, a.Port));
        var b = SystemProxy.Parse("http=127.0.0.1:8080;https=127.0.0.1:8080;socks=127.0.0.1:1080").ToList();
        Assert.Equal(3, b.Count);
        Assert.Equal("socks", b[2].Scheme);
        Assert.True(SystemProxy.IsLocal(b[0]));
    }

    [Fact]
    public void ParsesProxyRequests()
    {
        var c = ProxyRequestParser.TryParse("CONNECT api.game.com:443 HTTP/1.1\r\nHost: api.game.com:443\r\n\r\n"u8)!;
        Assert.Equal(("api.game.com", 443, "HTTP CONNECT"), (c.Host, c.Port, c.Kind));
        var g = ProxyRequestParser.TryParse("GET http://cdn.game.com/patch.bin HTTP/1.1\r\n\r\n"u8)!;
        Assert.Equal("cdn.game.com", g.Host);
        var name = System.Text.Encoding.ASCII.GetBytes("voice.game.com");
        var s5 = new byte[] { 5, 1, 0, 3, (byte)name.Length }.Concat(name).Concat(new byte[] { 0x1F, 0x90 }).ToArray();
        var r5 = ProxyRequestParser.TryParse(s5)!;
        Assert.Equal(("voice.game.com", 8080, "SOCKS5"), (r5.Host, r5.Port, r5.Kind));
        var s5ip = ProxyRequestParser.TryParse(new byte[] { 5, 1, 0, 1, 8, 8, 4, 4, 0x01, 0xBB })!;
        Assert.Equal(("8.8.4.4", 443), (s5ip.Host, s5ip.Port));
        var s4a = ProxyRequestParser.TryParse(new byte[] { 4, 1, 0, 80, 0, 0, 0, 1, 0 }.Concat(System.Text.Encoding.ASCII.GetBytes("example.org")).Concat(new byte[] { 0 }).ToArray())!;
        Assert.Equal(("example.org", 80, "SOCKS4a"), (s4a.Host, s4a.Port, s4a.Kind));
        Assert.Null(ProxyRequestParser.TryParse(new byte[] { 5, 1, 0 }));          // приветствие SOCKS5 — ещё не запрос
        Assert.Null(ProxyRequestParser.TryParse("hello world, not a proxy"u8));
    }
}

public class DependencyTests
{
    [Fact]
    public async Task Test7_MissingDriverGivesMessageAndFallback()
    {
        // В папке тестов нет WinDivert.dll/WinDivert64.sys — программа не должна падать.
        var (ok, msg) = ProcessMonitor.CheckDriver();
        Assert.False(ok);
        Assert.False(string.IsNullOrWhiteSpace(msg));
        await using var m = new ProcessMonitor(new ProcessMonitorOptions { Pid = Environment.ProcessId, FlushDnsCache = false });
        var logs = new List<string>();
        m.Log += logs.Add;
        m.Start(allowFallback: true);
        Assert.Equal(CaptureMode.IpHelperOnly, m.Mode);
        Assert.Contains(logs, l => l.Contains("ограниченном режиме"));
        Assert.Throws<InvalidOperationException>(() => new ProcessMonitor(new ProcessMonitorOptions { Pid = Environment.ProcessId, FlushDnsCache = false }).Start(allowFallback: false));
    }
}

public class SiteOwnershipTests
{
    [Fact]
    public void DuolingoScreenshotCase()
    {
        var site = SiteOwnership.SiteRegistrableFromSource("https://www.duolingo.com/");
        Assert.Equal("duolingo.com", site);
        var hosts = new[] { "cdn.cookielaw.org", "d35aaqx5ub95lt.cloudfront.net", "excess.duolingo.com", "www.duolingo.com", "zombie.duolingo.com",
                            "accounts.google.com", "fonts.gstatic.com", "www.gstatic.com", "geolocation.onetrust.com", "www.recaptcha.net" };
        var included = hosts.Where(h =>
        {
            var (cat, reason) = Classifier.ClassifyWeb(h, site, "script", "/", false, false);
            var e = new Entry { Value = h, Kind = EntryKind.Domain, Trust = Trust.High, Category = cat, CategoryReason = reason };
            return TrustPolicy.DefaultInclude(e, false, site);
        }).ToList();
        Assert.Equal(new[] { "d35aaqx5ub95lt.cloudfront.net", "excess.duolingo.com", "www.duolingo.com", "zombie.duolingo.com" }, included.OrderBy(x => x));
        Assert.Equal(ResourceCategory.Consent, Classifier.ClassifyWeb("cdn.cookielaw.org", site, "script", "/", false, false).Item1);
        Assert.Contains("Google", SiteOwnership.Classify("accounts.google.com", site).reason);
        Assert.Equal(Party.SiteFamily, SiteOwnership.Classify("static.duolingocdn.com", site).party);
        // Для программ (сайт не задан) правило не применяется.
        Assert.True(TrustPolicy.DefaultInclude(new Entry { Value = "accounts.google.com", Kind = EntryKind.Domain, Trust = Trust.High }, false, null));
    }
}
