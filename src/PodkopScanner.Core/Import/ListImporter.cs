using System.Net.Http.Json;
using System.Text.Json;
using System.Text.RegularExpressions;
using PodkopScanner.Core.Model;
using PodkopScanner.Core.Net;

namespace PodkopScanner.Core.Import;

public sealed class ImportResult
{
    public List<string> Domains { get; } = new();
    public List<string> Networks { get; } = new();
    public List<string> Rejected { get; } = new();
    public List<string> Notes { get; } = new();
    public int Duplicates { get; set; }
    public string Origin { get; set; } = "";

    public IEnumerable<Finding> ToFindings(ObservationMethod method)
    {
        foreach (var d in Domains)
            yield return new Finding { Value = d, Kind = EntryKind.Domain, Method = method, Detail = Origin };
        foreach (var n in Networks)
        {
            var net = IpNetwork.Parse(n);
            var kind = net.IsSingleHost ? (net.IsV6 ? EntryKind.IPv6 : EntryKind.IPv4) : (net.IsV6 ? EntryKind.Cidr6 : EntryKind.Cidr4);
            yield return new Finding { Value = n, Kind = kind, Method = method, Detail = Origin };
        }
    }
}

/// <summary>
/// Распознаёт домены, IP и CIDR в произвольном тексте: простые списки, CSV, JSON (включая наборы правил
/// sing-box), форматы dnsmasq/clash/hosts/adblock из allow-domains, журналы tcpdump/tshark/sing-box,
/// CSV PCAPdroid. Импортированные записи помечаются отдельно и получают низкую достоверность.
/// </summary>
public static class ListImporter
{
    private static readonly Regex UrlRx = new(@"[a-z][a-z0-9+.\-]*://[^\s""'<>,;|]+", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex V4Rx = new(@"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?(?![\d])", RegexOptions.Compiled);
    private static readonly Regex V6Rx = new(@"(?<![0-9a-f:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?:/\d{1,3})?(?![0-9a-f:])", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex DomainRx = new(@"(?<![\w\-.])(?:\*\.)?(?:[\p{L}\p{N}](?:[\p{L}\p{N}\-]{0,61}[\p{L}\p{N}])?\.)+(?:[\p{L}]{2,63}|xn--[a-z0-9\-]{1,59})\.?(?![\w\-])", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public static ImportResult ParseText(string text, string origin)
    {
        var r = new ImportResult { Origin = origin };
        var domains = new HashSet<string>(StringComparer.Ordinal);
        var nets = new HashSet<IpNetwork>();
        int dups = 0;

        if (TryParseSingBoxRuleset(text, r, domains, nets, ref dups)) { Finish(); return r; }

        foreach (var raw in text.Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith('#') || line.StartsWith("//") || line.StartsWith('!') || line.StartsWith(';')) continue;
            var ci = line.IndexOf(" //", StringComparison.Ordinal);
            if (ci >= 0) line = line[..ci];

            foreach (Match m in UrlRx.Matches(line))
            {
                if (Uri.TryCreate(m.Value, UriKind.Absolute, out var u)) AddToken(u.Host);
                line = line.Replace(m.Value, " ");
            }
            foreach (Match m in V4Rx.Matches(line)) { AddToken(m.Value); }
            line = V4Rx.Replace(line, " ");
            foreach (Match m in V6Rx.Matches(line))
                if (m.Value.Count(c => c == ':') >= 2 && IpNetwork.TryParse(m.Value, out _)) { AddToken(m.Value); line = line.Replace(m.Value, " "); }
            foreach (Match m in DomainRx.Matches(line)) AddToken(m.Value);
        }
        Finish();
        return r;

        void AddToken(string tok)
        {
            tok = tok.Trim().TrimEnd('.');
            if (IpNetwork.TryParse(tok, out var n, out var hostBits))
            {
                if (SpecialRanges.Match(n) is { } sp) { r.Rejected.Add($"{tok} — специальный диапазон ({sp.Description})"); return; }
                if (hostBits) r.Notes.Add($"{tok} приведён к адресу сети {n}");
                if (!nets.Add(n)) dups++;
                return;
            }
            var d = DomainNormalizer.Normalize(tok);
            // file.png, main.js и т.п. — не домены: верхний уровень должен существовать в Public Suffix List.
            var ascii = d.Domain ?? DomainNormalizer.Normalize(tok, rejectLocal: false).Domain;
            if (ascii != null && !PublicSuffixList.Default.IsKnownTld(ascii.Split('.')[^1])) return;
            if (!d.Ok) { r.Rejected.Add($"{tok} — {DomainNormalizer.Describe(d.Reason)}"); return; }
            if (!domains.Add(d.Domain!)) dups++;
        }

        void Finish()
        {
            r.Domains.AddRange(domains.OrderBy(x => x, Comparer<string>.Create(DomainNormalizer.CompareByRegistrable)));
            r.Networks.AddRange(nets.OrderBy(x => x).Select(x => x.ToString()));
            r.Duplicates = dups;
        }
    }

    private static bool TryParseSingBoxRuleset(string text, ImportResult r, HashSet<string> domains, HashSet<IpNetwork> nets, ref int dups)
    {
        var t = text.TrimStart();
        if (!t.StartsWith('{')) return false;
        try
        {
            using var doc = JsonDocument.Parse(text);
            if (!doc.RootElement.TryGetProperty("rules", out var rules) || rules.ValueKind != JsonValueKind.Array) return false;
            int skipped = 0;
            foreach (var rule in rules.EnumerateArray())
                foreach (var prop in rule.EnumerateObject())
                {
                    var vals = prop.Value.ValueKind == JsonValueKind.Array
                        ? prop.Value.EnumerateArray().Where(v => v.ValueKind == JsonValueKind.String).Select(v => v.GetString()!).ToList()
                        : prop.Value.ValueKind == JsonValueKind.String ? new List<string> { prop.Value.GetString()! } : new List<string>();
                    switch (prop.Name)
                    {
                        case "domain" or "domain_suffix":
                            foreach (var v in vals)
                            {
                                var d = DomainNormalizer.Normalize(v);
                                if (d.Ok) { if (!domains.Add(d.Domain!)) dups++; }
                                else r.Rejected.Add($"{v} — {DomainNormalizer.Describe(d.Reason)}");
                            }
                            break;
                        case "ip_cidr":
                            foreach (var v in vals)
                                if (IpNetwork.TryParse(v, out var n) && SpecialRanges.Match(n) == null) { if (!nets.Add(n)) dups++; }
                                else r.Rejected.Add($"{v} — некорректный или специальный адрес");
                            break;
                        case "domain_keyword" or "domain_regex":
                            skipped += vals.Count;
                            break;
                    }
                }
            if (skipped > 0) r.Notes.Add($"Пропущено {skipped} правил domain_keyword/domain_regex: Podkop принимает только конкретные домены.");
            r.Notes.Add("Распознан набор правил sing-box (JSON).");
            return true;
        }
        catch (JsonException) { return false; }
    }

    /// <summary>Ссылки github.com/…/blob/… автоматически превращаются в raw.githubusercontent.com.</summary>
    public static string ToRawUrl(string url)
    {
        var m = Regex.Match(url, @"^https?://github\.com/([^/]+)/([^/]+)/blob/(.+)$");
        if (m.Success) return $"https://raw.githubusercontent.com/{m.Groups[1].Value}/{m.Groups[2].Value}/{m.Groups[3].Value}";
        m = Regex.Match(url, @"^https?://gist\.github\.com/([^/]+)/([0-9a-f]+)/?$");
        if (m.Success) return $"https://gist.githubusercontent.com/{m.Groups[1].Value}/{m.Groups[2].Value}/raw";
        return url;
    }

    public static async Task<ImportResult> FetchAsync(string url, RouteSettings route, string? singBoxExe, CancellationToken ct)
    {
        var raw = ToRawUrl(url.Trim());
        using var http = route.CreateHttpClient(TimeSpan.FromSeconds(30));
        using var resp = await http.GetAsync(raw, HttpCompletionOption.ResponseHeadersRead, ct);
        resp.EnsureSuccessStatusCode();
        if (resp.Content.Headers.ContentLength > 20_000_000) throw new InvalidOperationException("Файл больше 20 МБ");
        var bytes = await resp.Content.ReadAsByteArrayAsync(ct);
        if (raw.EndsWith(".srs", StringComparison.OrdinalIgnoreCase))
        {
            if (string.IsNullOrEmpty(singBoxExe) || !File.Exists(singBoxExe))
                throw new InvalidOperationException("Это бинарный набор правил sing-box (.srs). Для чтения укажите в настройках путь к sing-box.exe.");
            var tmp = Path.Combine(Path.GetTempPath(), "pns-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(tmp);
            try
            {
                var srs = Path.Combine(tmp, "in.srs"); var json = Path.Combine(tmp, "out.json");
                await File.WriteAllBytesAsync(srs, bytes, ct);
                var psi = new System.Diagnostics.ProcessStartInfo(singBoxExe) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardError = true };
                foreach (var a in new[] { "rule-set", "decompile", "--output", json, srs }) psi.ArgumentList.Add(a);
                using var p = System.Diagnostics.Process.Start(psi)!;
                await p.WaitForExitAsync(ct);
                if (p.ExitCode != 0) throw new InvalidOperationException("sing-box не смог прочитать .srs: " + await p.StandardError.ReadToEndAsync(ct));
                return ParseText(await File.ReadAllTextAsync(json, ct), url);
            }
            finally { try { Directory.Delete(tmp, true); } catch { } }
        }
        if (bytes.Take(8000).Any(b => b == 0)) throw new InvalidOperationException("Получен двоичный файл, а не текстовый список");
        return ParseText(System.Text.Encoding.UTF8.GetString(bytes), url);
    }

    public sealed record GitHubFile(string Name, string Path, string DownloadUrl);

    /// <summary>Содержимое каталога GitHub-репозитория (для выбора списков из itdoginfo/allow-domains).</summary>
    public static async Task<List<GitHubFile>> ListGitHubDirectoryAsync(string owner, string repo, string path, RouteSettings route, CancellationToken ct)
    {
        using var http = route.CreateHttpClient(TimeSpan.FromSeconds(20));
        http.DefaultRequestHeaders.Accept.ParseAdd("application/vnd.github+json");
        var items = await http.GetFromJsonAsync<JsonElement>($"https://api.github.com/repos/{owner}/{repo}/contents/{path}", ct);
        var l = new List<GitHubFile>();
        foreach (var it in items.EnumerateArray())
            if (it.GetProperty("type").GetString() == "file")
                l.Add(new GitHubFile(it.GetProperty("name").GetString()!, it.GetProperty("path").GetString()!, it.GetProperty("download_url").GetString()!));
        return l;
    }
}
