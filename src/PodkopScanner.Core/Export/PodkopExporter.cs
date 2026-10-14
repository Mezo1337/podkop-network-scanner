using System.Diagnostics;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using PodkopScanner.Core.Model;
using PodkopScanner.Core.Net;

namespace PodkopScanner.Core.Export;

public sealed class ExportOptions
{
    /// <summary>Только записи высокой достоверности или подтверждённые вручную.</summary>
    public bool OnlyConfirmed { get; set; }
    /// <summary>Одиночный IPv4 выводить как /32 (Podkop принимает обе формы).</summary>
    public bool SingleAsCidr { get; set; } = true;
    /// <summary>
    /// Актуальный Podkop принимает в «Список пользовательских подсетей» и в .lst только IPv4
    /// (validateSubnet.ts, is_ipv4_cidr в helpers.sh). IPv6 можно вывести только в JSON-набор правил sing-box.
    /// </summary>
    public bool IPv6InJsonRuleset { get; set; }
    /// <summary>Убирать домены, уже покрытые родительской записью (domain_suffix) — покрытие не меняется.</summary>
    public bool RemoveRedundantDomains { get; set; } = true;
    /// <summary>Точная агрегация подсетей без расширения множества адресов.</summary>
    public bool AggregateSubnets { get; set; } = true;
}

public sealed class ExportResult
{
    public List<string> Domains { get; } = new();
    public List<string> Subnets { get; } = new();
    public List<string> SubnetsV6 { get; } = new();
    public List<string> Warnings { get; } = new();
    public string DomainsText => string.Join("\n", Domains);
    public string SubnetsText => string.Join("\n", Subnets);
}

public sealed record GeneralizationSuggestion(string Parent, List<string> Children, string Explanation);

/// <summary>
/// Формирует списки для Podkop. Формат проверен по исходникам Podkop (ветка main, октябрь 2026):
/// • поле доменов → sing-box <c>domain_suffix</c>: строка «example.com» охватывает и все поддомены;
/// • поле подсетей → <c>ip_cidr</c> + nftables-набор; принимается «X.X.X.X» или «X.X.X.X/Y», только IPv4;
/// • в текстовом режиме поля допускаются разделители «,», пробел, перевод строки и комментарии «//»,
///   но мы выводим строго по одной записи на строку без комментариев;
/// • локальные списки (.lst) читаются построчно без поддержки комментариев;
/// • удалённые списки: .json (source) и .srs (binary) — наборы правил sing-box, прочие — построчный текст.
/// </summary>
public static class PodkopExporter
{
    public static ExportResult Build(IEnumerable<Entry> entries, ExportOptions o)
    {
        var res = new ExportResult();
        var selected = entries.Where(e => e.Include && !e.Disabled)
            .Where(e => !o.OnlyConfirmed || e.Trust == Trust.High || e.ManualConfirmed).ToList();

        var domains = new List<string>();
        foreach (var e in selected.Where(e => e.IsDomain))
        {
            if (DomainNormalizer.IsValidForPodkop(e.Value)) domains.Add(e.Value);
            else res.Warnings.Add($"Пропущен домен с недопустимым для Podkop синтаксисом: {e.Value}");
        }
        domains = domains.Distinct(StringComparer.Ordinal).ToList();
        if (o.RemoveRedundantDomains)
        {
            var before = domains.Count;
            domains = DomainNormalizer.RemoveRedundant(domains);
            if (before > domains.Count)
                res.Warnings.Add($"Убрано {before - domains.Count} домен(ов), уже покрытых родительской записью (Podkop применяет domain_suffix).");
        }
        else domains.Sort(DomainNormalizer.CompareByRegistrable);
        res.Domains.AddRange(domains);

        var v4 = new List<IpNetwork>(); var v6 = new List<IpNetwork>();
        foreach (var e in selected.Where(e => e.IsIp))
        {
            if (!IpNetwork.TryParse(e.Value, out var n)) { res.Warnings.Add($"Пропущена некорректная запись: {e.Value}"); continue; }
            if (n.IsV4() && n.Network == 0) { res.Warnings.Add($"Пропущено {e.Value}: Podkop не допускает 0.0.0.0"); continue; }
            if (SpecialRanges.Match(n) is { } sp) res.Warnings.Add($"Внимание: {e.Value} относится к специальному диапазону ({sp.Description}).");
            if (Cidr.IsVeryLarge(n)) res.Warnings.Add($"Внимание: очень большая сеть {e.Value} ({Cidr.SizeText(n)}) — через прокси пойдут и посторонние сайты.");
            (n.IsV6 ? v6 : v4).Add(n);
        }
        var v4Out = o.AggregateSubnets ? Cidr.AggregateExact(v4) : v4.Distinct().OrderBy(n => n).ToList();
        res.Subnets.AddRange(v4Out.Select(n => n.ToString(o.SingleAsCidr)));
        if (v6.Count > 0)
        {
            var v6Out = o.AggregateSubnets ? Cidr.AggregateExact(v6) : v6.Distinct().OrderBy(n => n).ToList();
            res.SubnetsV6.AddRange(v6Out.Select(n => n.ToString(true)));
            res.Warnings.Add(o.IPv6InJsonRuleset
                ? $"{v6.Count} IPv6-адрес(ов) добавлены только в JSON-набор правил sing-box: поле подсетей и .lst в Podkop принимают только IPv4."
                : $"{v6.Count} IPv6-адрес(ов) не выведены: поле «Список пользовательских подсетей» в Podkop принимает только IPv4.");
        }
        return res;
    }

    private static bool IsV4(this IpNetwork n) => !n.IsV6;

    /// <summary>Тот же синтаксический контроль, что делает LuCI-валидатор Podkop (для тестов и самопроверки).</summary>
    public static List<string> ValidateDomainsText(string text) =>
        ParseValueList(text).Where(d => !DomainNormalizer.IsValidForPodkop(d)).ToList();

    public static List<string> ValidateSubnetsText(string text) =>
        ParseValueList(text).Where(s => !IsValidPodkopSubnet(s)).ToList();

    /// <summary>Копия parseValueList.ts из Podkop.</summary>
    public static List<string> ParseValueList(string value) =>
        string.Join(' ', value.Split('\n').Select(l => l.Split("//")[0]))
            .Split(new[] { ',', ' ', '\t', '\r' }, StringSplitOptions.RemoveEmptyEntries)
            .Select(s => s.Trim()).Where(s => s.Length > 0).ToList();

    /// <summary>Копия validateSubnet.ts: X.X.X.X или X.X.X.X/Y, IPv4, не 0.0.0.0, маска 0–32.</summary>
    public static bool IsValidPodkopSubnet(string v)
    {
        if (!System.Text.RegularExpressions.Regex.IsMatch(v, @"^(\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?$")) return false;
        var parts = v.Split('/');
        if (parts[0] == "0.0.0.0") return false;
        if (!System.Text.RegularExpressions.Regex.IsMatch(parts[0], @"^(?:(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$")) return false;
        return parts.Length == 1 || int.Parse(parts[1]) is >= 0 and <= 32;
    }

    // ───────────── Файлы ─────────────

    private static readonly UTF8Encoding Utf8NoBom = new(false);

    /// <summary>Простой текстовый список: по строке на запись, LF, UTF-8 без BOM, без комментариев.</summary>
    public static void WritePlainList(string path, IEnumerable<string> lines) =>
        File.WriteAllText(path, string.Join("\n", lines) + "\n", Utf8NoBom);

    /// <summary>Набор правил sing-box в исходном (JSON) формате — для remote_*_lists с расширением .json.</summary>
    public static string BuildRulesetJson(IEnumerable<string>? domainSuffixes, IEnumerable<string>? ipCidrs)
    {
        var rule = new Dictionary<string, object>();
        if (domainSuffixes?.Any() == true) rule["domain_suffix"] = domainSuffixes.ToArray();
        if (ipCidrs?.Any() == true) rule["ip_cidr"] = ipCidrs.Select(c => c.Contains('/') ? c : (c.Contains(':') ? c + "/128" : c + "/32")).ToArray();
        var doc = new { version = 1, rules = rule.Count > 0 ? new[] { rule } : Array.Empty<Dictionary<string, object>>() };
        return JsonSerializer.Serialize(doc, new JsonSerializerOptions { WriteIndented = true });
    }

    /// <summary>
    /// Компиляция в бинарный .srs выполняется официальной утилитой sing-box
    /// (<c>sing-box rule-set compile</c>), если пользователь указал путь к sing-box.exe.
    /// Собственный бинарный формат не эмулируется, чтобы не получить несовместимый файл.
    /// </summary>
    public static async Task<string> CompileSrsAsync(string singBoxExe, string jsonPath, string srsPath, CancellationToken ct)
    {
        if (!File.Exists(singBoxExe)) throw new FileNotFoundException("sing-box.exe не найден", singBoxExe);
        var psi = new ProcessStartInfo(singBoxExe) { RedirectStandardError = true, RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
        foreach (var a in new[] { "rule-set", "compile", "--output", srsPath, jsonPath }) psi.ArgumentList.Add(a);
        using var p = Process.Start(psi)!;
        var err = await p.StandardError.ReadToEndAsync(ct);
        await p.WaitForExitAsync(ct);
        if (p.ExitCode != 0) throw new InvalidOperationException("sing-box rule-set compile: " + err.Trim());
        return srsPath;
    }

    public static string BuildDetailedJson(Project p, IEnumerable<Entry> entries, ExportResult r)
    {
        var doc = new
        {
            project = p.Name,
            type = Ru.Of(p.Type),
            source = p.Source,
            generated = DateTime.UtcNow,
            podkop = new { user_domains = r.Domains, user_subnets = r.Subnets, ipv6_not_supported_by_podkop_fields = r.SubnetsV6 },
            warnings = r.Warnings,
            entries = entries.Select(e => new
            {
                value = e.Value, kind = Ru.Of(e.Kind), include = e.Include && !e.Disabled, disabled = e.Disabled,
                trust = Ru.Of(e.Trust), status = Ru.Of(e.Status), category = Ru.Of(e.Category), category_reason = e.CategoryReason,
                sources = e.Sources, process = e.ProcessInfo, protocols = e.Protocols, linked = e.LinkedNames,
                first_seen = e.FirstSeen, last_seen = e.LastSeen, last_confirmed = e.LastConfirmed,
                asn = e.Asn, provider = e.Provider, manual = e.ManualConfirmed, imported = e.Imported, note = e.Note,
            }),
        };
        return JsonSerializer.Serialize(doc, new JsonSerializerOptions { WriteIndented = true, Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping });
    }

    // ───────────── Изменения ─────────────

    public sealed record ListDiff(List<string> AddedDomains, List<string> RemovedDomains, List<string> AddedSubnets, List<string> RemovedSubnets)
    {
        public bool Empty => AddedDomains.Count + RemovedDomains.Count + AddedSubnets.Count + RemovedSubnets.Count == 0;
        public string ToText()
        {
            var sb = new StringBuilder();
            void Sec(string title, List<string> l, string sign) { if (l.Count == 0) return; sb.AppendLine(title); foreach (var x in l) sb.AppendLine(sign + x); sb.AppendLine(); }
            Sec("Новые домены:", AddedDomains, "+ "); Sec("Убранные домены:", RemovedDomains, "- ");
            Sec("Новые подсети:", AddedSubnets, "+ "); Sec("Убранные подсети:", RemovedSubnets, "- ");
            return sb.Length == 0 ? "Изменений нет." : sb.ToString().TrimEnd();
        }
    }

    public static ListDiff Diff(string oldDomains, string oldSubnets, string newDomains, string newSubnets)
    {
        static HashSet<string> S(string t) => t.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToHashSet();
        var od = S(oldDomains); var nd = S(newDomains); var os = S(oldSubnets); var ns = S(newSubnets);
        return new ListDiff(nd.Except(od).OrderBy(x => x).ToList(), od.Except(nd).OrderBy(x => x).ToList(),
            ns.Except(os).OrderBy(x => x).ToList(), os.Except(ns).OrderBy(x => x).ToList());
    }

    // ───────────── Обобщённый режим ─────────────

    /// <summary>Регистрируемые домены общих платформ: объединять их поддомены в одно правило нельзя.</summary>
    private static readonly HashSet<string> NeverGeneralize = new(StringComparer.Ordinal)
    {
        "amazonaws.com", "cloudfront.net", "akamaihd.net", "akamaized.net", "akamai.net", "akamaiedge.net", "edgekey.net",
        "edgesuite.net", "azureedge.net", "azurewebsites.net", "windows.net", "trafficmanager.net", "cloudapp.net",
        "googleusercontent.com", "googleapis.com", "gstatic.com", "googlevideo.com", "appspot.com", "firebaseio.com",
        "fastly.net", "fastlylb.net", "cloudflare.net", "workers.dev", "pages.dev", "herokuapp.com", "vercel.app",
        "netlify.app", "github.io", "githubusercontent.com", "digitaloceanspaces.com", "b-cdn.net", "llnwd.net",
        "cdn77.org", "fbcdn.net", "cdninstagram.com", "yandex.net", "msedge.net", "office.net",
    };

    /// <summary>
    /// Предложения для обобщённого режима. Важно: в Podkop запись "example.com" уже работает как
    /// domain_suffix, т.е. охватит все, в том числе ещё не замеченные поддомены. Поэтому предложение
    /// делается только при ≥ minChildren фактически замеченных поддоменах одного регистрируемого домена
    /// и никогда — для общих облачных/CDN-платформ.
    /// </summary>
    public static List<GeneralizationSuggestion> SuggestGeneralization(IEnumerable<Entry> entries, int minChildren = 3)
    {
        var domains = entries.Where(e => e.IsDomain && e.Include && !e.Disabled).Select(e => e.Value).ToHashSet();
        var result = new List<GeneralizationSuggestion>();
        foreach (var g in domains.GroupBy(d => DomainNormalizer.RegistrableDomain(d) ?? d))
        {
            var parent = g.Key;
            if (domains.Contains(parent) && g.Count() == 1) continue;
            if (domains.Contains(parent)) continue; // уже есть родительское правило
            if (NeverGeneralize.Contains(parent)) continue;
            var children = g.Where(d => d != parent).OrderBy(d => d).ToList();
            if (children.Count < minChildren) continue;
            result.Add(new GeneralizationSuggestion(parent, children,
                $"Замечено {children.Count} поддоменов {parent}. Запись «{parent}» в Podkop охватит их и ВСЕ остальные поддомены {parent}."));
        }
        return result.OrderByDescending(s => s.Children.Count).ToList();
    }
}
