using System.Globalization;
using System.Net;
using System.Text.RegularExpressions;

namespace PodkopScanner.Core.Net;

public enum DomainRejectReason
{
    None, Empty, IpLiteral, InvalidSyntax, LocalOrSpecial, PublicSuffixOnly, TooLong
}

public readonly record struct DomainResult(string? Domain, DomainRejectReason Reason)
{
    public bool Ok => Domain != null;
}

/// <summary>
/// Приведение произвольной строки (URL, host:port, IDN) к виду, принимаемому полем
/// «Список пользовательских доменов» Podkop. Правила синтаксиса повторяют валидаторы
/// Podkop (fe-app-podkop/src/validators/validateDomain.ts и helpers.sh: is_domain):
/// только ASCII в нижнем регистре, метки [a-z0-9-], не начинаются и не заканчиваются дефисом,
/// длина метки ≤ 63, имени ≤ 253, TLD — буквы или xn--.
/// </summary>
public static class DomainNormalizer
{
    private static readonly IdnMapping Idn = new() { AllowUnassigned = false, UseStd3AsciiRules = true };

    // Точная копия регулярного выражения из validateDomain.ts (без части с путём).
    private static readonly Regex PodkopDomainRegex = new(
        @"^(?=.{1,253}$)(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)\.)+(?:[a-zA-Z]{2,}|xn--[a-zA-Z0-9-]{1,59}[a-zA-Z0-9])$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    // is_domain из helpers.sh (используется при импорте .lst на роутере) — только нижний регистр.
    private static readonly Regex PodkopShellDomainRegex = new(
        @"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly string[] LocalSuffixes =
    {
        "localhost", "local", "lan", "home", "internal", "intranet", "corp", "localdomain",
        "home.arpa", "in-addr.arpa", "ip6.arpa", "arpa", "invalid", "test", "example", "onion",
    };

    private static readonly string[] SpecialHosts =
    {
        "wpad", "isatap", "use-application-dns.net", "ipv6.msftconnecttest.com", "www.msftconnecttest.com",
        "dns.msftncsi.com", "www.msftncsi.com",
    };

    /// <summary>Нормализует строку. Возвращает домен или причину отказа.</summary>
    public static DomainResult Normalize(string? input, bool rejectLocal = true)
    {
        if (string.IsNullOrWhiteSpace(input)) return new(null, DomainRejectReason.Empty);
        var s = input.Trim().Trim('"', '\'', ',', ';');

        // Убираем схему, учётные данные, путь, параметры и порт.
        var schemeIdx = s.IndexOf("://", StringComparison.Ordinal);
        if (schemeIdx >= 0) s = s[(schemeIdx + 3)..];
        var cut = s.IndexOfAny(new[] { '/', '?', '#', '\\' });
        if (cut >= 0) s = s[..cut];
        var at = s.LastIndexOf('@');
        if (at >= 0) s = s[(at + 1)..];

        // IPv6-литерал в скобках или голый IP — это не домен.
        if (s.StartsWith('[')) return new(null, DomainRejectReason.IpLiteral);
        if (IPAddress.TryParse(s, out _)) return new(null, DomainRejectReason.IpLiteral);

        var colon = s.LastIndexOf(':');
        if (colon >= 0) s = s[..colon];
        if (s.StartsWith("*.")) s = s[2..];
        s = s.TrimEnd('.').TrimStart('.');
        if (s.Length == 0) return new(null, DomainRejectReason.Empty);
        if (IPAddress.TryParse(s, out _)) return new(null, DomainRejectReason.IpLiteral);

        string ascii;
        try { ascii = Idn.GetAscii(s).ToLowerInvariant(); }
        catch (ArgumentException) { return new(null, DomainRejectReason.InvalidSyntax); }

        if (ascii.Length > 253) return new(null, DomainRejectReason.TooLong);
        if (!PodkopDomainRegex.IsMatch(ascii) || !PodkopShellDomainRegex.IsMatch(ascii))
            return new(null, DomainRejectReason.InvalidSyntax);
        if (ascii.Split('.').Any(l => l.Length > 63)) return new(null, DomainRejectReason.InvalidSyntax);

        if (rejectLocal && IsLocalOrSpecial(ascii)) return new(null, DomainRejectReason.LocalOrSpecial);
        if (PublicSuffixList.Default.IsPublicSuffix(ascii)) return new(null, DomainRejectReason.PublicSuffixOnly);
        return new(ascii, DomainRejectReason.None);
    }

    public static bool IsLocalOrSpecial(string asciiHost)
    {
        foreach (var h in SpecialHosts) if (asciiHost == h) return true;
        foreach (var suf in LocalSuffixes)
            if (asciiHost == suf || asciiHost.EndsWith("." + suf, StringComparison.Ordinal)) return true;
        return false;
    }

    /// <summary>Проверка строки так, как её проверит LuCI-валидатор Podkop для поля доменов.</summary>
    public static bool IsValidForPodkop(string domain)
    {
        if (Regex.IsMatch(domain, @"^\.[a-zA-Z]{2,}$")) return true; // разрешённая форма ".tld"
        return PodkopDomainRegex.IsMatch(domain) && PodkopShellDomainRegex.IsMatch(domain.TrimStart('.'))
               && domain.Split('.').All(p => p.Length <= 63);
    }

    /// <summary>Отображаемое (Unicode) имя для IDN.</summary>
    public static string ToUnicode(string ascii)
    {
        try { return Idn.GetUnicode(ascii); } catch { return ascii; }
    }

    public static string? RegistrableDomain(string ascii) => PublicSuffixList.Default.GetRegistrableDomain(ascii);

    /// <summary>
    /// Podkop помещает домены в правило sing-box <c>domain_suffix</c>: запись "example.com"
    /// совпадает с example.com и всеми *.example.com. Возвращает true, если domain покрыт parent.
    /// </summary>
    public static bool IsCoveredBySuffix(string domain, string parent) =>
        domain == parent || domain.EndsWith("." + parent, StringComparison.Ordinal);

    /// <summary>Убирает записи, которые уже покрыты другой записью списка (без изменения покрытия).</summary>
    public static List<string> RemoveRedundant(IEnumerable<string> domains)
    {
        var set = new HashSet<string>(domains, StringComparer.Ordinal);
        var result = new List<string>();
        foreach (var d in set)
        {
            var labels = d.Split('.');
            bool covered = false;
            for (int i = 1; i < labels.Length && !covered; i++)
                covered = set.Contains(string.Join('.', labels, i, labels.Length - i));
            if (!covered) result.Add(d);
        }
        result.Sort(CompareByRegistrable);
        return result;
    }

    /// <summary>Сортировка: сначала по регистрируемому домену, затем по глубине и имени.</summary>
    public static int CompareByRegistrable(string a, string b)
    {
        var ra = RegistrableDomain(a) ?? a;
        var rb = RegistrableDomain(b) ?? b;
        var c = string.CompareOrdinal(ra, rb);
        if (c != 0) return c;
        c = a.Count(ch => ch == '.').CompareTo(b.Count(ch => ch == '.'));
        return c != 0 ? c : string.CompareOrdinal(a, b);
    }

    public static string Describe(DomainRejectReason r) => r switch
    {
        DomainRejectReason.Empty => "пустая строка",
        DomainRejectReason.IpLiteral => "это IP-адрес, а не домен",
        DomainRejectReason.InvalidSyntax => "недопустимый синтаксис домена",
        DomainRejectReason.LocalOrSpecial => "локальное или служебное имя",
        DomainRejectReason.PublicSuffixOnly => "это публичный суффикс (например, com или co.uk)",
        DomainRejectReason.TooLong => "имя длиннее 253 символов",
        _ => "",
    };
}
