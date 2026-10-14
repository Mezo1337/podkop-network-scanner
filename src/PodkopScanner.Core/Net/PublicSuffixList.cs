using System.Globalization;
using System.Reflection;

namespace PodkopScanner.Core.Net;

/// <summary>
/// Реализация алгоритма Public Suffix List (publicsuffix.org). Используется для группировки
/// поддоменов по регистрируемому домену (eTLD+1). Список встроен в сборку.
/// Учитывается и приватная секция (например, cloudfront.net, github.io), чтобы не объединять
/// чужие сайты, размещённые на общих хостингах.
/// </summary>
public sealed class PublicSuffixList
{
    private readonly HashSet<string> _rules = new(StringComparer.Ordinal);
    private readonly HashSet<string> _wildcards = new(StringComparer.Ordinal);
    private readonly HashSet<string> _exceptions = new(StringComparer.Ordinal);
    private static readonly Lazy<PublicSuffixList> _default = new(LoadEmbedded);
    private static readonly IdnMapping Idn = new();

    public static PublicSuffixList Default => _default.Value;

    public PublicSuffixList(IEnumerable<string> lines)
    {
        foreach (var raw in lines)
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith("//")) continue;
            var sp = line.IndexOfAny(new[] { ' ', '\t' });
            if (sp > 0) line = line[..sp];
            string Ascii(string s) { try { return Idn.GetAscii(s).ToLowerInvariant(); } catch { return s.ToLowerInvariant(); } }
            if (line.StartsWith("!")) _exceptions.Add(Ascii(line[1..]));
            else if (line.StartsWith("*.")) _wildcards.Add(Ascii(line[2..]));
            else _rules.Add(Ascii(line));
        }
    }

    private static PublicSuffixList LoadEmbedded()
    {
        using var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("public_suffix_list.dat")
            ?? throw new InvalidOperationException("Встроенный public_suffix_list.dat не найден");
        using var r = new StreamReader(s);
        var lines = new List<string>();
        while (r.ReadLine() is { } l) lines.Add(l);
        return new PublicSuffixList(lines);
    }

    /// <summary>Публичный суффикс (eTLD) для ASCII-имени в нижнем регистре.</summary>
    public string GetPublicSuffix(string host)
    {
        var labels = host.Split('.');
        // Ищем самое длинное совпадение; исключения имеют приоритет.
        for (int i = 0; i < labels.Length; i++)
        {
            var candidate = string.Join('.', labels, i, labels.Length - i);
            if (_exceptions.Contains(candidate))
                return string.Join('.', labels, i + 1, labels.Length - i - 1);
            if (_rules.Contains(candidate)) return candidate;
            if (i + 1 < labels.Length)
            {
                var parent = string.Join('.', labels, i + 1, labels.Length - i - 1);
                if (_wildcards.Contains(parent)) return candidate;
            }
        }
        return labels[^1]; // правило по умолчанию "*"
    }

    /// <summary>Регистрируемый домен (eTLD+1) или null, если имя само является публичным суффиксом.</summary>
    public string? GetRegistrableDomain(string host)
    {
        var suffix = GetPublicSuffix(host);
        if (host.Length <= suffix.Length) return null;
        var rest = host[..(host.Length - suffix.Length - 1)];
        var lastDot = rest.LastIndexOf('.');
        return (lastDot < 0 ? rest : rest[(lastDot + 1)..]) + "." + suffix;
    }

    public bool IsPublicSuffix(string host) => GetPublicSuffix(host) == host;

    /// <summary>Существует ли такой домен верхнего уровня (есть в списке).</summary>
    public bool IsKnownTld(string label) => _rules.Contains(label) || _wildcards.Contains(label);
}
