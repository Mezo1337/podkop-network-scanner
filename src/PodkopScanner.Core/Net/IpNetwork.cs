using System.Net;
using System.Net.Sockets;

namespace PodkopScanner.Core.Net;

/// <summary>Сеть IPv4/IPv6 в виде (адрес сети, длина префикса). Адрес хранится как UInt128.</summary>
public readonly record struct IpNetwork(bool IsV6, UInt128 Network, int Prefix) : IComparable<IpNetwork>
{
    public int MaxBits => IsV6 ? 128 : 32;
    public bool IsSingleHost => Prefix == MaxBits;
    public UInt128 First => Network;
    public UInt128 Last => Network | HostMask(IsV6, Prefix);

    /// <summary>Количество адресов (для IPv6 ограничено сверху UInt128.MaxValue).</summary>
    public UInt128 Size => Prefix == 0 && IsV6 ? UInt128.MaxValue : (UInt128)1 << (MaxBits - Prefix);

    public static UInt128 HostMask(bool v6, int prefix)
    {
        int bits = v6 ? 128 : 32;
        int host = bits - prefix;
        if (host <= 0) return 0;
        if (host >= 128) return UInt128.MaxValue;
        return ((UInt128)1 << host) - 1;
    }

    public static UInt128 ToUInt128(IPAddress ip)
    {
        var b = ip.GetAddressBytes();
        UInt128 v = 0;
        foreach (var x in b) v = (v << 8) | x;
        return v;
    }

    public static IPAddress ToAddress(bool v6, UInt128 v)
    {
        var len = v6 ? 16 : 4;
        var b = new byte[len];
        for (int i = len - 1; i >= 0; i--) { b[i] = (byte)(v & 0xFF); v >>= 8; }
        return new IPAddress(b);
    }

    public IPAddress Address => ToAddress(IsV6, Network);

    public bool Contains(IPAddress ip)
    {
        ip = Unmap(ip);
        if ((ip.AddressFamily == AddressFamily.InterNetworkV6) != IsV6) return false;
        var v = ToUInt128(ip);
        return v >= First && v <= Last;
    }

    public bool Contains(IpNetwork other) => other.IsV6 == IsV6 && other.First >= First && other.Last <= Last;

    public static IPAddress Unmap(IPAddress ip) => ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip;

    public static IpNetwork FromAddress(IPAddress ip)
    {
        ip = Unmap(ip);
        ip.ScopeId = 0;
        bool v6 = ip.AddressFamily == AddressFamily.InterNetworkV6;
        return new IpNetwork(v6, ToUInt128(ip), v6 ? 128 : 32);
    }

    /// <summary>Разбор "1.2.3.4", "1.2.3.4/24", "2001:db8::/32". Адрес приводится к адресу сети.</summary>
    public static bool TryParse(string? s, out IpNetwork net) => TryParse(s, out net, out _);

    public static bool TryParse(string? s, out IpNetwork net, out bool hadHostBits)
    {
        net = default; hadHostBits = false;
        if (string.IsNullOrWhiteSpace(s)) return false;
        s = s.Trim();
        string addrPart = s; int prefix = -1;
        var slash = s.IndexOf('/');
        if (slash >= 0)
        {
            addrPart = s[..slash];
            if (!int.TryParse(s[(slash + 1)..], System.Globalization.NumberStyles.None, null, out prefix)) return false;
        }
        if (addrPart.StartsWith('[') && addrPart.EndsWith(']')) addrPart = addrPart[1..^1];
        var pct = addrPart.IndexOf('%');
        if (pct >= 0) addrPart = addrPart[..pct];
        if (!IPAddress.TryParse(addrPart, out var ip)) return false;
        // IPAddress.TryParse принимает "1" и "1.2" как IPv4 — такие формы не допускаем.
        if (ip.AddressFamily == AddressFamily.InterNetwork && addrPart.Count(c => c == '.') != 3) return false;
        if (ip.AddressFamily == AddressFamily.InterNetwork && addrPart.Split('.').Any(o => o.Length > 1 && o[0] == '0')) return false;
        ip = Unmap(ip);
        bool v6 = ip.AddressFamily == AddressFamily.InterNetworkV6;
        int max = v6 ? 128 : 32;
        if (prefix < 0) prefix = max;
        if (prefix > max) return false;
        var raw = ToUInt128(ip);
        var masked = raw & ~HostMask(v6, prefix);
        hadHostBits = masked != raw;
        net = new IpNetwork(v6, masked, prefix);
        return true;
    }

    public static IpNetwork Parse(string s) => TryParse(s, out var n) ? n : throw new FormatException($"Не IP/CIDR: {s}");

    /// <summary>Строка для Podkop. Одиночный адрес — либо без маски, либо /32 (/128).</summary>
    public string ToString(bool singleAsCidr) =>
        IsSingleHost && !singleAsCidr ? Address.ToString() : $"{Address}/{Prefix}";

    public override string ToString() => IsSingleHost ? Address.ToString() : $"{Address}/{Prefix}";

    public int CompareTo(IpNetwork other)
    {
        var c = IsV6.CompareTo(other.IsV6);
        if (c != 0) return c;
        c = Network.CompareTo(other.Network);
        return c != 0 ? c : Prefix.CompareTo(other.Prefix);
    }
}

public static class Cidr
{
    /// <summary>
    /// Точная агрегация: объединяет пересекающиеся и смежные сети и разбивает результат на минимальный
    /// набор CIDR. Множество покрываемых адресов не изменяется (ни одного нового адреса не добавляется).
    /// </summary>
    public static List<IpNetwork> AggregateExact(IEnumerable<IpNetwork> nets)
    {
        var result = new List<IpNetwork>();
        foreach (var fam in nets.GroupBy(n => n.IsV6))
        {
            bool v6 = fam.Key;
            var ranges = fam.Select(n => (n.First, n.Last)).OrderBy(r => r.First).ToList();
            var merged = new List<(UInt128 a, UInt128 b)>();
            foreach (var (a, b) in ranges)
            {
                if (merged.Count > 0)
                {
                    var (pa, pb) = merged[^1];
                    bool adjacent = pb != UInt128.MaxValue && a <= pb + 1;
                    if (a <= pb || adjacent) { merged[^1] = (pa, b > pb ? b : pb); continue; }
                }
                merged.Add((a, b));
            }
            foreach (var (a, b) in merged) result.AddRange(RangeToCidrs(v6, a, b));
        }
        result.Sort();
        return result;
    }

    public static IEnumerable<IpNetwork> RangeToCidrs(bool v6, UInt128 start, UInt128 end)
    {
        int bits = v6 ? 128 : 32;
        while (true)
        {
            // Наибольший блок, выровненный по start и не выходящий за end.
            int prefix = bits;
            while (prefix > 0)
            {
                int p = prefix - 1;
                var mask = IpNetwork.HostMask(v6, p);
                if ((start & mask) != 0) break;
                if ((start | mask) > end) break;
                prefix = p;
            }
            var net = new IpNetwork(v6, start, prefix);
            yield return net;
            var last = net.Last;
            if (last >= end || last == UInt128.MaxValue) yield break;
            start = last + 1;
        }
    }

    /// <summary>Порог предупреждения о слишком широкой сети.</summary>
    public static bool IsVeryLarge(IpNetwork n) => n.IsV6 ? n.Prefix < 48 : n.Prefix < 20;

    public static string SizeText(IpNetwork n) =>
        n.IsV6 ? $"/{n.Prefix}" : $"{(ulong)n.Size:N0} адресов";
}

/// <summary>Специальные и локальные диапазоны (RFC 6890 и др.), которые не нужно отправлять в прокси.</summary>
public static class SpecialRanges
{
    public sealed record Range(IpNetwork Net, string Description);

    public static readonly IReadOnlyList<Range> All = new[]
    {
        R("0.0.0.0/8", "«этот» сегмент"), R("10.0.0.0/8", "частная сеть"), R("100.64.0.0/10", "CGNAT"),
        R("127.0.0.0/8", "loopback"), R("169.254.0.0/16", "link-local"), R("172.16.0.0/12", "частная сеть"),
        R("192.0.0.0/24", "IETF"), R("192.0.2.0/24", "документация"), R("192.88.99.0/24", "6to4 relay"),
        R("192.168.0.0/16", "частная сеть"), R("198.18.0.0/15", "тестовая сеть / fake-ip sing-box"),
        R("198.51.100.0/24", "документация"), R("203.0.113.0/24", "документация"),
        R("224.0.0.0/4", "multicast"), R("240.0.0.0/4", "зарезервировано"),
        R("::/128", "неопределённый"), R("::1/128", "loopback"), R("64:ff9b:1::/48", "NAT64 локальный"),
        R("100::/64", "discard"), R("2001:db8::/32", "документация"), R("fc00::/7", "ULA"),
        R("fe80::/10", "link-local"), R("ff00::/8", "multicast"), R("2001::/32", "Teredo"),
    };

    private static Range R(string s, string d) => new(IpNetwork.Parse(s), d);

    public static Range? Match(IpNetwork n) => All.FirstOrDefault(r => r.Net.IsV6 == n.IsV6 && (r.Net.Contains(n) || n.Contains(r.Net)));

    public static bool IsSpecial(IpNetwork n) => Match(n) != null;

    public static bool IsSpecial(IPAddress ip) => IsSpecial(IpNetwork.FromAddress(ip));

    /// <summary>Диапазон fake-ip sing-box (Podkop использует 198.18.0.0/15) — признак туннеля.</summary>
    public static readonly IpNetwork FakeIp = IpNetwork.Parse("198.18.0.0/15");
}
