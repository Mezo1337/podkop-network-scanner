using System.Buffers.Binary;
using System.Net;
using System.Text;

namespace PodkopScanner.Core.Monitoring;

public readonly record struct PacketInfo(IPAddress Src, IPAddress Dst, int SrcPort, int DstPort, byte Protocol, int PayloadOffset, int PayloadLength, uint TcpSeq);

public static class PacketParsing
{
    /// <summary>Разбор заголовков IPv4/IPv6 + TCP/UDP (без расширенных заголовков IPv6).</summary>
    public static PacketInfo? Parse(ReadOnlySpan<byte> p)
    {
        if (p.Length < 20) return null;
        int ver = p[0] >> 4;
        IPAddress src, dst; byte proto; int off; int total;
        if (ver == 4)
        {
            int ihl = (p[0] & 0x0F) * 4;
            if (ihl < 20 || p.Length < ihl) return null;
            total = Math.Min(BinaryPrimitives.ReadUInt16BigEndian(p[2..]), p.Length);
            proto = p[9];
            src = new IPAddress(p.Slice(12, 4)); dst = new IPAddress(p.Slice(16, 4));
            off = ihl;
        }
        else if (ver == 6)
        {
            if (p.Length < 40) return null;
            total = Math.Min(40 + BinaryPrimitives.ReadUInt16BigEndian(p[4..]), p.Length);
            proto = p[6];
            src = new IPAddress(p.Slice(8, 16)); dst = new IPAddress(p.Slice(24, 16));
            off = 40;
        }
        else return null;

        if (proto == 6)
        {
            if (total < off + 20) return null;
            int sp = BinaryPrimitives.ReadUInt16BigEndian(p[off..]), dp = BinaryPrimitives.ReadUInt16BigEndian(p[(off + 2)..]);
            uint seq = BinaryPrimitives.ReadUInt32BigEndian(p[(off + 4)..]);
            int doff = (p[off + 12] >> 4) * 4;
            int po = off + doff;
            return new PacketInfo(src, dst, sp, dp, proto, po, Math.Max(0, total - po), seq);
        }
        if (proto == 17)
        {
            if (total < off + 8) return null;
            int sp = BinaryPrimitives.ReadUInt16BigEndian(p[off..]), dp = BinaryPrimitives.ReadUInt16BigEndian(p[(off + 2)..]);
            return new PacketInfo(src, dst, sp, dp, proto, off + 8, Math.Max(0, total - off - 8), 0);
        }
        return null;
    }
}

/// <summary>Извлечение имени сервера (SNI) из TLS ClientHello. Поддерживает ClientHello из нескольких TCP-сегментов.</summary>
public static class TlsSni
{
    public enum State { NotTls, NeedMore, Found, NoSni }

    /// <summary>
    /// Ожидаемая полная длина TLS-записи с ClientHello по первому сегменту (или -1, если это не ClientHello).
    /// </summary>
    public static int ExpectedRecordLength(ReadOnlySpan<byte> first)
    {
        if (first.Length < 6) return -1;
        if (first[0] != 0x16 || first[1] != 0x03) return -1; // handshake, TLS 1.x
        if (first[5] != 0x01) return -1;                       // ClientHello
        return 5 + BinaryPrimitives.ReadUInt16BigEndian(first[3..]);
    }

    public static State TryGetSni(ReadOnlySpan<byte> rec, out string? sni) => TryGetSni(rec, out sni, out _);

    public static State TryGetSni(ReadOnlySpan<byte> rec, out string? sni, out bool ech)
    {
        sni = null; ech = false;
        int need = ExpectedRecordLength(rec);
        if (need < 0) return State.NotTls;
        if (rec.Length < Math.Min(need, 16384 + 5)) return State.NeedMore;
        try
        {
            int pos = 5 + 4;          // заголовок записи + заголовок handshake
            pos += 2 + 32;            // версия + random
            pos += 1 + rec[pos];      // session id
            pos += 2 + BinaryPrimitives.ReadUInt16BigEndian(rec[pos..]); // cipher suites
            pos += 1 + rec[pos];      // compression
            if (pos + 2 > rec.Length) return State.NoSni;
            int extEnd = pos + 2 + BinaryPrimitives.ReadUInt16BigEndian(rec[pos..]);
            pos += 2;
            while (pos + 4 <= Math.Min(extEnd, rec.Length))
            {
                int type = BinaryPrimitives.ReadUInt16BigEndian(rec[pos..]);
                int len = BinaryPrimitives.ReadUInt16BigEndian(rec[(pos + 2)..]);
                pos += 4;
                if (type == 0 && pos + len <= rec.Length)
                {
                    int p = pos + 2; // длина списка
                    while (p + 3 <= pos + len)
                    {
                        int nt = rec[p]; int nl = BinaryPrimitives.ReadUInt16BigEndian(rec[(p + 1)..]);
                        p += 3;
                        if (nt == 0 && p + nl <= rec.Length)
                            sni = Encoding.ASCII.GetString(rec.Slice(p, nl)).ToLowerInvariant();
                        p += nl;
                    }
                }
                // Encrypted Client Hello (0xfe0d): настоящее имя зашифровано, внешний SNI — имя фронта.
                if (type == 0xFE0D) ech = true;
                pos += len;
            }
            return sni != null ? State.Found : State.NoSni;
        }
        catch (ArgumentOutOfRangeException) { return State.NoSni; }
        catch (IndexOutOfRangeException) { return State.NoSni; }
    }
}
