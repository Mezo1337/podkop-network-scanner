using System.Buffers.Binary;
using System.Net;
using System.Text;

namespace PodkopScanner.Core.Net;

public enum DnsType : ushort { A = 1, CNAME = 5, TXT = 16, AAAA = 28 }

public sealed record DnsRecord(string Name, DnsType Type, uint Ttl, string Data, IPAddress? Address);

public sealed class DnsResponse
{
    public ushort Id { get; init; }
    public int RCode { get; init; }
    public bool Truncated { get; init; }
    public bool IsResponse { get; init; }
    public List<string> Questions { get; } = new();
    public List<DnsRecord> Answers { get; } = new();
}

/// <summary>Минимальный кодек DNS (RFC 1035) — запросы A/AAAA/TXT и разбор ответов, включая сжатие имён.</summary>
public static class DnsMessage
{
    public static byte[] BuildQuery(string name, DnsType type, ushort id)
    {
        var ms = new MemoryStream();
        Span<byte> hdr = stackalloc byte[12];
        BinaryPrimitives.WriteUInt16BigEndian(hdr, id);
        hdr[2] = 0x01; // RD
        BinaryPrimitives.WriteUInt16BigEndian(hdr[4..], 1);
        ms.Write(hdr);
        foreach (var label in name.TrimEnd('.').Split('.'))
        {
            var b = Encoding.ASCII.GetBytes(label);
            if (b.Length is 0 or > 63) throw new ArgumentException("Недопустимая метка DNS: " + name);
            ms.WriteByte((byte)b.Length);
            ms.Write(b);
        }
        ms.WriteByte(0);
        Span<byte> q = stackalloc byte[4];
        BinaryPrimitives.WriteUInt16BigEndian(q, (ushort)type);
        BinaryPrimitives.WriteUInt16BigEndian(q[2..], 1);
        ms.Write(q);
        return ms.ToArray();
    }

    public static DnsResponse Parse(ReadOnlySpan<byte> msg)
    {
        if (msg.Length < 12) throw new FormatException("DNS-сообщение слишком короткое");
        var flags = BinaryPrimitives.ReadUInt16BigEndian(msg[2..]);
        var resp = new DnsResponse
        {
            Id = BinaryPrimitives.ReadUInt16BigEndian(msg),
            IsResponse = (flags & 0x8000) != 0,
            Truncated = (flags & 0x0200) != 0,
            RCode = flags & 0x000F,
        };
        int qd = BinaryPrimitives.ReadUInt16BigEndian(msg[4..]);
        int an = BinaryPrimitives.ReadUInt16BigEndian(msg[6..]);
        int pos = 12;
        for (int i = 0; i < qd; i++)
        {
            resp.Questions.Add(ReadName(msg, ref pos));
            pos += 4;
        }
        for (int i = 0; i < an && pos < msg.Length; i++)
        {
            var name = ReadName(msg, ref pos);
            if (pos + 10 > msg.Length) break;
            var type = (DnsType)BinaryPrimitives.ReadUInt16BigEndian(msg[pos..]);
            var ttl = BinaryPrimitives.ReadUInt32BigEndian(msg[(pos + 4)..]);
            int rdlen = BinaryPrimitives.ReadUInt16BigEndian(msg[(pos + 8)..]);
            pos += 10;
            if (pos + rdlen > msg.Length) break;
            var rdata = msg.Slice(pos, rdlen);
            switch (type)
            {
                case DnsType.A when rdlen == 4:
                case DnsType.AAAA when rdlen == 16:
                    var ip = new IPAddress(rdata);
                    resp.Answers.Add(new DnsRecord(name, type, ttl, ip.ToString(), ip));
                    break;
                case DnsType.CNAME:
                    int p2 = pos;
                    resp.Answers.Add(new DnsRecord(name, type, ttl, ReadName(msg, ref p2), null));
                    break;
                case DnsType.TXT:
                    var sb = new StringBuilder();
                    int t = 0;
                    while (t < rdlen) { int l = rdata[t++]; if (t + l > rdlen) break; sb.Append(Encoding.ASCII.GetString(rdata.Slice(t, l))); t += l; }
                    resp.Answers.Add(new DnsRecord(name, type, ttl, sb.ToString(), null));
                    break;
            }
            pos += rdlen;
        }
        return resp;
    }

    private static string ReadName(ReadOnlySpan<byte> msg, ref int pos)
    {
        var sb = new StringBuilder();
        int p = pos; bool jumped = false; int guard = 0;
        while (true)
        {
            if (p >= msg.Length || ++guard > 128) throw new FormatException("Повреждённое имя DNS");
            int len = msg[p];
            if ((len & 0xC0) == 0xC0)
            {
                if (p + 1 >= msg.Length) throw new FormatException("Повреждённый указатель DNS");
                int ptr = ((len & 0x3F) << 8) | msg[p + 1];
                if (!jumped) pos = p + 2;
                jumped = true; p = ptr; continue;
            }
            p++;
            if (len == 0) break;
            if (p + len > msg.Length) throw new FormatException("Повреждённая метка DNS");
            if (sb.Length > 0) sb.Append('.');
            sb.Append(Encoding.ASCII.GetString(msg.Slice(p, len)));
            p += len;
        }
        if (!jumped) pos = p;
        return sb.ToString().ToLowerInvariant();
    }
}
