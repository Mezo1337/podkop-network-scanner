using System.ComponentModel;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace PodkopScanner.Core.Monitoring;

/// <summary>P/Invoke для WinDivert 2.2 (WinDivert.dll + WinDivert64.sys рядом с exe).</summary>
internal static unsafe class WinDivertNative
{
    public const int LayerNetwork = 0, LayerFlow = 2, LayerSocket = 3;
    public const ulong FlagSniff = 0x0001, FlagRecvOnly = 0x0004;
    public const int EventFlowEstablished = 1, EventFlowDeleted = 2, EventSocketConnect = 4;
    public const int ParamQueueLength = 0, ParamQueueTime = 1, ParamQueueSize = 2;

    [StructLayout(LayoutKind.Explicit, Size = 80)]
    public struct Address
    {
        [FieldOffset(0)] public long Timestamp;
        [FieldOffset(8)] public uint Bits;           // Layer:8 Event:8 Sniffed:1 Outbound:1 Loopback:1 Impostor:1 IPv6:1 ...
        // Объединение Flow/Socket начинается со смещения 16.
        [FieldOffset(16)] public ulong EndpointId;
        [FieldOffset(24)] public ulong ParentEndpointId;
        [FieldOffset(32)] public uint ProcessId;
        [FieldOffset(36)] public fixed uint LocalAddr[4];
        [FieldOffset(52)] public fixed uint RemoteAddr[4];
        [FieldOffset(68)] public ushort LocalPort;
        [FieldOffset(70)] public ushort RemotePort;
        [FieldOffset(72)] public byte Protocol;

        public int Layer => (int)(Bits & 0xFF);
        public int Event => (int)((Bits >> 8) & 0xFF);
        public bool Outbound => ((Bits >> 17) & 1) != 0;
        public bool Loopback => ((Bits >> 18) & 1) != 0;
        public bool IPv6 => ((Bits >> 20) & 1) != 0;
    }

    [DllImport("WinDivert.dll", SetLastError = true, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr WinDivertOpen(string filter, int layer, short priority, ulong flags);

    [DllImport("WinDivert.dll", SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
    public static extern bool WinDivertRecv(IntPtr handle, byte* packet, uint packetLen, out uint recvLen, Address* addr);

    [DllImport("WinDivert.dll", SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
    public static extern bool WinDivertShutdown(IntPtr handle, int how);

    [DllImport("WinDivert.dll", SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
    public static extern bool WinDivertClose(IntPtr handle);

    [DllImport("WinDivert.dll", SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
    public static extern bool WinDivertSetParam(IntPtr handle, int param, ulong value);

    [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern bool WinDivertHelperFormatIPv6Address(uint* addr, byte* buffer, uint bufLen);

    public static IPAddress ToIp(uint* a)
    {
        byte* buf = stackalloc byte[64];
        if (!WinDivertHelperFormatIPv6Address(a, buf, 64)) return IPAddress.IPv6None;
        var s = Marshal.PtrToStringAnsi((IntPtr)buf) ?? "::";
        var ip = IPAddress.Parse(s);
        return ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip;
    }

    public static readonly IntPtr Invalid = new(-1);

    /// <summary>Понятное объяснение ошибки открытия WinDivert.</summary>
    public static string Explain(int err) => err switch
    {
        2 => "Не найден драйвер WinDivert64.sys рядом с программой. Переустановите программу.",
        5 => "Нет прав администратора. Перезапустите программу от имени администратора.",
        87 => "Внутренняя ошибка: неверный фильтр WinDivert.",
        577 => "Windows не приняла подпись драйвера WinDivert (ERROR_INVALID_IMAGE_HASH). Проверьте, не блокирует ли его политика целостности кода.",
        654 => "Ранее загружена другая версия драйвера WinDivert. Закройте программы, использующие WinDivert (например, GoodbyeDPI, zapret), или перезагрузите компьютер.",
        1275 => "Драйвер WinDivert заблокирован системой или антивирусом (ERROR_DRIVER_BLOCKED). " +
                "Защиту отключать не нужно: можно использовать режим без драйвера (только TCP) или добавить разрешение в антивирусе самостоятельно.",
        1753 => "Служба «Base Filtering Engine» (BFE) не запущена — WinDivert не может работать.",
        _ => $"WinDivert вернул ошибку {err}: {new Win32Exception(err).Message}",
    };
}

internal static class IpHelperNative
{
    public const int AF_INET = 2, AF_INET6 = 23;
    public const int TCP_TABLE_OWNER_PID_ALL = 5;

    [DllImport("iphlpapi.dll", SetLastError = true)]
    public static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int pdwSize, bool bOrder, int ulAf, int tableClass, uint reserved = 0);

    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_TCPROW_OWNER_PID
    {
        public uint state, localAddr, localPort, remoteAddr, remotePort, owningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    public unsafe struct MIB_TCP6ROW_OWNER_PID
    {
        public fixed byte localAddr[16];
        public uint localScopeId, localPort;
        public fixed byte remoteAddr[16];
        public uint remoteScopeId, remotePort, state, owningPid;
    }

    public sealed record TcpConn(int Pid, IPAddress Remote, int RemotePort, int LocalPort, int State);

    /// <summary>Таблица TCP-соединений Windows с PID владельца (не требует прав администратора).</summary>
    public static unsafe List<TcpConn> GetTcpConnections()
    {
        var list = new List<TcpConn>();
        foreach (var af in new[] { AF_INET, AF_INET6 })
        {
            int size = 0;
            GetExtendedTcpTable(IntPtr.Zero, ref size, false, af, TCP_TABLE_OWNER_PID_ALL);
            var buf = Marshal.AllocHGlobal(size + 1024);
            try
            {
                size += 1024;
                if (GetExtendedTcpTable(buf, ref size, false, af, TCP_TABLE_OWNER_PID_ALL) != 0) continue;
                int n = Marshal.ReadInt32(buf);
                var p = buf + 4;
                if (af == AF_INET)
                {
                    var rows = new ReadOnlySpan<MIB_TCPROW_OWNER_PID>((void*)p, n);
                    foreach (var r in rows)
                    {
                        if (r.remoteAddr == 0) continue;
                        list.Add(new TcpConn((int)r.owningPid, new IPAddress(r.remoteAddr), Port(r.remotePort), Port(r.localPort), (int)r.state));
                    }
                }
                else
                {
                    var rows = new ReadOnlySpan<MIB_TCP6ROW_OWNER_PID>((void*)(p), n);
                    foreach (var r in rows)
                    {
                        var b = new byte[16];
                        for (int i = 0; i < 16; i++) b[i] = r.remoteAddr[i];
                        var ip = new IPAddress(b);
                        if (ip.Equals(IPAddress.IPv6Any)) continue;
                        list.Add(new TcpConn((int)r.owningPid, ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip, Port(r.remotePort), Port(r.localPort), (int)r.state));
                    }
                }
            }
            finally { Marshal.FreeHGlobal(buf); }
        }
        return list;
        static int Port(uint p) => (int)(((p & 0xFF) << 8) | ((p >> 8) & 0xFF));
    }
}

/// <summary>Сведения о процессах Windows: дерево родителей, путь к образу, время запуска.</summary>
public static class ProcessInfo
{
    public sealed record Proc(int Pid, int ParentPid, string Name, string? Path, DateTime? Created);

    [DllImport("kernel32.dll", SetLastError = true)] private static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint pid);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)] private static extern bool Process32FirstW(IntPtr snap, ref PROCESSENTRY32W e);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)] private static extern bool Process32NextW(IntPtr snap, ref PROCESSENTRY32W e);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)] private static extern bool QueryFullProcessImageNameW(IntPtr h, int flags, StringBuilder name, ref int size);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool GetProcessTimes(IntPtr h, out long creation, out long exit, out long kernel, out long user);
    [DllImport("dnsapi.dll")] private static extern bool DnsFlushResolverCache();

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct PROCESSENTRY32W
    {
        public uint dwSize, cntUsage, th32ProcessID; public IntPtr th32DefaultHeapID; public uint th32ModuleID, cntThreads, th32ParentProcessID; public int pcPriClassBase; public uint dwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szExeFile;
    }

    public static Dictionary<int, Proc> Snapshot()
    {
        var d = new Dictionary<int, Proc>();
        var snap = CreateToolhelp32Snapshot(0x2, 0);
        if (snap == new IntPtr(-1)) return d;
        try
        {
            var e = new PROCESSENTRY32W { dwSize = (uint)Marshal.SizeOf<PROCESSENTRY32W>() };
            if (!Process32FirstW(snap, ref e)) return d;
            do
            {
                var pid = (int)e.th32ProcessID;
                d[pid] = new Proc(pid, (int)e.th32ParentProcessID, e.szExeFile, null, null);
            } while (Process32NextW(snap, ref e));
        }
        finally { CloseHandle(snap); }
        return d;
    }

    /// <summary>Путь к образу и время запуска процесса (PROCESS_QUERY_LIMITED_INFORMATION).</summary>
    public static (string? path, DateTime? created) Details(int pid)
    {
        var h = OpenProcess(0x1000, false, pid);
        if (h == IntPtr.Zero) return (null, null);
        try
        {
            var sb = new StringBuilder(1024); int size = sb.Capacity;
            string? path = QueryFullProcessImageNameW(h, 0, sb, ref size) ? sb.ToString() : null;
            DateTime? created = GetProcessTimes(h, out var c, out _, out _, out _) ? DateTime.FromFileTimeUtc(c) : null;
            return (path, created);
        }
        finally { CloseHandle(h); }
    }

    public static bool IsAdministrator()
    {
        using var id = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
    }

    /// <summary>Очистка DNS-кэша Windows (аналог ipconfig /flushdns), чтобы увидеть запросы, ответы на которые закэшированы.</summary>
    public static bool FlushDnsCache()
    {
        try { return DnsFlushResolverCache(); } catch { return false; }
    }
}
