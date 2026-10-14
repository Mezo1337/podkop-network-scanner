using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Threading.Channels;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;
using PodkopScanner.Core.Analysis;
using PodkopScanner.Core.Model;
using PodkopScanner.Core.Net;

namespace PodkopScanner.Core.Monitoring;

public sealed class ProcessMonitorOptions
{
    public string? ExePath { get; init; }
    public int? Pid { get; init; }
    public bool IncludeChildren { get; init; } = true;
    public bool IncludeFolderProcesses { get; init; }
    public bool FlushDnsCache { get; init; } = true;
    /// <summary>Адреса туннеля/прокси, которые не являются адресами серверов программы.</summary>
    public IReadOnlyCollection<IPAddress> TunnelEndpoints { get; init; } = Array.Empty<IPAddress>();
    /// <summary>Порты локальных прокси-клиентов на 127.0.0.1 (системный прокси Windows и т.п.).</summary>
    public IReadOnlyCollection<int> LocalProxyPorts { get; init; } = Array.Empty<int>();
    public string Route { get; init; } = "direct";
}

public sealed record LiveConnection(
    DateTime Time, int Pid, string Process, string Protocol, string Remote, int Port, string? Domain,
    string Source, string Relation, bool Undetermined, string Note);

public enum CaptureMode { WinDivert, IpHelperOnly }

/// <summary>
/// Мониторинг сетевых соединений выбранной программы.
/// Основной режим (администратор + драйвер WinDivert):
///   • FLOW-слой — каждый установленный TCP/UDP-поток с PID владельца из ядра (WFP ALE);
///   • SOCKET-слой — каждый вызов connect(), в том числе неудачный;
///   • NETWORK-слой (только чтение) — SNI из TLS ClientHello и DNS-ответы по UDP/53, привязанные к PID
///     через точное совпадение 5-кортежа с потоком;
///   • ETW Microsoft-Windows-DNS-Client — DNS-запросы процесса через системный резолвер.
/// Резервный режим (без драйвера): опрос таблицы TCP Windows с PID — только TCP, короткие соединения могут быть пропущены.
/// Все хэндлы WinDivert открываются в режиме SNIFF|RECV_ONLY: трафик не изменяется и не блокируется.
/// </summary>
public sealed class ProcessMonitor : IAsyncDisposable
{
    private readonly ProcessMonitorOptions _o;
    private readonly ProcessTracker _tracker;
    private readonly Channel<Action> _events = Channel.CreateUnbounded<Action>(new UnboundedChannelOptions { SingleReader = true });
    private readonly CancellationTokenSource _cts = new();
    private readonly List<IntPtr> _handles = new();
    private readonly List<Thread> _threads = new();
    private TraceEventSession? _etw;
    private Task? _consumer;

    // Состояние обработчика (только поток-потребитель).
    private readonly Dictionary<(byte proto, int lport, IPAddress raddr, int rport), int> _flowPid = new();
    private readonly Dictionary<(byte proto, int lport), int> _localPortPid = new();
    private readonly Dictionary<int, Dictionary<IPAddress, (string name, string how, DateTime t)>> _dnsByPid = new();
    private readonly HashSet<string> _emitted = new();
    private readonly List<(DateTime t, IPAddress laddr, int lport, IPAddress raddr, int rport, string sni, bool ech)> _pendingSni = new();
    private readonly HashSet<(int pid, string ip)> _tcpTableSeen = new();
    private int _fakeIpWarnings;
    private readonly Dictionary<int, int> _loopbackProxyPid = new();   // локальный порт клиента → PID
    private readonly HashSet<int> _proxyPorts;
    private readonly List<(DateTime t, int lport, ProxyRequestParser.Target target)> _pendingProxy = new();

    // Сборка ClientHello из сегментов (потоки чтения пакетов).
    private readonly ConcurrentDictionary<(IPAddress, int, IPAddress, int), SniBuffer> _sniBuf = new();
    private sealed class SniBuffer { public byte[] Data = Array.Empty<byte>(); public int Expected; public DateTime Started = DateTime.UtcNow; public bool Done; }

    public event Action<Finding>? Found;
    public event Action<LiveConnection>? Connection;
    public event Action<string>? Log;

    public CaptureMode Mode { get; private set; }
    public bool DnsEtwActive { get; private set; }
    public IReadOnlyCollection<TrackedProcess> Tracked => _tracker.Tracked;
    public int FlowCount { get; private set; }

    public ProcessMonitor(ProcessMonitorOptions o)
    {
        _o = o;
        _tracker = new ProcessTracker(o.ExePath, o.Pid, o.IncludeChildren, o.IncludeFolderProcesses);
        _proxyPorts = o.LocalProxyPorts.ToHashSet();
        _tracker.ProcessAdded += t => Log?.Invoke($"Отслеживается процесс {t.Name} (PID {t.Pid}) — {t.Explanation}");
    }

    /// <summary>Проверка доступности драйвера без запуска мониторинга.</summary>
    public static (bool ok, string message) CheckDriver()
    {
        var dir = AppContext.BaseDirectory;
        if (!Environment.Is64BitProcess) return (false, "Нужна 64-битная версия программы.");
        if (!File.Exists(Path.Combine(dir, "WinDivert.dll")) || !File.Exists(Path.Combine(dir, "WinDivert64.sys")))
            return (false, "Рядом с программой нет WinDivert.dll / WinDivert64.sys.");
        if (!ProcessInfo.IsAdministrator())
            return (false, "Для захвата соединений через драйвер WinDivert нужны права администратора.");
        try
        {
            var h = WinDivertNative.WinDivertOpen("false", WinDivertNative.LayerFlow, 0, WinDivertNative.FlagSniff | WinDivertNative.FlagRecvOnly);
            if (h == WinDivertNative.Invalid) return (false, WinDivertNative.Explain(Marshal.GetLastWin32Error()));
            WinDivertNative.WinDivertClose(h);
            return (true, "Драйвер WinDivert доступен.");
        }
        catch (DllNotFoundException) { return (false, "Не удалось загрузить WinDivert.dll."); }
        catch (BadImageFormatException) { return (false, "WinDivert.dll повреждён или не той разрядности."); }
    }

    /// <summary>Запуск. Все источники открываются ДО запуска программы, чтобы не пропустить короткие соединения.</summary>
    public void Start(bool allowFallback)
    {
        _consumer = Task.Run(ConsumeAsync);
        if (_o.FlushDnsCache && ProcessInfo.FlushDnsCache())
            Log?.Invoke("DNS-кэш Windows очищен (как ipconfig /flushdns) — программа заново запросит имена, и мы их увидим.");

        var (ok, msg) = CheckDriver();
        if (ok)
        {
            try
            {
                var proxyFlow = _proxyPorts.Count == 0 ? "" :
                    " or (loopback and tcp and (" + string.Join(" or ", _proxyPorts.Select(p => $"remotePort == {p}")) + "))";
                var proxyPkt = _proxyPorts.Count == 0 ? "" :
                    " or (loopback and tcp and tcp.PayloadLength > 0 and (" + string.Join(" or ", _proxyPorts.Select(p => $"tcp.DstPort == {p}")) + "))";
                OpenHandle("(not loopback and (tcp or udp))" + proxyFlow, WinDivertNative.LayerFlow, FlowLoop, "FLOW");
                OpenHandle("event == CONNECT and not loopback", WinDivertNative.LayerSocket, SocketLoop, "SOCKET");
                OpenHandle("(not loopback and ((outbound and tcp and tcp.PayloadLength > 0) or (inbound and udp and udp.SrcPort == 53)))" + proxyPkt,
                    WinDivertNative.LayerNetwork, PacketLoop, "NETWORK");
                if (_proxyPorts.Count > 0)
                    Log?.Invoke($"Учитываются запросы к локальному прокси на портах {string.Join(", ", _proxyPorts)} (HTTP CONNECT / SOCKS) — видны исходные назначения программ, работающих через прокси-клиент.");
                Mode = CaptureMode.WinDivert;
                Log?.Invoke("Захват через WinDivert запущен: TCP и UDP-потоки с PID из ядра, connect(), TLS SNI, DNS-ответы. Трафик не изменяется.");
            }
            catch (Exception ex)
            {
                CloseHandles();
                if (!allowFallback) throw;
                Log?.Invoke("WinDivert не запустился: " + ex.Message);
                ok = false;
            }
        }
        else if (!allowFallback) throw new InvalidOperationException(msg);
        else Log?.Invoke(msg);

        if (!ok)
        {
            Mode = CaptureMode.IpHelperOnly;
            Log?.Invoke("Работаю в ограниченном режиме без драйвера: опрос таблицы TCP-соединений Windows с PID каждые 250 мс. " +
                        "UDP-соединения (игровые серверы, голос) в этом режиме НЕ видны, очень короткие TCP-соединения могут быть пропущены.");
        }
        // Таблица TCP полезна и в основном режиме — подхватывает соединения, открытые до старта.
        StartThread(TcpTableLoop, "TcpTable");
        StartThread(TrackerLoop, "Tracker");
        StartEtw();
    }

    private void OpenHandle(string filter, int layer, Action<IntPtr> loop, string name)
    {
        var h = WinDivertNative.WinDivertOpen(filter, layer, 0, WinDivertNative.FlagSniff | WinDivertNative.FlagRecvOnly);
        if (h == WinDivertNative.Invalid) throw new InvalidOperationException($"{name}: {WinDivertNative.Explain(Marshal.GetLastWin32Error())}");
        WinDivertNative.WinDivertSetParam(h, WinDivertNative.ParamQueueLength, 16384);
        WinDivertNative.WinDivertSetParam(h, WinDivertNative.ParamQueueTime, 8000);
        WinDivertNative.WinDivertSetParam(h, WinDivertNative.ParamQueueSize, 33554432);
        lock (_handles) _handles.Add(h);
        StartThread(() => loop(h), "WinDivert-" + name);
    }

    private void StartThread(Action a, string name)
    {
        var t = new Thread(() => { try { a(); } catch (Exception ex) { Log?.Invoke($"{name}: {ex.Message}"); } }) { IsBackground = true, Name = name };
        _threads.Add(t);
        t.Start();
    }

    private void StartEtw()
    {
        if (!ProcessInfo.IsAdministrator())
        {
            Log?.Invoke("DNS-запросы процесса (ETW) недоступны без прав администратора — домены будут известны только из TLS SNI (если доступен драйвер).");
            return;
        }
        try
        {
            _etw = new TraceEventSession($"PodkopScanner-DNS-{Environment.ProcessId}") { StopOnDispose = true };
            _etw.EnableProvider("Microsoft-Windows-DNS-Client", TraceEventLevel.Verbose, ulong.MaxValue);
            var parser = new RegisteredTraceEventParser(_etw.Source);
            parser.All += OnEtwEvent;
            StartThread(() => _etw.Source.Process(), "ETW-DNS");
            DnsEtwActive = true;
            Log?.Invoke("Наблюдение за DNS-запросами процессов (ETW Microsoft-Windows-DNS-Client) запущено.");
        }
        catch (Exception ex)
        {
            Log?.Invoke("Не удалось включить ETW DNS: " + ex.Message);
        }
    }

    // ───────────── Источники ─────────────

    private unsafe void FlowLoop(IntPtr h)
    {
        var addr = new WinDivertNative.Address();
        while (!_cts.IsCancellationRequested)
        {
            if (!WinDivertNative.WinDivertRecv(h, null, 0, out _, &addr)) break;
            if (addr.Event != WinDivertNative.EventFlowEstablished) continue;
            var pid = (int)addr.ProcessId; var proto = addr.Protocol;
            var laddr = WinDivertNative.ToIp(addr.LocalAddr); var raddr = WinDivertNative.ToIp(addr.RemoteAddr);
            int lport = addr.LocalPort, rport = addr.RemotePort;
            var t = DateTime.UtcNow;
            _events.Writer.TryWrite(() => OnConnection(pid, proto, laddr, lport, raddr, rport, ObservationMethod.FlowEstablished, t));
        }
    }

    private unsafe void SocketLoop(IntPtr h)
    {
        var addr = new WinDivertNative.Address();
        while (!_cts.IsCancellationRequested)
        {
            if (!WinDivertNative.WinDivertRecv(h, null, 0, out _, &addr)) break;
            if (addr.Event != WinDivertNative.EventSocketConnect) continue;
            var pid = (int)addr.ProcessId; var proto = addr.Protocol;
            var laddr = WinDivertNative.ToIp(addr.LocalAddr); var raddr = WinDivertNative.ToIp(addr.RemoteAddr);
            int lport = addr.LocalPort, rport = addr.RemotePort;
            var t = DateTime.UtcNow;
            _events.Writer.TryWrite(() => OnConnection(pid, proto, laddr, lport, raddr, rport, ObservationMethod.SocketConnect, t));
        }
    }

    private unsafe void PacketLoop(IntPtr h)
    {
        var buf = new byte[0xFFFF + 64];
        var addr = new WinDivertNative.Address();
        long lastPrune = Environment.TickCount64;
        fixed (byte* pb = buf)
        {
            while (!_cts.IsCancellationRequested)
            {
                if (!WinDivertNative.WinDivertRecv(h, pb, (uint)buf.Length, out var len, &addr)) break;
                var span = new ReadOnlySpan<byte>(buf, 0, (int)len);
                var pi = PacketParsing.Parse(span);
                if (pi is not { } p) continue;
                if (p.Protocol == 6 && addr.Outbound) HandleTcpPayload(p, span);
                else if (p.Protocol == 17 && p.SrcPort == 53) HandleDnsPacket(p, span);
                if (Environment.TickCount64 - lastPrune > 10000) { PruneSni(); lastPrune = Environment.TickCount64; }
            }
        }
    }

    private void HandleTcpPayload(PacketInfo p, ReadOnlySpan<byte> pkt)
    {
        var key = (p.Src, p.SrcPort, p.Dst, p.DstPort);
        var payload = pkt.Slice(p.PayloadOffset, p.PayloadLength);
        if (IPAddress.IsLoopback(p.Dst) && _proxyPorts.Contains(p.DstPort))
        {
            // Первые сегменты клиента локального прокси: SOCKS5 отправляет запрос вторым пакетом после приветствия.
            var pb = _sniBuf.GetOrAdd(key, _ => new SniBuffer());
            if (pb.Done) return;
            if (++pb.Expected > 3) { pb.Done = true; return; }
            var target = ProxyRequestParser.TryParse(payload);
            if (target != null)
            {
                pb.Done = true;
                int lport = p.SrcPort; var t = DateTime.UtcNow;
                _events.Writer.TryWrite(() => OnProxyRequest(t, lport, target));
            }
            return;
        }
        if (!_sniBuf.TryGetValue(key, out var b))
        {
            int expected = TlsSni.ExpectedRecordLength(payload);
            b = new SniBuffer { Expected = expected, Done = expected < 0 };
            _sniBuf[key] = b;
            if (b.Done) return;
        }
        if (b.Done) return;
        var nb = new byte[b.Data.Length + payload.Length];
        b.Data.CopyTo(nb, 0); payload.CopyTo(nb.AsSpan(b.Data.Length));
        b.Data = nb;
        var st = TlsSni.TryGetSni(b.Data, out var sni, out var ech);
        if (st == TlsSni.State.NeedMore && b.Data.Length < 20000) return;
        b.Done = true; b.Data = Array.Empty<byte>();
        if (st == TlsSni.State.Found && sni != null)
        {
            var t = DateTime.UtcNow;
            _events.Writer.TryWrite(() => OnSni(t, p.Src, p.SrcPort, p.Dst, p.DstPort, sni, ech));
        }
    }

    private void PruneSni()
    {
        var cutoff = DateTime.UtcNow.AddMinutes(-2);
        foreach (var kv in _sniBuf) if (kv.Value.Started < cutoff) _sniBuf.TryRemove(kv.Key, out _);
    }

    private void HandleDnsPacket(PacketInfo p, ReadOnlySpan<byte> pkt)
    {
        DnsResponse r;
        try { r = DnsMessage.Parse(pkt.Slice(p.PayloadOffset, p.PayloadLength)); } catch { return; }
        if (!r.IsResponse || r.Questions.Count == 0) return;
        var name = r.Questions[0];
        var ips = r.Answers.Where(a => a.Address != null).Select(a => IpNetwork.Unmap(a.Address!)).ToList();
        int lport = p.DstPort; var t = DateTime.UtcNow;
        _events.Writer.TryWrite(() => OnDnsSniff(t, lport, name, ips));
    }

    private void OnEtwEvent(TraceEvent e)
    {
        try
        {
            var idx = Array.IndexOf(e.PayloadNames, "QueryName");
            if (idx < 0) return;
            var name = e.PayloadValue(idx) as string;
            if (string.IsNullOrEmpty(name)) return;
            var ri = Array.IndexOf(e.PayloadNames, "QueryResults");
            var results = ri >= 0 ? e.PayloadValue(ri) as string : null;
            var ips = new List<IPAddress>();
            if (!string.IsNullOrEmpty(results))
                foreach (var part in results.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                    if (IPAddress.TryParse(part, out var ip)) ips.Add(IpNetwork.Unmap(ip));
            int pid = e.ProcessID; var t = DateTime.UtcNow;
            _events.Writer.TryWrite(() => OnEtwDns(t, pid, name.TrimEnd('.'), ips));
        }
        catch { }
    }

    private void TcpTableLoop()
    {
        while (!_cts.IsCancellationRequested)
        {
            try
            {
                var conns = IpHelperNative.GetTcpConnections();
                var t = DateTime.UtcNow;
                _events.Writer.TryWrite(() =>
                {
                    foreach (var c in conns)
                    {
                        if (IPAddress.IsLoopback(c.Remote))
                        {
                            if (Mode == CaptureMode.IpHelperOnly && _proxyPorts.Contains(c.RemotePort) && _tracker.Resolve(c.Pid) is { Relation: not ProcessRelation.SharedService } lp
                                && _emitted.Add($"lpw|{c.Pid}"))
                                Log?.Invoke($"{lp.Name} подключается к локальному прокси 127.0.0.1:{c.RemotePort}. Без драйвера (права администратора) настоящие адреса назначения не видны.");
                            continue;
                        }
                        if (!_tcpTableSeen.Add((c.Pid, $"{c.Remote}:{c.RemotePort}"))) continue;
                        OnConnection(c.Pid, 6, IPAddress.Any, c.LocalPort, c.Remote, c.RemotePort, ObservationMethod.IpHelperTable, t);
                    }
                });
            }
            catch (Exception ex) { Log?.Invoke("Таблица TCP: " + ex.Message); }
            _cts.Token.WaitHandle.WaitOne(Mode == CaptureMode.WinDivert ? 1000 : 250);
        }
    }

    private void TrackerLoop()
    {
        while (!_cts.IsCancellationRequested)
        {
            try { _tracker.ScanForNew(); } catch { }
            _cts.Token.WaitHandle.WaitOne(1000);
        }
    }

    // ───────────── Обработка (единственный поток) ─────────────

    private async Task ConsumeAsync()
    {
        try
        {
            await foreach (var a in _events.Reader.ReadAllAsync())
            {
                try { a(); } catch (Exception ex) { Log?.Invoke("Ошибка обработки события: " + ex.Message); }
                RetryPendingSni();
            }
        }
        catch (OperationCanceledException) { }
    }

    private void OnConnection(int pid, byte proto, IPAddress laddr, int lport, IPAddress raddr, int rport, ObservationMethod method, DateTime t)
    {
        if (proto is not (6 or 17)) return;
        if (IPAddress.IsLoopback(raddr) && proto == 6 && _proxyPorts.Contains(rport))
        {
            _loopbackProxyPid[lport] = pid;
            var lp = _tracker.Resolve(pid);
            if (lp != null && lp.Relation != ProcessRelation.SharedService && _emitted.Add($"lp|{pid}|{rport}"))
                Log?.Invoke($"{lp.Name} (PID {pid}) работает через локальный прокси 127.0.0.1:{rport} — назначения берутся из его запросов к прокси.");
            return;
        }
        if (IPAddress.IsLoopback(raddr) || raddr.Equals(IPAddress.Any) || raddr.Equals(IPAddress.IPv6Any)) return;
        _flowPid[(proto, lport, raddr, rport)] = pid;
        if (proto == 17) _localPortPid[(proto, lport)] = pid;

        var tp = _tracker.Resolve(pid);
        if (tp == null) return;
        var protoName = proto == 6 ? "TCP" : (rport == 443 ? "UDP (QUIC?)" : "UDP");
        var protoKey = proto == 6 ? "TCP" : "UDP";
        if (tp.Relation == ProcessRelation.SharedService)
        {
            if (_emitted.Add($"u|{pid}|{raddr}|{rport}|{protoKey}"))
                Connection?.Invoke(new LiveConnection(t, pid, tp.Name, protoName, raddr.ToString(), rport, null, Ru.Of(method), tp.Explanation, true,
                    "нельзя достоверно связать с выбранной программой"));
            return;
        }
        if (method == ObservationMethod.FlowEstablished) FlowCount++;

        if (_o.TunnelEndpoints.Any(e => e.Equals(raddr)))
        {
            if (_emitted.Add($"tun|{raddr}|{rport}"))
                Log?.Invoke($"{tp.Name} подключается к {raddr}:{rport} — это адрес вашего прокси/VPN, а не сервер программы. Он не добавляется в список.");
            return;
        }
        if (SpecialRanges.FakeIp.Contains(raddr))
        {
            if (_fakeIpWarnings++ == 0)
                Log?.Invoke("Обнаружены адреса 198.18.x.x (fake-ip): трафик идёт через TUN sing-box/Podkop, настоящие IP не видны. " +
                            "Ориентируйтесь на найденные домены (DNS/SNI) — они достоверны.");
        }

        var rel = tp.Relation == ProcessRelation.RelatedFolder ? ObservationMethod.RelatedProcessFlow : method;
        string? domain = null; string? linkHow = null;
        if (_dnsByPid.TryGetValue(pid, out var map) && map.TryGetValue(raddr, out var d)) { domain = d.name; linkHow = d.how; }

        var (cat, reason) = Classifier.ClassifyProcess(domain, protoKey, rport);
        var key = $"c|{pid}|{raddr}|{rport}|{protoKey}|{rel}";
        if (_emitted.Add(key))
        {
            Found?.Invoke(new Finding
            {
                Value = raddr.ToString(), Kind = raddr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? EntryKind.IPv6 : EntryKind.IPv4,
                Method = rel, Time = t, ProcessName = tp.Name, Pid = pid, Protocol = protoKey, Port = rport,
                Detail = tp.Explanation, LinkedDomain = domain, LinkMethod = linkHow, Route = _o.Route,
                Category = cat, CategoryReason = reason,
            });
            Connection?.Invoke(new LiveConnection(t, pid, tp.Name, protoName, raddr.ToString(), rport, domain, Ru.Of(method), tp.Explanation, false,
                domain == null ? "имя сервера не установлено" : $"имя: {linkHow}"));
        }
        if (domain != null && rel != ObservationMethod.RelatedProcessFlow && _emitted.Add($"dc|{pid}|{domain}"))
        {
            // DNS-ответ этому процессу + соединение того же процесса с этим IP = домен подтверждён соединением.
            Found?.Invoke(new Finding
            {
                Value = domain, Kind = EntryKind.Domain, Method = rel, Time = t, ProcessName = tp.Name, Pid = pid, Protocol = protoKey, Port = rport,
                Detail = $"{linkHow} → соединение с {raddr}", Route = _o.Route, Category = cat, CategoryReason = reason,
            });
        }
    }

    private void OnSni(DateTime t, IPAddress laddr, int lport, IPAddress raddr, int rport, string sni, bool ech)
    {
        if (!TryBindSni(t, laddr, lport, raddr, rport, sni, ech)) _pendingSni.Add((t, laddr, lport, raddr, rport, sni, ech));
    }

    private void OnProxyRequest(DateTime t, int lport, ProxyRequestParser.Target target)
    {
        if (!TryBindProxy(t, lport, target)) _pendingProxy.Add((t, lport, target));
    }

    private bool TryBindProxy(DateTime t, int lport, ProxyRequestParser.Target target)
    {
        if (!_loopbackProxyPid.TryGetValue(lport, out var pid)) return false;
        var tp = _tracker.Resolve(pid);
        if (tp == null || tp.Relation == ProcessRelation.SharedService) return true;
        var method = tp.Relation == ProcessRelation.RelatedFolder ? ObservationMethod.RelatedProcessFlow : ObservationMethod.ProxyRequest;
        var proto = target.Kind.Contains("UDP") ? "UDP" : "TCP";
        var detail = $"{target.Kind} через локальный прокси, порт {target.Port}";
        if (IPAddress.TryParse(target.Host, out var ip))
        {
            ip = IpNetwork.Unmap(ip);
            var (cat, reason) = Classifier.ClassifyProcess(null, proto, target.Port);
            if (_emitted.Add($"pr|{pid}|{ip}|{target.Port}"))
            {
                Found?.Invoke(new Finding
                {
                    Value = ip.ToString(), Kind = ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? EntryKind.IPv6 : EntryKind.IPv4,
                    Method = method, Time = t, ProcessName = tp.Name, Pid = pid, Protocol = proto, Port = target.Port, Detail = detail, Route = _o.Route,
                    Category = cat, CategoryReason = reason,
                });
                Connection?.Invoke(new LiveConnection(t, pid, tp.Name, proto + " (прокси)", ip.ToString(), target.Port, null, target.Kind, tp.Explanation, false, "назначение из запроса к прокси"));
            }
            return true;
        }
        var n = DomainNormalizer.Normalize(target.Host);
        if (!n.Ok) return true;
        var (c2, r2) = Classifier.ClassifyProcess(n.Domain, proto, target.Port);
        if (_emitted.Add($"pr|{pid}|{n.Domain}|{target.Port}"))
        {
            Found?.Invoke(new Finding
            {
                Value = n.Domain!, Kind = EntryKind.Domain, Method = method, Time = t, ProcessName = tp.Name, Pid = pid, Protocol = proto, Port = target.Port,
                Detail = detail, Route = _o.Route, Category = c2, CategoryReason = r2,
            });
            Connection?.Invoke(new LiveConnection(t, pid, tp.Name, proto + " (прокси)", "—", target.Port, n.Domain, target.Kind, tp.Explanation, false, "назначение из запроса к прокси; IP определит DNS-проверка"));
        }
        return true;
    }

    private void RetryPendingSni()
    {
        if (_pendingProxy.Count > 0)
        {
            var now0 = DateTime.UtcNow;
            _pendingProxy.RemoveAll(p => TryBindProxy(p.t, p.lport, p.target) || now0 - p.t > TimeSpan.FromSeconds(5));
        }
        if (_pendingSni.Count == 0) return;
        var now = DateTime.UtcNow;
        _pendingSni.RemoveAll(p => TryBindSni(p.t, p.laddr, p.lport, p.raddr, p.rport, p.sni, p.ech) || now - p.t > TimeSpan.FromSeconds(5));
    }

    private bool TryBindSni(DateTime t, IPAddress laddr, int lport, IPAddress raddr, int rport, string sni, bool ech)
    {
        raddr = IpNetwork.Unmap(raddr);
        if (!_flowPid.TryGetValue((6, lport, raddr, rport), out var pid)) return false;
        var tp = _tracker.Resolve(pid);
        if (tp == null || tp.Relation == ProcessRelation.SharedService) return true;
        var n = DomainNormalizer.Normalize(sni);
        if (!n.Ok) return true;
        var how = ech ? "TLS SNI (внешнее имя ECH)" : "TLS SNI";
        var (cat, reason) = Classifier.ClassifyProcess(n.Domain, "TCP", rport);
        if (ech) reason = "внешнее имя ECH: настоящий сервер скрыт шифрованием; " + reason;
        var method = tp.Relation == ProcessRelation.RelatedFolder ? ObservationMethod.RelatedProcessFlow : ObservationMethod.TlsSni;
        if (_emitted.Add($"sni|{pid}|{n.Domain}"))
            Found?.Invoke(new Finding
            {
                Value = n.Domain!, Kind = EntryKind.Domain, Method = method, Time = t, ProcessName = tp.Name, Pid = pid, Protocol = "TCP", Port = rport,
                Detail = $"{how}, сервер {raddr}", Route = _o.Route, Category = cat, CategoryReason = reason,
            });
        if (_emitted.Add($"sniip|{pid}|{raddr}|{n.Domain}"))
        {
            Found?.Invoke(new Finding
            {
                Value = raddr.ToString(), Kind = raddr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? EntryKind.IPv6 : EntryKind.IPv4,
                Method = method, Time = t, ProcessName = tp.Name, Pid = pid, Protocol = "TCP", Port = rport,
                Detail = tp.Explanation, LinkedDomain = n.Domain, LinkMethod = how, Route = _o.Route, Category = cat, CategoryReason = reason,
            });
            Connection?.Invoke(new LiveConnection(t, pid, tp.Name, "TCP/TLS", raddr.ToString(), rport, n.Domain, how, tp.Explanation, false, ech ? "ECH: имя — внешнее" : ""));
        }
        return true;
    }

    private void OnDnsSniff(DateTime t, int lport, string name, List<IPAddress> ips)
    {
        if (!_localPortPid.TryGetValue((17, lport), out var pid)) return;
        RecordProcessDns(t, pid, name, ips, ObservationMethod.ProcessDnsSniff, "DNS-ответ на сокет процесса");
    }

    private void OnEtwDns(DateTime t, int pid, string name, List<IPAddress> ips) =>
        RecordProcessDns(t, pid, name, ips, ObservationMethod.ProcessDnsEtw, "DNS-запрос процесса (ETW)");

    private void RecordProcessDns(DateTime t, int pid, string name, List<IPAddress> ips, ObservationMethod method, string how)
    {
        var tp = _tracker.Resolve(pid);
        if (tp == null || tp.Relation == ProcessRelation.SharedService) return;
        var n = DomainNormalizer.Normalize(name);
        if (!n.Ok) return;
        if (!_dnsByPid.TryGetValue(pid, out var map)) _dnsByPid[pid] = map = new();
        foreach (var ip in ips) map[ip] = (n.Domain!, how, t);
        if (_emitted.Add($"dns|{pid}|{n.Domain}"))
        {
            var (cat, reason) = Classifier.ClassifyProcess(n.Domain, "TCP", 443);
            Found?.Invoke(new Finding
            {
                Value = n.Domain!, Kind = EntryKind.Domain, Method = tp.Relation == ProcessRelation.RelatedFolder ? ObservationMethod.RelatedProcessFlow : method,
                Time = t, ProcessName = tp.Name, Pid = pid, Detail = ips.Count > 0 ? $"{how}: {string.Join(", ", ips.Take(4))}" : how,
                Route = _o.Route, Category = cat, CategoryReason = reason,
            });
            Connection?.Invoke(new LiveConnection(t, pid, tp.Name, "DNS", string.Join(", ", ips.Take(3)), 53, n.Domain, Ru.Of(method), tp.Explanation, false, "имя запрошено"));
        }
    }

    // ───────────── Запуск программы и остановка ─────────────

    /// <summary>
    /// Запуск выбранного EXE (только по явному согласию пользователя). Если сканер работает с правами
    /// администратора, программа запускается через explorer.exe — с обычными правами пользователя.
    /// Отслеживание в этом случае идёт по пути EXE.
    /// </summary>
    public static void LaunchExe(string exe)
    {
        if (ProcessInfo.IsAdministrator())
            Process.Start(new ProcessStartInfo("explorer.exe") { ArgumentList = { exe }, UseShellExecute = false });
        else
            Process.Start(new ProcessStartInfo(exe) { UseShellExecute = true, WorkingDirectory = Path.GetDirectoryName(exe)! });
    }

    private void CloseHandles()
    {
        lock (_handles)
        {
            foreach (var h in _handles) { try { WinDivertNative.WinDivertShutdown(h, 3); } catch { } }
            foreach (var h in _handles) { try { WinDivertNative.WinDivertClose(h); } catch { } }
            _handles.Clear();
        }
    }

    private int _disposed;

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 1) return;
        _cts.Cancel();
        CloseHandles();
        try { _etw?.Stop(); _etw?.Dispose(); } catch { }
        foreach (var t in _threads) t.Join(TimeSpan.FromSeconds(3));
        _events.Writer.TryComplete();
        if (_consumer != null) try { await _consumer.WaitAsync(TimeSpan.FromSeconds(3)); } catch { }
        _cts.Dispose();
    }
}
