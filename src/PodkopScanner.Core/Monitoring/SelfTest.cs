using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Text;
using PodkopScanner.Core.Model;

namespace PodkopScanner.Core.Monitoring;

public sealed record SelfTestResult(bool Passed, CaptureMode Mode, string Report, List<Finding> Findings);

/// <summary>
/// Самопроверка мониторинга процесса на реальном трафике:
/// • целевой процесс (PowerShell) открывает TCP-соединение с example.com:443 и отправляет UDP DNS-запрос на 1.1.1.1:53;
/// • параллельно посторонний процесс соединяется с github.com:443.
/// Проверяется, что адреса цели найдены, а адрес постороннего процесса — нет.
/// </summary>
public static class SelfTest
{
    public static async Task<SelfTestResult> RunProcessCaptureAsync(CancellationToken ct)
    {
        var sb = new StringBuilder();
        var exampleIps = (await Dns.GetHostAddressesAsync("example.com", ct)).Select(IpNetworkUnmap).ToHashSet();
        var githubIps = (await Dns.GetHostAddressesAsync("github.com", ct)).Select(IpNetworkUnmap).ToHashSet();
        sb.AppendLine($"example.com → {string.Join(", ", exampleIps)}");
        sb.AppendLine($"github.com (посторонний процесс) → {string.Join(", ", githubIps)}");

        const string targetScript =
            "Start-Sleep -Milliseconds 2500; " +
            "$c = New-Object Net.Sockets.TcpClient; $c.Connect('example.com', 443); " +
            "$u = New-Object Net.Sockets.UdpClient; $q = [byte[]](0x12,0x34,1,0,0,1,0,0,0,0,0,0,7,101,120,97,109,112,108,101,3,99,111,109,0,0,1,0,1); " +
            "[void]$u.Send($q, $q.Length, '1.1.1.1', 53); Start-Sleep -Milliseconds 300; " +
            "Start-Sleep -Seconds 4; $c.Close(); $u.Close()";
        const string decoyScript =
            "Start-Sleep -Milliseconds 2500; $c = New-Object Net.Sockets.TcpClient; $c.Connect('github.com', 443); Start-Sleep -Seconds 4; $c.Close()";

        var target = StartPs(targetScript);
        var findings = new ConcurrentBag<Finding>();
        var log = new ConcurrentQueue<string>();
        await using var mon = new ProcessMonitor(new ProcessMonitorOptions { Pid = target.Id, FlushDnsCache = true, IncludeChildren = true });
        mon.Found += findings.Add;
        mon.Log += log.Enqueue;
        mon.Start(allowFallback: true);
        var decoy = StartPs(decoyScript);
        try
        {
            await Task.WhenAny(target.WaitForExitAsync(ct), Task.Delay(TimeSpan.FromSeconds(20), ct));
            await Task.Delay(1500, ct);
        }
        finally
        {
            try { if (!target.HasExited) target.Kill(); } catch { }
            try { if (!decoy.HasExited) decoy.Kill(); } catch { }
        }
        await mon.DisposeAsync();

        var all = findings.ToList();
        var ips = all.Where(f => f.Kind is EntryKind.IPv4 or EntryKind.IPv6).ToList();
        bool tcpOk = ips.Any(f => exampleIps.Contains(IPAddress.Parse(f.Value)) && f.Protocol == "TCP" && f.Port == 443 && f.Pid == target.Id);
        bool udpOk = ips.Any(f => f.Value == "1.1.1.1" && f.Protocol == "UDP" && f.Port == 53);
        bool noDecoy = !ips.Any(f => githubIps.Contains(IPAddress.Parse(f.Value)));
        bool domainOk = all.Any(f => f.Kind == EntryKind.Domain && f.Value == "example.com");
        var mode = mon.Mode;

        sb.AppendLine($"Режим захвата: {(mode == CaptureMode.WinDivert ? "WinDivert (FLOW/SOCKET/NETWORK)" : "без драйвера (таблица TCP)")}; ETW DNS: {(mon.DnsEtwActive ? "да" : "нет")}");
        sb.AppendLine($"[{(tcpOk ? "OK" : "FAIL")}] TCP-соединение целевого процесса с example.com:443 обнаружено с правильным PID");
        if (mode == CaptureMode.WinDivert)
        {
            sb.AppendLine($"[{(udpOk ? "OK" : "FAIL")}] UDP-поток целевого процесса на 1.1.1.1:53 обнаружен");
            sb.AppendLine($"[{(domainOk ? "OK" : "FAIL")}] Домен example.com связан с процессом (DNS ETW / SNI)");
        }
        else
        {
            sb.AppendLine($"[ПРОПУЩЕНО] UDP: в режиме без драйвера UDP-соединения не видны (обнаружено: {(udpOk ? "да" : "нет")})");
            sb.AppendLine($"[ПРОПУЩЕНО] Домен по DNS/SNI: требует прав администратора (обнаружено: {(domainOk ? "да" : "нет")})");
        }
        sb.AppendLine($"[{(noDecoy ? "OK" : "FAIL")}] Соединение постороннего процесса с github.com НЕ попало в результаты");
        sb.AppendLine();
        sb.AppendLine("Находки:");
        foreach (var f in all.OrderBy(f => f.Time)) sb.AppendLine($"  {Ru.Of(f.Method),-36} {f.Value,-22} {f.Protocol}:{f.Port}  {f.ProcessName} PID {f.Pid}  {f.LinkedDomain}");
        sb.AppendLine();
        sb.AppendLine("Журнал:");
        foreach (var l in log) sb.AppendLine("  " + l);

        bool passed = tcpOk && noDecoy && (mode != CaptureMode.WinDivert || (udpOk && domainOk));
        return new SelfTestResult(passed, mode, sb.ToString(), all);
    }

    private static IPAddress IpNetworkUnmap(IPAddress ip) => ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip;

    private static Process StartPs(string script)
    {
        var psi = new ProcessStartInfo("powershell.exe") { UseShellExecute = false, CreateNoWindow = true };
        foreach (var a in new[] { "-NoProfile", "-NonInteractive", "-Command", script }) psi.ArgumentList.Add(a);
        return Process.Start(psi)!;
    }
}
