using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using PodkopScanner.Core.Net;
using PodkopScanner.Core.Settings;
using PodkopScanner.Core.Web;

namespace PodkopScanner.App;

public partial class SettingsWindow : Window
{
    private readonly AppSettings _s;

    public SettingsWindow(AppSettings s)
    {
        InitializeComponent();
        _s = s;
        var r = s.Route;
        (r.UseProxy ? RouteProxy : RouteDirect).IsChecked = true;
        ProxyType.SelectedIndex = (int)r.Kind;
        ProxyHost.Text = r.Host; ProxyPort.Text = r.Port.ToString(); ProxyUser.Text = r.User ?? ""; ProxyPass.Password = r.Password ?? "";
        ProxyUrl.Text = r.UseProxy ? r.Describe() : "";
        (s.Dns.Mode switch { DnsMode.Udp => DnsUdp, DnsMode.Tcp => DnsTcp, DnsMode.DoH => DnsDoh, _ => DnsSystem }).IsChecked = true;
        DnsServer.Text = s.Dns.Server; DohUrl.Text = s.Dns.DohUrl; DnsIpv6.IsChecked = s.Dns.QueryIPv6;
        (s.Browser switch { BrowserChoice.Edge => BrEdge, BrowserChoice.Chrome => BrChrome, _ => BrChromium }).IsChecked = true;
        CrawlPages.Text = s.AutoCrawlMaxPages.ToString(); CrawlDelay.Text = s.AutoCrawlDelaySeconds.ToString();
        AutoRefresh.IsChecked = s.AutoRefreshEnabled;
        AutoRefreshPeriod.SelectedItem = AutoRefreshPeriod.Items.Cast<ComboBoxItem>().FirstOrDefault(i => (string)i.Tag == s.AutoRefreshHours.ToString()) ?? AutoRefreshPeriod.Items[1];
        Concurrency.Text = s.RefreshConcurrency.ToString(); DelayMs.Text = s.RefreshDelayMs.ToString(); FreshDays.Text = s.FreshDays.ToString();
        SingBoxPath.Text = s.SingBoxPath ?? ""; IpServices.Text = string.Join(", ", s.ExternalIpServices);
        ShowUndetermined.IsChecked = s.ShowUndeterminedConnections;
        DataInfo.Text = $"Данные: {AppSettings.DataDirectory}. Телеметрии нет; история сканирований хранится только локально.";
        SchedulerHint.Text = "Чтобы обновлять адреса, когда программа закрыта, создайте задачу в Планировщике заданий Windows с запуском:\n" +
                             $"\"{Environment.ProcessPath}\" --refresh-all\nСама программа задачи не создаёт и системные настройки не меняет.";
        Route_Changed(this, new RoutedEventArgs());
    }

    private void Route_Changed(object sender, RoutedEventArgs e)
    {
        if (ProxyPanel != null) ProxyPanel.IsEnabled = RouteProxy.IsChecked == true;
    }

    private void ParseUrl_Click(object sender, RoutedEventArgs e)
    {
        if (!RouteSettings.TryParseUrl(ProxyUrl.Text, out var r, out var err)) { RouteResult.Text = "⚠ " + err; return; }
        ProxyType.SelectedIndex = (int)r.Kind; ProxyHost.Text = r.Host; ProxyPort.Text = r.Port.ToString();
        ProxyUser.Text = r.User ?? ""; if (r.Password != null) ProxyPass.Password = r.Password;
        RouteProxy.IsChecked = true;
        RouteResult.Text = "Ссылка разобрана.";
    }

    private RouteSettings? ReadRoute(bool forceProxy = false)
    {
        var r = new RouteSettings { UseProxy = forceProxy || RouteProxy.IsChecked == true, Kind = (ProxyKind)Math.Max(0, ProxyType.SelectedIndex), Host = ProxyHost.Text.Trim() };
        if (!int.TryParse(ProxyPort.Text, out var port) || port is < 1 or > 65535)
        {
            if (r.UseProxy) { RouteResult.Text = "⚠ Порт должен быть числом от 1 до 65535"; return null; }
            port = 1080;
        }
        r.Port = port;
        if (r.UseProxy && r.Host.Length == 0) { RouteResult.Text = "⚠ Укажите адрес прокси"; return null; }
        r.User = string.IsNullOrWhiteSpace(ProxyUser.Text) ? null : ProxyUser.Text.Trim();
        r.Password = ProxyPass.Password.Length > 0 ? ProxyPass.Password : null;
        return r;
    }

    private string[] Services_() => IpServices.Text.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    private async void CheckRoute_Click(object sender, RoutedEventArgs e)
    {
        var r = ReadRoute(); if (r == null) return;
        RouteResult.Text = $"Проверяю {r.Describe()} …";
        var res = await RouteChecker.CheckAsync(r, Services_(), CancellationToken.None);
        RouteResult.Text = res.Ok
            ? $"✔ Маршрут {res.Route} работает. Внешний IP: {res.ExternalIp} (ответ {res.LatencyMs} мс, сервис {res.ServiceUsed})."
            : $"✖ Маршрут {res.Route} не работает: {res.Error}";
    }

    private async void CompareRoutes_Click(object sender, RoutedEventArgs e)
    {
        var p = ReadRoute(forceProxy: true); if (p == null) return;
        RouteResult.Text = "Сравниваю…";
        var directTask = RouteChecker.CheckAsync(new RouteSettings(), Services_(), CancellationToken.None);
        var proxyTask = RouteChecker.CheckAsync(p, Services_(), CancellationToken.None);
        var d = await directTask; var x = await proxyTask;
        var lines = new List<string>
        {
            d.Ok ? $"Напрямую: внешний IP {d.ExternalIp}" : $"Напрямую: ошибка — {d.Error}",
            x.Ok ? $"Через {x.Route}: внешний IP {x.ExternalIp}" : $"Через {x.Route}: ошибка — {x.Error}",
        };
        if (d.Ok && x.Ok)
            lines.Add(d.ExternalIp == x.ExternalIp
                ? "⚠ Внешний IP одинаковый — трафик через прокси выходит тем же адресом (прокси может работать без смены маршрута)."
                : "✔ Внешние IP различаются — запросы действительно идут через прокси.");
        RouteResult.Text = string.Join("\n", lines);
    }

    private async void InstallChromium_Click(object sender, RoutedEventArgs e)
    {
        if (MessageBox.Show(this, "Скачать Chromium для Playwright (около 170 МБ) в %LOCALAPPDATA%\\ms-playwright?", "Установка Chromium",
                MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;
        IsEnabled = false;
        try
        {
            var code = await WebAnalyzer.InstallChromiumAsync();
            MessageBox.Show(this, code == 0 ? "Chromium установлен." : $"Установка завершилась с кодом {code}. Проверьте подключение к интернету.", "Установка Chromium");
        }
        finally { IsEnabled = true; }
    }

    private void BrowseSingBox_Click(object sender, RoutedEventArgs e)
    {
        var d = new Microsoft.Win32.OpenFileDialog { Filter = "sing-box.exe|sing-box.exe|Программы|*.exe" };
        if (d.ShowDialog(this) == true) SingBoxPath.Text = d.FileName;
    }

    private void Backup_Click(object sender, RoutedEventArgs e)
    {
        try { var f = Services.Database.Backup("manual"); MessageBox.Show(this, "Копия создана:\n" + f, "Резервная копия"); }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error); }
    }

    private void OpenData_Click(object sender, RoutedEventArgs e)
    {
        Directory.CreateDirectory(AppSettings.DataDirectory);
        Process.Start(new ProcessStartInfo("explorer.exe", $"\"{AppSettings.DataDirectory}\"") { UseShellExecute = true });
    }

    private static int Int(string s, int def, int min, int max) => int.TryParse(s, out var v) ? Math.Clamp(v, min, max) : def;

    private void Save_Click(object sender, RoutedEventArgs e)
    {
        var r = ReadRoute(); if (r == null) return;
        if (DnsUdp.IsChecked == true || DnsTcp.IsChecked == true)
            if (!IPAddress_TryParse(DnsServer.Text.Trim())) { RouteResult.Text = "⚠ DNS-сервер должен быть IP-адресом"; return; }
        if (DnsDoh.IsChecked == true && !Uri.TryCreate(DohUrl.Text.Trim(), UriKind.Absolute, out _)) { RouteResult.Text = "⚠ Некорректный адрес DoH"; return; }
        _s.Route = r;
        _s.Dns = new DnsSettings
        {
            Mode = DnsUdp.IsChecked == true ? DnsMode.Udp : DnsTcp.IsChecked == true ? DnsMode.Tcp : DnsDoh.IsChecked == true ? DnsMode.DoH : DnsMode.System,
            Server = DnsServer.Text.Trim(), DohUrl = DohUrl.Text.Trim(), QueryIPv6 = DnsIpv6.IsChecked == true,
        };
        _s.Browser = BrEdge.IsChecked == true ? BrowserChoice.Edge : BrChrome.IsChecked == true ? BrowserChoice.Chrome : BrowserChoice.BundledChromium;
        _s.AutoCrawlMaxPages = Int(CrawlPages.Text, 10, 1, 50);
        _s.AutoCrawlDelaySeconds = Int(CrawlDelay.Text, 3, 1, 60);
        _s.AutoRefreshEnabled = AutoRefresh.IsChecked == true;
        _s.AutoRefreshHours = int.Parse((string)((ComboBoxItem)AutoRefreshPeriod.SelectedItem).Tag);
        _s.RefreshConcurrency = Int(Concurrency.Text, 4, 1, 16);
        _s.RefreshDelayMs = Int(DelayMs.Text, 150, 0, 5000);
        _s.FreshDays = Int(FreshDays.Text, 60, 1, 3650);
        _s.SingBoxPath = string.IsNullOrWhiteSpace(SingBoxPath.Text) ? null : SingBoxPath.Text.Trim();
        var svc = Services_();
        _s.ExternalIpServices = svc.Length > 0 ? svc : RouteChecker.DefaultIpServices;
        _s.ShowUndeterminedConnections = ShowUndetermined.IsChecked == true;
        _s.Save();
        DialogResult = true;
    }

    private static bool IPAddress_TryParse(string s) => System.Net.IPAddress.TryParse(s, out _);
}
