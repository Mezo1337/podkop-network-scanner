using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using Microsoft.Win32;
using PodkopScanner.Core.Analysis;
using PodkopScanner.Core.Data;
using PodkopScanner.Core.Export;
using PodkopScanner.Core.Import;
using PodkopScanner.Core.Model;
using PodkopScanner.Core.Monitoring;
using PodkopScanner.Core.Net;
using PodkopScanner.Core.Settings;
using PodkopScanner.Core.Update;
using PodkopScanner.Core.Web;

namespace PodkopScanner.App;

/// <summary>Коллекция с массовой заменой содержимого (одно уведомление Reset вместо тысяч Add).</summary>
public sealed class BulkCollection<T> : ObservableCollection<T>
{
    public void ReplaceAll(IEnumerable<T> items)
    {
        Items.Clear();
        foreach (var i in items) Items.Add(i);
        OnPropertyChanged(new PropertyChangedEventArgs(nameof(Count)));
        OnPropertyChanged(new PropertyChangedEventArgs("Item[]"));
        OnCollectionChanged(new NotifyCollectionChangedEventArgs(NotifyCollectionChangedAction.Reset));
    }
}

public partial class MainWindow : Window
{
    private Repository Repo => Services.Repo;
    private AppSettings Settings => Services.Settings;

    private Project? _current;
    private List<EntryRow> _rows = new();
    private readonly BulkCollection<EntryRow> _domainView = new();
    private readonly BulkCollection<EntryRow> _ipView = new();
    private readonly ObservableCollection<LiveRow> _live = new();
    private readonly List<LiveRow> _liveAll = new();
    private readonly ObservableCollection<string> _log = new();

    private WebAnalyzer? _web;
    private ProcessMonitor? _proc;
    private ScanSession? _session;
    private CancellationTokenSource? _opCts;
    private ImportResult? _pendingImport;
    private string? _targetExe;
    private int? _targetPid;
    private bool _closingAfterStop;
    private int _sessionFound;

    private readonly DispatcherTimer _reloadTimer = new() { Interval = TimeSpan.FromMilliseconds(1200) };
    private readonly DispatcherTimer _autoRefreshTimer = new() { Interval = TimeSpan.FromMinutes(15) };

    public MainWindow()
    {
        InitializeComponent();
        LogList.ItemsSource = _log;
        DomainsGrid.ItemsSource = _domainView;
        IpsGrid.ItemsSource = _ipView;
        LiveGrid.ItemsSource = _live;

        StatusFilter.Items.Add(new ComboBoxItem { Content = "Любой статус", IsSelected = true });
        foreach (EntryStatus st in Enum.GetValues<EntryStatus>()) StatusFilter.Items.Add(new ComboBoxItem { Content = Ru.Of(st), Tag = st });
        CategoryFilter.Items.Add(new ComboBoxItem { Content = "Любое назначение", IsSelected = true });
        foreach (ResourceCategory c in Enum.GetValues<ResourceCategory>()) CategoryFilter.Items.Add(new ComboBoxItem { Content = Ru.Of(c), Tag = c });

        var ex = Settings.Export;
        OptOnlyConfirmed.IsChecked = ex.OnlyConfirmed; OptSingleCidr.IsChecked = ex.SingleAsCidr; OptRedundant.IsChecked = ex.RemoveRedundantDomains;
        OptAggregate.IsChecked = ex.AggregateSubnets; OptIpv6Json.IsChecked = ex.IPv6InJsonRuleset;
        WebRouteCombo.SelectedIndex = Settings.Route.UseProxy ? 1 : 0;
        ShowUndeterminedCheck.IsChecked = Settings.ShowUndeterminedConnections;
        AutoCrawlCheck.Content = $"Ограниченный автообход страниц сайта (до {Settings.AutoCrawlMaxPages})";

        _reloadTimer.Tick += (_, _) => { _reloadTimer.Stop(); ReloadEntries(); };
        _autoRefreshTimer.Tick += async (_, _) => await AutoRefreshTick();
        _autoRefreshTimer.Start();

        var sysProxy = SystemProxy.ToRoute();
        if (sysProxy != null) SystemProxyItem.Content = $"Системный прокси Windows ({sysProxy.Host}:{sysProxy.Port})";
        else SystemProxyItem.Visibility = Visibility.Collapsed;
        UpdatePrivilegeInfo();
        UpdateRouteBadge();
        LoadProjects();
        if (sysProxy != null)
            Log($"Обнаружен системный прокси Windows {sysProxy.Host}:{sysProxy.Port}. Режим «Напрямую» его НЕ использует; для анализа через него выберите «Системный прокси Windows».");

        var args = Environment.GetCommandLineArgs();
        var pi = Array.FindIndex(args, a => a == "--project");
        if (pi >= 0 && pi + 1 < args.Length && long.TryParse(args[pi + 1], out var pid))
        {
            SelectProject(pid);
            if (_current?.Type == ProjectType.Program) ModeTabs.SelectedIndex = 1;
        }
        else if (ProjectsList.Items.Count > 0) ProjectsList.SelectedIndex = 0;
        Closing += MainWindow_Closing;
    }

    // ═══════════════ Общие помощники ═══════════════

    private void Log(string msg)
    {
        void Add()
        {
            _log.Add($"{DateTime.Now:HH:mm:ss}  {msg}");
            while (_log.Count > 600) _log.RemoveAt(0);
            LogList.ScrollIntoView(_log[^1]);
        }
        if (Dispatcher.CheckAccess()) Add(); else Dispatcher.BeginInvoke(Add);
    }

    private void Status(string text) => StatusText.Text = text;

    private CancellationToken BeginOp(string text)
    {
        _opCts?.Dispose();
        _opCts = new CancellationTokenSource();
        Busy.Visibility = Visibility.Visible; CancelOpButton.Visibility = Visibility.Visible;
        Status(text);
        return _opCts.Token;
    }

    private void EndOp(string? text = null)
    {
        Busy.Visibility = Visibility.Collapsed; CancelOpButton.Visibility = Visibility.Collapsed;
        if (text != null) Status(text);
    }

    private void CancelOp_Click(object sender, RoutedEventArgs e) => _opCts?.Cancel();

    private bool ScanRunning => _web != null || _proc != null;

    private void Error(string title, Exception ex)
    {
        Services.LogError(title, ex);
        MessageBox.Show(this, ex is OperationCanceledException ? "Операция отменена." : RouteChecker.Flatten(ex), title, MessageBoxButton.OK,
            ex is OperationCanceledException ? MessageBoxImage.Information : MessageBoxImage.Warning);
    }

    private void UpdatePrivilegeInfo()
    {
        bool admin = ProcessInfo.IsAdministrator();
        AdminText.Text = admin ? "✔ Запущено с правами администратора" : "Обычные права пользователя";
        AdminText.Foreground = (System.Windows.Media.Brush)FindResource(admin ? "Good" : "Sub");
        ElevateButton.Visibility = admin ? Visibility.Collapsed : Visibility.Visible;
        var (ok, msg) = ProcessMonitor.CheckDriver();
        DriverText.Text = ok ? "Драйвер WinDivert: готов (TCP + UDP + DNS + SNI)" :
            (admin ? "Драйвер WinDivert: " + msg : "Анализ программ: без прав администратора доступен только ограниченный режим (TCP).");
    }

    private RouteSettings CurrentWebRoute()
    {
        if (WebRouteCombo.SelectedIndex == 2 && SystemProxy.ToRoute() is { } sys) return sys;
        if (WebRouteCombo.SelectedIndex == 1)
        {
            var r = Settings.Route.Clone(); r.UseProxy = true;
            return r;
        }
        return new RouteSettings { UseProxy = false };
    }

    private void UpdateRouteBadge()
    {
        var r = CurrentWebRoute();
        RouteBadge.Text = $"Маршрут веб-анализа: {(r.UseProxy ? r.Describe() : "напрямую")} · DNS: {new DnsResolver(Settings.Dns, r).Describe()}";
    }

    private void WebRouteCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!IsLoaded) return;
        if (WebRouteCombo.SelectedIndex == 1 && string.IsNullOrWhiteSpace(Settings.Route.Host))
            MessageBox.Show(this, "Сначала укажите прокси в настройках (кнопка «Настройки и подключение»).", "Прокси не настроен");
        if (WebRouteCombo.SelectedIndex == 2 && SystemProxy.ToRoute() == null)
        {
            MessageBox.Show(this, "Системный прокси Windows не включён.", "Системный прокси");
            WebRouteCombo.SelectedIndex = 0;
        }
        UpdateRouteBadge();
    }

    // ═══════════════ Проекты ═══════════════

    private void LoadProjects(long? select = null)
    {
        var list = Repo.GetProjects().Select(p => new ProjectRow(p)).ToList();
        ProjectsList.ItemsSource = list;
        if (select != null) SelectProject(select.Value);
    }

    private void SelectProject(long id)
    {
        var items = (List<ProjectRow>)ProjectsList.ItemsSource;
        var row = items.FirstOrDefault(r => r.Project.Id == id);
        if (row != null) ProjectsList.SelectedItem = row;
    }

    private void ProjectsList_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (ProjectsList.SelectedItem is not ProjectRow row) return;
        if (ScanRunning && _current != null && row.Project.Id != _current.Id)
        {
            MessageBox.Show(this, "Сначала остановите текущий анализ.", "Идёт анализ");
            SelectProject(_current.Id);
            return;
        }
        _current = Repo.GetProject(row.Project.Id);
        if (_current == null) return;
        ProjectTitle.Text = _current.Name;
        UpdateProjectSubtitle();
        if (_current.Type == ProjectType.Website) { UrlBox.Text = _current.Source; ModeTabs.SelectedIndex = 0; }
        else if (_current.Type == ProjectType.Program)
        {
            ModeTabs.SelectedIndex = 1;
            if (File.Exists(_current.Source)) { _targetExe = _current.Source; _targetPid = null; TargetText.Text = _targetExe; }
        }
        _liveAll.Clear(); _live.Clear();
        Repo.RecomputeEntries(_current.Id); // применить текущие правила включения по умолчанию к старым данным
        ReloadEntries();
        ReloadHistory();
        ReloadExclusions();
    }

    private void UpdateProjectSubtitle()
    {
        if (_current == null) return;
        var last = _current.LastRefresh is { } lr ? $"последнее обновление адресов: {lr.ToLocalTime():dd.MM.yyyy HH:mm}" : "адреса ещё не обновлялись";
        ProjectSubtitle.Text = $"{Ru.Of(_current.Type)} · {(_current.Source.Length > 0 ? _current.Source + " · " : "")}{last}";
    }

    private Project EnsureProject(ProjectType type, string defaultName, string source)
    {
        if (_current != null) return _current;
        var p = Repo.CreateProject(defaultName, type, source);
        LoadProjects(p.Id);
        return _current!;
    }

    private void NewSite_Click(object sender, RoutedEventArgs e) => CreateProject(ProjectType.Website);
    private void NewProgram_Click(object sender, RoutedEventArgs e) => CreateProject(ProjectType.Program);

    private void CreateProject(ProjectType type)
    {
        if (ScanRunning) { MessageBox.Show(this, "Сначала остановите текущий анализ.", "Идёт анализ"); return; }
        var name = InputDialog.Ask(this, "Новый проект", type == ProjectType.Website ? "Название проекта (например, YouTube):" : "Название проекта (например, название игры):");
        if (name == null) return;
        var p = Repo.CreateProject(name, type, "");
        LoadProjects(p.Id);
        if (type == ProjectType.Website) { UrlBox.Text = ""; UrlBox.Focus(); }
    }

    private void RenameProject_Click(object sender, RoutedEventArgs e)
    {
        if (_current == null) return;
        var name = InputDialog.Ask(this, "Переименовать", "Новое название проекта:", _current.Name);
        if (name == null) return;
        _current.Name = name; Repo.UpdateProject(_current);
        LoadProjects(_current.Id);
    }

    private void DeleteProject_Click(object sender, RoutedEventArgs e)
    {
        if (_current == null || ScanRunning) return;
        if (MessageBox.Show(this, $"Удалить проект «{_current.Name}» со всей историей? Перед удалением будет создана резервная копия базы.", "Удаление проекта",
                MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
        try { Services.Database.Backup("before-delete"); } catch { }
        Repo.DeleteProject(_current.Id);
        _current = null;
        _rows.Clear(); _domainView.ReplaceAll(Array.Empty<EntryRow>()); _ipView.ReplaceAll(Array.Empty<EntryRow>());
        ProjectTitle.Text = "Выберите или создайте проект"; ProjectSubtitle.Text = "";
        LoadProjects();
        if (ProjectsList.Items.Count > 0) ProjectsList.SelectedIndex = 0;
    }

    // ═══════════════ Записи, фильтры, детали ═══════════════

    private void ScheduleReload()
    {
        if (!_reloadTimer.IsEnabled) _reloadTimer.Start();
    }

    private void ReloadEntries()
    {
        if (_current == null) return;
        var entries = Repo.GetEntries(_current.Id);
        var site = _current.Type != ProjectType.Program ? SiteOwnership.SiteRegistrableFromSource(_current.Source) : null;
        _rows = entries.Select(en => new EntryRow(en, OnIncludeChanged, site)).ToList();
        ApplyFilter();
        UpdateCounters();
        RebuildExport();
    }

    private void OnIncludeChanged(EntryRow row, bool include)
    {
        Repo.SetInclude(new[] { row.Id }, include);
        if (include && row.E.Kind is EntryKind.Cidr4 or EntryKind.Cidr6 && IpNetwork.TryParse(row.E.Value, out var n) && Cidr.IsVeryLarge(n))
            MessageBox.Show(this, $"Сеть {n} очень большая ({Cidr.SizeText(n)}). Через прокси пойдут и посторонние сайты в этом диапазоне.", "Предупреждение", MessageBoxButton.OK, MessageBoxImage.Warning);
        if (include && row.E.Trust == Trust.Low)
            Log($"{row.E.Value}: включена запись низкой достоверности — по вашему решению.");
        UpdateCounters();
        RebuildExport();
    }

    private void Filter_Changed(object sender, RoutedEventArgs e) { if (IsLoaded) ApplyFilter(); }

    private void ApplyFilter()
    {
        var q = SearchBox.Text.Trim();
        Trust? trust = TrustFilter.SelectedIndex switch { 1 => Trust.High, 2 => Trust.Medium, 3 => Trust.Low, _ => null };
        var status = (StatusFilter.SelectedItem as ComboBoxItem)?.Tag as EntryStatus?;
        var cat = (CategoryFilter.SelectedItem as ComboBoxItem)?.Tag as ResourceCategory?;
        bool onlyInc = OnlyIncludedCheck.IsChecked == true, hideDis = HideDisabledCheck.IsChecked == true;
        IEnumerable<EntryRow> f = _rows.Where(r => r.Matches(q)
            && (trust == null || r.E.Trust == trust) && (status == null || r.E.Status == status) && (cat == null || r.E.Category == cat)
            && (!onlyInc || (r.E.Include && !r.E.Disabled)) && (!hideDis || !r.E.Disabled));
        var list = f.ToList();
        _domainView.ReplaceAll(list.Where(r => r.E.IsDomain));
        _ipView.ReplaceAll(list.Where(r => r.E.IsIp));
        DomainsTab.Header = $"Домены ({_domainView.Count})";
        IpsTab.Header = $"IP и подсети ({_ipView.Count})";
    }

    private void UpdateCounters()
    {
        CountDomains.Text = _rows.Count(r => r.E.IsDomain).ToString();
        CountIps.Text = _rows.Count(r => r.E.Kind is EntryKind.IPv4 or EntryKind.IPv6).ToString();
        CountNets.Text = _rows.Count(r => r.E.Kind is EntryKind.Cidr4 or EntryKind.Cidr6).ToString();
        CountIncluded.Text = _rows.Count(r => r.E.Include && !r.E.Disabled).ToString();
    }

    private void Grid_Sorting(object sender, DataGridSortingEventArgs e) { }

    private void Grid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        var grid = (DataGrid)sender;
        var box = grid == DomainsGrid ? DomainDetails : IpDetails;
        if (grid.SelectedItem is not EntryRow row) { box.Text = ""; return; }
        var obs = Repo.GetObservations(row.Id);
        var lines = new List<string>
        {
            $"{row.E.Value} — {Ru.Of(row.E.Kind)}, достоверность: {Ru.Of(row.E.Trust)}, статус: {Ru.Of(row.E.Status)}",
            $"Назначение: {Ru.Of(row.E.Category)} ({row.E.CategoryReason})" + (row.E.IsIp ? $"; домены: {row.LinkedText}" : ""),
        };
        if (row.E.Provider.Length > 0 || row.E.Asn.Length > 0) lines.Add($"Сеть: {row.NetworkText}");
        lines.Add($"Наблюдения ({obs.Count}):");
        foreach (var o in obs.Take(60))
            lines.Add($"  {o.Time.ToLocalTime():dd.MM HH:mm:ss}  {Ru.Of(o.Method),-34} {o.Detail}" +
                      (string.IsNullOrEmpty(o.ProcessName) ? "" : $"  [{o.ProcessName} PID {o.Pid}]") +
                      (string.IsNullOrEmpty(o.Protocol) ? "" : $"  {o.Protocol}:{o.Port}") + $"  маршрут: {o.Route}");
        box.Text = string.Join("\n", lines);
    }

    private void ResultTabs_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (e.Source != ResultTabs) return;
        bool entriesTab = ResultTabs.SelectedItem == DomainsTab || ResultTabs.SelectedItem == IpsTab;
        foreach (var c in new Control[] { SearchBox, TrustFilter, StatusFilter, CategoryFilter, OnlyIncludedCheck, HideDisabledCheck }) c.IsEnabled = entriesTab;
    }

    // ═══════════════ Контекстное меню ═══════════════

    private List<EntryRow> SelectedRows(object sender)
    {
        DataGrid? grid = null;
        if (sender is MenuItem mi)
        {
            DependencyObject? d = mi;
            while (d != null && d is not System.Windows.Controls.ContextMenu) d = LogicalTreeHelperParent(d);
            grid = (d as System.Windows.Controls.ContextMenu)?.PlacementTarget as DataGrid;
        }
        grid ??= ResultTabs.SelectedItem == IpsTab ? IpsGrid : DomainsGrid;
        return grid.SelectedItems.Cast<EntryRow>().ToList();
    }

    private static DependencyObject? LogicalTreeHelperParent(DependencyObject d) =>
        LogicalTreeHelper.GetParent(d) ?? (d as FrameworkElement)?.Parent;

    private void EntryMenu_Opened(object sender, RoutedEventArgs e)
    {
        var menu = (ContextMenu)sender;
        var catItem = menu.Items.OfType<MenuItem>().First(m => (m.Tag as string) == "category");
        if (catItem.Items.Count > 0) return;
        foreach (ResourceCategory c in Enum.GetValues<ResourceCategory>())
        {
            var item = new MenuItem { Header = Ru.Of(c), Tag = c };
            item.Click += (s, _) =>
            {
                var rows = SelectedRows(catItem);
                Repo.SetCategory(rows.Select(r => r.Id), c);
                ReloadEntries();
            };
            catItem.Items.Add(item);
        }
    }

    private void Mutate(object sender, Action<List<long>> action)
    {
        var rows = SelectedRows(sender);
        if (rows.Count == 0) return;
        action(rows.Select(r => r.Id).ToList());
        if (_current != null) Repo.RecomputeEntries(_current.Id, rows.Select(r => r.Id));
        ReloadEntries();
    }

    private void CtxInclude_Click(object s, RoutedEventArgs e)
    {
        var rows = SelectedRows(s);
        var low = rows.Count(r => r.E.Trust == Trust.Low);
        var large = rows.Where(r => IpNetwork.TryParse(r.E.Value, out var n) && Cidr.IsVeryLarge(n)).Select(r => r.E.Value).ToList();
        if (low > 0 || large.Count > 0)
        {
            var msg = (low > 0 ? $"Среди выбранных {low} записей низкой достоверности (импорт, старые данные).\n" : "") +
                      (large.Count > 0 ? $"Очень большие сети: {string.Join(", ", large.Take(5))} — через прокси пойдут посторонние сайты.\n" : "") + "\nВключить в экспорт?";
            if (MessageBox.Show(this, msg, "Подтверждение", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
        }
        Mutate(s, ids => Repo.SetInclude(ids, true));
    }
    private void CtxExclude_Click(object s, RoutedEventArgs e) => Mutate(s, ids => Repo.SetInclude(ids, false));
    private void CtxDefault_Click(object s, RoutedEventArgs e) => Mutate(s, ids => Repo.ResetIncludeToDefault(ids));
    private void CtxManual_Click(object s, RoutedEventArgs e) => Mutate(s, ids => Repo.SetManualConfirmed(ids, true));
    private void CtxUnmanual_Click(object s, RoutedEventArgs e) => Mutate(s, ids => Repo.SetManualConfirmed(ids, false));
    private void CtxDisable_Click(object s, RoutedEventArgs e) => Mutate(s, ids => Repo.SetDisabled(ids, true));
    private void CtxEnable_Click(object s, RoutedEventArgs e) => Mutate(s, ids => Repo.SetDisabled(ids, false));

    private void CtxWhitelist_Click(object s, RoutedEventArgs e) => AddToList(s, true);
    private void CtxBlacklist_Click(object s, RoutedEventArgs e) => AddToList(s, false);

    private void AddToList(object s, bool white)
    {
        if (_current == null) return;
        var rows = SelectedRows(s);
        foreach (var r in rows) Repo.AddExclusion(_current.Id, r.E.Value, white);
        if (white) Repo.SetInclude(rows.Select(r => r.Id), true);
        else Repo.SetDisabled(rows.Select(r => r.Id), true);
        ReloadExclusions(); ReloadEntries();
        Log($"{rows.Count} записей добавлено в {(white ? "белый" : "чёрный")} список проекта.");
    }

    private void CtxCopy_Click(object s, RoutedEventArgs e)
    {
        var rows = SelectedRows(s);
        if (ClipboardHelper.SetText(string.Join("\n", rows.Select(r => r.E.Value)))) Status($"Скопировано: {rows.Count}");
    }

    private void CtxDelete_Click(object s, RoutedEventArgs e)
    {
        var rows = SelectedRows(s);
        if (rows.Count == 0) return;
        if (MessageBox.Show(this, $"Удалить {rows.Count} записей вместе с историей наблюдений? Чтобы просто убрать из экспорта, используйте «Исключить» или «Отключить».",
                "Удаление", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
        Repo.DeleteEntries(rows.Select(r => r.Id));
        ReloadEntries();
    }

    private async void CtxResolve_Click(object s, RoutedEventArgs e)
    {
        if (_current == null) return;
        var domains = SelectedRows(s).Where(r => r.E.IsDomain).Select(r => r.E.Value).ToList();
        if (domains.Count == 0) return;
        var route = Settings.Route.UseProxy ? Settings.Route : new RouteSettings();
        var ct = BeginOp("DNS-разрешение выбранных доменов…");
        try
        {
            using var resolver = new DnsResolver(Settings.Dns, route);
            var scan = Repo.StartScan(_current.Id, "manual", route.Describe());
            var findings = new List<Finding>();
            var lines = new List<string>();
            foreach (var d in domains)
            {
                var r = await resolver.ResolveAsync(d, ct);
                lines.Add($"{d}: {(r.Addresses.Count > 0 ? string.Join(", ", r.Addresses) : r.Error)}");
                findings.AddRange(r.Addresses.Select(ip => new Finding
                {
                    Value = ip.ToString(), Kind = ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? EntryKind.IPv6 : EntryKind.IPv4,
                    Method = ObservationMethod.DnsResolve, Detail = r.Method, LinkedDomain = d, LinkMethod = "DNS: " + r.Method, Route = route.Describe(),
                }));
            }
            Repo.RecordFindings(_current.Id, scan, findings);
            Repo.FinishScan(scan, $"Ручное DNS-разрешение: {domains.Count} доменов");
            ReloadEntries(); ReloadHistory();
            ChecklistDialog.ShowText(this, $"DNS ({resolver.Describe()})", string.Join("\n", lines));
        }
        catch (Exception ex) { Error("DNS", ex); }
        finally { EndOp(); }
    }

    // ═══════════════ Анализ сайта ═══════════════

    private void UrlBox_KeyDown(object sender, System.Windows.Input.KeyEventArgs e)
    {
        if (e.Key == System.Windows.Input.Key.Enter && WebStartButton.IsEnabled) WebStart_Click(sender, e);
    }

    private async void WebStart_Click(object sender, RoutedEventArgs e)
    {
        if (ScanRunning) return;
        string url;
        try { url = WebAnalyzer.NormalizeUrl(UrlBox.Text); }
        catch (ArgumentException ex) { MessageBox.Show(this, ex.Message, "Адрес сайта"); return; }
        var route = CurrentWebRoute();
        if (route.UseProxy && string.IsNullOrWhiteSpace(route.Host))
        { MessageBox.Show(this, "Прокси не настроен. Откройте настройки и укажите прокси или выберите «Напрямую».", "Прокси"); return; }

        var host = new Uri(url).Host;
        var project = EnsureProject(ProjectType.Website, DomainNormalizer.RegistrableDomain(host) ?? host, url);
        if (project.Source != url || project.ProxyJson != AppSettings.SerializeRoute(StripPassword(route)))
        {
            project.Source = url; project.ProxyJson = AppSettings.SerializeRoute(StripPassword(route));
            if (project.Type != ProjectType.Website && project.Type != ProjectType.Mixed) project.Type = ProjectType.Mixed;
            Repo.UpdateProject(project);
        }

        WebStartButton.IsEnabled = false; WebStopButton.IsEnabled = true; InstallChromiumButton.Visibility = Visibility.Collapsed;
        _sessionFound = 0;
        try
        {
            if (route.UseProxy)
            {
                Log($"Проверяю прокси {route.Describe()} …");
                var chk = await RouteChecker.CheckAsync(route, Settings.ExternalIpServices, CancellationToken.None);
                if (!chk.Ok)
                {
                    Log("✖ Прокси не работает: " + chk.Error);
                    MessageBox.Show(this, "Прокси не работает:\n" + chk.Error + "\n\nАнализ не запущен, чтобы не выдать прямое подключение за проксированное.", "Прокси недоступен", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }
                Log($"✔ Прокси работает. Внешний IP маршрута: {chk.ExternalIp}");
            }

            _session = new ScanSession(Repo, project.Id, "web", route, WebResolveCheck.IsChecked == true ? Settings.Dns : null, Settings.RefreshDelayMs);
            _session.Flushed += _ => Dispatcher.BeginInvoke(ScheduleReload);
            _session.Log += Log;
            if (_session.DnsRouteWarning is { } w) Log("⚠ " + w);
            if (_session.DnsDescription is { } dd) Log("DNS-проверка найденных доменов: " + dd);

            _web = new WebAnalyzer(new WebAnalyzerOptions
            {
                Url = url, Route = route, Browser = Settings.Browser, AutoCrawl = AutoCrawlCheck.IsChecked == true,
                AutoCrawlMaxPages = Settings.AutoCrawlMaxPages, AutoCrawlDelaySeconds = Settings.AutoCrawlDelaySeconds,
            });
            _web.Found += f => { _session?.Add(f); Interlocked.Increment(ref _sessionFound); };
            _web.Log += Log;
            Status("Идёт анализ сайта — работайте в окне браузера, затем нажмите «Остановить».");
            Busy.Visibility = Visibility.Visible;
            await _web.RunAsync(CancellationToken.None);
        }
        catch (BrowserMissingException ex)
        {
            Log(ex.Message);
            InstallChromiumButton.Visibility = ex.Browser == BrowserChoice.BundledChromium ? Visibility.Visible : Visibility.Collapsed;
            MessageBox.Show(this, ex.Message, "Браузер не найден", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            Log("Ошибка анализа: " + RouteChecker.Flatten(ex).Split('\n')[0]);
            Error("Анализ сайта", ex);
        }
        finally
        {
            await FinishWebAsync();
        }
    }

    private static RouteSettings StripPassword(RouteSettings r) { var c = r.Clone(); c.Password = null; c.PasswordProtected = null; return c; }

    private async Task FinishWebAsync()
    {
        var web = _web; _web = null;
        string summary = "";
        if (web != null)
        {
            summary = $"Запросов: {web.RequestCount}; находок: {_sessionFound}" + (web.Failures.Count > 0 ? $"; ошибок запросов: {web.Failures.Values.Sum()}" : "");
            await web.DisposeAsync();
        }
        if (_session != null)
        {
            Status("Завершаю: DNS-проверка найденных доменов и запись в базу…");
            await _session.FinishAsync(summary);
            await _session.DisposeAsync();
            _session = null;
            AutoSaveVersion("после анализа сайта");
        }
        Busy.Visibility = Visibility.Collapsed;
        WebStartButton.IsEnabled = true; WebStopButton.IsEnabled = false;
        ReloadEntries(); ReloadHistory();
        Status(summary.Length > 0 ? "Анализ сайта завершён. " + summary : "Готово");
        if (_closingAfterStop) Close();
    }

    private void WebStop_Click(object sender, RoutedEventArgs e)
    {
        WebStopButton.IsEnabled = false;
        Status("Останавливаю анализ…");
        _web?.Stop();
    }

    private async void InstallChromium_Click(object sender, RoutedEventArgs e)
    {
        if (MessageBox.Show(this, "Скачать Chromium для Playwright (около 170 МБ) в %LOCALAPPDATA%\\ms-playwright?\nАльтернатива без загрузки — выбрать Microsoft Edge в настройках.",
                "Установка Chromium", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;
        InstallChromiumButton.IsEnabled = false;
        BeginOp("Скачиваю Chromium…");
        try
        {
            var code = await WebAnalyzer.InstallChromiumAsync();
            Log(code == 0 ? "Chromium установлен." : $"Установка Chromium завершилась с кодом {code}.");
            if (code == 0) InstallChromiumButton.Visibility = Visibility.Collapsed;
        }
        catch (Exception ex) { Error("Установка Chromium", ex); }
        finally { InstallChromiumButton.IsEnabled = true; EndOp(); }
    }

    // ═══════════════ Анализ программы ═══════════════

    private void PickExe_Click(object sender, RoutedEventArgs e)
    {
        var d = new OpenFileDialog { Filter = "Программы (*.exe)|*.exe", Title = "Выберите EXE программы или игры" };
        if (d.ShowDialog(this) != true) return;
        _targetExe = d.FileName; _targetPid = null;
        TargetText.Text = _targetExe;
    }

    private void PickProcess_Click(object sender, RoutedEventArgs e)
    {
        var p = ProcessPicker.Pick(this);
        if (p == null) return;
        _targetPid = p.Pid; _targetExe = p.Path;
        TargetText.Text = $"{p.Name} (PID {p.Pid}){(p.Path != null ? " — " + p.Path : "")}";
    }

    private async void ProcStart_Click(object sender, RoutedEventArgs e)
    {
        if (ScanRunning) return;
        if (_targetExe == null && _targetPid == null) { MessageBox.Show(this, "Сначала выберите EXE или запущенную программу.", "Программа не выбрана"); return; }
        var exeName = _targetExe != null ? Path.GetFileNameWithoutExtension(_targetExe) : $"PID {_targetPid}";
        var project = EnsureProject(ProjectType.Program, exeName, _targetExe ?? "");
        if (_targetExe != null && project.Source != _targetExe)
        {
            project.Source = _targetExe;
            if (project.Type == ProjectType.Website) project.Type = ProjectType.Mixed;
            Repo.UpdateProject(project);
        }

        bool admin = ProcessInfo.IsAdministrator();
        if (!admin)
        {
            var ans = MessageBox.Show(this,
                "Для полного захвата нужны права администратора:\n• UDP-соединения (игровые серверы, голосовой чат);\n• короткие соединения;\n• DNS-запросы и TLS SNI программы.\n\n" +
                "«Да» — перезапустить сканер от имени администратора.\n«Нет» — продолжить в ограниченном режиме (только TCP, опрос таблицы соединений).",
                "Нужны права администратора", MessageBoxButton.YesNoCancel, MessageBoxImage.Question);
            if (ans == MessageBoxResult.Cancel) return;
            if (ans == MessageBoxResult.Yes) { Elevate(); return; }
        }

        var tunnel = new List<IPAddress>();
        if (Settings.Route.UseProxy && IPAddress.TryParse(Settings.Route.Host, out var pip) && !IPAddress.IsLoopback(pip)) tunnel.Add(pip);
        // Локальные прокси-клиенты (системный прокси Windows, прокси из настроек на 127.0.0.1): разбираем запросы к ним.
        var localProxyPorts = SystemProxy.Get().Where(SystemProxy.IsLocal).Select(ep => ep.Port).ToHashSet();
        if (Settings.Route.UseProxy && (Settings.Route.Host == "localhost" || (IPAddress.TryParse(Settings.Route.Host, out var lip) && IPAddress.IsLoopback(lip))))
            localProxyPorts.Add(Settings.Route.Port);
        var route = new RouteSettings();
        _sessionFound = 0;
        _session = new ScanSession(Repo, project.Id, "process", route, Settings.Dns, Settings.RefreshDelayMs);
        _session.Flushed += _ => Dispatcher.BeginInvoke(ScheduleReload);
        _session.Log += Log;
        _liveAll.Clear(); _live.Clear();

        try
        {
            _proc = new ProcessMonitor(new ProcessMonitorOptions
            {
                ExePath = _targetExe, Pid = _targetPid, IncludeChildren = ChildrenCheck.IsChecked == true,
                IncludeFolderProcesses = FolderCheck.IsChecked == true, FlushDnsCache = FlushDnsCheck.IsChecked == true,
                TunnelEndpoints = tunnel, LocalProxyPorts = localProxyPorts, Route = "наблюдение на этом ПК",
            });
            _proc.Found += f => { _session?.Add(f); Interlocked.Increment(ref _sessionFound); };
            _proc.Log += Log;
            _proc.Connection += c => Dispatcher.BeginInvoke(() => AddLive(c));
            var proc = _proc;
            await Task.Run(() => proc.Start(allowFallback: true));
            CaptureText.Text = proc.Mode == CaptureMode.WinDivert
                ? $"Режим: WinDivert (TCP+UDP, PID из ядра){(proc.DnsEtwActive ? " + DNS (ETW)" : "")} + TLS SNI"
                : "Режим: ограниченный — только TCP (таблица соединений Windows). UDP не виден.";
            ProcStartButton.IsEnabled = false; ProcStopButton.IsEnabled = true;
            Busy.Visibility = Visibility.Visible;
            Status("Идёт мониторинг — пользуйтесь программой как обычно, затем нажмите «Остановить».");
            ResultTabs.SelectedItem = LiveTab;

            if (LaunchCheck.IsChecked == true && _targetExe != null && File.Exists(_targetExe))
            {
                if (MessageBox.Show(this, $"Запустить программу?\n{_targetExe}" + (admin ? "\n\nОна будет запущена с обычными правами пользователя (через проводник)." : ""),
                        "Запуск программы", MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes)
                {
                    ProcessMonitor.LaunchExe(_targetExe);
                    Log("Программа запущена: " + _targetExe);
                }
            }
        }
        catch (Exception ex)
        {
            Error("Мониторинг программы", ex);
            await StopProcAsync();
        }
    }

    private void AddLive(LiveConnection c)
    {
        var row = new LiveRow(c);
        _liveAll.Add(row);
        if (_liveAll.Count > 20000) _liveAll.RemoveAt(0);
        if (!row.Undetermined || ShowUndeterminedCheck.IsChecked == true)
        {
            _live.Insert(0, row);
            if (_live.Count > 5000) _live.RemoveAt(_live.Count - 1);
        }
        var tracked = _proc?.Tracked.Count ?? 0;
        LiveInfo.Text = $"Соединений: {_liveAll.Count(r => !r.Undetermined)}, неопределённых: {_liveAll.Count(r => r.Undetermined)}, отслеживаемых процессов: {tracked}";
    }

    private void ShowUndetermined_Click(object sender, RoutedEventArgs e)
    {
        _live.Clear();
        foreach (var r in Enumerable.Reverse(_liveAll).Where(r => !r.Undetermined || ShowUndeterminedCheck.IsChecked == true).Take(5000)) _live.Add(r);
    }

    private void ClearLive_Click(object sender, RoutedEventArgs e) { _liveAll.Clear(); _live.Clear(); LiveInfo.Text = ""; }

    private async void ProcStop_Click(object sender, RoutedEventArgs e) => await StopProcAsync();

    private async Task StopProcAsync()
    {
        ProcStopButton.IsEnabled = false;
        Status("Останавливаю мониторинг и освобождаю драйвер…");
        var proc = _proc; _proc = null;
        string summary = "";
        if (proc != null)
        {
            summary = $"Режим: {(proc.Mode == CaptureMode.WinDivert ? "WinDivert" : "только TCP")}; процессов: {proc.Tracked.Count}; потоков: {proc.FlowCount}; находок: {_sessionFound}";
            await proc.DisposeAsync();
        }
        if (_session != null)
        {
            await _session.FinishAsync(summary);
            await _session.DisposeAsync();
            _session = null;
            AutoSaveVersion("после анализа программы");
        }
        Busy.Visibility = Visibility.Collapsed;
        ProcStartButton.IsEnabled = true;
        ReloadEntries(); ReloadHistory();
        Status(summary.Length > 0 ? "Мониторинг остановлен. " + summary : "Готово");
        if (_closingAfterStop) Close();
    }

    private void Elevate_Click(object sender, RoutedEventArgs e) => Elevate();

    private void Elevate()
    {
        if (ScanRunning) { MessageBox.Show(this, "Сначала остановите текущий анализ.", "Идёт анализ"); return; }
        try
        {
            var psi = new ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute = true, Verb = "runas" };
            if (_current != null) { psi.ArgumentList.Add("--project"); psi.ArgumentList.Add(_current.Id.ToString()); }
            Process.Start(psi);
            Application.Current.Shutdown();
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223) { Log("Запуск от имени администратора отменён."); }
    }

    // ═══════════════ Импорт ═══════════════

    private void ImportFile_Click(object sender, RoutedEventArgs e)
    {
        var d = new OpenFileDialog { Filter = "Списки (*.txt;*.lst;*.csv;*.json;*.conf;*.log)|*.txt;*.lst;*.csv;*.json;*.conf;*.log|Все файлы|*.*" };
        if (d.ShowDialog(this) != true) return;
        try
        {
            if (new FileInfo(d.FileName).Length > 20_000_000) { MessageBox.Show(this, "Файл больше 20 МБ.", "Импорт"); return; }
            ShowImport(ListImporter.ParseText(File.ReadAllText(d.FileName), "файл: " + Path.GetFileName(d.FileName)));
        }
        catch (Exception ex) { Error("Импорт файла", ex); }
    }

    private void ImportParse_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(ImportText.Text)) { ImportSummary.Text = "Вставьте текст списка."; return; }
        ShowImport(ListImporter.ParseText(ImportText.Text, "вставленный текст"));
    }

    private async void ImportUrl_Click(object sender, RoutedEventArgs e)
    {
        var url = ImportUrl.Text.Trim();
        if (!Uri.TryCreate(url, UriKind.Absolute, out var u) || u.Scheme is not ("http" or "https")) { ImportSummary.Text = "Укажите ссылку http(s)://…"; return; }
        var ct = BeginOp("Загружаю список…");
        try { ShowImport(await ListImporter.FetchAsync(url, Settings.Route.UseProxy ? Settings.Route : new RouteSettings(), Settings.SingBoxPath, ct)); }
        catch (Exception ex) { Error("Загрузка списка", ex); }
        finally { EndOp(); }
    }

    private async void ImportAllowDomains_Click(object sender, RoutedEventArgs e)
    {
        var route = Settings.Route.UseProxy ? Settings.Route : new RouteSettings();
        var ct = BeginOp("Получаю список файлов itdoginfo/allow-domains…");
        try
        {
            var rows = new List<ChecklistDialog.Row>();
            foreach (var dir in new[] { "Services", "Categories", "Subnets/IPv4", "Subnets/IPv6", "Russia", "Ukraine" })
            {
                List<ListImporter.GitHubFile> files;
                try { files = await ListImporter.ListGitHubDirectoryAsync("itdoginfo", "allow-domains", dir, route, ct); }
                catch (HttpRequestException) { continue; }
                foreach (var f in files.Where(f => f.Name.EndsWith(".lst") && (dir is not ("Russia" or "Ukraine") || f.Name.Contains("-raw"))))
                    rows.Add(new ChecklistDialog.Row { Title = f.Path, Detail = dir.StartsWith("Subnets") ? "подсети" : (dir is "Russia" or "Ukraine" ? "большой общий список" : "домены"), Tag = f.DownloadUrl });
            }
            EndOp();
            if (rows.Count == 0) { MessageBox.Show(this, "Не удалось получить список файлов с GitHub (возможно, лимит запросов API). Укажите ссылку вручную.", "allow-domains"); return; }
            var chosen = ChecklistDialog.Show(this, "itdoginfo/allow-domains", "Выберите списки. Импорт — вспомогательная функция: записи получат низкую достоверность и не попадут в экспорт, пока вы их не проверите.", rows, "Загрузить");
            if (chosen == null || chosen.Count == 0) return;
            ct = BeginOp("Загружаю выбранные списки…");
            var text = new System.Text.StringBuilder();
            foreach (var c in chosen)
            {
                var r = await ListImporter.FetchAsync((string)c.Tag!, route, null, ct);
                foreach (var d in r.Domains) text.AppendLine(d);
                foreach (var n in r.Networks) text.AppendLine(n);
            }
            var merged = ListImporter.ParseText(text.ToString(), "allow-domains: " + string.Join(", ", chosen.Select(c => c.Title)));
            ShowImport(merged);
        }
        catch (Exception ex) { Error("allow-domains", ex); }
        finally { EndOp(); }
    }

    private void ShowImport(ImportResult r)
    {
        _pendingImport = r;
        ImportAddButton.IsEnabled = r.Domains.Count + r.Networks.Count > 0;
        ImportSummary.Text = $"Распознано: доменов {r.Domains.Count}, IP/подсетей {r.Networks.Count}, дубликатов {r.Duplicates}, отклонено {r.Rejected.Count}." +
                             (r.Notes.Count > 0 ? " " + string.Join(" ", r.Notes.Take(3)) : "");
        if (r.Rejected.Count > 0) Log("Импорт — отклонено: " + string.Join("; ", r.Rejected.Take(15)) + (r.Rejected.Count > 15 ? " …" : ""));
    }

    private void ImportAdd_Click(object sender, RoutedEventArgs e)
    {
        if (_pendingImport == null) return;
        var project = EnsureProject(ProjectType.Website, "Импорт", "");
        var method = ImportIsLog.IsChecked == true ? ObservationMethod.ProxyLog : ObservationMethod.Import;
        var scan = Repo.StartScan(project.Id, "import", "—");
        var r = Repo.RecordFindings(project.Id, scan, _pendingImport.ToFindings(method).ToList());
        Repo.FinishScan(scan, $"{_pendingImport.Origin}: новых {r.NewEntries}, обновлено {r.UpdatedEntries}, пропущено {r.Skipped}");
        Log($"Импорт добавлен: новых {r.NewEntries}, уже были {r.UpdatedEntries}, пропущено {r.Skipped}. Записи помечены как импортированные.");
        _pendingImport = null; ImportAddButton.IsEnabled = false;
        ReloadEntries(); ReloadHistory();
    }

    // ═══════════════ Обновление, офиц. диапазоны, ASN, обобщение ═══════════════

    /// <summary>Маршрут для проверок проекта: если проект анализировался через прокси — тот же прокси из настроек.</summary>
    private RouteSettings ProjectRoute()
    {
        var saved = _current != null ? AppSettings.DeserializeRoute(_current.ProxyJson) : null;
        if (saved?.UseProxy == true || WebRouteCombo.SelectedIndex == 1)
        {
            var c = Settings.Route.Clone(); c.UseProxy = !string.IsNullOrWhiteSpace(c.Host);
            return c;
        }
        return new RouteSettings();
    }

    private async void Refresh_Click(object sender, RoutedEventArgs e)
    {
        if (_current == null) return;
        if (ScanRunning) { MessageBox.Show(this, "Дождитесь окончания анализа.", "Идёт анализ"); return; }
        var ct = BeginOp("Обновляю адреса: повторное DNS-разрешение…");
        try
        {
            var route = ProjectRoute();
            var progress = new Progress<string>(Status);
            var report = await new Refresher(Repo).RefreshAsync(_current.Id, route, Settings.Dns, Settings.RefreshConcurrency, Settings.RefreshDelayMs, progress, ct);
            _current = Repo.GetProject(_current.Id);
            UpdateProjectSubtitle();
            ReloadEntries(); ReloadHistory();
            AutoSaveVersion("после обновления адресов");
            EndOp("Обновление завершено.");
            ChecklistDialog.ShowText(this, "Результат обновления адресов", report.ToText());
        }
        catch (Exception ex) { EndOp(); Error("Обновление адресов", ex); }
    }

    private async void Official_Click(object sender, RoutedEventArgs e)
    {
        if (_current == null) return;
        var ct = BeginOp("Загружаю официальные списки диапазонов…");
        try
        {
            var notes = await new Refresher(Repo).CheckOfficialRangesAsync(_current.Id, ProjectRoute(), new Progress<string>(Status), ct);
            ReloadEntries(); ReloadHistory();
            EndOp("Проверка официальных диапазонов завершена.");
            ChecklistDialog.ShowText(this, "Официальные диапазоны", notes.Count > 0 ? string.Join("\n\n", notes) :
                "Изменений и совпадений нет. IP из общих CDN/облаков только помечаются — их диапазоны не предлагаются, чтобы не проксировать посторонние сайты.");
        }
        catch (Exception ex) { EndOp(); Error("Официальные диапазоны", ex); }
    }

    private async void Asn_Click(object sender, RoutedEventArgs e)
    {
        if (_current == null) return;
        var rows = (sender is MenuItem ? SelectedRows(sender) : IpsGrid.SelectedItems.Cast<EntryRow>().ToList())
            .Where(r => r.E.Kind is EntryKind.IPv4 or EntryKind.IPv6).ToList();
        if (rows.Count == 0) rows = _rows.Where(r => r.E.Kind is EntryKind.IPv4 or EntryKind.IPv6 && r.E.Asn.Length == 0).ToList();
        if (rows.Count == 0) { Status("Нет IP для определения ASN."); return; }
        if (MessageBox.Show(this, $"Определить ASN и оператора для {rows.Count} IP?\nАдреса будут переданы в DNS-запросах сервису Team Cymru (origin.asn.cymru.com).",
                "ASN", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;
        var ct = BeginOp("Определяю ASN…");
        try
        {
            using var lookup = new AsnLookup(Settings.Dns, ProjectRoute());
            int i = 0;
            foreach (var r in rows)
            {
                ct.ThrowIfCancellationRequested();
                Status($"ASN {++i}/{rows.Count}: {r.E.Value}");
                try
                {
                    var info = await lookup.LookupAsync(IPAddress.Parse(r.E.Value), ct);
                    Repo.SetAsn(r.Id, info == null ? "ASN не найден" : $"{info.Asn} {info.Name} ({info.Prefix}, {info.Country})");
                }
                catch (Exception ex) when (ex is not OperationCanceledException) { Repo.SetAsn(r.Id, "ошибка запроса"); }
                await Task.Delay(100, ct);
            }
            ReloadEntries();
            EndOp("ASN определены. Префикс ASN показан для справки — он не добавляется в экспорт автоматически.");
        }
        catch (Exception ex) { EndOp(); Error("ASN", ex); }
    }

    private void Generalize_Click(object sender, RoutedEventArgs e)
    {
        if (_current == null) return;
        var sugg = PodkopExporter.SuggestGeneralization(_rows.Select(r => r.E));
        if (sugg.Count == 0)
        {
            MessageBox.Show(this, "Подходящих предложений нет. Обобщение предлагается, только если у одного основного домена замечено не меньше трёх поддоменов, " +
                                  "и никогда — для общих облаков и CDN (amazonaws.com, cloudfront.net, googleusercontent.com и т.п.).", "Обобщённый режим");
            return;
        }
        var rows = sugg.Select(s => new ChecklistDialog.Row { Title = s.Parent, Detail = $"{s.Children.Count}: {string.Join(", ", s.Children.Take(6))}{(s.Children.Count > 6 ? " …" : "")}", Tag = s }).ToList();
        var chosen = ChecklistDialog.Show(this, "Обобщённый режим",
            "Podkop трактует запись домена как domain_suffix: «example.com» охватывает ВСЕ его поддомены, в том числе ещё не замеченные. " +
            "Отметьте только те домены, которые целиком принадлежат нужному сервису.", rows, "Добавить родительские домены");
        if (chosen == null || chosen.Count == 0) return;
        var scan = Repo.StartScan(_current.Id, "manual", "—");
        Repo.RecordFindings(_current.Id, scan, chosen.Select(c => new Finding
        {
            Value = c.Title, Kind = EntryKind.Domain, Method = ObservationMethod.Manual,
            Detail = $"обобщение: {((GeneralizationSuggestion)c.Tag!).Children.Count} поддоменов",
        }).ToList());
        var ids = Repo.GetEntries(_current.Id).Where(en => chosen.Any(c => c.Title == en.Value)).Select(en => en.Id).ToList();
        Repo.SetManualConfirmed(ids, true); Repo.SetInclude(ids, true);
        Repo.FinishScan(scan, $"Обобщение: {chosen.Count} родительских доменов");
        ReloadEntries(); ReloadHistory();
    }

    // ═══════════════ Экспорт ═══════════════

    private ExportOptions ReadExportOptions() => new()
    {
        OnlyConfirmed = OptOnlyConfirmed.IsChecked == true, SingleAsCidr = OptSingleCidr.IsChecked == true,
        RemoveRedundantDomains = OptRedundant.IsChecked == true, AggregateSubnets = OptAggregate.IsChecked == true,
        IPv6InJsonRuleset = OptIpv6Json.IsChecked == true,
    };

    private ExportResult? _export;

    private void RebuildExport()
    {
        _export = PodkopExporter.Build(_rows.Select(r => r.E), ReadExportOptions());
        DomainsOut.Text = _export.DomainsText;
        SubnetsOut.Text = _export.SubnetsText;
        DomainsOutCount.Text = $"  ·  {_export.Domains.Count}";
        SubnetsOutCount.Text = $"  ·  {_export.Subnets.Count}";
        var lowExcluded = _rows.Count(r => r.E.Trust == Trust.Low && !r.E.Include);
        var warnings = _export.Warnings.ToList();
        var thirdOff = _rows.Where(r => r.E.IsDomain && r.Party == Party.ThirdParty && !r.E.Include && !r.E.Disabled).Select(r => r.E.Value).ToList();
        if (thirdOff.Count > 0)
            warnings.Insert(0, $"Не включены сторонние домены ({thirdOff.Count}): {string.Join(", ", thirdOff.Take(8))}{(thirdOff.Count > 8 ? " …" : "")}. " +
                               "Если без них что-то не работает (вход через Google, капча) — отметьте их во вкладке «Домены».");
        if (lowExcluded > 0) warnings.Add($"{lowExcluded} записей низкой достоверности не включены (по умолчанию требуется ваше решение).");
        ExportWarnings.Text = string.Join("\n", warnings.Take(12)) + (warnings.Count > 12 ? $"\n… ещё {warnings.Count - 12}" : "");
    }

    private void ExportOption_Click(object sender, RoutedEventArgs e)
    {
        Settings.Export = ReadExportOptions();
        Settings.Save();
        RebuildExport();
    }

    private void CopyDomains_Click(object sender, RoutedEventArgs e)
    {
        if (_export == null) return;
        if (ClipboardHelper.SetText(_export.DomainsText)) Status($"Скопировано доменов: {_export.Domains.Count}. Вставьте в поле «Список пользовательских доменов» Podkop (тип «Text List»).");
        AutoSaveVersion("экспорт");
    }

    private void CopySubnets_Click(object sender, RoutedEventArgs e)
    {
        if (_export == null) return;
        if (ClipboardHelper.SetText(_export.SubnetsText)) Status($"Скопировано IP/подсетей: {_export.Subnets.Count}. Вставьте в поле «Список пользовательских подсетей» Podkop.");
        AutoSaveVersion("экспорт");
    }

    private void CopyBoth_Click(object sender, RoutedEventArgs e)
    {
        if (_export == null) return;
        ClipboardHelper.SetText(_export.DomainsText);
        if (MessageBox.Show(this, $"Домены скопированы ({_export.Domains.Count}).\nВставьте их в «Список пользовательских доменов», затем нажмите OK — скопирую IP и подсети.",
                "Шаг 1 из 2", MessageBoxButton.OKCancel, MessageBoxImage.Information) != MessageBoxResult.OK) return;
        ClipboardHelper.SetText(_export.SubnetsText);
        MessageBox.Show(this, $"IP и подсети скопированы ({_export.Subnets.Count}).\nВставьте их в «Список пользовательских подсетей».", "Шаг 2 из 2");
        AutoSaveVersion("экспорт");
    }

    private string SafeName => string.Concat((_current?.Name ?? "podkop").Select(c => Path.GetInvalidFileNameChars().Contains(c) || c == ' ' ? '_' : c));

    private string? AskSave(string fileName, string filter)
    {
        var d = new SaveFileDialog { FileName = fileName, Filter = filter };
        return d.ShowDialog(this) == true ? d.FileName : null;
    }

    private void SaveDomains_Click(object sender, RoutedEventArgs e)
    {
        if (_export == null || AskSave("domains.txt", "Текст (*.txt)|*.txt") is not { } f) return;
        PodkopExporter.WritePlainList(f, _export.Domains); Status("Сохранено: " + f);
    }

    private void SaveSubnets_Click(object sender, RoutedEventArgs e)
    {
        if (_export == null || AskSave("subnets.txt", "Текст (*.txt)|*.txt") is not { } f) return;
        PodkopExporter.WritePlainList(f, _export.Subnets); Status("Сохранено: " + f);
    }

    private void SaveLst_Click(object sender, RoutedEventArgs e)
    {
        if (_export == null || AskSave($"{SafeName}-domains.lst", "Список (*.lst)|*.lst") is not { } f) return;
        var dir = Path.GetDirectoryName(f)!;
        var sub = Path.Combine(dir, Path.GetFileName(f).Replace("domains", "subnets"));
        if (sub == f) sub = Path.Combine(dir, $"{SafeName}-subnets.lst");
        PodkopExporter.WritePlainList(f, _export.Domains);
        PodkopExporter.WritePlainList(sub, _export.Subnets);
        ChecklistDialog.ShowText(this, "Локальные списки Podkop",
            $"Сохранены файлы:\n{f}\n{sub}\n\nФормат: одна запись на строку, без комментариев (Podkop читает .lst построчно и комментарии в них не поддерживает).\n\n" +
            "1. Скопируйте файлы на роутер, например:\n   scp domains.lst root@192.168.1.1:/etc/podkop/\n   (каталог /tmp очищается при перезагрузке роутера)\n" +
            "2. В Podkop укажите пути в полях «Локальные списки доменов» (local_domain_lists) и «Локальные списки подсетей» (local_subnet_lists).\n" +
            "3. Для удалённых списков (remote_domain_lists / remote_subnet_lists) разместите файл по прямой ссылке. Файлы с расширением .json и .srs Podkop " +
            "подключает как наборы правил sing-box, любые другие — как простой текстовый список.");
    }

    private void SaveRuleset_Click(object sender, RoutedEventArgs e)
    {
        if (_export == null || AskSave($"{SafeName}-domains.json", "Набор правил sing-box (*.json)|*.json") is not { } f) return;
        var dir = Path.GetDirectoryName(f)!;
        var sub = Path.Combine(dir, Path.GetFileName(f).Replace("domains", "subnets"));
        if (sub == f) sub = Path.Combine(dir, $"{SafeName}-subnets.json");
        var cidrs = _export.Subnets.Concat(OptIpv6Json.IsChecked == true ? _export.SubnetsV6 : Enumerable.Empty<string>());
        File.WriteAllText(f, PodkopExporter.BuildRulesetJson(_export.Domains, null));
        File.WriteAllText(sub, PodkopExporter.BuildRulesetJson(null, cidrs));
        Status($"Сохранены наборы правил sing-box (source, version 1): {Path.GetFileName(f)}, {Path.GetFileName(sub)} — для remote_domain_lists / remote_subnet_lists по прямой ссылке.");
    }

    private async void SaveSrs_Click(object sender, RoutedEventArgs e)
    {
        if (_export == null) return;
        if (string.IsNullOrEmpty(Settings.SingBoxPath) || !File.Exists(Settings.SingBoxPath))
        {
            MessageBox.Show(this, "Бинарный формат .srs создаётся официальной утилитой sing-box (sing-box rule-set compile).\n" +
                                  "Укажите путь к sing-box.exe в настройках. Без неё используйте набор правил .json — Podkop поддерживает оба формата.", ".srs");
            return;
        }
        if (AskSave($"{SafeName}-domains.srs", "Бинарный набор правил sing-box (*.srs)|*.srs") is not { } f) return;
        var ct = BeginOp("Компилирую .srs…");
        try
        {
            var dir = Path.GetDirectoryName(f)!;
            var tmpD = Path.Combine(Path.GetTempPath(), "pns-d.json"); var tmpS = Path.Combine(Path.GetTempPath(), "pns-s.json");
            File.WriteAllText(tmpD, PodkopExporter.BuildRulesetJson(_export.Domains, null));
            File.WriteAllText(tmpS, PodkopExporter.BuildRulesetJson(null, _export.Subnets.Concat(OptIpv6Json.IsChecked == true ? _export.SubnetsV6 : Enumerable.Empty<string>())));
            var sub = Path.Combine(dir, Path.GetFileName(f).Replace("domains", "subnets"));
            if (sub == f) sub = Path.Combine(dir, $"{SafeName}-subnets.srs");
            await PodkopExporter.CompileSrsAsync(Settings.SingBoxPath, tmpD, f, ct);
            await PodkopExporter.CompileSrsAsync(Settings.SingBoxPath, tmpS, sub, ct);
            EndOp($"Скомпилировано: {Path.GetFileName(f)}, {Path.GetFileName(sub)}");
        }
        catch (Exception ex) { EndOp(); Error(".srs", ex); }
    }

    private void SaveDetailedJson_Click(object sender, RoutedEventArgs e)
    {
        if (_current == null || _export == null || AskSave($"{SafeName}-details.json", "JSON (*.json)|*.json") is not { } f) return;
        File.WriteAllText(f, PodkopExporter.BuildDetailedJson(_current, _rows.Select(r => r.E), _export));
        Status("Сохранено: " + f);
    }

    private void ExportChanges_Click(object sender, RoutedEventArgs e)
    {
        if (_current == null || _export == null) return;
        var versions = Repo.GetVersions(_current.Id);
        var prev = versions.FirstOrDefault(v => v.DomainsText != _export.DomainsText || v.SubnetsText != _export.SubnetsText);
        if (prev == null) { ChecklistDialog.ShowText(this, "Изменения", "Сохранённых версий, отличающихся от текущих списков, нет."); return; }
        var d = PodkopExporter.Diff(prev.DomainsText, prev.SubnetsText, _export.DomainsText, _export.SubnetsText);
        ChecklistDialog.ShowText(this, $"Изменения с версии {prev}", d.ToText());
    }

    private void SaveVersion_Click(object sender, RoutedEventArgs e)
    {
        if (_current == null || _export == null) return;
        var id = Repo.SaveVersion(_current.Id, "сохранено вручную", _export.DomainsText, _export.SubnetsText);
        Status(id < 0 ? "Списки не изменились с последней версии." : "Версия сохранена.");
        ReloadHistory();
    }

    private void AutoSaveVersion(string reason)
    {
        if (_current == null) return;
        var rows = Repo.GetEntries(_current.Id);
        var ex = PodkopExporter.Build(rows, ReadExportOptions());
        if (ex.Domains.Count + ex.Subnets.Count == 0) return;
        Repo.SaveVersion(_current.Id, reason, ex.DomainsText, ex.SubnetsText);
        ReloadHistory();
    }

    // ═══════════════ История и исключения ═══════════════

    private void ReloadHistory()
    {
        if (_current == null) return;
        ScansGrid.ItemsSource = Repo.GetScans(_current.Id).Select(s => new ScanRow(s)).ToList();
        VersionsList.ItemsSource = Repo.GetVersions(_current.Id);
    }

    private void VersionDiff_Click(object sender, RoutedEventArgs e)
    {
        if (VersionsList.SelectedItem is not ListVersion v || _export == null) { VersionDiffText.Text = "Выберите версию."; return; }
        VersionDiffText.Text = $"Версия {v} → текущие списки:\n\n" + PodkopExporter.Diff(v.DomainsText, v.SubnetsText, _export.DomainsText, _export.SubnetsText).ToText();
    }

    private void VersionRollback_Click(object sender, RoutedEventArgs e)
    {
        if (VersionsList.SelectedItem is not ListVersion v || _current == null) return;
        if (MessageBox.Show(this, $"Вернуть выбор записей к версии {v}?\nИстория наблюдений не удаляется; записи, появившиеся позже, будут исключены из экспорта.",
                "Откат", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;
        AutoSaveVersion("перед откатом");
        Repo.Rollback(v);
        ReloadEntries();
        Repo.SaveVersion(_current.Id, $"откат к версии от {v.Time.ToLocalTime():dd.MM.yyyy HH:mm}", _export!.DomainsText, _export.SubnetsText);
        ReloadHistory();
        Status("Откат выполнен.");
    }

    private sealed record ExclusionRow(Exclusion X)
    {
        public override string ToString() => $"{(X.IsWhitelist ? "[белый]" : "[чёрный]")}  {X.Pattern}  {(X.ProjectId == null ? "(все проекты)" : "")}";
    }

    private void ReloadExclusions()
    {
        ExclusionsList.ItemsSource = Repo.GetExclusions(_current?.Id).Select(x => new ExclusionRow(x)).ToList();
    }

    private void AddExclusion_Click(object sender, RoutedEventArgs e)
    {
        var p = ExclusionPattern.Text.Trim().ToLowerInvariant();
        if (p.Length == 0) return;
        if (!IpNetwork.TryParse(p, out _) && !p.Contains('*') && !DomainNormalizer.Normalize(p, rejectLocal: false).Ok)
        { MessageBox.Show(this, "Укажите домен, маску со звёздочкой, IP или подсеть.", "Исключения"); return; }
        Repo.AddExclusion(ExclGlobal.IsChecked == true ? null : _current?.Id, p, ExclWhite.IsChecked == true);
        if (_current != null && ExclBlack.IsChecked == true)
        {
            var hit = _rows.Where(r => ExclusionMatcher.Matches(p, r.E.Value)).Select(r => r.Id).ToList();
            if (hit.Count > 0) { Repo.SetDisabled(hit, true); Log($"Отключено существующих записей по шаблону: {hit.Count}"); }
        }
        ExclusionPattern.Text = "";
        ReloadExclusions(); ReloadEntries();
    }

    private void DeleteExclusion_Click(object sender, RoutedEventArgs e)
    {
        if (ExclusionsList.SelectedItem is not ExclusionRow r) return;
        Repo.DeleteExclusion(r.X.Id);
        ReloadExclusions();
    }

    // ═══════════════ Настройки, автообновление, закрытие ═══════════════

    private void Settings_Click(object sender, RoutedEventArgs e)
    {
        var w = new SettingsWindow(Settings) { Owner = this };
        if (w.ShowDialog() == true)
        {
            Core.Analysis.TrustPolicy.FreshWindow = TimeSpan.FromDays(Settings.FreshDays);
            if (!Settings.Route.UseProxy && WebRouteCombo.SelectedIndex == 1) WebRouteCombo.SelectedIndex = 0;
            AutoCrawlCheck.Content = $"Ограниченный автообход страниц сайта (до {Settings.AutoCrawlMaxPages})";
            UpdateRouteBadge();
            UpdatePrivilegeInfo();
            Log("Настройки сохранены.");
        }
    }

    private bool _autoRefreshing;

    private async Task AutoRefreshTick()
    {
        if (!Settings.AutoRefreshEnabled || ScanRunning || _autoRefreshing || Busy.Visibility == Visibility.Visible) return;
        _autoRefreshing = true;
        try
        {
            foreach (var p in Repo.GetProjects())
            {
                if (p.LastRefresh is { } lr && DateTime.UtcNow - lr < TimeSpan.FromHours(Settings.AutoRefreshHours)) continue;
                if (!Repo.GetEntries(p.Id).Any(en => en.IsDomain)) continue;
                Log($"Автообновление адресов: {p.Name}");
                var route = AppSettings.DeserializeRoute(p.ProxyJson) is { UseProxy: true } ? Settings.Route : new RouteSettings();
                var rep = await new Refresher(Repo).RefreshAsync(p.Id, route, Settings.Dns, Math.Min(2, Settings.RefreshConcurrency), Math.Max(300, Settings.RefreshDelayMs), null, CancellationToken.None);
                var changed = rep.Changes.Count(c => c.added.Count + c.missing.Count > 0);
                Log($"Автообновление «{p.Name}»: проверено {rep.DomainsChecked}, доменов с изменениями: {changed}.");
                if (_current?.Id == p.Id) { _current = Repo.GetProject(p.Id); UpdateProjectSubtitle(); ReloadEntries(); ReloadHistory(); }
            }
        }
        catch (Exception ex) { Services.LogError("auto-refresh", ex); Log("Автообновление: " + ex.Message); }
        finally { _autoRefreshing = false; }
    }

    private void MainWindow_Closing(object? sender, CancelEventArgs e)
    {
        if (!ScanRunning || _closingAfterStop) return;
        if (MessageBox.Show(this, "Идёт анализ. Остановить его, сохранить результаты и выйти?", "Выход", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
        { e.Cancel = true; return; }
        e.Cancel = true;
        _closingAfterStop = true;
        if (_web != null) _web.Stop();
        else if (_proc != null) _ = StopProcAsync();
    }
}
