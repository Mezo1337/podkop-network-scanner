using System.IO;
using System.Windows;
using System.Windows.Threading;
using PodkopScanner.Core.Analysis;
using PodkopScanner.Core.Data;
using PodkopScanner.Core.Settings;
using PodkopScanner.Core.Update;

namespace PodkopScanner.App;

/// <summary>Общие сервисы приложения.</summary>
public static class Services
{
    public static AppSettings Settings { get; set; } = null!;
    public static Database Database { get; set; } = null!;
    public static Repository Repo { get; set; } = null!;
    public static string LogPath => Path.Combine(AppSettings.DataDirectory, "podkop-scanner.log");

    public static void LogError(string context, Exception ex)
    {
        try
        {
            Directory.CreateDirectory(AppSettings.DataDirectory);
            File.AppendAllText(LogPath, $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {context}: {ex}\n\n");
        }
        catch { }
    }
}

public partial class App : Application
{
    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        DispatcherUnhandledException += OnUiException;
        AppDomain.CurrentDomain.UnhandledException += (_, a) => Services.LogError("Unhandled", (Exception)a.ExceptionObject);
        TaskScheduler.UnobservedTaskException += (_, a) => { Services.LogError("Task", a.Exception); a.SetObserved(); };

        try
        {
            Services.Settings = AppSettings.Load();
            TrustPolicy.FreshWindow = TimeSpan.FromDays(Math.Max(1, Services.Settings.FreshDays));
            Services.Database = new Database(Path.Combine(AppSettings.DataDirectory, "podkop-scanner.db"));
            Services.Repo = new Repository(Services.Database);
        }
        catch (Exception ex)
        {
            Services.LogError("Startup", ex);
            MessageBox.Show("Не удалось открыть базу данных или настройки:\n\n" + ex.Message, "Podkop Network Scanner", MessageBoxButton.OK, MessageBoxImage.Error);
            Shutdown(1);
            return;
        }

        // Режим без окна для Планировщика заданий: PodkopScanner.exe --refresh-all
        if (e.Args.Contains("--refresh-all", StringComparer.OrdinalIgnoreCase))
        {
            int code = 0;
            try
            {
                var refresher = new Refresher(Services.Repo);
                foreach (var p in Services.Repo.GetProjects())
                {
                    var route = AppSettings.DeserializeRoute(p.ProxyJson) ?? Services.Settings.Route;
                    var rep = await refresher.RefreshAsync(p.Id, route, Services.Settings.Dns, Services.Settings.RefreshConcurrency, Services.Settings.RefreshDelayMs, null, CancellationToken.None);
                    File.AppendAllText(Path.Combine(AppSettings.DataDirectory, "refresh.log"), $"[{DateTime.Now:yyyy-MM-dd HH:mm}] {p.Name}\n{rep.ToText()}\n\n");
                }
            }
            catch (Exception ex) { Services.LogError("refresh-all", ex); code = 2; }
            Shutdown(code);
            return;
        }

        // Самопроверка мониторинга программ: PodkopScanner.exe --self-test (лучше от имени администратора)
        if (e.Args.Contains("--self-test", StringComparer.OrdinalIgnoreCase))
        {
            var res = await PodkopScanner.Core.Monitoring.SelfTest.RunProcessCaptureAsync(CancellationToken.None);
            var file = Path.Combine(AppSettings.DataDirectory, "self-test.txt");
            Directory.CreateDirectory(AppSettings.DataDirectory);
            File.WriteAllText(file, $"Podkop Network Scanner — самопроверка {DateTime.Now:yyyy-MM-dd HH:mm}\nИтог: {(res.Passed ? "ПРОЙДЕНО" : "НЕ ПРОЙДЕНО")}\n\n{res.Report}");
            MessageBox.Show($"Самопроверка: {(res.Passed ? "пройдена" : "НЕ пройдена")}.\nОтчёт: {file}", "Podkop Network Scanner",
                MessageBoxButton.OK, res.Passed ? MessageBoxImage.Information : MessageBoxImage.Warning);
            Shutdown(res.Passed ? 0 : 3);
            return;
        }

        var w = new MainWindow();
        MainWindow = w;
        w.Show();

        // Служебный режим для проверки отрисовки: --ui-snapshot файл.png [--tab N] [--mode N]
        var si = Array.IndexOf(e.Args, "--ui-snapshot");
        if (si >= 0 && si + 1 < e.Args.Length)
        {
            var file = e.Args[si + 1];
            int Arg(string name) { var i = Array.IndexOf(e.Args, name); return i >= 0 && i + 1 < e.Args.Length && int.TryParse(e.Args[i + 1], out var v) ? v : -1; }
            if (Arg("--tab") is var tab and >= 0) w.ResultTabs.SelectedIndex = tab;
            if (Arg("--mode") is var mode and >= 0) w.ModeTabs.SelectedIndex = mode;
            await Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ContextIdle);
            await Task.Delay(800);
            var dpi = System.Windows.Media.VisualTreeHelper.GetDpi(w);
            var rtb = new System.Windows.Media.Imaging.RenderTargetBitmap((int)(w.ActualWidth * dpi.DpiScaleX), (int)(w.ActualHeight * dpi.DpiScaleY), dpi.PixelsPerInchX, dpi.PixelsPerInchY, System.Windows.Media.PixelFormats.Pbgra32);
            rtb.Render(w);
            var enc = new System.Windows.Media.Imaging.PngBitmapEncoder();
            enc.Frames.Add(System.Windows.Media.Imaging.BitmapFrame.Create(rtb));
            using (var fs = File.Create(file)) enc.Save(fs);
            Shutdown(0);
            return;
        }
        if (Services.Database.RecoveryMessage is { } msg)
            MessageBox.Show(w, msg, "Восстановление базы данных", MessageBoxButton.OK, MessageBoxImage.Warning);
    }

    private void OnUiException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        Services.LogError("UI", e.Exception);
        MessageBox.Show("Произошла ошибка, программа продолжит работу:\n\n" + e.Exception.Message +
                        $"\n\nПодробности записаны в журнал:\n{Services.LogPath}", "Podkop Network Scanner", MessageBoxButton.OK, MessageBoxImage.Warning);
        e.Handled = true;
    }
}
