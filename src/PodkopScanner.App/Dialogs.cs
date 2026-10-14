using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using PodkopScanner.Core.Monitoring;

namespace PodkopScanner.App;

internal static class Ui
{
    public static Window Dialog(Window owner, string title, double w, double h) => new()
    {
        Title = title, Owner = owner, Width = w, Height = h, WindowStartupLocation = WindowStartupLocation.CenterOwner,
        ShowInTaskbar = false, ResizeMode = ResizeMode.CanResizeWithGrip,
    };

    public static StackPanel Buttons(params Button[] buttons)
    {
        var p = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 10, 0, 0) };
        foreach (var b in buttons) p.Children.Add(b);
        return p;
    }

    public static Button Btn(string text, bool primary = false, bool isDefault = false, bool isCancel = false)
    {
        var b = new Button { Content = text, IsDefault = isDefault, IsCancel = isCancel, MinWidth = 90 };
        if (primary) b.Style = (Style)Application.Current.FindResource("Primary");
        return b;
    }

    public static TextBlock Caption(string text) => new() { Text = text, Style = (Style)Application.Current.FindResource("Caption"), TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 6) };
}

public static class InputDialog
{
    public static string? Ask(Window owner, string title, string prompt, string initial = "")
    {
        var w = Ui.Dialog(owner, title, 460, 190);
        w.ResizeMode = ResizeMode.NoResize;
        var tb = new TextBox { Text = initial };
        var ok = Ui.Btn("OK", true, isDefault: true); var cancel = Ui.Btn("Отмена", isCancel: true);
        string? result = null;
        ok.Click += (_, _) => { result = tb.Text.Trim(); w.DialogResult = true; };
        var root = new StackPanel { Margin = new Thickness(14) };
        root.Children.Add(Ui.Caption(prompt)); root.Children.Add(tb); root.Children.Add(Ui.Buttons(ok, cancel));
        w.Content = root;
        w.Loaded += (_, _) => { tb.Focus(); tb.SelectAll(); };
        return w.ShowDialog() == true && result!.Length > 0 ? result : null;
    }
}

/// <summary>Выбор запущенного процесса.</summary>
public static class ProcessPicker
{
    public sealed record Item(int Pid, string Name, string? Path, string Title, string Parent);

    public static Item? Pick(Window owner)
    {
        var w = Ui.Dialog(owner, "Выбор запущенной программы", 900, 600);
        var search = new TextBox { Margin = new Thickness(0, 0, 0, 8) };
        var grid = new DataGrid { IsReadOnly = true, SelectionMode = DataGridSelectionMode.Single };
        grid.Columns.Add(new DataGridTextColumn { Header = "Программа", Binding = new Binding(nameof(Item.Name)), Width = 180 });
        grid.Columns.Add(new DataGridTextColumn { Header = "PID", Binding = new Binding(nameof(Item.Pid)), Width = 70 });
        grid.Columns.Add(new DataGridTextColumn { Header = "Окно", Binding = new Binding(nameof(Item.Title)), Width = 220 });
        grid.Columns.Add(new DataGridTextColumn { Header = "Путь", Binding = new Binding(nameof(Item.Path)), Width = new DataGridLength(1, DataGridLengthUnitType.Star) });
        var onlyWindows = new CheckBox { Content = "Только программы с окнами", IsChecked = true };

        List<Item> all = Load();
        void Apply()
        {
            var q = search.Text.Trim();
            grid.ItemsSource = all.Where(i => (onlyWindows.IsChecked != true || i.Title.Length > 0)
                                              && (q.Length == 0 || i.Name.Contains(q, StringComparison.OrdinalIgnoreCase) || (i.Path ?? "").Contains(q, StringComparison.OrdinalIgnoreCase) || i.Title.Contains(q, StringComparison.OrdinalIgnoreCase)))
                .OrderBy(i => i.Name, StringComparer.OrdinalIgnoreCase).ToList();
        }
        search.TextChanged += (_, _) => Apply();
        onlyWindows.Click += (_, _) => Apply();
        Apply();

        Item? result = null;
        var ok = Ui.Btn("Выбрать", true, isDefault: true); var cancel = Ui.Btn("Отмена", isCancel: true); var refresh = Ui.Btn("Обновить список");
        ok.Click += (_, _) => { if (grid.SelectedItem is Item i) { result = i; w.DialogResult = true; } };
        grid.MouseDoubleClick += (_, _) => { if (grid.SelectedItem is Item i) { result = i; w.DialogResult = true; } };
        refresh.Click += (_, _) => { all = Load(); Apply(); };

        var root = new DockPanel { Margin = new Thickness(12) };
        var top = new StackPanel(); DockPanel.SetDock(top, Dock.Top);
        top.Children.Add(Ui.Caption("Поиск по имени, окну или пути. Связь с соединениями устанавливается по PID и дереву процессов."));
        top.Children.Add(search); top.Children.Add(onlyWindows);
        var bottom = Ui.Buttons(refresh, ok, cancel); DockPanel.SetDock(bottom, Dock.Bottom);
        root.Children.Add(top); root.Children.Add(bottom); root.Children.Add(grid);
        w.Content = root;
        w.Loaded += (_, _) => search.Focus();
        return w.ShowDialog() == true ? result : null;
    }

    private static List<Item> Load()
    {
        var snap = ProcessInfo.Snapshot();
        var list = new List<Item>();
        foreach (var p in Process.GetProcesses())
        {
            using (p)
            {
                if (p.Id <= 4) continue;
                string title = "";
                try { title = p.MainWindowTitle; } catch { }
                var (path, _) = ProcessInfo.Details(p.Id);
                var parent = snap.TryGetValue(p.Id, out var sp) && snap.TryGetValue(sp.ParentPid, out var pp) ? pp.Name : "";
                list.Add(new Item(p.Id, p.ProcessName + ".exe", path, title, parent));
            }
        }
        return list;
    }
}

/// <summary>Список с флажками (выбор файлов allow-domains, предложения обобщения и т.п.).</summary>
public static class ChecklistDialog
{
    public sealed class Row : System.ComponentModel.INotifyPropertyChanged
    {
        private bool _checked;
        public required string Title { get; init; }
        public string Detail { get; init; } = "";
        public object? Tag { get; init; }
        public bool Checked { get => _checked; set { _checked = value; PropertyChanged?.Invoke(this, new(nameof(Checked))); } }
        public event System.ComponentModel.PropertyChangedEventHandler? PropertyChanged;
    }

    public static List<Row>? Show(Window owner, string title, string caption, List<Row> rows, string okText)
    {
        var w = Ui.Dialog(owner, title, 760, 560);
        var grid = new DataGrid { CanUserAddRows = false, ItemsSource = rows };
        var chk = new DataGridTemplateColumn { Header = "✓", Width = 40 };
        var f = new FrameworkElementFactory(typeof(CheckBox));
        f.SetBinding(CheckBox.IsCheckedProperty, new Binding(nameof(Row.Checked)) { Mode = BindingMode.TwoWay, UpdateSourceTrigger = UpdateSourceTrigger.PropertyChanged });
        f.SetValue(FrameworkElement.HorizontalAlignmentProperty, HorizontalAlignment.Center);
        chk.CellTemplate = new DataTemplate { VisualTree = f };
        grid.Columns.Add(chk);
        grid.Columns.Add(new DataGridTextColumn { Header = "Элемент", Binding = new Binding(nameof(Row.Title)), Width = 240, IsReadOnly = true });
        grid.Columns.Add(new DataGridTextColumn { Header = "Подробности", Binding = new Binding(nameof(Row.Detail)), Width = new DataGridLength(1, DataGridLengthUnitType.Star), IsReadOnly = true });
        var ok = Ui.Btn(okText, true, isDefault: true); var cancel = Ui.Btn("Отмена", isCancel: true);
        ok.Click += (_, _) => w.DialogResult = true;
        var root = new DockPanel { Margin = new Thickness(12) };
        var cap = Ui.Caption(caption); DockPanel.SetDock(cap, Dock.Top);
        var bottom = Ui.Buttons(ok, cancel); DockPanel.SetDock(bottom, Dock.Bottom);
        root.Children.Add(cap); root.Children.Add(bottom); root.Children.Add(grid);
        w.Content = root;
        return w.ShowDialog() == true ? rows.Where(r => r.Checked).ToList() : null;
    }

    public static void ShowText(Window owner, string title, string text)
    {
        var w = Ui.Dialog(owner, title, 760, 560);
        var tb = new TextBox { Text = text, IsReadOnly = true, Style = (Style)Application.Current.FindResource("Mono") };
        var copy = Ui.Btn("Скопировать"); var close = Ui.Btn("Закрыть", true, isCancel: true);
        copy.Click += (_, _) => ClipboardHelper.SetText(text);
        close.Click += (_, _) => w.Close();
        var root = new DockPanel { Margin = new Thickness(12) };
        var bottom = Ui.Buttons(copy, close); DockPanel.SetDock(bottom, Dock.Bottom);
        root.Children.Add(bottom); root.Children.Add(tb);
        w.Content = root;
        w.ShowDialog();
    }
}

public static class ClipboardHelper
{
    /// <summary>Буфер обмена бывает занят другой программой — повторяем несколько раз.</summary>
    public static bool SetText(string text)
    {
        for (int i = 0; i < 10; i++)
        {
            try { Clipboard.SetDataObject(text, true); return true; }
            catch (System.Runtime.InteropServices.COMException) { Thread.Sleep(50); }
        }
        return false;
    }
}
