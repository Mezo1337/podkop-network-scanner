using System.ComponentModel;
using PodkopScanner.Core.Analysis;
using PodkopScanner.Core.Model;
using PodkopScanner.Core.Monitoring;
using PodkopScanner.Core.Net;

namespace PodkopScanner.App;

public sealed class ProjectRow
{
    public Project Project { get; }
    public ProjectRow(Project p) => Project = p;
    public string Name => Project.Name;
    public string Subtitle => $"{Ru.Of(Project.Type)} · {(Project.LastRefresh ?? Project.Updated).ToLocalTime():dd.MM.yyyy HH:mm}";
}

/// <summary>Строка таблицы доменов/IP. Изменение флажка «В Podkop» сразу сохраняется в базе.</summary>
public sealed class EntryRow : INotifyPropertyChanged
{
    private readonly Action<EntryRow, bool> _onInclude;
    public Entry E { get; }
    public Party Party { get; }
    public string PartyReason { get; }
    public EntryRow(Entry e, Action<EntryRow, bool> onInclude, string? site = null)
    {
        E = e; _onInclude = onInclude;
        if (e.IsDomain && site != null) (Party, PartyReason) = SiteOwnership.Classify(e.Value, site);
        else { Party = Party.FirstParty; PartyReason = ""; }
    }
    public string PartyText => E.IsDomain && PartyReason.Length > 0 ? SiteOwnership.PartyText(Party) : "";
    public int PartySort => (int)Party;
    public event PropertyChangedEventHandler? PropertyChanged;

    public long Id => E.Id;
    public bool Include
    {
        get => E.Include;
        set { if (E.Include == value) return; E.Include = value; _onInclude(this, value); PropertyChanged?.Invoke(this, new(nameof(Include))); }
    }
    public bool Disabled => E.Disabled;
    public string Display
    {
        get
        {
            var v = E.Value;
            if (E.IsDomain && v.Contains("xn--")) v = $"{DomainNormalizer.ToUnicode(v)} ({v})";
            if (E.ManualConfirmed) v += "  ✔";
            if (E.Disabled) v += "  [отключено]";
            return v;
        }
    }
    public string SortKey => E.IsDomain ? (DomainNormalizer.RegistrableDomain(E.Value) ?? E.Value) + "|" + E.Value
        : IpNetwork.TryParse(E.Value, out var n) ? $"{(n.IsV6 ? 1 : 0)}|{n.Network:D40}|{n.Prefix:D3}" : E.Value;
    public string Registrable => E.IsDomain ? DomainNormalizer.RegistrableDomain(E.Value) ?? "" : "";
    public string KindText => Ru.Of(E.Kind);
    public string CategoryText => Ru.Of(E.Category);
    public string CategoryReason => E.CategoryReason;
    public string TrustText => Ru.Of(E.Trust);
    public int TrustValue => (int)E.Trust;
    public string StatusText => Ru.Of(E.Status);
    public string Sources => E.Sources;
    public string ProcessInfo => E.ProcessInfo;
    public string Protocols => E.Protocols;
    public string LinkedText => string.IsNullOrEmpty(E.LinkedNames) ? (E.Kind is EntryKind.IPv4 or EntryKind.IPv6 ? "нет доменной привязки" : "") : E.LinkedNames;
    public string NetworkText => string.Join(" · ", new[] { E.Provider, E.Asn }.Where(s => !string.IsNullOrEmpty(s)));
    public DateTime FirstSeen => E.FirstSeen;
    public string FirstSeenText => E.FirstSeen.ToLocalTime().ToString("dd.MM.yy HH:mm");
    public DateTime LastConfirmedSort => E.LastConfirmed ?? DateTime.MinValue;
    public string LastConfirmedText => E.LastConfirmed?.ToLocalTime().ToString("dd.MM.yy HH:mm") ?? "—";

    public bool Matches(string search) =>
        search.Length == 0 || E.Value.Contains(search, StringComparison.OrdinalIgnoreCase) || Display.Contains(search, StringComparison.OrdinalIgnoreCase)
        || E.Sources.Contains(search, StringComparison.OrdinalIgnoreCase) || E.ProcessInfo.Contains(search, StringComparison.OrdinalIgnoreCase)
        || E.LinkedNames.Contains(search, StringComparison.OrdinalIgnoreCase) || E.Provider.Contains(search, StringComparison.OrdinalIgnoreCase)
        || E.Asn.Contains(search, StringComparison.OrdinalIgnoreCase) || CategoryText.Contains(search, StringComparison.OrdinalIgnoreCase);
}

public sealed class LiveRow
{
    public LiveRow(LiveConnection c) => C = c;
    public LiveConnection C { get; }
    public string TimeText => C.Time.ToLocalTime().ToString("HH:mm:ss");
    public string Process => C.Process;
    public int Pid => C.Pid;
    public string Protocol => C.Protocol;
    public string Remote => C.Remote;
    public int Port => C.Port;
    public string? Domain => C.Domain;
    public string Source => C.Source;
    public string Relation => C.Relation;
    public string Note => C.Note;
    public bool Undetermined => C.Undetermined;
}

public sealed class ScanRow
{
    public ScanRow(Scan s) => S = s;
    public Scan S { get; }
    public long Id => S.Id;
    public string KindText => S.Kind switch
    {
        "web" => "Анализ сайта", "process" => "Анализ программы", "refresh" => "Обновление DNS",
        "import" => "Импорт", "official" => "Офиц. диапазоны", "manual" => "Вручную", _ => S.Kind,
    };
    public string StartedText => S.Started.ToLocalTime().ToString("dd.MM.yy HH:mm");
    public string Route => S.Route;
    public string Summary => S.Finished == null ? "(не завершено)" : S.Summary;
}
