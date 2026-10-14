using PodkopScanner.Core.Model;

namespace PodkopScanner.Core.Analysis;

/// <summary>
/// Детерминированные правила достоверности (раздел 12 ТЗ). Никаких «оценок нейросети»:
/// уровень зависит только от метода наблюдения, вида записи и давности.
/// </summary>
public static class TrustPolicy
{
    /// <summary>Наблюдения старше этого срока считаются «старыми данными» (низкая достоверность).</summary>
    public static TimeSpan FreshWindow { get; set; } = TimeSpan.FromDays(60);

    public static Trust BaseTrust(ObservationMethod m, EntryKind kind) => m switch
    {
        // Прямое наблюдение в контролируемом браузере или в потоке выбранного процесса.
        ObservationMethod.BrowserRequest or ObservationMethod.BrowserWebSocket or ObservationMethod.BrowserRedirect => Trust.High,
        ObservationMethod.BrowserServerAddr => Trust.High,
        ObservationMethod.FlowEstablished or ObservationMethod.SocketConnect or ObservationMethod.IpHelperTable => Trust.High,
        ObservationMethod.TlsSni => Trust.High,
        ObservationMethod.ProxyRequest => Trust.High,
        // Процесс запрашивал имя, но соединение с его адресом ещё не подтверждено.
        ObservationMethod.ProcessDnsEtw or ObservationMethod.ProcessDnsSniff => Trust.Medium,
        ObservationMethod.RelatedProcessFlow => Trust.Medium,
        ObservationMethod.DnsResolve => Trust.Medium,
        ObservationMethod.ProxyLog => Trust.Medium,
        ObservationMethod.OfficialRange => Trust.Medium,
        ObservationMethod.Manual => Trust.High,
        _ => Trust.Low, // Import
    };

    /// <summary>
    /// Достоверность записи = максимум по свежим наблюдениям; если свежих нет — Low.
    /// Подтверждённые вручную записи — High.
    /// </summary>
    public static Trust Compute(IEnumerable<(ObservationMethod Method, DateTime Time)> observations, EntryKind kind, bool manual, DateTime now)
    {
        if (manual) return Trust.High;
        var best = Trust.Low;
        foreach (var (m, t) in observations)
        {
            if (now - t > FreshWindow) continue;
            var b = BaseTrust(m, kind);
            if (b > best) best = b;
        }
        return best;
    }

    /// <summary>Методы, означающие подтверждение фактическим соединением.</summary>
    public static bool IsConnectionEvidence(ObservationMethod m) => m is
        ObservationMethod.BrowserRequest or ObservationMethod.BrowserServerAddr or ObservationMethod.BrowserWebSocket or
        ObservationMethod.BrowserRedirect or ObservationMethod.FlowEstablished or ObservationMethod.SocketConnect or
        ObservationMethod.IpHelperTable or ObservationMethod.TlsSni or ObservationMethod.ProxyRequest;

    /// <summary>Включать ли запись в экспорт по умолчанию. Низкая достоверность — никогда без согласия.</summary>
    public static bool DefaultInclude(Entry e, bool autoIncludeIps, string? siteRegistrable = null)
    {
        if (e.Trust == Trust.Low) return false;
        if (e.Category is ResourceCategory.AdsAnalytics or ResourceCategory.Consent) return false;
        if (e.IsDomain)
        {
            if (e.Trust != Trust.High) return false;
            // Проект-сайт: по умолчанию только домены самого сайта; сторонние сервисы — вашим решением.
            if (siteRegistrable != null && SiteOwnership.Classify(e.Value, siteRegistrable).party == Party.ThirdParty) return false;
            return true;
        }
        if (e.Kind is EntryKind.Cidr4 or EntryKind.Cidr6) return false; // подсети — только вручную
        return autoIncludeIps && e.Trust == Trust.High;
    }
}
