using PodkopScanner.Core.Net;

namespace PodkopScanner.Core.Analysis;

public enum Party
{
    FirstParty,   // домен самого сайта (тот же регистрируемый домен)
    SiteFamily,   // другой домен с тем же «брендом» (duolingo.com → duolingocdn.com)
    SiteCdn,      // персональный поддомен сайта на общей CDN-платформе (dxxxx.cloudfront.net)
    ThirdParty,   // сторонний сервис
}

/// <summary>
/// Принадлежность домена сайту проекта. Для проектов-сайтов по умолчанию в экспорт попадают только
/// домены сайта: сторонние сервисы (баннеры cookie, вход через Google, капча, шрифты, аналитика)
/// показываются, но включаются только вашим решением.
/// </summary>
public static class SiteOwnership
{
    /// <summary>Платформы, где у каждого клиента свой поддомен (имя поддомена принадлежит одному владельцу).</summary>
    private static readonly string[] PerCustomerPlatforms =
    {
        "cloudfront.net", "akamaized.net", "akamaihd.net", "azureedge.net", "azurefd.net", "b-cdn.net", "cdn77.org",
        "edgekey.net", "edgesuite.net", "vercel.app", "netlify.app", "herokuapp.com", "appspot.com", "firebaseapp.com",
        "web.app", "pages.dev", "workers.dev", "github.io", "s3.amazonaws.com", "blob.core.windows.net", "imgix.net",
        "kxcdn.com", "r2.dev", "gitbook.io",
    };

    /// <summary>Известные сторонние сервисы с понятным пояснением, зачем они сайту.</summary>
    private static readonly (string suffix, string why)[] KnownThirdParty =
    {
        ("accounts.google.com", "вход через Google — включайте, если входите в аккаунт через Google"),
        ("apis.google.com", "API Google (часто кнопка «Войти через Google»)"),
        ("recaptcha.net", "капча Google reCAPTCHA — нужна, если сайт показывает капчу"),
        ("www.google.com", "сервисы Google (часто reCAPTCHA)"),
        ("gstatic.com", "статика Google (шрифты, скрипты reCAPTCHA/входа)"),
        ("fonts.googleapis.com", "шрифты Google — сайт работает и без них"),
        ("hcaptcha.com", "капча hCaptcha"),
        ("challenges.cloudflare.com", "проверка Cloudflare Turnstile"),
        ("appleid.apple.com", "вход через Apple"),
        ("facebook.com", "вход/виджеты Facebook"),
        ("stripe.com", "платежи Stripe"),
        ("paypal.com", "платежи PayPal"),
        ("sentry.io", "отчёты об ошибках"),
        ("intercom.io", "чат поддержки"),
        ("zendesk.com", "поддержка Zendesk"),
    };

    private static readonly string[] Consent =
    {
        "cookielaw.org", "onetrust.com", "cookiebot.com", "consensu.org", "trustarc.com", "usercentrics.eu",
        "didomi.io", "osano.com", "termly.io", "iubenda.com", "cookieyes.com", "privacy-mgmt.com", "quantcast.com",
    };

    public static string? SiteRegistrableFromSource(string? source)
    {
        if (string.IsNullOrWhiteSpace(source) || !Uri.TryCreate(source, UriKind.Absolute, out var u) || u.Scheme is not ("http" or "https")) return null;
        var host = DomainNormalizer.Normalize(u.IdnHost).Domain;
        return host == null ? null : DomainNormalizer.RegistrableDomain(host) ?? host;
    }

    public static bool IsConsent(string host) => Consent.Any(c => DomainNormalizer.IsCoveredBySuffix(host, c));

    public static string? KnownThirdPartyReason(string host) =>
        KnownThirdParty.FirstOrDefault(k => DomainNormalizer.IsCoveredBySuffix(host, k.suffix)).why;

    public static (Party party, string reason) Classify(string host, string? siteRegistrable)
    {
        if (siteRegistrable == null) return (Party.FirstParty, "");
        var reg = DomainNormalizer.RegistrableDomain(host) ?? host;
        if (reg == siteRegistrable) return (Party.FirstParty, $"домен сайта {siteRegistrable}");

        var brand = siteRegistrable.Split('.')[0];
        var regLabel = reg.Split('.')[0];
        if (brand.Length >= 5 && regLabel.Contains(brand, StringComparison.Ordinal))
            return (Party.SiteFamily, $"вероятно, домен того же сервиса ({reg} содержит «{brand}»)");

        foreach (var p in PerCustomerPlatforms)
            if (host.EndsWith("." + p, StringComparison.Ordinal) && host.Length > p.Length + 1)
            {
                var label = host[..^(p.Length + 1)];
                if (!label.Contains('.') || p is "s3.amazonaws.com" or "blob.core.windows.net")
                    return (Party.SiteCdn, $"персональный поддомен на {p}, загружен страницами сайта — вероятно, CDN самого сайта");
            }

        if (IsConsent(host)) return (Party.ThirdParty, "баннер согласия на cookie — сайту для работы не нужен");
        return (Party.ThirdParty, KnownThirdPartyReason(host) is { } why ? $"сторонний сервис: {why}" : $"сторонний домен ({reg}), не принадлежит {siteRegistrable}");
    }

    public static string PartyText(Party p) => p switch
    {
        Party.FirstParty => "сайт",
        Party.SiteFamily => "сайт (родств.)",
        Party.SiteCdn => "CDN сайта",
        _ => "сторонний",
    };
}
