using System.Text.RegularExpressions;
using PodkopScanner.Core.Model;
using PodkopScanner.Core.Net;

namespace PodkopScanner.Core.Analysis;

/// <summary>
/// Эвристическая классификация назначения ресурса. Возвращает категорию и текст обоснования
/// с уровнем уверенности. Классификация — только подсказка: решение о включении принимает пользователь.
/// </summary>
public static class Classifier
{
    // Известные рекламные/аналитические регистрируемые домены (только явные, без общих CDN).
    private static readonly HashSet<string> AdsAnalytics = new(StringComparer.Ordinal)
    {
        "doubleclick.net", "googlesyndication.com", "googleadservices.com", "google-analytics.com",
        "googletagmanager.com", "googletagservices.com", "adservice.google.com", "app-measurement.com",
        "hotjar.com", "hotjar.io", "mixpanel.com", "segment.io", "segment.com", "amplitude.com",
        "scorecardresearch.com", "criteo.com", "criteo.net", "taboola.com", "outbrain.com",
        "adnxs.com", "rubiconproject.com", "pubmatic.com", "openx.net", "moatads.com", "quantserve.com",
        "yandexadexchange.net", "adfox.ru", "top-fwz1.mail.ru", "tns-counter.ru", "mc.yandex.ru",
        "clarity.ms", "newrelic.com", "nr-data.net", "sentry.io", "bugsnag.com", "branch.io",
        "adsrvr.org", "bidswitch.net", "casalemedia.com", "everesttech.net", "demdex.net", "omtrdc.net",
        "facebook.net", "ads-twitter.com", "analytics.tiktok.com", "ads.linkedin.com", "bat.bing.com",
        "statcounter.com", "chartbeat.com", "parsely.com", "onesignal.com", "appsflyer.com", "adjust.com",
    };

    private static readonly HashSet<string> KnownCdnRegistrable = new(StringComparer.Ordinal)
    {
        "cloudflare.com", "cdnjs.cloudflare.com", "jsdelivr.net", "unpkg.com", "akamaihd.net", "akamaized.net",
        "akamai.net", "edgekey.net", "edgesuite.net", "fastly.net", "fastlylb.net", "cloudfront.net",
        "azureedge.net", "gstatic.com", "googleusercontent.com", "ggpht.com", "ytimg.com", "fbcdn.net",
        "twimg.com", "cdninstagram.com", "llnwd.net", "b-cdn.net", "bunnycdn.com", "yastatic.net",
        "steamstatic.com", "discordapp.net", "imgix.net", "cdn77.org", "stackpathdns.com",
    };

    private static readonly Regex AuthTokens = new(@"(^|[.-])(auth|login|signin|sso|oauth2?|accounts?|id|identity|passport|session|token|secure)([.-]|\d|$)", RegexOptions.Compiled);
    private static readonly Regex ApiTokens = new(@"(^|[.-])(api|gateway|graphql|rpc|backend|svc|services?)([.-]|\d|$)", RegexOptions.Compiled);
    private static readonly Regex CdnTokens = new(@"(^|[.-])(cdn|static|assets?|img|images?|cache|edge|fonts?|s\d*|st)([.-]|\d|$)", RegexOptions.Compiled);
    private static readonly Regex MediaTokens = new(@"(^|[.-])(video|media|stream|hls|dash|vod|live|cdn-video|rr\d+|music|audio|tv)([.-]|\d|$)", RegexOptions.Compiled);
    private static readonly Regex WsTokens = new(@"(^|[.-])(ws|wss|socket|realtime|push|gateway|events?|pubsub|mqtt)([.-]|\d|$)", RegexOptions.Compiled);
    private static readonly Regex VoiceTokens = new(@"(^|[.-])(voice|rtc|webrtc|turn|stun|media-relay|relay|voip|sfu)([.-]|\d|$)", RegexOptions.Compiled);
    private static readonly Regex GameTokens = new(@"(^|[.-])(game|gs|match|matchmaking|mm|lobby|server|realm|shard|region|udp)([.-]|\d|$)", RegexOptions.Compiled);
    private static readonly Regex UpdateTokens = new(@"(^|[.-])(update|updates|patch|patcher|download|dl|launcher|cdn-dl|content)([.-]|\d|$)", RegexOptions.Compiled);
    private static readonly Regex TelemetryTokens = new(@"(^|[.-])(telemetry|metrics|stats|crash|crashreport|log|logs|logging|events?-collector|beacon|collect|track|tracking)([.-]|\d|$)", RegexOptions.Compiled);

    public static (ResourceCategory, string) IsAds(string host)
    {
        var reg = DomainNormalizer.RegistrableDomain(host) ?? host;
        foreach (var d in AdsAnalytics)
            if (DomainNormalizer.IsCoveredBySuffix(host, d) || reg == d)
                return (ResourceCategory.AdsAnalytics, $"высокая уверенность: {d} — известный рекламный/аналитический сервис");
        return (ResourceCategory.Unknown, "");
    }

    /// <summary>Классификация хоста, загруженного браузером.</summary>
    public static (ResourceCategory, string) ClassifyWeb(string host, string? siteRegistrable, string? resourceType, string? path, bool isWebSocket, bool isNavigation)
    {
        var ads = IsAds(host);
        if (ads.Item1 != ResourceCategory.Unknown) return ads;
        if (SiteOwnership.IsConsent(host))
            return (ResourceCategory.Consent, "высокая уверенность: сервис баннера согласия на cookie — для работы сайта не нужен");
        var reg = DomainNormalizer.RegistrableDomain(host) ?? host;
        bool firstParty = siteRegistrable != null && reg == siteRegistrable;
        if (!firstParty && SiteOwnership.KnownThirdPartyReason(host) is { } why)
            return (ResourceCategory.ThirdParty, "высокая уверенность: " + why);
        var first = host.Split('.')[0];
        path = path?.ToLowerInvariant() ?? "";

        if (isWebSocket) return (ResourceCategory.WebSocket, "высокая уверенность: установлено WebSocket-соединение");
        if (firstParty && isNavigation && (host == siteRegistrable || first == "www"))
            return (ResourceCategory.MainSite, "высокая уверенность: основной документ сайта");
        if (AuthTokens.IsMatch(host) || Regex.IsMatch(path, @"/(oauth|login|signin|auth|sso|token)\b"))
            return (ResourceCategory.Auth, $"средняя уверенность: имя или путь указывают на авторизацию");
        if (resourceType is "media") return (ResourceCategory.Media, "высокая уверенность: браузер загрузил медиаресурс");
        if (MediaTokens.IsMatch(host) || Regex.IsMatch(path, @"\.(m3u8|mpd|mp4|webm|ts|m4s|mp3|aac)(\?|$)"))
            return (ResourceCategory.Media, "средняя уверенность: имя хоста или путь указывают на видео/аудио");
        if (resourceType is "xhr" or "fetch" or "eventsource")
        {
            if (ApiTokens.IsMatch(host) || path.Contains("/api/") || path.Contains("graphql"))
                return (ResourceCategory.Api, "высокая уверенность: XHR/fetch-запросы к API");
            if (!firstParty) return (ResourceCategory.ThirdParty, "средняя уверенность: XHR/fetch к стороннему домену");
            return (ResourceCategory.Api, "средняя уверенность: XHR/fetch-запросы");
        }
        if (KnownCdnRegistrable.Contains(reg) || KnownCdnRegistrable.Contains(host))
            return (ResourceCategory.Cdn, $"высокая уверенность: {reg} — известная CDN");
        if (resourceType is "image" or "font" or "stylesheet" or "script")
        {
            if (CdnTokens.IsMatch(host) || !firstParty)
                return (ResourceCategory.Cdn, $"средняя уверенность: статические ресурсы ({resourceType})");
            return (ResourceCategory.Cdn, $"низкая уверенность: статические ресурсы основного домена ({resourceType})");
        }
        if (firstParty)
        {
            if (ApiTokens.IsMatch(host)) return (ResourceCategory.Api, "средняя уверенность: имя хоста содержит api/gateway");
            if (CdnTokens.IsMatch(host)) return (ResourceCategory.Cdn, "средняя уверенность: имя хоста содержит cdn/static");
            return (ResourceCategory.MainSite, "средняя уверенность: домен сайта");
        }
        return (ResourceCategory.ThirdParty, "низкая уверенность: сторонний домен, назначение не определено");
    }

    /// <summary>Классификация соединения программы по имени хоста (если известно), протоколу и порту.</summary>
    public static (ResourceCategory, string) ClassifyProcess(string? host, string protocol, int port)
    {
        if (host != null)
        {
            var ads = IsAds(host);
            if (ads.Item1 != ResourceCategory.Unknown) return ads;
            if (VoiceTokens.IsMatch(host)) return (ResourceCategory.Voice, "средняя уверенность: имя хоста указывает на голос/RTC");
            if (AuthTokens.IsMatch(host)) return (ResourceCategory.Auth, "средняя уверенность: имя хоста указывает на авторизацию");
            if (TelemetryTokens.IsMatch(host)) return (ResourceCategory.Telemetry, "средняя уверенность: имя хоста указывает на телеметрию");
            if (UpdateTokens.IsMatch(host)) return (ResourceCategory.Update, "средняя уверенность: имя хоста указывает на обновления/загрузки");
            if (GameTokens.IsMatch(host)) return (ResourceCategory.GameServer, "средняя уверенность: имя хоста указывает на игровой сервер");
            if (ApiTokens.IsMatch(host)) return (ResourceCategory.Api, "средняя уверенность: имя хоста указывает на API");
            var reg = DomainNormalizer.RegistrableDomain(host) ?? host;
            if (KnownCdnRegistrable.Contains(reg)) return (ResourceCategory.Cdn, $"высокая уверенность: {reg} — известная CDN");
        }
        if (protocol == "UDP")
        {
            if (port is >= 3478 and <= 3481 || port is 19302 or 19305)
                return (ResourceCategory.Voice, "средняя уверенность: порт STUN/TURN (голос, видео, P2P)");
            if (port is >= 50000 and <= 65535)
                return (ResourceCategory.Voice, "низкая уверенность: UDP на высоком порту — часто голос/RTC или игровой трафик");
            if (port == 443) return (ResourceCategory.Api, "низкая уверенность: QUIC/HTTP3");
            if (port == 53) return (ResourceCategory.Unknown, "DNS-запрос напрямую к серверу");
            return (ResourceCategory.GameServer, "низкая уверенность: UDP-соединение — характерно для игровых серверов");
        }
        if (port is 443 or 8443) return (ResourceCategory.Api, "низкая уверенность: HTTPS (API, авторизация или загрузки)");
        if (port == 80) return (ResourceCategory.Update, "низкая уверенность: HTTP (часто загрузки и обновления)");
        return (ResourceCategory.GameServer, "низкая уверенность: TCP на нестандартном порту");
    }
}
