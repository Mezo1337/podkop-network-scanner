using System.Collections.Concurrent;
using System.Net;
using Microsoft.Playwright;
using PodkopScanner.Core.Analysis;
using PodkopScanner.Core.Model;
using PodkopScanner.Core.Net;
using PodkopScanner.Core.Settings;

namespace PodkopScanner.Core.Web;

public sealed class WebAnalyzerOptions
{
    public required string Url { get; init; }
    public required RouteSettings Route { get; init; }
    public BrowserChoice Browser { get; init; } = BrowserChoice.BundledChromium;
    public bool Headless { get; init; }
    public bool AutoCrawl { get; init; }
    public int AutoCrawlMaxPages { get; init; } = 10;
    public int AutoCrawlDelaySeconds { get; init; } = 3;
    /// <summary>Сценарий действий на странице после загрузки (для автоматических проверок); по завершении анализ останавливается.</summary>
    public Func<IPage, Task>? AutomationScript { get; init; }
}

/// <summary>
/// Анализ сайта в настоящем Chromium (Playwright). Пользователь сам работает в открывшемся окне;
/// анализатор слушает сетевые события всего контекста (все вкладки, всплывающие окна, перенаправления,
/// WebSocket). Сохраняются только метаданные: имя хоста, тип ресурса, IP соединения.
/// Тела запросов, заголовки, cookies, пароли и токены не читаются и не сохраняются.
/// Контекст браузера — временный (как инкогнито): после остановки ничего не остаётся на диске.
/// </summary>
public sealed class WebAnalyzer : IAsyncDisposable
{
    private readonly WebAnalyzerOptions _o;
    private IPlaywright? _pw;
    private IBrowser? _browser;
    private IBrowserContext? _ctx;
    private LocalSocksBridge? _bridge;
    private readonly CancellationTokenSource _stop = new();
    private readonly TaskCompletionSource _closed = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private string? _siteRegistrable;
    private readonly ConcurrentDictionary<string, byte> _seenHostKeys = new();
    private readonly ConcurrentDictionary<string, int> _failures = new();
    private int _requests;

    public event Action<Finding>? Found;
    public event Action<string>? Log;

    public int RequestCount => _requests;
    public IReadOnlyDictionary<string, int> Failures => _failures;

    public WebAnalyzer(WebAnalyzerOptions o) => _o = o;

    public static string NormalizeUrl(string input)
    {
        input = input.Trim();
        if (!input.Contains("://")) input = "https://" + input;
        if (!Uri.TryCreate(input, UriKind.Absolute, out var u) || (u.Scheme != "http" && u.Scheme != "https"))
            throw new ArgumentException("Введите адрес сайта, например https://example.com");
        return u.ToString();
    }

    /// <summary>Запускает браузер, открывает сайт и ждёт, пока пользователь нажмёт «Остановить» или закроет окно.</summary>
    public async Task RunAsync(CancellationToken ct)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, _stop.Token);
        var url = NormalizeUrl(_o.Url);
        var host = new Uri(url).IdnHost.ToLowerInvariant();
        _siteRegistrable = DomainNormalizer.RegistrableDomain(host) ?? host;

        _pw = await Playwright.CreateAsync();
        var launch = new BrowserTypeLaunchOptions
        {
            Headless = _o.Headless,
            Channel = _o.Browser switch { BrowserChoice.Edge => "msedge", BrowserChoice.Chrome => "chrome", _ => null },
            Args = new[] { "--no-first-run", "--no-default-browser-check" },
        };
        if (_o.Route.UseProxy)
        {
            if (_o.Route.Kind == ProxyKind.Socks5 && _o.Route.HasAuth)
            {
                // Chromium не поддерживает логин/пароль для SOCKS5 → локальный мост.
                _bridge = new LocalSocksBridge(_o.Route);
                _bridge.Start();
                launch.Proxy = new Proxy { Server = $"socks5://127.0.0.1:{_bridge.Port}" };
                Log?.Invoke($"SOCKS5 с авторизацией: браузер подключён через локальный мост 127.0.0.1:{_bridge.Port} → {_o.Route.Describe()}");
            }
            else
            {
                launch.Proxy = new Proxy { Server = _o.Route.ProxyUri.ToString().TrimEnd('/'), Username = _o.Route.User, Password = _o.Route.Password };
            }
            Log?.Invoke($"Весь трафик браузера идёт через прокси {_o.Route.Describe()}. " +
                        "IP соединения в этом режиме — адрес прокси, поэтому IP серверов определяются только DNS-проверкой.");
        }
        else
        {
            // --no-proxy-server Playwright перекрывает; надёжно работает явный «direct://» с обходом для всех адресов.
            launch.Args = launch.Args!.Concat(new[] { "--proxy-server=direct://", "--proxy-bypass-list=*" }).ToArray();
            Log?.Invoke("Подключение напрямую: системный прокси Windows для браузера отключён.");
        }

        try
        {
            _browser = await _pw.Chromium.LaunchAsync(launch);
        }
        catch (PlaywrightException ex) when (ex.Message.Contains("Executable doesn't exist") || ex.Message.Contains("executable doesn't exist"))
        {
            throw new BrowserMissingException(_o.Browser, ex);
        }
        catch (PlaywrightException ex) when (_o.Browser != BrowserChoice.BundledChromium && ex.Message.Contains("is not found"))
        {
            throw new BrowserMissingException(_o.Browser, ex);
        }
        _browser.Disconnected += (_, _) => _closed.TrySetResult();

        _ctx = await _browser.NewContextAsync(new BrowserNewContextOptions
        {
            Locale = "ru-RU",
            ViewportSize = ViewportSize.NoViewport,
            AcceptDownloads = false,
        });
        _ctx.Request += OnRequest;
        _ctx.Response += OnResponse;
        _ctx.RequestFailed += OnRequestFailed;
        _ctx.Page += (_, p) => AttachPage(p);
        _ctx.Close += (_, _) => _closed.TrySetResult();

        var page = await _ctx.NewPageAsync();
        AttachPage(page);
        page.Close += (_, _) => { if (_ctx.Pages.Count == 0) _closed.TrySetResult(); };

        Log?.Invoke($"Открываю {url} …");
        try
        {
            var resp = await page.GotoAsync(url, new PageGotoOptions { WaitUntil = WaitUntilState.Load, Timeout = 60000 });
            if (resp == null) Log?.Invoke("Страница открыта без ответа сервера (возможно, из кэша).");
            else if (resp.Status >= 400) Log?.Invoke($"Сервер ответил кодом {resp.Status} {resp.StatusText}. Анализ продолжается.");
            else Log?.Invoke($"Страница загружена (HTTP {resp.Status}). Работайте с сайтом в окне браузера — новые запросы будут добавляться. Нажмите «Остановить», когда закончите.");
        }
        catch (PlaywrightException ex)
        {
            Log?.Invoke("Не удалось открыть сайт: " + ExplainNetError(ex.Message) + ". Окно браузера остаётся открытым — можно попробовать вручную.");
        }

        if (_o.AutomationScript != null)
        {
            try { await _o.AutomationScript(page); }
            catch (Exception ex) { Log?.Invoke("Сценарий: " + ex.Message.Split('\n')[0]); }
            await Task.Delay(1500);
            _stop.Cancel();
        }

        if (_o.AutoCrawl && !linked.IsCancellationRequested)
            _ = Task.Run(() => AutoCrawlAsync(page, linked.Token));

        try { await _closed.Task.WaitAsync(linked.Token); }
        catch (OperationCanceledException) { }
        Log?.Invoke($"Анализ завершён. Сетевых запросов: {_requests}.");
    }

    public void Stop() => _stop.Cancel();

    private void AttachPage(IPage p)
    {
        p.WebSocket += (_, ws) => Emit(ws.Url, "websocket", false, ObservationMethod.BrowserWebSocket, "WS");
    }

    private void OnRequest(object? sender, IRequest req)
    {
        Interlocked.Increment(ref _requests);
        try
        {
            var method = req.RedirectedFrom != null ? ObservationMethod.BrowserRedirect : ObservationMethod.BrowserRequest;
            Emit(req.Url, req.ResourceType, req.IsNavigationRequest, method, null);
        }
        catch { /* запрос мог быть уже уничтожен */ }
    }

    private void Emit(string url, string? resourceType, bool isNavigation, ObservationMethod method, string? proto)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var u)) return;
        if (u.Scheme is not ("http" or "https" or "ws" or "wss")) return; // data:, blob:, chrome-extension: и т.п.
        var rawHost = u.IdnHost.Trim('[', ']');
        bool isWs = method == ObservationMethod.BrowserWebSocket || u.Scheme is "ws" or "wss";
        var protocol = proto ?? (isWs ? "WS" : u.Scheme.ToUpperInvariant());
        if (IPAddress.TryParse(rawHost, out var ip))
        {
            // Сайт обращается к серверу прямо по IP — это и есть IP соединения.
            var key = $"ip|{ip}|{method}";
            if (!_seenHostKeys.TryAdd(key, 0)) return;
            Found?.Invoke(new Finding
            {
                Value = ip.ToString(), Kind = ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? EntryKind.IPv6 : EntryKind.IPv4,
                Method = method, Detail = $"обращение по IP ({resourceType})", Protocol = protocol, Port = u.Port, Route = _o.Route.Describe(),
                Category = ResourceCategory.ThirdParty, CategoryReason = "низкая уверенность: обращение напрямую по IP, имя сервера неизвестно",
            });
            return;
        }
        var n = DomainNormalizer.Normalize(rawHost);
        if (!n.Ok) return;
        var (cat, reason) = Classifier.ClassifyWeb(n.Domain!, _siteRegistrable, resourceType, u.AbsolutePath, isWs, isNavigation);
        // Повторы того же хоста с тем же типом ресурса не нужны — экономим базу.
        var k = $"{n.Domain}|{method}|{resourceType}|{protocol}";
        if (!_seenHostKeys.TryAdd(k, 0)) return;
        Found?.Invoke(new Finding
        {
            Value = n.Domain!, Kind = EntryKind.Domain, Method = method, Detail = resourceType ?? "",
            Protocol = protocol, Port = u.Port, Route = _o.Route.Describe(), Category = cat, CategoryReason = reason,
        });
    }

    private async void OnResponse(object? sender, IResponse resp)
    {
        if (_o.Route.UseProxy) return; // ServerAddr — адрес прокси, а не сервера
        try
        {
            var addr = await resp.ServerAddrAsync();
            if (addr == null || !IPAddress.TryParse(addr.IpAddress, out var ip)) return;
            ip = IpNetwork.Unmap(ip);
            if (!Uri.TryCreate(resp.Url, UriKind.Absolute, out var u)) return;
            var host = DomainNormalizer.Normalize(u.IdnHost).Domain;
            var key = $"addr|{ip}|{host}";
            if (!_seenHostKeys.TryAdd(key, 0)) return;
            Found?.Invoke(new Finding
            {
                Value = ip.ToString(), Kind = ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? EntryKind.IPv6 : EntryKind.IPv4,
                Method = ObservationMethod.BrowserServerAddr, Detail = host != null ? $"соединение браузера с {host}" : "соединение браузера",
                Protocol = u.Scheme.ToUpperInvariant(), Port = addr.Port, LinkedDomain = host, LinkMethod = "соединение браузера",
                Route = _o.Route.Describe(),
            });
        }
        catch { /* ответ уже недоступен */ }
    }

    private void OnRequestFailed(object? sender, IRequest req)
    {
        try
        {
            var reason = req.Failure ?? "неизвестно";
            if (reason.Contains("ERR_ABORTED")) return; // обычная отмена загрузки страницей
            var host = Uri.TryCreate(req.Url, UriKind.Absolute, out var u) ? u.Host : req.Url;
            var key = $"{host}: {ExplainNetError(reason)}";
            if (_failures.AddOrUpdate(key, 1, (_, v) => v + 1) == 1) Log?.Invoke("Ошибка запроса " + key);
        }
        catch { }
    }

    public static string ExplainNetError(string msg)
    {
        string Add(string code, string ru) => msg.Contains(code) ? $"{ru} ({code})" : "";
        var s = Add("ERR_NAME_NOT_RESOLVED", "имя сайта не разрешается в DNS")
              + Add("ERR_CONNECTION_RESET", "соединение сброшено — возможна блокировка")
              + Add("ERR_CONNECTION_TIMED_OUT", "истёк таймаут соединения")
              + Add("ERR_TIMED_OUT", "истёк таймаут")
              + Add("ERR_CONNECTION_REFUSED", "соединение отклонено")
              + Add("ERR_PROXY_CONNECTION_FAILED", "не удалось подключиться к прокси")
              + Add("ERR_TUNNEL_CONNECTION_FAILED", "прокси не смог установить туннель")
              + Add("ERR_SOCKS_CONNECTION_FAILED", "ошибка SOCKS-прокси")
              + Add("ERR_CERT", "ошибка сертификата — возможна подмена трафика")
              + Add("ERR_SSL_PROTOCOL_ERROR", "ошибка TLS — возможна блокировка")
              + Add("ERR_INTERNET_DISCONNECTED", "нет подключения к интернету")
              + Add("ERR_BLOCKED_BY_CLIENT", "заблокировано браузером");
        if (s.Length > 0) return s;
        var line = msg.Split('\n')[0];
        return line.Length > 200 ? line[..200] : line;
    }

    /// <summary>
    /// Ограниченный автообход: только ссылки того же регистрируемого домена, только переходы GET,
    /// не более N страниц, с паузой, без ссылок выхода/удаления. Выполняется в отдельной вкладке.
    /// </summary>
    private async Task AutoCrawlAsync(IPage start, CancellationToken ct)
    {
        try
        {
            var links = await start.EvalOnSelectorAllAsync<string[]>("a[href]", "els => els.map(e => e.href)");
            var queue = links.Where(l => Uri.TryCreate(l, UriKind.Absolute, out var u) && (u.Scheme is "http" or "https")
                    && (DomainNormalizer.RegistrableDomain(u.IdnHost.ToLowerInvariant()) == _siteRegistrable)
                    && !System.Text.RegularExpressions.Regex.IsMatch(l, @"logout|log-out|signout|sign-out|exit|delete|remove|unsubscribe|выход", System.Text.RegularExpressions.RegexOptions.IgnoreCase))
                .Select(l => l.Split('#')[0]).Distinct().Where(l => l != start.Url).Take(_o.AutoCrawlMaxPages).ToList();
            if (queue.Count == 0) { Log?.Invoke("Автообход: ссылок внутри сайта не найдено."); return; }
            Log?.Invoke($"Автообход: будет открыто {queue.Count} страниц(ы) сайта во второй вкладке.");
            var tab = await _ctx!.NewPageAsync();
            int i = 0;
            foreach (var link in queue)
            {
                ct.ThrowIfCancellationRequested();
                await Task.Delay(TimeSpan.FromSeconds(_o.AutoCrawlDelaySeconds), ct);
                try
                {
                    await tab.GotoAsync(link, new PageGotoOptions { WaitUntil = WaitUntilState.Load, Timeout = 30000 });
                    Log?.Invoke($"Автообход {++i}/{queue.Count}: {new Uri(link).PathAndQuery.Split('?')[0]}");
                }
                catch (PlaywrightException ex) { Log?.Invoke($"Автообход: {ExplainNetError(ex.Message)}"); }
            }
            await tab.CloseAsync();
            Log?.Invoke("Автообход завершён. Окно остаётся открытым для ручной работы.");
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) { Log?.Invoke("Автообход прерван: " + ex.Message.Split('\n')[0]); }
    }

    public async ValueTask DisposeAsync()
    {
        try { if (_ctx != null) await _ctx.CloseAsync(); } catch { }
        try { if (_browser != null) await _browser.CloseAsync(); } catch { }
        _pw?.Dispose();
        if (_bridge != null) await _bridge.DisposeAsync();
        _stop.Dispose();
    }

    /// <summary>Установка Chromium для Playwright (~170 МБ, в %LOCALAPPDATA%\ms-playwright).</summary>
    public static Task<int> InstallChromiumAsync() => Task.Run(() => Microsoft.Playwright.Program.Main(new[] { "install", "chromium" }));
}

public sealed class BrowserMissingException(BrowserChoice b, Exception inner) : Exception(
    b switch
    {
        BrowserChoice.Edge => "Microsoft Edge не найден. Выберите в настройках встроенный Chromium.",
        BrowserChoice.Chrome => "Google Chrome не найден. Выберите в настройках Microsoft Edge или встроенный Chromium.",
        _ => "Chromium для анализа ещё не установлен. Нажмите «Установить Chromium» (около 170 МБ) или выберите в настройках Microsoft Edge.",
    }, inner)
{
    public BrowserChoice Browser { get; } = b;
}
