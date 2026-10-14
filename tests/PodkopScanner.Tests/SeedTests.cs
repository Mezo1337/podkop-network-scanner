using PodkopScanner.Core.Data;
using PodkopScanner.Core.Model;
using PodkopScanner.Core.Net;
using PodkopScanner.Core.Update;
using PodkopScanner.Core.Web;
using PodkopScanner.Core.Import;
namespace PodkopScanner.Tests;

/// <summary>Наполнение базы для визуальной проверки интерфейса. Запуск: PNS_SEED_DB=путь dotnet test --filter Category=Seed</summary>
[Trait("Category", "Seed")]
public class SeedTests
{
    [Fact]
    public async Task SeedUiDatabase()
    {
        var marker = Path.Combine(Path.GetTempPath(), "pns-seed-path.txt");
        var path = File.Exists(marker) ? File.ReadAllText(marker).Trim() : null;
        if (string.IsNullOrEmpty(path)) return;
        var repo = new Repository(new Database(path));
        var p = repo.CreateProject("Wikipedia", ProjectType.Website, "https://www.wikipedia.org/");
        await using (var s = new ScanSession(repo, p.Id, "web", new RouteSettings(), new DnsSettings(), 30))
        {
            var w = new WebAnalyzer(new WebAnalyzerOptions { Url = "https://www.wikipedia.org/", Route = new RouteSettings(), Headless = true,
                AutomationScript = async pg => { await pg.WaitForTimeoutAsync(2000); await pg.GotoAsync("https://ru.wikipedia.org/wiki/OpenWrt"); await pg.WaitForTimeoutAsync(4000); } });
            w.Found += s.Add;
            await w.RunAsync(default);
            await w.DisposeAsync();
            await s.FinishAsync($"Запросов: {w.RequestCount}");
        }
        var imp = ListImporter.ParseText("discord.com\ndiscord.gg\n162.159.128.0/19", "пример импорта");
        var sc = repo.StartScan(p.Id, "import", "—");
        repo.RecordFindings(p.Id, sc, imp.ToFindings(ObservationMethod.Import));
        repo.FinishScan(sc, "импорт");
        var ex = PodkopScanner.Core.Export.PodkopExporter.Build(repo.GetEntries(p.Id), new());
        repo.SaveVersion(p.Id, "после анализа сайта", ex.DomainsText, ex.SubnetsText);
    }
}
