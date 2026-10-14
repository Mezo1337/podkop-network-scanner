<#
  Сборка Podkop Network Scanner.
    .\build.ps1              — тесты (модульные) + выпуск в .\dist
    .\build.ps1 -Integration — дополнительно интеграционные тесты (реальная сеть, Chromium)
    .\build.ps1 -SkipTests
  Требуется .NET 8 SDK (https://dotnet.microsoft.com/download/dotnet/8.0).
  Если путь к папке проекта длиннее ~200 символов, задайте $env:PNS_ARTIFACTS = 'C:\pns-build'.
#>
param([switch]$Integration, [switch]$SkipTests, [string]$Output = "$PSScriptRoot\dist")
$ErrorActionPreference = 'Stop'
$env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
Set-Location $PSScriptRoot

if (-not $SkipTests) {
    $filter = if ($Integration) { 'Category!=Seed' } else { 'Category!=Integration&Category!=Seed' }
    dotnet test tests/PodkopScanner.Tests --filter $filter
    if ($LASTEXITCODE -ne 0) { throw 'Тесты не прошли' }
}

$pub = Join-Path $Output 'PodkopScanner'
if (Test-Path $pub) { Remove-Item $pub -Recurse -Force }
# Самодостаточная сборка: .NET на компьютере пользователя не нужен. Не single-file: Playwright требует папку .playwright рядом с exe.
dotnet publish src/PodkopScanner.App -c Release -r win-x64 --self-contained true -p:PublishReadyToRun=true -p:DebugType=none -o $pub
if ($LASTEXITCODE -ne 0) { throw 'Ошибка публикации' }
Copy-Item README.md $pub
Copy-Item native\WinDivert-LICENSE.txt (Join-Path $pub 'licenses') -Force
$zip = Join-Path $Output 'PodkopScanner-win-x64.zip'
if (Test-Path $zip) { Remove-Item $zip }
Compress-Archive -Path "$pub\*" -DestinationPath $zip
Write-Host "Готово: $pub`nАрхив: $zip"
