param(
    [switch]$Install,
    [switch]$Debug,
    [string]$Name = "TimelineBuilder"
)

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
$outDir = Join-Path $root "dist"
$workDir = Join-Path $root "build"

Write-Host "==> TimelineBuilder portable build" -ForegroundColor Cyan
Write-Host "    root : $root" -ForegroundColor DarkGray
Write-Host "    out  : $outDir" -ForegroundColor DarkGray

if ($Install -or -not (Get-Command pyinstaller -ErrorAction SilentlyContinue)) {
    Write-Host "==> Installing build dependencies" -ForegroundColor Yellow
    python -m pip install --upgrade pip
    python -m pip install -r (Join-Path $root "requirements.txt")
    python -m pip install pyinstaller
}

$mode = if ($Debug) { "--console" } else { "--windowed" }

$iconArgs = @()
$icon = Join-Path $root "assets\app.ico"
if (Test-Path -LiteralPath $icon) { $iconArgs = @("--icon", $icon) }

Write-Host "==> Running PyInstaller ($mode)" -ForegroundColor Yellow
python -m PyInstaller `
    --noconfirm `
    --clean `
    --onefile `
    $mode `
    --name $Name `
    --distpath $outDir `
    --workpath $workDir `
    --specpath (Join-Path $root "build") `
    --paths (Join-Path $root "src") `
    --collect-submodules "timeline_builder" `
    --add-data "$(Join-Path $root 'src\timeline_builder\resources');timeline_builder/resources" `
    @iconArgs `
    (Join-Path $root "run_app.py")

$exe = Join-Path $outDir "$Name.exe"
if (-not (Test-Path -LiteralPath $exe)) { throw "Build failed: $exe not found" }

$hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $exe).Hash
$manifest = Join-Path $outDir "SHA256SUMS.txt"
Set-Content -LiteralPath $manifest -Value "$hash  $Name.exe" -Encoding ASCII

Write-Host "==> Built $exe" -ForegroundColor Green
Write-Host "    SHA256 $hash" -ForegroundColor DarkGray
Write-Host "    Manifest written to $manifest" -ForegroundColor DarkGray
