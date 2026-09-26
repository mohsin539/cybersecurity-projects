# Build the portable .EXE (architecture section 3 pipeline step 2-3).
# Usage:  .\build_exe.ps1
param(
    [switch]$SkipTests,
    [switch]$SkipAudit
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

Write-Host "== L3.2 PyInstaller one-file build ==" -ForegroundColor Cyan
if (-not $SkipTests) {
    Write-Host "  running quick smoke (pytest)" -ForegroundColor Yellow
    python -m pytest -q .
}

Write-Host "  building windowed single-file exe" -ForegroundColor Cyan
& pyinstaller --noconfirm --clean C2_Detection_Lab.spec

$exe = Join-Path $root "dist\C2DetectionLab.exe"
if (-not (Test-Path $exe)) { throw "build failed: $exe not found" }

Write-Host "== L3.3 sign & harden ==" -ForegroundColor Cyan
$sha = (Get-FileHash -Algorithm SHA256 $exe).Hash
Write-Host "  SHA256  $sha"
(Get-Item $exe).Length / 1MB | ForEach-Object {
    Write-Host ("  size    {0:N1} MB" -f $_) }

if (-not $SkipAudit) {
    $manifest = Join-Path $root "dist\manifest.sha256.txt"
    "SHA256  $exe" | Out-File -Encoding utf8 $manifest
    Write-Host "  manifest -> $manifest"
    Write-Host "  (signing requires a code-sign cert; run osslsigncode/signtool manually)"
}

Write-Host ""
Write-Host "Build OK. Run:  .\dist\C2DetectionLab.exe" -ForegroundColor Green