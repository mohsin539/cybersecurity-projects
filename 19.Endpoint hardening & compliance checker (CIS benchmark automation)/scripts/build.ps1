# Builds the portable CISGuard.exe (tests -> PyInstaller -> verify -> smoke -> zip).
# Usage:  powershell -ExecutionPolicy Bypass -File scripts/build.ps1
# Optional: -SkipTests -SkipSmoke

param(
    [switch]$SkipTests,
    [switch]$SkipSmoke
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$python = ".venv\Scripts\python.exe"
$exe    = "dist\CISGuard\CISGuard.exe"
$plugin = "dist\CISGuard\_internal\PySide6\plugins\platforms\qwindows.dll"

if (-not $SkipTests) {
    Write-Host "[1/4] Running test suite (release gate)..." -ForegroundColor Cyan
    & $python -m pytest tests -q
    if ($LASTEXITCODE -ne 0) { throw "Tests failed; aborting build." }
}

Write-Host "[2/4] Building portable exe (PyInstaller, clean)..." -ForegroundColor Cyan
Remove-Item -Recurse -Force "build\portable", "dist\CISGuard" -ErrorAction SilentlyContinue
& $python -m PyInstaller portable.spec --noconfirm --clean
if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed." }

Write-Host "[3/4] Verifying self-contained bundle..." -ForegroundColor Cyan
if (-not (Test-Path $exe)) { throw "Missing $exe" }
if (-not (Test-Path $plugin)) { throw "Qt platform plugin missing: $plugin (GUI would silently fail)" }

if (-not $SkipSmoke) {
    Write-Host "[4/4] CLI smoke test..." -ForegroundColor Cyan
    $smoke = "build\smoke"
    Remove-Item -Recurse -Force $smoke -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force -Path $smoke | Out-Null
    # Windowed-subsystem exe: only Start-Process passes args + captures output.
    $jobArgs = @("--cli", "--data-dir", "$smoke\data", "--demo", "scan", "--out", "$smoke\reports\report")
    $p = Start-Process -FilePath $exe -WorkingDirectory (Get-Location) -ArgumentList $jobArgs -Wait -PassThru `
        -RedirectStandardOutput "$smoke\stdout.txt" -RedirectStandardError "$smoke\stderr.txt"
    Write-Host "smoke exit code: $($p.ExitCode) (non-zero = findings, expected)"
    Get-Content "$smoke\stdout.txt" | Select-Object -Last 2
    $smokeOk = (Test-Path "$smoke\reports\report.html") -and
               (Test-Path "$smoke\reports\report.json") -and
               (Test-Path "$smoke\reports\report.csv") -and
               (Test-Path "$smoke\data\history.db")
    if (-not $smokeOk) {
        Get-Content "$smoke\stderr.txt" -ErrorAction SilentlyContinue
        throw "CLI smoke test did not produce reports/history."
    }
    Write-Host "Smoke OK - scan + HTML/JSON/CSV + history verified." -ForegroundColor Green
}

# Optional distributable zip
$ver = & $python -c "import sys; sys.path.insert(0,'src'); import cisguard; print(cisguard.__version__)"
$zip = "dist\CISGuard-$ver-portable.zip"
if (Test-Path $zip) { Remove-Item $zip -Force }
Compress-Archive -Path "dist\CISGuard" -DestinationPath $zip
Write-Host "Build complete: $exe" -ForegroundColor Green
Write-Host "Archive       : $zip"