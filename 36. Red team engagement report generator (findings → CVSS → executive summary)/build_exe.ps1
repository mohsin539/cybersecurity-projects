# Builds the portable RedTeamReport.exe with PyInstaller.
# Prerequisite: pip install -e .[gui,build]   (or pip install pyinstaller openpyxl)
$ErrorActionPreference = "Continue"   # PyInstaller logs to stderr; don't treat as failures

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Push-Location $root
try {
    Write-Host "Cleaning previous build output..." -ForegroundColor Cyan
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue -LiteralPath "build", "dist"

    Write-Host "Running PyInstaller (onefile, windowed)..." -ForegroundColor Cyan
    python -m PyInstaller --noconfirm --clean redteam_report.spec 2>&1 | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed with exit code $LASTEXITCODE" }

    $exe = Join-Path $root "dist\RedTeamReport.exe"
    if (-not (Test-Path -LiteralPath $exe)) { throw "Build succeeded but $exe was not produced." }

    Write-Host ""
    Write-Host "Build complete." -ForegroundColor Green
    Write-Host "Portable executable: $exe" -ForegroundColor Green
}
finally {
    Pop-Location
}