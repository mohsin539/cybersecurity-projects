# Builds a portable Windows .exe for the C2 Deconfliction Lab console.
# Usage:  powershell -ExecutionPolicy Bypass -File build_exe.ps1
$ErrorActionPreference = "Stop"
$root = $PSScriptRoot

Write-Host "[1/3] ensuring PyInstaller..." -ForegroundColor Cyan
pip install pyinstaller>=6.0 -q

Write-Host "[2/3] building portable exe (this may take a few minutes)..." -ForegroundColor Cyan
Push-Location $root
pyinstaller --clean --onefile --noconfirm build.spec
Pop-Location

$exe = Join-Path $root "dist\C2DeconflictionLab.exe"
if (Test-Path $exe) {
    Write-Host "[3/3] build complete: $exe" -ForegroundColor Green
    Write-Host "Run it, then open http://127.0.0.1:8443  (admin token printed on launch)" -ForegroundColor Yellow
} else {
    Write-Host "Build failed - dist exe not found" -ForegroundColor Red
}