# Build the portable DIHT Windows GUI executable (PyInstaller one-file).
# Run:  powershell -ExecutionPolicy Bypass -File .\build_portable.ps1
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

$Venv = Join-Path $Root ".venv-portable"
$Py   = Join-Path $Venv "Scripts\python.exe"

Write-Host "==> Creating virtual environment: $Venv" -ForegroundColor Cyan
if (-not (Test-Path $Py)) {
    python -m venv $Venv
}

Write-Host "==> Installing dependencies (pip)" -ForegroundColor Cyan
& $Py -m pip install --upgrade pip
& $Py -m pip install -r requirements.txt
if ($LASTEXITCODE -ne 0) { throw "pip install failed" }

Write-Host "==> Running headless self-test" -ForegroundColor Cyan
& $Py -m app.main --self-test "$env:TEMP\diht_build_selftest"
if ($LASTEXITCODE -ne 0) { throw "self-test failed" }

Write-Host "==> Freezing portable .exe (PyInstaller one-file)" -ForegroundColor Cyan
if (Test-Path -LiteralPath "build") { Remove-Item -Recurse -Force -LiteralPath "build" }
if (Test-Path -LiteralPath "dist")  { Remove-Item -Recurse -Force -LiteralPath "dist" }

& $Py -m PyInstaller --noconfirm --clean `
    --onefile --windowed `
    --name "DIHT_Portable" `
    --collect-data customtkinter `
    --hidden-import reportlab `
    --hidden-import openpyxl `
    --hidden-import customtkinter `
    --paths "$Root" `
    app\main.py

if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed" }

$Exe = Join-Path $Root "dist\DIHT_Portable.exe"
Write-Host ""
Write-Host "==> Portable executable built:" -ForegroundColor Green
Write-Host "    $Exe" -ForegroundColor Green
Write-Host "    Size: $([math]::Round((Get-Item $Exe).Length/1MB,1)) MB"

# Post-build verification of the frozen exe (runs headless self-test inside exe)
Write-Host "==> Verifying frozen executable (self-test)" -ForegroundColor Cyan
$Out = Join-Path $env:TEMP "diht_exe_selftest"
if (Test-Path -LiteralPath $Out) { Remove-Item -Recurse -Force -LiteralPath $Out }
& $Exe --self-test $Out
if ($LASTEXITCODE -ne 0) {
    Write-Host "WARNING: exe self-test exited with code $LASTEXITCODE" -ForegroundColor Yellow
} else {
    Write-Host "exe self-test PASSED" -ForegroundColor Green
}