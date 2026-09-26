# Build a portable single-file Windows .exe with PyInstaller.
# Usage (from the project root):
#   powershell -ExecutionPolicy Bypass -File scripts/build_exe.ps1
# Output: dist\VpnTunnelBuilder.exe

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

Write-Host "[1/4] Installing requirements (if missing)..."
python -m pip install -r requirements.txt
python -m pip install pyinstaller

Write-Host "[2/4] Running test suite..."
python -m pytest tests -q
if ($LASTEXITCODE -ne 0) {
    Write-Host "Tests failed — aborting build." -ForegroundColor Red
    exit 1
}

Write-Host "[3/4] Building single-file exe..."
if (Test-Path "build") { Remove-Item -Recurse -Force "build" }
if (Test-Path "dist\VpnTunnelBuilder.exe") { Remove-Item "dist\VpnTunnelBuilder.exe" -Force }

python -m PyInstaller --noconfirm --clean --onefile --windowed --name VpnTunnelBuilder `
    --collect-all app run.py

Write-Host "[4/4] Done."
$exe = Join-Path $root "dist\VpnTunnelBuilder.exe"
if (Test-Path $exe) {
    Write-Host "Artifact: $exe"
    Write-Host "Run:      .\dist\VpnTunnelBuilder.exe --no-browser --backend auto"
} else {
    Write-Host "Build produced no exe (check PyInstaller output)." -ForegroundColor Yellow
}