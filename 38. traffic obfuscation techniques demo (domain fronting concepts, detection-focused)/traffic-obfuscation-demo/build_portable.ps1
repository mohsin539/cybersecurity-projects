# Build the portable single-file GUI .exe with PyInstaller.
#
# Usage:  powershell -ExecutionPolicy Bypass -File build_portable.ps1
#
# Output: dist\TrafficObfuscationDemo.exe  (portable, windowed, no installer)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

python -c "import PyInstaller; print('PyInstaller', PyInstaller.__version__)" | Out-Host

python tools\make_icon.py | Out-Host

pyinstaller --noconfirm --clean --onefile --windowed `
  --name TrafficObfuscationDemo `
  --icon assets\app.ico `
  --add-data "index.html;." `
  --add-data "assets\app.ico;assets" `
  traffic_obfuscation_gui.py

if (-not $?) { Write-Error "PyInstaller build failed"; exit 1 }

$exe = Join-Path $root "dist\TrafficObfuscationDemo.exe"
Write-Host ""
Write-Host "Build complete: $exe"
Write-Host ("Size            : {0:N1} MB" -f ((Get-Item $exe).Length / 1MB))
Write-Host "Portable        : single file, no installer, no Python required on target"
Write-Host "Reports written : next to the exe under Reports\report_<stamp>\"
Write-Host ""
Write-Host "Verify:        .\dist\TrafficObfuscationDemo.exe --selftest"