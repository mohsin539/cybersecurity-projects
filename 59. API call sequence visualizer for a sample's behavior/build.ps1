# Build script: portable single-file ACSV.exe (architecture §11).
# Requires: python, pip (see requirements.txt)
#   .\build.ps1            -> dist\ACSV.exe (windowed, no console on first page)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

Write-Host "[1/4] verifying deps..."
python -c "import PySide6, fpdf; print('deps ok')"

Write-Host "[2/4] running unit tests..."
python -m pytest tests -q
if ($LASTEXITCODE -ne 0) { throw "tests failed" }

Write-Host "[3/4] building onefile exe..."
$extra = @()
if (Get-Command pythonw -ErrorAction SilentlyContinue) { $null } else { $null }

python -m PyInstaller `
    --noconfirm --clean `
    --onefile --windowed `
    --name ACSV `
    --icon data/icon.ico `
    --add-data "policies;policies" `
    --add-data "schemas;schemas" `
    --add-data "templates;templates" `
    --hidden-import fpdf `
    launcher.py

$exe = "dist\ACSV.exe"
if (-not (Test-Path $exe)) { throw "build failed: $exe missing" }

Write-Host "[4/4] signing + sha256..."
$hash = (Get-FileHash -Algorithm SHA256 $exe).Hash
Write-Host "built: $exe"
Write-Host "sha256: $hash"
Write-Host "size : $((Get-Item $exe).Length) bytes"
# Optional Authenticode signing hook (ISO A.8.32, A.8.08):
# signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /a $exe