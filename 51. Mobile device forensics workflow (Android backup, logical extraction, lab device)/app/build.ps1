$ErrorActionPreference = "Stop"

Write-Host "== Mobile Device Forensics Lab - portable build ==" -ForegroundColor Cyan
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $here

python -m pip install -r requirements.txt

python -m PyInstaller `
    main.py `
    --name MobileForensicsLabPortable `
    --onefile `
    --noconsole `
    --clean `
    --noconfirm `
    --icon build/app.ico

if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed" }

$exe = Join-Path $here "dist\MobileForensicsLabPortable.exe"
if (Test-Path $exe) {
    $size = (Get-Item $exe).Length / 1MB
    Write-Host "OK -> $exe ($([math]::Round($size,1)) MB) - portable, data stays beside exe" -ForegroundColor Green
} else {
    throw "Build produced no exe"
}