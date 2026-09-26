# Build a portable, GUI-based, one-file Honeypot.exe (no Python needed on target).
$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot

if (-not (Test-Path -LiteralPath "$PSScriptRoot\assets\honeypot.ico")) {
    Write-Host "generating icon..."
    py scripts/make_icon.py
}

py -m compileall -q honeypot_gui.py honeypot scripts\make_icon.py
if ($LASTEXITCODE -ne 0) { throw "syntax precheck failed" }

py -m PyInstaller `
    --noconfirm `
    --clean `
    --onefile `
    --windowed `
    --name Honeypot `
    --icon "assets\honeypot.ico" `
    honeypot_gui.py
if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed" }

Copy-Item -LiteralPath "dist\Honeypot.exe" -Destination "Honeypot.exe" -Force
Write-Host ""
Write-Host "BUILD OK -> dist\Honeypot.exe  (also copied to .\Honeypot.exe)"
Write-Host "Portable: copy the exe anywhere; sessions.jsonl is written next to it under .\data"