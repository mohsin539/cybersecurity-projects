# build_exe.ps1 — builds the portable single-file Windows .exe (no console)
# Usage:  powershell -ExecutionPolicy Bypass -File .\build_exe.ps1
$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

Write-Host ">> Cleaning previous builds..."
if (Test-Path -LiteralPath "build")  { Remove-Item -Recurse -Force "build" }
if (Test-Path -LiteralPath "dist")   { Remove-Item -Recurse -Force "dist" }
if (Test-Path -LiteralPath "*.spec") { Remove-Item -Force "*.spec" }

Write-Host ">> Building portable .exe (PyInstaller onefile, windowed)..."
& python -m PyInstaller `
    --noconfirm `
    --clean `
    --onefile `
    --windowed `
    --name "PCAPtoStorySuite" `
    --collect-submodules "dpkt" `
    --collect-data "reportlab" `
    --hidden-import "app.gui" `
    --hidden-import "app.core.state" `
    --hidden-import "app.core.security" `
    --hidden-import "app.core.audit" `
    --hidden-import "app.core.pcap_engine" `
    --hidden-import "app.core.story_engine" `
    --hidden-import "app.core.reports" `
    --hidden-import "app.core.memory" `
    --hidden-import "reportlab.pdfbase.pdfmetrics" `
    --hidden-import "reportlab.lib.pagesizes" `
    --hidden-import "reportlab.platypus" `
    main.py

if (-not $?) { Write-Error "PyInstaller failed"; exit 1 }

Write-Host ">> Staging portable payload..."
if (Test-Path -LiteralPath "sample_triage.pcap") {
    Copy-Item -LiteralPath "sample_triage.pcap" -Destination "dist\sample_triage.pcap" -Force
}

Write-Host ""
Write-Host ">> Done. Deliverables:"
Get-ChildItem -LiteralPath "dist" | ForEach-Object {
    Write-Host ("    {0,-28} {1,10:N0} bytes" -f $_.Name, $_.Length)
}
Write-Host ""
Write-Host ">> Portable bundle ready. Run dist\PCAPtoStorySuite.exe"