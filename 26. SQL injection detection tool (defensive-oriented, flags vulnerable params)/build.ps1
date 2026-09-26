# SQLiDetect Shield - portable .exe build (Windows)
# Produces dist\SQLiDetectShield.exe (single-file, no install required)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

Write-Host "[1/3] Self-test (CI acceptance gate + fixture verification)..."
python -m src --selftest
if ($LASTEXITCODE -ne 0) { throw "Self-test failed; aborting packaging." }

Write-Host "[2/3] Cleaning prior build..."
foreach ($d in @("build", "dist")) {
    if (Test-Path $d) { Remove-Item -Recurse -Force $d }
}
New-Item -ItemType Directory -Force -Path "dist" | Out-Null

Write-Host "[3/3] Building portable EXE (onefile, windowed)..."
& pyinstaller --noconfirm --clean --onefile --windowed --name SQLiDetectShield --hidden-import requests --hidden-import requests.sessions src\__main__.py

$exe = Join-Path $root "dist\SQLiDetectShield.exe"
if (-not (Test-Path $exe)) { throw "Build failed: $exe not found" }

$hash = (Get-FileHash -Algorithm SHA256 $exe).Hash
$size = (Get-Item $exe).Length

Write-Host ""
Write-Host "OK  artifact: $exe"
Write-Host "    size   : $([math]::Round($size / 1MB, 2)) MB"
Write-Host "    sha256 : $hash"
Write-Host ""
Write-Host "Smoke test (CLI selftest from frozen exe):"
& $exe --selftest