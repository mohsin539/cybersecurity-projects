$ErrorActionPreference = "Stop"
Push-Location $PSScriptRoot
Write-Host "[1/3] install build deps" -ForegroundColor Cyan
python -m pip install -q -r requirements.txt
Write-Host "[2/3] test gate" -ForegroundColor Cyan
python -m pytest -q
if ($LASTEXITCODE -ne 0) { Write-Host "TEST GATE FAILED - aborting" -ForegroundColor Red; exit 1 }
Write-Host "[3/3] build onefile exe" -ForegroundColor Cyan
python -m PyInstaller specs\build.spec --noconfirm --clean
if ($LASTEXITCODE -ne 0) { Write-Host "BUILD FAILED" -ForegroundColor Red; exit 1 }
Write-Host "Build OK: dist\AgentJitterStudy.exe" -ForegroundColor Green
Pop-Location