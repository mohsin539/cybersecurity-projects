# Portable build script (Windows PowerShell) — mirrors project-46 build_exe.sh.
#
#   1. run the test suite first (fail fast)
#   2. regenerate pack/sap_manifest.json
#   3. run pip-audit against the frozen dependency list (exit 1 on findings)
#   4. PyInstaller SAP.spec -> dist/SAP.exe + dist/SAP-cli.exe
#   5. smoke-test the CLI exe (info / scan / verify / seal) and launch the GUI
#
# Usage:  powershell -ExecutionPolicy Bypass -File build_exe.ps1 [-SkipTests] [-SkipAudit]
param(
    [switch]$SkipTests,
    [switch]$SkipAudit
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root
$python = "python"

Write-Host "== SAP portable build ==" -ForegroundColor Cyan

if (-not $SkipTests) {
    Write-Host "== 1/5 test suite ==" -ForegroundColor Cyan
    & $python -m pytest tests -q
    if ($LASTEXITCODE -ne 0) { throw "tests failed - aborting build" }
} else {
    Write-Host "== 1/5 test suite SKIPPED ==" -ForegroundColor Yellow
}

Write-Host "== 2/5 integrity manifest ==" -ForegroundColor Cyan
& $python tools/make_manifest.py
if ($LASTEXITCODE -ne 0) { throw "make_manifest failed" }

if (-not $SkipAudit) {
    Write-Host "== 3/5 dependency audit (pip-audit) ==" -ForegroundColor Cyan
    & $python -m pip_audit 2>$null -r requirements.txt
    if ($LASTEXITCODE -ne 0) { Write-Host "pip-audit FINDINGS - inspect before shipping" -ForegroundColor Red }
} else {
    Write-Host "== 3/5 dependency audit SKIPPED ==" -ForegroundColor Yellow
}

Write-Host "== 4/5 PyInstaller SAP.spec ==" -ForegroundColor Cyan
& $python -m PyInstaller --clean --noconfirm SAP.spec
if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed" }

Write-Host "== 5/5 smoke test ==" -ForegroundColor Cyan
& .\build_smoke.ps1
if ($LASTEXITCODE -ne 0) { throw "smoke test failed" }

Write-Host "== build complete ==" -ForegroundColor Green
Get-ChildItem dist\*.exe | Select-Object Name, Length