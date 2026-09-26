# Post-build smoke test for the portable SAP exes (run by build_exe.ps1).
# Usage:  powershell -ExecutionPolicy Bypass -File build_smoke.ps1 [-CaseDir <path>]
param(
    [string]$CaseDir = (Join-Path $env:TEMP "sap_smoke_$([guid]::NewGuid().ToString('N').Substring(0,8))")
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$cli = Join-Path $root "dist\SAP-cli.exe"
$gui = Join-Path $root "dist\SAP.exe"

if (-not (Test-Path $cli)) { throw "SAP-cli.exe missing - run PyInstaller first" }
if (-not (Test-Path $gui)) { throw "SAP.exe missing - run PyInstaller first" }

# 1. info + doctor ------------------------------------------------------------
Write-Host "== SAP-cli.exe info ==" -ForegroundColor Cyan
$infoOut = & $cli info
$code = $LASTEXITCODE
if ($code -ne 0) { throw "info failed" }
$infoOut | Select-Object -First 8

Write-Host "== SAP-cli.exe doctor ==" -ForegroundColor Cyan
& $cli doctor
if ($LASTEXITCODE -ne 0) { throw "doctor failed" }

# 2. build a sample, then full scan --------------------------------------------
$sample = Join-Path $env:TEMP ("sap_smoke_sample_{0}.exe" -f [guid]::NewGuid().ToString('N').Substring(0,8))
& python -c "import sys; sys.path.insert(0, 'tests'); from helpers import build_minimal_pe; build_minimal_pe(r'$sample')"
if (-not (Test-Path $sample)) { throw "could not build smoke sample" }

Write-Host "== SAP-cli.exe scan ==" -ForegroundColor Cyan
& $cli scan $sample --case-dir $CaseDir --analyst smoketest
if ($LASTEXITCODE -ne 0) { throw "scan failed" }

# 3. verify + seal --------------------------------------------------------------
Write-Host "== SAP-cli.exe verify ==" -ForegroundColor Cyan
& $cli verify --case-dir $CaseDir
if ($LASTEXITCODE -ne 0) { throw "verify failed" }

Write-Host "== SAP-cli.exe seal ==" -ForegroundColor Cyan
& $cli seal --case-dir $CaseDir --password "smoketest"
if ($LASTEXITCODE -ne 0) { throw "seal failed" }

# 4. GUI launch check (start, wait, kill) -----------------------------------------
Write-Host "== SAP.exe GUI launch check ==" -ForegroundColor Cyan
$proc = Start-Process -FilePath $gui -PassThru
Start-Sleep -Seconds 6
if ($proc.HasExited) {
    $code = $proc.ExitCode
    Remove-Item -Recurse -Force $CaseDir -ErrorAction SilentlyContinue
    throw "SAP.exe exited early (code $code) - GUI failed to stay up"
}
Stop-Process -Id $proc.Id -Force
Write-Host "SAP.exe stayed up (GUI OK) and was stopped cleanly." -ForegroundColor Green

Remove-Item -Force $sample -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force $CaseDir -ErrorAction SilentlyContinue
Write-Host "== smoke test PASSED ==" -ForegroundColor Green
exit 0