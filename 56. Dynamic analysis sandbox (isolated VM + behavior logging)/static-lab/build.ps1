<#
.SYNOPSIS
    Build the portable StaticLab .exe with PyInstaller (onefile, windowed GUI).
.PARAMETER Console
    Also emit a console variant (useful for --cli).
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File build.ps1
#>
param([switch]$Console)

$ErrorActionPreference = "Continue"  # native tools write to stderr; we check exit codes explicitly
$Root   = Split-Path -Parent $MyInvocation.MyCommand.Path
$AppDir = Join-Path $Root "app"
$Dist   = Join-Path $Root "dist"
$Build  = Join-Path $Root "build"

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    throw "Python not found on PATH."
}

Write-Host "[build] installing build dependencies (if missing)..." -ForegroundColor Cyan
python -m pip install --quiet "pyinstaller>=6.0" "pefile>=2024.8.26" 2>$null
if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) { throw "pip install failed ($LASTEXITCODE)" }

$outName = "StaticLab"
if ($Console) { $outName = "StaticLab-CLI" }

# --onedir is more robust for Tk + we still zip it into a portable folder.
# Launch through launcher.py so the `app` package resolves as a real package
# (relative imports inside app/* work when frozen by PyInstaller).
$entry = Join-Path $Root "launcher.py"

$args = @(
    "--name", $outName,
    "--onefile",
    "--clean",
    "--noconfirm",
    "--windowed",
    "--noupx",
    "--distpath", $Dist,
    "--workpath", $Build,
    "--specpath", $Root,
    "--paths", $Root,
    "--collect-submodules", "app",
    $entry
)

Write-Host "[build] running PyInstaller..." -ForegroundColor Cyan
python -m PyInstaller @args
if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) { throw "PyInstaller failed ($LASTEXITCODE)" }

$exe = Join-Path $Dist "$outName.exe"
if (-not (Test-Path $exe)) { throw "Build failed - expected $exe not found." }

$size = (Get-Item $exe).Length
Write-Host "[build] OK -> $exe ($([math]::Round($size/1MB,1)) MB)" -ForegroundColor Green
Write-Host "[build] Signing hint (optional):" -ForegroundColor Yellow
Write-Host '        signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /f cert.pfx /p password .\dist\StaticLab.exe'

if ($Console) {
    $cliExe = Join-Path $Dist "StaticLab-CLI.exe"
    if (Test-Path $cliExe) {
        Write-Host "[build] CLI variant: $cliExe" -ForegroundColor Green
    }
}