#Requires -Version 5.1
<#
.SYNOPSIS
  Builds portable, self-contained single-file executables of Proxy Suite.
.DESCRIPTION
  Produces ProxyCoreSvc.exe (proxy engine + IPC) and ProxyGui.exe (WPF GUI)
  that run with NO .NET runtime installed on the target machine.
  Output: dist\ProxySuite-Portable-win-x64\  + a ready-to-share zip.
.PARAMETER Runtime
  Target RID: win-x64 (default) or win-arm64.
.PARAMETER SkipZip
  Skip creating the distribution zip.
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\publish-portable.ps1
#>
param(
    [ValidateSet('win-x64', 'win-arm64')]
    [string]$Runtime = 'win-x64',
    [switch]$SkipZip
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot   # repo root (scripts\..)
Set-Location $root

$outDir = Join-Path $root "dist\ProxySuite-Portable-$Runtime"
if (Test-Path $outDir) { Remove-Item $outDir -Recurse -Force }
New-Item -ItemType Directory -Path $outDir | Out-Null

$common = @(
    '--configuration', 'Release',
    '--runtime', $Runtime,
    '--self-contained', 'true',
    '-p:PublishSingleFile=true',
    '-p:IncludeNativeLibrariesForSelfExtract=true',
    '-p:EnableCompressionInSingleFile=true',
    '-p:DebugType=none',
    '-p:DebugSymbols=false',
    '--nologo'
)

Write-Host "==> Publishing ProxyCoreSvc (single-file, self-contained)..." -ForegroundColor Cyan
dotnet publish src/ProxyCoreSvc/ProxyCoreSvc.csproj -o (Join-Path $outDir 'service') @common
if ($LASTEXITCODE -ne 0) { throw "ProxyCoreSvc publish failed" }

Write-Host "==> Publishing ProxyGui (single-file, self-contained)..." -ForegroundColor Cyan
dotnet publish src/ProxyGui/ProxyGui.csproj -o (Join-Path $outDir 'gui') @common
if ($LASTEXITCODE -ne 0) { throw "ProxyGui publish failed" }

# Flatten: keep only the exe files at the top level of the portable dir
Copy-Item (Join-Path $outDir 'service\ProxyCoreSvc.exe') $outDir
Copy-Item (Join-Path $outDir 'gui\ProxyGui.exe')         $outDir
Remove-Item (Join-Path $outDir 'service') -Recurse -Force
Remove-Item (Join-Path $outDir 'gui')     -Recurse -Force

# Sample config (opt-in): loopback binds + a demo deny rule
$configJson = @'
{
  "schemaVersion": 1,
  "listeners": {
    "http":   { "bind": "127.0.0.1", "port": 8080, "authMode": "None" },
    "socks5": { "bind": "127.0.0.1", "port": 1080, "authMode": "None" }
  },
  "upstreams": [ { "name": "direct", "type": "Direct" } ],
  "routing": { "default": "direct", "failover": [] },
  "rules": [
    { "id": 1, "action": "Allow", "match": {} }
  ],
  "limits": {
    "maxConnections": 2000,
    "maxConnectionsPerClient": 128,
    "connectRatePerMinute": 240,
    "rateBlockSeconds": 60,
    "idleTimeoutSec": 300,
    "connectTimeoutSec": 15,
    "maxHeaderBytes": 32768
  },
  "security": {
    "denyPrivateTargets": false,
    "resolveViaUpstream": false,
    "secretVaultPath": "data/vault.bin",
    "httpRatePerMinute": 600
  },
  "logging": { "level": "info", "directory": "logs", "maxFileBytes": 104857600, "maxFiles": 14 }
}
'@
Set-Content -Path (Join-Path $outDir 'config.sample.json') -Value $configJson -Encoding UTF8

# Launcher scripts
$startSvc = @'
@echo off
rem Proxy Suite - start the proxy service (portable)
setlocal
cd /d "%~dp0"
echo Starting ProxyCoreSvc (HTTP 127.0.0.1:8080, SOCKS5 127.0.0.1:1080)...
start "ProxyCoreSvc" /min ProxyCoreSvc.exe
timeout /t 2 >nul
echo Started. Logs: %~dp0logs\  Audit: %~dp0logs\audit-*.jsonl
'@
Set-Content -Path (Join-Path $outDir 'start-service.cmd') -Value $startSvc -Encoding ASCII

$startGui = @'
@echo off
rem Proxy Suite - start the management GUI (portable)
setlocal
cd /d "%~dp0"
start "" ProxyGui.exe
'@
Set-Content -Path (Join-Path $outDir 'start-gui.cmd') -Value $startGui -Encoding ASCII

# Python edition launcher (scripts/pyproxy is copied into pyproxy\ by the packaging step)
$startPy = @'
@echo off
rem Proxy Suite - start the PYTHON proxy edition (stdlib-only, no pip installs)
setlocal
cd /d "%~dp0pyproxy"

rem Use the config.json next to this script if present; otherwise built-in defaults
if not exist config.json (
  if exist config.sample.json echo [info] config.json not found - using built-in defaults ^(see config.sample.json^)
)

where py >nul 2>nul
if %errorlevel%==0 (
  start "ProxySuite-Python" /min py proxy_server.py
  goto :started
)
where python >nul 2>nul
if %errorlevel%==0 (
  start "ProxySuite-Python" /min python proxy_server.py
  goto :started
)
echo Python 3.10+ not found. Install from https://www.python.org/downloads/ or: winget install Python.Python.3.12
pause
exit /b 1

:started
timeout /t 2 >nul
echo Started. HTTP 127.0.0.1:8080  SOCKS5 127.0.0.1:1080  Status: pyproxy\status.json
'@
Set-Content -Path (Join-Path $outDir 'start-pyproxy.cmd') -Value $startPy -Encoding ASCII

# Portable README
$readme = @'
Proxy Suite - Portable (win-x64)
================================

Contents
  ProxyCoreSvc.exe      Proxy engine + IPC service (HTTP :8080, SOCKS5 :1080 on 127.0.0.1)
  ProxyGui.exe          Management GUI (dashboard, rules, logs, diagnostics)
  start-service.cmd     Convenience launcher for the service
  start-gui.cmd         Convenience launcher for the GUI
  config.sample.json    Sample configuration - rename to config.json to use

Quick start
  1. Double-click start-service.cmd  (or run ProxyCoreSvc.exe directly)
  2. Double-click start-gui.cmd
  3. Point your browser at 127.0.0.1:8080 (HTTP) or 127.0.0.1:1080 (SOCKS5)

Notes
  - Self-contained: no .NET installation required on the target machine.
  - First launch of ProxyGui.exe may take a few seconds (single-file extraction).
  - config.json, logs\ and data\ are created NEXT TO the exe files (portable layout).
    Override the root with the PROXYCORE_HOME environment variable.
  - Set config security.denyPrivateTargets=true to block loopback/private/metadata targets.
  - Audit trail: logs\audit-*.jsonl (hash-chained, tamper-evident - see SECURITY.md).

Python edition (no .NET needed - requires Python 3.10+)
  start-pyproxy.cmd     Starts the stdlib-only Python proxy (pyproxy\proxy_server.py)
  pyproxy\config.sample.json - rename to config.json to customize
  pyproxy\status.json   Live status/metrics written by the Python server
  pyproxy\README.md     Python edition documentation
'@
Set-Content -Path (Join-Path $outDir 'README.txt') -Value $readme -Encoding ASCII

Write-Host "==> Publish complete: $outDir" -ForegroundColor Green

# Python edition: copy the stdlib-only proxy into the bundle (kept outside the zip build
# above so this step is safe to re-run; zip is rebuilt afterwards when not skipped)
$pySrc = Join-Path $root 'scripts\pyproxy'
$pyDst = Join-Path $outDir 'pyproxy'
if (Test-Path $pySrc) {
    New-Item -ItemType Directory -Force -Path $pyDst | Out-Null
    Copy-Item (Join-Path $pySrc 'proxy_server.py') $pyDst -Force
    Copy-Item (Join-Path $pySrc 'config.sample.json') $pyDst -Force
    Copy-Item (Join-Path $pySrc 'README.md') $pyDst -Force
    Write-Host "==> Python edition copied to pyproxy\" -ForegroundColor Green
}

# SHA-256 manifest (before zip so the manifest ships inside the archive)
Write-Host "==> SHA-256 manifest:" -ForegroundColor Cyan
Remove-Item (Join-Path $outDir 'SHA256SUMS.txt') -ErrorAction SilentlyContinue
Get-ChildItem $outDir -File | ForEach-Object {
    $h = (Get-FileHash $_.FullName -Algorithm SHA256).Hash
    "{0}  {1}" -f $h, $_.Name | Tee-Object -FilePath (Join-Path $outDir 'SHA256SUMS.txt') -Append
} | Out-Null
Get-Content (Join-Path $outDir 'SHA256SUMS.txt')

# Zip (includes SHA256SUMS.txt)
if (-not $SkipZip)
{
    $zip = "$outDir.zip"
    if (Test-Path $zip) { Remove-Item $zip -Force }
    Compress-Archive -Path "$outDir\*" -DestinationPath $zip
    Write-Host "==> Zip created: $zip" -ForegroundColor Green
}
