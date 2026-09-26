#Requires -Version 5.1
<#
.SYNOPSIS
  Interactive manual-IP setup for Proxy Suite (C# service and/or Python edition).
.DESCRIPTION
  Lists this machine's network interfaces, lets you pick the proxy listen IP (or auto /
  all-interfaces), and writes config.json with a matching security.clients.allow list so
  LAN exposure stays restricted to your subnet.
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\set-my-ip.ps1                 # configure both
  powershell -ExecutionPolicy Bypass -File scripts\set-my-ip.ps1 -PythonOnly     # pyproxy only
  powershell -ExecutionPolicy Bypass -File scripts\set-my-ip.ps1 -Bind 192.168.1.20 -Allow 192.168.1.0/24
#>
param(
    [string]$Bind,
    [string]$Allow,
    [switch]$PythonOnly,
    [switch]$ServiceOnly
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

function Get-LanIPs {
    Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } |
        Sort-Object IPAddress |
        Select-Object IPAddress, InterfaceAlias
}

function Suggest-Allow($ip) {
    if (-not $ip) { return '' }
    if ($ip -like '192.168.*') { return ($ip -replace '\.\d+$', '.0/24') }
    if ($ip -like '10.*')      { return ($ip -replace '(\.\d+){2}$', '.0.0/16') }
    return $ip + '/32'
}

Write-Host ''
Write-Host '=== Proxy Suite - Manual Proxy IP Setup ===' -ForegroundColor Cyan
$ips = Get-LanIPs
if ($ips) {
    Write-Host ''
    Write-Host 'This machine''s IPv4 addresses:'
    $i = 0
    foreach ($n in $ips) {
        $i++
        Write-Host ("  [{0}] {1}  ({2})" -f $i, $n.IPAddress, $n.InterfaceAlias)
    }
}
else {
    Write-Host 'No LAN IPv4 addresses detected.' -ForegroundColor Yellow
}

$defaultAuto = 'auto'
if (-not $Bind) {
    Write-Host ''
    Write-Host 'Bind options:'
    Write-Host '  [1] auto        - pick my LAN IP automatically (recommended)'
    Write-Host '  [2] 127.0.0.1   - this PC only (loopback, default)'
    Write-Host '  [3] 0.0.0.0     - all interfaces (explicit open exposure)'
    Write-Host '  [4] type an IP  - e.g. 192.168.1.20'
    $sel = Read-Host 'Choose listen IP [1-4, default 1]'
    $Bind = switch ($sel) {
        '2' { '127.0.0.1' }
        '3' { '0.0.0.0' }
        '4' { (Read-Host 'Enter IP or hostname') }
        default { $defaultAuto }
    }
}

$allowSuggested = if ($Bind -eq 'auto' -or $ips -contains $Bind -or $ips.IPAddress -contains $Bind) {
    Suggest-Allow ($ips | Select-Object -First 1).IPAddress
} elseif ($Bind -eq '0.0.0.0') {
    Suggest-Allow ($ips | Select-Object -First 1).IPAddress
} else {
    Suggest-Allow $Bind
}

if (-not $Allow) {
    Write-Host ''
    Write-Host "Client allowlist: which devices may use this proxy?"
    Write-Host ("  Suggested for your subnet: {0}" -f $allowSuggested)
    Write-Host '  Enter a CIDR list (comma-separated), or press Enter to accept the suggestion.'
    Write-Host '  Type "open" to allow ALL clients (not recommended on Wi-Fi).'
    $inp = Read-Host 'Allow'
    if ($inp -eq 'open') { $Allow = '' }
    elseif ($inp) { $Allow = $inp }
    else { $Allow = $allowSuggested }
}

$allowList = @()
if ($Allow) {
    $allowList = ($Allow -split ',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
}

# Loopback must stay allowed or local apps (and the GUI) get locked out.
if ($allowList.Count -gt 0 -and -not ($allowList | Where-Object { $_ -match '^(127\.0\.0\.1(/32)?|localhost$)' })) {
    $allowList = @('127.0.0.1/32') + $allowList
}

$allowJson = if ($allowList.Count) {
    ($allowList | ForEach-Object { '"{0}"' -f $_ }) -join ', '
} else { '' }

Write-Host ''
Write-Host ("Selected bind: {0}   client allow: {1}" -f $Bind, ($(if ($allowList.Count) { $allowList -join ', ' } else { 'ALL (open)' }))) -ForegroundColor Green

function Write-ConfigJson($path, $isPython) {
    if (Test-Path $path) {
        try { $cfg = Get-Content $path -Raw | ConvertFrom-Json } catch {
            Write-Host "  [skip] $path is not valid JSON - fix it manually" -ForegroundColor Yellow
            return
        }
        $existingAllow = @($cfg.security.clients.allow | ForEach-Object { $_ })
        $hasClients = $null -ne $cfg.security.clients
    } else {
        $cfg = $null
        $existingAllow = @()
        $hasClients = $false
    }

    $allowArr = if ($allowList.Count) { $allowList } else { $existingAllow }
    $allowArrJson = if ($allowArr.Count) {
        ($allowArr | ForEach-Object { '"{0}"' -f $_ }) -join ', '
    } else { '' }

    if (-not $cfg) {
        # Start from the sample config shipped with the repo
        $src = if ($isPython) { Join-Path $root 'scripts\pyproxy\config.sample.json' } else { Join-Path $root 'dist\ProxySuite-Portable-win-x64\config.sample.json' }
        if (-not (Test-Path $src)) { $src = Join-Path $root 'dist\ProxySuite-Portable-win-x64\config.sample.json' }
        if (Test-Path $src) {
            $cfg = Get-Content $src -Raw | ConvertFrom-Json
        } else {
            Write-Host "  [warn] no sample config found for $path" -ForegroundColor Yellow
            return
        }
    }

    # Apply chosen bind
    $cfg.listeners.http.bind = $Bind
    $cfg.listeners.socks5.bind = $Bind

    # Apply allowlist
    if (-not $cfg.security) { $cfg.security = New-Object PSObject }
    if (-not $cfg.security.clients) {
        $cfg.security | Add-Member -NotePropertyName clients -NotePropertyValue (New-Object PSObject) -Force
    }
    if ($allowArr.Count) {
        $cfg.security.clients | Add-Member -NotePropertyName allow -NotePropertyValue @() -Force
        $cfg.security.clients.allow = @($allowArr)
    } else {
        if ($cfg.security.clients.PSObject.Properties['allow']) { $cfg.security.clients.allow = @() }
    }

    $json = $cfg | ConvertTo-Json -Depth 12
    # ConvertTo-Json escapes non-ASCII; fine for configs
    Set-Content -Path $path -Value $json -Encoding UTF8
    Write-Host ("  [ok] wrote {0}  (bind={1}, allow={2})" -f $path, $Bind, ($(if ($allowArr.Count) { $allowArr -join ',' } else { 'open' }))) -ForegroundColor Green
}

Write-Host ''
if (-not $PythonOnly) {
    Write-Host 'C# service (dist\...\config.json):'
    Write-ConfigJson -path (Join-Path $root 'dist\ProxySuite-Portable-win-x64\config.json') -isPython $false
}
if (-not $ServiceOnly) {
    Write-Host 'Python edition (scripts\pyproxy\config.json):'
    Write-ConfigJson -path (Join-Path $root 'scripts\pyproxy\config.json') -isPython $true
}
