<#
  collector.ps1 — on-device, per-app bandwidth sampler (Windows)
  -------------------------------------------------------------------
  Emits ONE compact JSON document on stdout:

    {
      "ts": <epoch seconds>,
      "adapter": [{ "name","rxBps","txBps" }],
      "apps": [{ "pid","name","category","color","rx","tx","conns" }]
    }

  Technique: Windows exposes per-interface byte counters but no public
  per-process byte counters, so we measure link throughput and distribute
  it across processes by connection weight (TCP established = 1.0,
  UDP = 0.35). Runs as the standard user — no elevation required.
#>
[CmdletBinding()]
param (
  [int]$DelayMs = 900
)

$ErrorActionPreference = 'SilentlyContinue'

function Get-AdapterThroughput {
  # sample twice, derive bytes/sec per adapter where possible
  $a = @{}
  $b = @{}
  Get-NetAdapterStatistics | ForEach-Object { $a[$_.Name] = @($_.ReceivedBytes, $_.SentBytes) }
  Start-Sleep -Milliseconds $DelayMs
  Get-NetAdapterStatistics | ForEach-Object { $b[$_.Name] = @($_.ReceivedBytes, $_.SentBytes) }

  $dt = $DelayMs / 1000.0
  $out = @()
  foreach ($name in $b.Keys) {
    if (-not $a.ContainsKey($name)) { continue }
    $rx = ($b[$name][0] - $a[$name][0]) / $dt
    $tx = ($b[$name][1] - $a[$name][1]) / $dt
    if ($rx -lt 0) { $rx = 0 }; if ($tx -lt 0) { $tx = 0 }
    $out += @{ name = $name; rxBps = [math]::Round($rx); txBps = [math]::Round($tx) }
  }
  , $out
}

function Get-ConnectionMap {
  # PID -> { name, weight, conns }  (PIDs normalized to [int]: Get-NetTCPConnection
  # returns UInt32 but Get-Process returns Int32, so raw hashtable lookup misses)
  $map = @{}
  Get-NetTCPConnection -State Established | ForEach-Object {
    $pid_ = [int]$_.OwningProcess
    if ($pid_ -gt 0) {
      if (-not $map.ContainsKey($pid_)) { $map[$pid_] = @{ name = ''; weight = 0.0; conns = 0 } }
      $map[$pid_].weight += 1.0      # TCP established
      $map[$pid_].conns += 1
    }
  }
  Get-NetUDPEndpoint | ForEach-Object {
    $pid_ = [int]$_.OwningProcess
    if ($pid_ -gt 0) {
      if (-not $map.ContainsKey($pid_)) { $map[$pid_] = @{ name = ''; weight = 0.0; conns = 0 } }
      $map[$pid_].weight += 0.35     # UDP
      $map[$pid_].conns += 1
    }
  }
  , $map
}

function Get-ProcessNameMap {
  $m = @{}
  Get-Process | ForEach-Object { $m[$_.Id] = $_.ProcessName }
  , $m
}

function Get-Category([string]$name) {
  $l = $name.ToLowerInvariant()
  if ($l -match 'chrom|firefox|edge|msedge|opera|brave|iexplore|browser') { return 'browser' }
  if ($l -match 'spotify|vlc|youtube|music|itunes|netflix|twitch|obs|wmplayer') { return 'streaming' }
  if ($l -match 'steam|epic|epicgames|games|valorant|league|minecraft|origin|blizzard|gog') { return 'gaming' }
  if ($l -match 'svchost|services|explorer|dwm|system|csrss|lsass|powershell|msmpeng|search|defender') { return 'system' }
  if ($l -match 'zoom|teams|slack|discord|skype|whatsapp|telegram|outlook') { return 'messaging' }
  return 'other'
}

function Get-Color([string]$cat) {
  switch ($cat) {
    'browser'   { '#4fc3f7' }
    'streaming' { '#7c4dff' }
    'gaming'    { '#fb7185' }
    'system'    { '#fbbf24' }
    'messaging' { '#34d399' }
    default     { '#8b96b8' }
  }
}

# --- pipeline ---------------------------------------------------------------
$ts = [int][double]::Parse((Get-Date -UFormat %s))
$adapters = Get-AdapterThroughput
$connMap  = Get-ConnectionMap
$procMap  = Get-ProcessNameMap
$totalW   = 0.0
$connMap.Values | ForEach-Object { $totalW += $_.weight }

$totRx = 0; $totTx = 0
$adapters | ForEach-Object { $totRx += $_.rxBps; $totTx += $_.txBps }

$apps = @()
foreach ($key in $connMap.Keys) {
  $e = $connMap[$key]
  $share = if ($totalW -gt 0) { $e.weight / $totalW } else { 0 }
  $procName = if ($procMap.ContainsKey($key)) { $procMap[$key] } else { $e.name }
  $cat = Get-Category $procName
  $apps += @{
    pid      = [int]$key
    name     = $procName
    category = $cat
    color    = Get-Color $cat
    rx       = [math]::Round($totRx * $share)
    tx       = [math]::Round($totTx * $share)
    conns    = $e.conns
  }
}

$apps = $apps | Sort-Object @{ Expression = { $_.rx + $_.tx } } -Descending
@{
  ts      = $ts
  totalRx = $totRx
  totalTx = $totTx
  adapters = @($adapters | Select-Object -First 6)
  apps    = @($apps | Select-Object -First 25)
} | ConvertTo-Json -Compress -Depth 4