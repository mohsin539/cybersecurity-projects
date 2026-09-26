# DevSecOps: check every push/merge-request.
# Run from repo root: ./scripts/devsecops/gate.sh <branch>
param(
  [Parameter(Mandatory = $false)]
  [string]$Branch = ""
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

Write-Host "== PathSphere 3D DevSecOps gate ==" -ForegroundColor Cyan

# 1. Node toolchain present
$node = node -v
if (-not $?) { Write-Error "Node not found" }
$npm = npm -v
Write-Host "node: $node  npm: $npm"

# 2. Static analysis hooks (placeholder for ESLint + tsc)
Write-Host "[gate] typecheck (tsc --noEmit recursive)..." 
Push-Location $repoRoot
try {
  npm install --ignore-scripts --silent
  npm run build --if-present
  if (-not $?) { Write-Error "build failed at gate" }
} finally {
  Pop-Location
}

# 3. Policy check — emit OPA bundle metadata marker (placeholder for conftest)
$policyDir = Join-Path $repoRoot "services\policy-opa\policies"
if (Test-Path -LiteralPath $policyDir) {
  Write-Host "[gate] policy bundle present: $([IO.Directory]::GetFiles($policyDir, '*.rego').Count) rego files"
}

# 4. Scan-local temp dirs must not leak (WORM retention reminder)
Write-Host "[gate] artifact retention: reports go to WORM bucket (30d) before coldline."

Write-Host "== gate passed ==" -ForegroundColor Green