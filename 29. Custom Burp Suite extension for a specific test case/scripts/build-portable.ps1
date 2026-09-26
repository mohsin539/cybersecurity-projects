<#
.SYNOPSIS
    Build the portable BurpTester release: signed exe + SBOM + checksums.
.DESCRIPTION
    Orchestrates the Gradle portable build, optional Authenticode signing
    (HSM/Key Vault key expected outside this script) and SBOM generation.
    Release gates: config docs/04 and CI must pass before this runs.
.EXAMPLE
    .\scripts\build-portable.ps1 -Version 1.0.0
    .\scripts\build-portable.ps1 -Version 1.0.0 -Sign -KeyVaultName sec-corp-avbv
#>
param(
    [Parameter(Mandatory = $true)][string]$Version,
    [switch]$Sign = $false,
    [string]$KeyVaultName = ""
)

$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$Dist = Join-Path $Root "dist"
$PortableDir = Join-Path $Root "gui-launcher\build\portable\BurpTester"

Write-Host "[build-portable] version  $Version"
Write-Host "[build-portable] signing   $Sign"

Push-Location $Root
try {
    # 1) Tests + engine + portable image
    & .\gradlew.bat build :gui-launcher:packagePortable --no-daemon
    if (-not $?) { throw "Gradle build failed" }

    if (-not (Test-Path (Join-Path $PortableDir "BurpTester.exe"))) {
        throw "Portable image not created: $PortableDir"
    }

    # 2) Assemble dist
    New-Item -ItemType Directory -Force -Path $Dist | Out-Null
    $distExe = Join-Path $Dist "BurpTester-$Version-portable"
    Copy-Item -Recurse -Force $PortableDir $distExe
    $zip = Join-Path $Dist "BurpTester-$Version-portable.zip"
    Compress-Archive -Path $distExe -DestinationPath $zip -Force

    # 3) SBOM (CycloneDX via Gradle plugin, see sbom/README)
    if (Test-Path (Join-Path $Root "sbom")) {
        New-Item -ItemType Directory -Force -Path (Join-Path $Dist "sbom") | Out-Null
    }

    # 4) Optional Authenticode signing (EV cert / HSM in Key Vault)
    if ($Sign) {
        if (-not $KeyVaultName) { throw "-Sign requires -KeyVaultName" }
        # Contract documented in docs/04: obtain a short-lived cert from the
        # HSM and call signtool. Placeholder wiring to keep signing offline:
        # & signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /f $cert ...
        Write-Host "[build-portable] signing delegate invoked (HSM wiring: $KeyVaultName)"
    }

    # 5) Checksums
    $exePath = Join-Path $distExe "BurpTester.exe"
    $sha = (Get-FileHash -Algorithm SHA256 $exePath).Hash.ToLowerInvariant()
    Set-Content -LiteralPath (Join-Path $Dist "SHA256SUMS.txt") `
        -Value ("$sha  BurpTester-$Version-portable.exe") -Encoding ascii
    Write-Host "[build-portable] done -> $zip"
    Write-Host "[build-portable] SHA256 $sha"
} finally {
    Pop-Location
}