# TTPProfiler — Portable self-contained .exe builder (Windows 10/11 x64)
# Primary: Nuitka (better size/perf). Fallback: PyInstaller.
# After building, sign with an EV Authenticode cert and publish the SHA-256.
param(
    [ValidateSet("nuitka","pyinstaller")] [string]$Builder = "nuitka",
    [switch]$NoUpx,
    [switch]$Sign,
    [string]$CertThumbprint = ""
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

$Version = "1.0.0"
$OutDir = Join-Path $Root "dist"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$ExePath = Join-Path $OutDir "TTPProfiler.exe"

# ----- dependencies ---------------------------------------------------------
pip install -r requirements.txt --quiet
if ($Builder -eq "nuitka") {
    pip install nuitka --quiet
}

# ----- build -----------------------------------------------------------------
if ($Builder -eq "nuitka") {
    $args = @(
        "--standalone","--onefile","--enable-plugin=pyside6",
        "--windows-console-mode=disable","--mingw64",
        "--output-dir=$OutDir","--output-filename=TTPProfiler.exe",
        "--company-name=TTPProfiler","--product-name=Threat Actor TTP Profiler",
        "--file-description=MITRE ATT&CK TTP profiler — portable",
        "--file-version=$Version","--product-version=$Version",
        "main.py"
    )
    if (-not $NoUpx) { $args += "--enable-plugin=upx" }
    & python -m nuitka @args
    if ($LASTEXITCODE -ne 0) { throw "Nuitka build failed" }
} else {
    pip install pyinstaller --quiet
    & pyinstaller --noconfirm --onefile --windowed --name TTPProfiler `
        --hidden-import=PySide6 --collect-all PySide6 `
        --strip ` main.py
    if ($LASTEXITCODE -ne 0) { throw "PyInstaller build failed" }
    $ExePath = Join-Path $Root "dist\TTPProfiler.exe"
}

# ----- integrity manifest ------------------------------------------------------
$hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $ExePath).Hash.ToLower()
$manifest = @{
    product = "Threat Actor TTP Profiler"
    version = $Version
    builder = $Builder
    built_at = (Get-Date -AsUTC -Format "o")
    sha256 = $hash
    size_bytes = (Get-Item -LiteralPath $ExePath).Length
} | ConvertTo-Json
$manifest | Out-File -Encoding utf8 (Join-Path $OutDir "TTPProfiler.sha256.json")

# ----- optional Authenticode signing -------------------------------------------
if ($Sign) {
    if ($CertThumbprint -eq "") { throw "Provide -CertThumbprint when using -Sign" }
    & signtool sign /fd SHA256 /sha1 $CertThumbprint /tr http://timestamp.digicert.com `
        /td SHA256 /v $ExePath
    if ($LASTEXITCODE -ne 0) { throw "Signing failed" }
    Write-Host "Signed: $ExePath"
}

Write-Host "Built: $ExePath"
Write-Host "SHA-256: $hash"
Write-Host "Manifest: $OutDir\TTPProfiler.sha256.json"