$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Push-Location $root
Write-Host "=== Building portable .exe ==="
py -m PyInstaller --noconfirm --clean --onefile --console --specpath . `
    --name CustomChainPackDemo `
    --paths scripts `
    --add-data "etc;etc" `
    --add-data "tests;tests" `
    --add-data "scripts;scripts" `
    --add-data "pack.yaml;." `
    main.py
if ($LASTEXITCODE -ne 0) {
    Write-Host "BUILD FAILED: $LASTEXITCODE"
    Pop-Location; exit $LASTEXITCODE
}
$exe = Join-Path $root "dist\CustomChainPackDemo.exe"
if (Test-Path $exe) {
    $release = Join-Path $root "release"
    New-Item -ItemType Directory -Force -Path $release | Out-Null
    Copy-Item $exe -Destination $release -Force
    Write-Host "=== DONE ==="
    Write-Host "Portable exe : $release\CustomChainPackDemo.exe"
    Write-Host "Size          : $([math]::Round((Get-Item $release\CustomChainPackDemo.exe).Length/1MB,1)) MB"
} else {
    Write-Host "EXE NOT FOUND"
    Pop-Location; exit 1
}
Pop-Location
