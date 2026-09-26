# Build RansomLens portable single-file .exe (Windows).
# Produces dist\RansomLens.exe. Run at repository root.
$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Push-Location $root

try {
    python -m pip install -r requirements.txt --quiet
    if (-not $?) { throw "pip install failed" }

    python -m PyInstaller `
        --noconfirm `
        --clean `
        --onefile `
        --windowed `
        --name "RansomLens" `
        --paths "src" `
        --collect-all "workbench" `
        --exclude-module "matplotlib" `
        --exclude-module "PIL" `
        --exclude-module "scipy" `
        --exclude-module "numpy" `
        "src\run.py"

    if (-not $?) { throw "PyInstaller build failed" }

    $exe = Join-Path $root "dist\RansomLens.exe"
    if (Test-Path $exe) {
        $size = (Get-Item $exe).Length
        $hash = (Get-FileHash $exe -Algorithm SHA256).Hash
        Write-Host "BUILD OK"
        Write-Host "  exe : $exe"
        Write-Host ("  size: {0:N2} MB" -f ($size / 1MB))
        Write-Host "  sha : $hash"
    } else {
        throw "exe not produced"
    }
}
finally {
    Pop-Location
}