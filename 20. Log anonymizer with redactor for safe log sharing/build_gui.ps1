# Builds the Log Anonymizer desktop .exe with PyInstaller (one-command build).
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

Write-Host "==> Installing build requirements" -ForegroundColor Cyan
py -m pip install --quiet pyinstaller cryptography 2>$null

Write-Host "==> Verifying the engine test suite" -ForegroundColor Cyan
py -m ruff check src tests; if (-not $?) { throw "ruff check failed" }
py -m pytest tests -q; if (-not $?) { throw "pytest failed" }

Write-Host "==> Building .exe" -ForegroundColor Cyan
pyinstaller --noconfirm --clean anonymizer_gui.spec
if (-not $?) { throw "pyinstaller failed" }

$exe = Join-Path $root "dist\LogAnonymizer.exe"
if (Test-Path $exe) {
    Write-Host "SUCCESS: $exe" -ForegroundColor Green
} else {
    throw "expected $exe not found"
}