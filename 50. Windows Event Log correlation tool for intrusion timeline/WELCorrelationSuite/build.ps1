$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

# Clean previous build artifacts
Remove-Item -Recurse -Force dist, build -ErrorAction SilentlyContinue
Remove-Item -Force *.spec -ErrorAction SilentlyContinue

# Preconditions
python --version
if (-not $?) { Write-Host "Python not found"; exit 1 }
python -c "import PyInstaller; print('PyInstaller', PyInstaller.__version__)"
if (-not $?) { Write-Host "PyInstaller not found - run: python -m pip install pyinstaller"; exit 1 }

python -m PyInstaller --noconfirm --clean --onefile --windowed `
  --name "WELIntrusionCorrelationSuite" `
  --add-data "app\web;web" `
  app\main.py
if (-not $?) { Write-Host "BUILD FAILED"; exit 1 }

$exe = "dist\WELIntrusionCorrelationSuite.exe"
if (Test-Path $exe) {
    $sz = (Get-Item $exe).Length
    $sha = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash
    Write-Host ("BUILD OK: {0} ({1:N1} MB)" -f $exe, ($sz / 1MB))
    Write-Host "SHA256: $sha"
    Set-Content -LiteralPath "$exe.sha256" -Value $sha
} else {
    Write-Host "BUILD FAILED (no exe produced)"
    exit 1
}