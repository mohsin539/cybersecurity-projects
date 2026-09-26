$ErrorActionPreference = "Stop"

Write-Host "=== PasswordGuardian portable build ==="

python -m pip install --upgrade pyinstaller

python -m PyInstaller --noconfirm --clean --onefile --windowed --name PasswordGuardian --add-data "data;data" main.py

if (Test-Path "dist\PasswordGuardian.exe") {
    Write-Host "DONE: dist\PasswordGuardian.exe"
    Read-Host "Press Enter to exit"
} else {
    Write-Error "Build failed - no dist\PasswordGuardian.exe produced"
    exit 1
}