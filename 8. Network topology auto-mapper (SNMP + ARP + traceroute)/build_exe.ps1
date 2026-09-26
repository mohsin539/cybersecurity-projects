# Build a single-file Windows executable (PyInstaller) for the NTM API + UI.
# Run from repo root. Output: dist\ntm.exe with data/ + ui/ packaged alongside.

$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot

$py = "python"
if (Test-Path ".venv\Scripts\python.exe") { $py = ".venv\Scripts\python.exe" }

& $py -m pip install -q --disable-pip-version-check pyinstaller
if ($LASTEXITCODE -ne 0) { throw "pyinstaller install failed" }

# Collect the packaged entrypoint. We ship the API directly (app.main:app) and
# bundle the static UI so the exe is self-contained offline.
$pyArgs = @(
  "-X", "utf8",
  "-m", "PyInstaller",
  "--noconfirm", "--clean", "--onefile", "--name", "ntm",
  "--add-data", "app;app",
  "--add-data", "ui;ui",
  "--collect-all", "fastapi",
  "entry.py"
)
& $py @pyArgs
if ($LASTEXITCODE -ne 0) { throw "pyinstaller build failed" }

Write-Host "[ntm] built dist\ntm.exe"
if (Test-Path "dist\ntm.exe") {
  Write-Host "[ntm] size: $((Get-Item 'dist\ntm.exe').Length) bytes"
}
