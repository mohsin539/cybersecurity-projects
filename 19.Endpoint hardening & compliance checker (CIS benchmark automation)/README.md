# CISGuard

Portable Windows GUI endpoint-hardening & CIS Benchmark compliance checker.
**Read-only assessment** — nothing on the endpoint is ever changed; remediation
is advisory only.

## Usage

### Portable exe (Windows)

Run `dist\CISGuard\CISGuard.exe` (the whole `CISGuard` folder is the app —
never copy just the `.exe`; it needs its `_internal` directory beside it).

- **GUI** — double-click to run a scan and view/export findings.
- **Headless CLI** — from PowerShell:

```powershell
.\CISGuard.exe --cli --data-dir "%USERPROFILE%\CISGuard" scan --out report
.\CISGuard.exe --cli --demo scan                       # offline sample data
.\CISGuard.exe --cli history                            # past scans
```

Reports are written as `report.html` / `report.json` / `report.csv`.
History lives in `--data-dir\history.db`. A clean scan exit code is `0`;
non-zero means findings (use it for automation gates).

### From source (dev)

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
pytest tests               # release gate
python src\cisguard\gui\main_window.py   # or: cisguard --help
```

## Building the portable exe

Requires PySide6 + PyInstaller in the venv (`pip install -e ".[dev]"`).

```powershell
powershell -ExecutionPolicy Bypass -File scripts\build.ps1
# or, on bash/CI:
bash scripts/build_exe.sh
```

The build runs the test suite, builds `dist\CISGuard\CISGuard.exe`, verifies the
Qt platform plugins are bundled, runs a headless smoke scan, and produces
`dist\CISGuard-<version>-portable.zip`.

## Notes for packagers

- Onedir (not onefile): `portable.spec` collects the PySide6 Qt plugins
  (`platforms`, `styles`, `imageformats`, `iconengines`, ...) explicitly under
  `datas`. Without `plugins\platforms\qwindows.dll` the frozen GUI exits
  silently with *"no Qt platform plugin could be initialized"*.
- `console=False`: the GUI has no console. Use `--cli` for automation.
- No UPX (AV false positives); assessment only ever calls read-only APIs
  (`winreg` reads, `sc query/qc`, `auditpol /get`, `Get-MpPreference`, ...).

## Security posture

- Strictly read-only; command argv comes from a fixed whitelist in the domain
  catalog (`INV-2`/`INV-3`), timeouts and output caps apply.
- HTML reports are self-contained and CSP-locked; JSON is SIEM-ready.
- Data dir and reports hold host-specific evidence — protect accordingly.