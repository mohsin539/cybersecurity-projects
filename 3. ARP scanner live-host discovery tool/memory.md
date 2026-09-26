# Memory — ARP Live-Host Discovery Tool

**Doc purpose:** long-lived project memory for future sessions. Read this first
before touching the repo. It captures conventions, environment quirks, command
cheatsheets, security invariants, and pointers. Companion: `state.md` (status &
reservations), `security.md` (control mappings), `archetecture.md` (design).

---

## 1. Environment At-a-Glance

- **OS:** Windows (win32) · Shell: **PowerShell 5.1**
- **Python:** 3.12.7 at `C:\Users\mohsi\AppData\Local\Programs\Python\Python312`
  — **NOT** on PATH. Always use the `py` launcher: `py -3.12`.
- **Project dir has spaces:** `D:\AI Masterclass\Project\3. ARP scanner live-host discovery tool`
  → always quote paths in PowerShell.
- **Npcap:** installed and the service is running (required at runtime for raw L2).
- **Raw L2 access needs Administrator** — the dev shell is **not** elevated;
  expect `PermissionDenied "exit code 3"` style errors in non-elevated tests.

---

## 2. Command Cheatsheet (PowerShell)

```powershell
# activate dev venv
.\.venv\Scripts\Activate.ps1

# run the GUI from source
python run_app.py
python -m arp_scanner

# run tests  (NOTE: use file-redirect pattern below, not bare piping)
python -m pytest -p no:cacheprovider

# build the exe (creates .venv_build, installs, runs pyinstaller)
.\build_exe.bat
# artifact: dist\ArpScanner\ArpScanner.exe

# rebuild spec-only (fast path after code changes)
.\.venv_build\Scripts\python.exe -m PyInstaller --noconfirm --clean arp_scanner.spec
```

## 3. PowerShell Quirks You WILL Hit (learned, required)

1. **Native stderr pipes can stall forever.** `python ... 2>&1 | Select-Object`
   hung the shell. **Use:** `Start-Process ... -RedirectStandardOutput/-Error` +
   `WaitForExit(timeout)` + kill-on-timeout. See example below.
2. **Argument quoting is fragile** with `-ArgumentList` (semicolons/quotes get
   mangled). Prefer writing a temp `.py`/`.bat` file, or use `-EncodedCommand`.
3. **No `&&` chains** — use `;` and PowerShell conditionals.
4. **`python` resolves to the Microsoft Store stub** — never use bare `python`.
5. Multi-line Python in `-c` breaks; use script files (`tests/_*.py`, `scripts/`).

### Reliable process-run pattern

```powershell
$p = Start-Process -FilePath ".\.venv\Scripts\python.exe" `
  -ArgumentList "tests\test_probe.py" -NoNewWindow `
  -RedirectStandardOutput "$env:TEMP\o.txt" -RedirectStandardError "$env:TEMP\e.txt" -PassThru
if (-not $p.WaitForExit(60000)) { $p.Kill(); Write-Output "HUNG" } else { Write-Output "exit=$($p.ExitCode)" }
Get-Content "$env:TEMP\o.txt"; Get-Content "$env:TEMP\e.txt"
```

---

## 4. Key Files & Responsibilities (do not rename without updating docs)

| File | Role |
|---|---|
| `arp_scanner/app.py` | Qt entry; consent gate; Fusion style; crash excepthook |
| `arp_scanner/gui/main_window.py` | MainWindow (form/table/progress/audit/export/menus) |
| `arp_scanner/gui/scan_worker.py` | `ScanWorker(QObject)` moved to QThread; emits `progress/host_found/scan_finished/scan_error/audit` |
| `arp_scanner/core/engine.py` | `run_scan`, interface resolution (psutil↔scapy), large-scan guard |
| `arp_scanner/core/sender.py` | Burst-send + `AsyncSniffer` capture; returns `{ip: (mac, rtt_ms)}` |
| `arp_scanner/core/packets.py` | ARP who-has build / is-at parse |
| `arp_scanner/core/result.py` | `HostInfo`, `ScanResult`, aggregation |
| `arp_scanner/core/devices.py` | Curated OUI table + `lookup_vendor()` |
| `arp_scanner/core/config.py` | `ScannerConfig` + `build_config` |
| `arp_scanner/util/net.py` | `expand_target`, `normalize_mac`, `oui_prefix`, reserved-host logic |
| `arp_scanner/security/guard.py` | Consent, `check_privileges`, `sanitize_cell`, `validate_export_path`, `audit` |
| `arp_scanner/report/exporters.py` | CSV/JSON generation + atomic `write_export` |
| `tests/` | 59 pytest cases (net, packets, config, export, guard, devices) |
| `scripts/` | Dev smoke scripts (`_gui_smoke.py`, `_scan_probe.py`, `_smoke_imports.py`) |
| `arp_scanner.spec`, `build_exe.bat` | PyInstaller packaging |
| `archetecture.md`/`security.md`/`state.md`/`memory.md` | Reference docs (canonical) |

---

## 5. Security Invariants — NEVER break (see `security.md`)

1. **Never auto-elevate.** Privilege is checked, guidance shown, operator elevates.
2. **No network egress beyond ARP** on the operator-selected interface/segment.
3. **No secrets or PII** in code, logs, or exports.
4. **All external input validated**: targets (regex+size caps), export paths,
   MACs. **No eval/exec of input.**
5. **CSV cells sanitized** against formula injection before writing.
6. **Exports are atomic** (tempfile in same dir + `os.replace`).
7. **Every security-relevant action is audit-logged** (UTC, PID).
8. **Results are ephemeral**; exports are operator-owned and sensitive.
9. Build artifacts reproducible from pinned deps (`build_exe.bat`).
10. Consent gate stays mandatory on first use.

---

## 6. Conventions

- Python 3.10+ syntax; `from __future__ import annotations` on modules; dataclasses with `slots=True` where hot.
- scapy imports are **lazy** (inside functions) — keeps GUI cold start fast.
- Logging to **stderr** only (`util/log.py`); stdout reserved for piped results.
- Exceptions: domain-specific (`TargetError`, `ScanError`, `ConfigError`, `PermissionDenied`, `SenderError`) — keep granular.
- Dataclass `HostInfo`/`ScanResult` are `frozen`; results sorted by IP at read time.
- Interface flow: psutil friendly-name (GUI/config) → `resolve_interface()` → scapy device name (runtime).
- Test files: `tests/test_*.py`; smoke scripts start with `_` so pytest skips them (they live in `scripts/`).
- Docs: 2 spaces after sentence-newline not required; keep tables tight; update `state.md` on ANY status/reservation change.

---

## 7. Recurring Facts Worth Remembering

- **Total scan wall-time ≈ timeout (not host count)** because all who-has frames
  are sent first, then one capture window elapses. `retries` multiplies rounds.
- Windows interface names differ **between psutil and scapy/Npcap**; this was
  the leading integration risk — `resolve_interface()` is the single chokepoint.
- `consent.v1` / `audit.log` / `crash.log` live in `%APPDATA%\ArpScanner` at runtime.
- The built exe was verified to **start** (offscreen) and write a correct UTC
  audit entry. A **live elevated scan** remains the top validation to run.
- PyInstaller warnings about missing Qt SQL/QML DLLs are **expected & harmless**
  (we use QtWidgets only; the spec explicitly excludes WebEngine/QML).

---

## 8. Useful Snippets

```python
# resolve config once, scan once, get result dict
from arp_scanner.core.config import build_config
from arp_scanner.core.engine import run_scan
cfg = build_config(target="192.168.1.0/24", interface="auto", timeout=1.0, retries=1)
res = run_scan(cfg)
print(res.to_dict()["hosts"])
```

```powershell
# run GUI smoke test headlessly
$env:QT_QPA_PLATFORM="offscreen"
python scripts\_gui_smoke.py
```

---