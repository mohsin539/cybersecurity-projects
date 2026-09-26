# 🧠 Memory — Continuity Notes for Future Sessions

Context reservoir for resuming work on **StaticLab** (and later the dynamic-sandbox half).
Read this first when picking this project back up.

---

## 1. One-paragraph mental model

`StaticLab` is the **static-analysis half** of the "Dynamic analysis sandbox" blueprint ([`architecture.md`](../architecture.md)). It is a **portable Windows GUI+CLI** that hashes, parses (PE headers/sections/imports/Rich header), extracts strings, optionally queries 4 threat-intel hash engines, computes a 0–100 verdict, exports reports (HTML/JSON/TXT), and logs every action into a **hash-chained HMAC-signed SQLite audit ledger**. It packs to a single ~12.6 MB `StaticLab.exe` via PyInstaller. Runtime deps are deliberately **stdlib + pefile only** for portability.

## 2. Terminal commands (remember these)

```powershell
# from the static-lab/ directory
python -m unittest discover -s tests -v      # verify, must be 12/12 OK
python -m app                                # GUI
python -m app --cli <FILE> --format json     # headless (progress -> stderr)
& .\build.ps1                                # rebuild portable exe
python -m app --cli <FILE> --format html > r.html  # sample report
```

## 3. Decisions & their rationale (do not silently revert)

| Decision | Rationale |
| :--- | :--- |
| stdlib + pefile only at runtime | tiny exe, offline, no dependency-pocalypse for users |
| Tkinter/ttk (no Qt/webview) | ships with CPython, PyInstaller-friendly, dark theme is custom |
| PyInstaller entry = `launcher.py`, `--collect-submodules app` | a bare `main.py` entry breaks relative imports when frozen |
| Cloud lookups are **hash-only** | never uploads samples; removes liability |
| API keys → DPAPI vault (`secrets.bin`), never config.json | fail-closed secrecy; kill-switch on non-Windows |
| Audit = SQLite + HMAC chain, not Ed25519/TSA | stdlib-only feasible now; parent arch uses TSA-HSM later |
| Progress prints → **stderr** in CLI | keeps stdout clean for `--format json` pipes |
| Unicode strings via 16-bit LE unit scan (both alignments) | GNU `strings -el` semantics; prevents ASCII-pollution artifacts |
| `is_driver` uses `0x1000` (`IMAGE_FILE_SYSTEM`) | `0x0002` is `IMAGE_FILE_EXECUTABLE_IMAGE` (earlier bug) |

## 4. Known gotchas (expensive to rediscover)

- PowerShell `>` + `2>$null` combined kills file output in PS 5.1; use `Start-Process -RedirectStandardOutput` for exe tests.
- `build.ps1` keeps `$ErrorActionPreference="Continue"` intentionally — native tools spam stderr; we check `$LASTEXITCODE`.
- `pefile.get_imphash()` returns `""` for zero-function imports (e.g. `python.exe`) → normalized to `None` → shows `-`.
- DPAPI (CryptProtectData) is current-user + machine bound; vaults do not move to other machines/users.
- Tk `after()` loop polls a `queue.Queue` from a worker thread — never touch Tk widgets off the main thread.

## 5. Conventions used

- Dataclass-heavy model (`model.py`); services are pure functions in `core/`.
- Reports are dataclass-serialized via `to_dict()`; HTML is rendered from an embedded template string (`report/template.py`) — **no external assets** → still works offline & when frozen.
- Verdict: score 0–100; thresholds 20/50/80 → Clean/Suspicious/Malicious/HC-Malicious; local heuristics cap at 70 so lookups can add up to +30.
- Every exported file and analysis append an audit entry (`action`, `target`, `detail`).

## 6. Next-session pointers (fresh eyes → 15 min on-ramp)

1. Read `architecture.md` §4, §8 (the design contract).
2. Read `security.md` §4–6 (threat + secrets + audit).
3. Run the four terminal commands in §2 to re-establish trust.
4. Pick a Backlog item in `state.md` §6; align TTP/IoC naming with MITRE ATT&CK for the dynamic half.

## 7. Dynamic-sandbox future module (reserved)

The parent architecture's **VM isolate + behavior logging** half will be added as `sandbox/` module:
- hypervisor adapters (Hyper-V/VirtualBox/QEMU), CoW snapshot discipline
- telemetry agents (process/file/registry/net/api/memory)
- MITRE ATT&CK TTP correlation + YARA/Sigma
- evidence bundle (`manifest.txt` + `signature.sig`) and REST layer
Porting notes: VM agents should write Parquet events; orchestrator language stays Python so `core/` can be shared.