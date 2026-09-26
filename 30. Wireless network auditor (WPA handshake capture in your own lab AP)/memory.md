# Project Memory - Wireless Network Auditor

Persistent context for the next session. Read before continuing work.

## Project map

```
root/
├─ main.py                  entry (GUI or --selftest)
├─ security.md              threat model, controls, crypto posture
├─ state.md                 snapshot of progress + verification log
├─ docs/architecture.html   reference architecture (colors + stack)
├─ build/
│  ├─ WirelessAuditor.spec  PyInstaller onefile spec (console=False)
│  └─ build.bat             selftest -> pip install -> PyInstaller
├─ dist/WirelessAuditor.exe shipped portable binary
└─ app/
   ├─ config.py             paths, version, repo root
   ├─ core/  scope.py, eapol.py, simulator.py, events.py, engine.py
   ├─ data/  crypto.py (AES-256-GCM+DPAPI), vault.py (SQLite), hashchain.py
   ├─ report/base.py, html_exporter.py, csv_exporter.py, xlsx_exporter.py, json_exporter.py
   └─ gui/   theme.py (colors), views.py (4 views), app.py (main window)
```

## Key decisions (do not silently reverse)

1. **Scope lock is in the engine**, not the UI. ScopeGuard is the single point
   that decides what may be recorded (OWASP A04).
2. **AES-256-GCM is mandatory** for storage; key wrapped by DPAPI on Windows,
   PBKDF2 fallback elsewhere (OAuth-free, no network egress).
3. **Evidence is sealed-then-logged**: every vault insert appends a SHA-256 link
   (data/hashchain.py) BEFORE the row write is visible.
4. **Zero third-party GUI deps**: Tkinter only; **XLSX is written by a minimal
   stdlib zipfile/XML exporter** in report/xlsx_exporter.py (openpyxl not used).
5. **Simulator is the default backend** so the app is demonstrable without a
   radio; live capture is designed to slot into engine.backend later.
6. **Lab-only**: no real AP scan, no deauth tooling shipped; capture is passive
   or lab-simulated in the interests of legal, authorized testing.

## Conventions

- Follow `app/gui/theme.py` color palette in any new UI (cyan/green/purple/amber accents on dark).
- Keep reports deterministic + offline (no remote assets) and HTML-escape all user strings.
- New findings go through engine `_tick()` and vault `add_finding()` so the flow stays observable.
- Console-safe ASCII output in CLI/CI paths (Windows cp1252) - do not print unicode glyphs to stdout.
- Use env var `WNA_DATA_DIR=<tmp>` to isolate selftests/GUI smoke tests from real data.

## Gotchas

- `EvidenceVault` uses one sqlite connection per thread via threading.local - never share a connection.
- PyInstaller: tkinter + cryptography hooks are auto; do NOT add unnecessary hidden imports.
- `record_eapol` dedupes at the engine level (`_recorded` / `_completed` sets), the table itself is append-only.
- selftest must exit 0 before any rebuild (`build.bat` enforces this).
- DPAPI-sealed keystore is user-bound: the vault won't open under a different Windows account.

## Verification commands

    python main.py --selftest
    python -c "import os,tempfile;os.environ['WNA_DATA_DIR']=tempfile.mkdtemp();import main;main.run_selftest()"

## Next session: pick up from state.md "Remaining" items.