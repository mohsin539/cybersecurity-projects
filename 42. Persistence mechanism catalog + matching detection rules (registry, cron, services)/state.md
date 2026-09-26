# 📌 PEM-CAT Project State — Reservation File

> **Reservation purpose:** captures *exactly where the project stands* so the next session (human or
> AI) resumes from a known, verified point. Companion to `architecture.md`, `security.md`, `memory.md`.

**Last updated:** 2026-09-20
**Version:** 1.0.0 (shipped)

---

## 1. What Exists (verified artifacts)

| Artifact | Path | Status |
|----------|------|--------|
| Architecture design | `architecture.md` (project root) | ✅ reviewed |
| Security posture | `security.md` (project root) | ✅ written |
| **Portable GUI app** | `app/dist/PEMCAT.exe` (≈ 30.6 MB, onefile, windowed) | ✅ built & launched |
| App source | `app/` (see inventory below) | ✅ code-complete v1 |
| Catalog test DB | `app/data_test/pemcat.db`, `app/data_exe/pemcat.db` | ✅ generated |
| Icon | `app/pemcat.ico` | ✅ bundled into exe |

### App source inventory (`app/`)

| File | Role | LOC (approx) |
|------|------|--------------|
| `main.py` | CLI entry: GUI launcher, `--headless`, `--data-dir` | 90 |
| `pemcat/catalog.py` | `Storage` SQLite layer, canonical fingerprint, allowlist, audit | 450 |
| `pemcat/collect.py` | Enumerators: registry (winreg), services (SCM keys), `schtasks`, cron (POSIX), startup folders, WMI (PowerShell) | 330 |
| `pemcat/rules.py` | Rule DSL evaluator + 9 built-in rules + matcher + summary | 240 |
| `pemcat/report.py` | `.xlsx` (openpyxl, 6 sheets), `.csv` bundle (5), `.html` (escaped) | 380 |
| `pemcat/ui.py` | Tkinter app: Dashboard/Catalog/Detections/Rules/Reports/Audit, worker queue | 470 |
| `pemcat/audit.py` | Audit event constants + `log()` | 30 |
| `build.bat`, `make_icon.py`, `PEMCAT.spec`, `README.txt` | build & docs | — |

---

## 2. Verified Behavior (measured 2026-09-20)

Run on **host `MOHSINIT-PC`** (Windows 11 26200, Python 3.12.7, openpyxl 3.1.5, PyInstaller 6.22.3):

| Check | Result |
|-------|--------|
| `python main.py --headless` (fresh DB) | 910 artifacts: registry 47 / scheduled_task 91 / service 771 / startup 1; baselined 8; 56 matches (high 55, medium 1) by T1053.005·T1547.001·T1543.003·T1546.002 |
| Second scan (dedup) | 0 new matches (dedup confirmed), baseline promoted to 854 (seen≥3) |
| GUI from source | 6 tabs render, KPIs populate, status bar shows counts + DB path |
| `dist/PEMCAT.exe --headless` | Writes fresh DB, resolves `PEMCAT_DATA_DIR` |
| `dist/PEMCAT.exe` (GUI) | Launched, stayed alive (pid verified), killed cleanly |
| Report exporters | `.xlsx` 127 KB / 5× `.csv` / `.html` 180 KB — all generated, HTML has no script tags (XSS guard in place) |
| WMI collector on this host | 0 (only legit `NTEventLogEventConsumer` present → skipped, *correct*) |

### Known behavior notes
- **WMI consumer discovery** was rewritten twice during this session (CIM `__RELPATH` not
  enumerable via `Select-Object`; final approach enumerates `__EventConsumer` class and keys on
  `CimSystemProperties.ClassName`). Do not regress to binding-based joins without re-testing.
- **`schtasks /query /fo LIST /v`** parse is locale-sensitive (`TaskName`/`Task To Run` keys).
  English-locale verified; non-English requires the block-parser key mapping update.
- **Baseline promotion** (`seen_count >= 3`) may hide genuinely new-but-similar artifacts; the
  `new_only` rule flag preserves that intent. Tune threshold in `catalog.BASELINE_SEEN_THRESHOLD`.

---

## 3. Commands (resume checklist)

```powershell
$env:PEMCAT_DATA_DIR = "D:\AI Masterclass\Project\18-09-2026\41. Persistence mechanism catalog + matching detection rules (registry, cron, services)\app\data_dev"

# run the engine headless (scan + match + summary)
python main.py --headless

# launch GUI
python main.py

# rebuild the portable exe (from app\)
.\build.bat
# or manually:
python -m PyInstaller --noconfirm --onefile --windowed --name PEMCAT --clean --icon pemcat.ico main.py

# sanity compile
python -m py_compile main.py pemcat\__init__.py pemcat\audit.py pemcat\catalog.py pemcat\collect.py pemcat\report.py pemcat\rules.py pemcat\ui.py
```

---

## 4. Open Items / Next Steps (priority)

| # | Item | Priority | Notes |
|---|------|----------|-------|
| O1 | Pin build deps (`requirements-build.txt`: pyinstaller, openpyxl, pillow + versions) | P1 | Prevent supply-chain drift |
| O2 | `PRAGMA journal_mode=WAL` + `foreign_keys=ON` | P1 | Crash-resilience; check `Storage._init_schema` |
| O3 | Non-English `schtasks` block-parser mapping | P2 | Localization |
| O4 | `.lnk` shortcut parsing (Shell Link) to resolve target in startup folders | P2 | Better T1547.009 fidelity |
| O5 | TI hash lookup integration (reserved interface in security.md) | P3 | Must gate egress (SSRF control) |
| O6 | Rule CI test corpus (`tests/` with replay of matches) | P3 | Rule store confidence |
| O7 | Portable "data-next-to-exe" mode toggle in UI settings | P3 | True off-box portability |
| O8 | `report_xlsx` Overview KPI-cell tidy (redundant font assignment near "Artifact distribution") | P4 | Cosmetic |
| O9 | Remove unreferenced `json/threading` deps in `ui.py` if linted later | P4 | Hygiene |

### Decisions locked this session (do not revisit without a reason)
1. **Storage = SQLite single file** (not server DB) to honor "portable".
2. **Rule store seeded from Python `BUILTIN_RULES`** into the `rules` table with UPSERT
   (`ON CONFLICT DO UPDATE`) so rule logic edits propagate on next launch.
3. **Match dedup**: a rule+fingerprint pair with an `open`/`acked` alert is not re-inserted; only
   `fp` / allowlisted states allow re-alert.
4. **GUI worker model**: background `threading.Thread` + `queue.Queue` consumed by `after(200)`
   poller — no `threading`-on-Tk calls.
5. **Report default folder** = user-chosen via `filedialog.askdirectory`; data dir configurable by
   `PEMCAT_DATA_DIR` env or `--data-dir`.

---

## 5. Fresh-DB Baseline Signature (regression beacon)

First run on `MOHSINIT-PC` produced exactly:
```
by_type    = {'registry': 47, 'scheduled_task': 91, 'service': 771, 'startup': 1}
by_sev     = {'high': 55, 'medium': 1}
by_techniq = {'T1053.005': 7, 'T1547.001': 18, 'T1546.002': 30, 'T1543.003': 1}
```

Use 56 total matches / 910 artifacts as a **delta check** when changing collectors or rules on the
same host. Expected drift: machine changes (installed apps → registry/svc counts vary).

---

*State reserved at PEM-CAT v1.0.0. Next session: start with the `run_headless` command above, then
check `#4 Open Items`.*