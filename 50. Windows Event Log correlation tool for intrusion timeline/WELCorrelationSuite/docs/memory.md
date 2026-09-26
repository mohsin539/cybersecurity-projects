# Project Memory

Persistent memory for the agent and future maintainers of the
**Windows Event Log Intrusion Correlation Suite**. Update this file whenever project
knowledge changes (new versions, new modules, environment drift, discovered gotchas).

---

## 1. Identity

- **Product:** WEL Intrusion Correlation Suite — portable Windows Event Log correlation tool
  for intrusion timeline / attack reconstruction.
- **Version:** 1.0.0
- **Stack:** Python 3.12.7, stdlib only (no third-party runtime deps)
- **Distribution:** single-file `.exe` built with PyInstaller 6.22.3
- **Working dir:** `D:\AI Masterclass\Project\18-09-2026\50. Windows Event Log correlation tool for intrusion timeline\WELCorrelationSuite`
- **Tool name (frozen):** `WELIntrusionCorrelationSuite.exe` (~8.9 MB)
- **Latest build SHA-256:** `1559C35AC56034EA14F84F7A4C63102CC621AD70179489A3A572C0F13782F938`
  (written to `dist\WELIntrusionCorrelationSuite.exe.sha256`)

## 2. Current status (as of last session)

- **Engine tests:** 30/30 PASS — "ENGINE TESTS: ALL GREEN"
- **HTTP smoke tests:** 28/28 PASS — "SERVER TESTS: ALL GREEN"
- **Frozen exe smoke tests:** 10/10 PASS — "EXE SMOKE: ALL GREEN"
- All deliverables complete, incl. docs (architecture/security/user-guide + security-compliance,
  README), sample report, build script.

## 3. Running & rebuilding

```powershell
# Run from source (console mode -> workspace data dir):
python app\main.py

# Optional fixed URL for automation:
$env:WELICS_PORT = 8765; $env:WELICS_TOKEN = "0123456789abcdef0123456789abcdef"; python app\main.py

# Rebuild the exe (needs: pip install pyinstaller):
.\build.ps1

# Verify:
python tests\run_tests.py
python tests\server_smoke.py
python tests\exe_smoke.py          # requires a fresh dist build first
```

## 4. Environment facts

- Python 3.12.7 at `C:\Users\mohsi\AppData\Local\Programs\Python\Python312`
- PyInstaller 6.22.3
- Node available (v24.20.0) — used for `node --check app\web\app.js` syntax verification
- .NET 9.0.300 + `csc.exe` available on the box (not used by this project)
- PowerShell 5.1 is the shell. Prefer full cmdlets; backtick is escape char.

## 5. Key architecture decisions (why)

- **Native `wevtutil` subprocess, no pywin32** → portable, zero deps, no admin rights.
- **Loopback-only web UI** instead of CLI → analyst-friendly, but hardened (token gate, CSP).
- **Pure stdlib** → the exe is small (~9 MB) and reproducible anywhere.
- **Aggressive self-termination** (30 min idle) + `os._exit(0)` in frozen mode → hygiene for a
  portable forensic tool. Windowed bootloaders otherwise linger after shutdown.
- **Hash-chained JSONL audit** → reproducible, append-only, tamper-evident chain of custody.
- **Snapshot of test data lives in `tests/data/case_guest.json`** (37 events / 41 incidents /
  9 phases) — the exe smoke test relies on it.

## 6. Gotchas & hard-won lessons (read before editing)

1. **PyInstaller runs `main.py` as a top-level script** → relative imports crash at runtime
   (`ImportError: attempted relative import with no known parent package`).
   Fix pattern in `app/main.py`:
   `if __package__ is None: sys.path.insert(0, <repo root>); from app... else: from . ...`
2. **`--windowed` (no console) hides all errors.** If the frozen app fails mysteriously, build a
   `--console` variant or read `welics_case_data\_startup.log` (written by `main.py` on error).
   Diagnosing this bug: the exe showed a *responsive, idle, listener-free* process — symptom of a
   stuck runw bootloader after a failed script, not a hang in our code.
3. **Leftover exe processes lock the build.** If `build.ps1` fails with `PermissionError` on the
   exe, run `Stop-Process -Name WELIntrusionCorrelationSuite -Force` first. The smoke test leaves
   zombies when it aborts early — always terminate the spawned process in `finally`.
4. **`--add-data "app\web;web"`** → assets land at `_MEIPASS/web/*`, and `resource_path("web")`
   in `main.py` must match. (If you change dest to `app/web`, update `resource_path`.)
5. **Every py file can be large; Write tool truncates big payloads** → write big files in chunks
   (write then edit-append). Keep per-file writes under a few thousand lines.
6. **`audit_trail.jsonl` persists between test runs.** Tests reset the trail dir first; if an old
   buggy entry exists, `verify()` correctly fails the chain — that's a *feature*, not a bug.
7. **JSON import contract:** POST the raw JSON array/export text as the request body with
   `Content-Type: application/json`. Wrapping in `{"content": ...}` yields `imported: 0`.
   Multipart upload should use `name="file"` + a `text/plain` content type per part
   (the parser extracts the first `text/plain` part with a filename).
8. **`/api/audit` returns `{entries: [...], stats: {...}}`** — count is `stats.entries`, or
   `len(entries)`; `entries > 0` is a bug in any consumer.
9. **Operators** in rule `opts`: `~x` contains / `!x` not-equal / `>n` `<n` numeric / bare literal
   exact. `!` alone means "field is empty".
10. **Test buttons**: engine `run_tests.py` must be run from the repo root because it imports
    `app.*` and reads `tests/data`.

## 7. Module & file map (with roles)

```
app/main.py            entrypoint: bootstrap, watchdog, browser, os._exit(frozen)
app/server.py          AppServer + Handler + Case + REST API + static + headers
app/events.py          ingestion: live/importer + XML/CSV/JSON parse + normalize + hash
app/rules.py           Rule engine + match_op
app/rules_registry.py  40 rules (R-001..R-040), MITRE/ISO/NIST-tagged
app/correlate.py       analyse(): clusters, spikes, phases, mitre matrix, risk
app/compliance.py      ISO27001/NIST/OWASP maps + coverage_matrix + tool compliance
app/audit.py           AuditTrail JSONL chain + artefact_hash + sidecar writer
app/report.py          html_report + csv_events + csv_timeline + json_case
app/web/index.html     dashboard shell
app/web/style.css      cyber theme
app/web/app.js         SPA logic
tests/run_tests.py     engine suite (30 checks)
tests/server_smoke.py  HTTP suite (28 checks)
tests/exe_smoke.py     .exe suite (10 checks)
tests/make_dataset.py  synthetic case generator → tests/data/case_guest.json
tests/make_sample_report.py → samples/intrusion_report_sample.html
build.ps1              PyInstaller single-file build
docs/architecture.md   code-free design reference
docs/security.md       security & threat-model reference
docs/SECURITY_COMPLIANCE.md  framework mapping detail
docs/USER_GUIDE.md     operator guide
README.md              top-level summary
```

## 8. Test dataset facts

- `tests/data/case_guest.json`: synthetic guest scenario, **37 events**, kill-chain across all
  9 phases, produces **41 incidents**, risk ~100/100 for that scenario.

## 9. Conventions

- No comments added to code unless the task explicitly asks (repo guideline). Docstrings are
  used at module/function heads.
- No emoji in files unless requested.
- Minimal dependency policy: stdlib++ only; anything added must be justified in
  `docs/architecture.md` and this file.
- Test assertions are printed as `PASS <name>` / `FAIL <name>` lines; suites print a final
  `x/y passed` + banner line. Keep that convention so greps stay simple.

## 10. Backlog / open items

- (none known as of last session) — all planned milestones shipped and green.
- If a future session extends rules beyond 40, update README + docs/architecture claims and the
  compliance coverage table knob (`rules_registry` only).
- Consider an optional `--open-browser/--no-browser` flag for fully headless CI use.