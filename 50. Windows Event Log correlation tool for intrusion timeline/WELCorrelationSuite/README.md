# Windows Event Log Intrusion Correlation Suite

Portable, single-file, **local-first** Windows Event Log correlation tool that builds an
**intrusion/attack timeline** in seconds and exports tamper-evident, auditable reports.

Fully offline. No cloud, no telemetry, no third-party runtime dependencies — it shells out to the
native `wevtutil.exe` that ships with Windows.

---

## What it does

1. **Ingest** — collect live Event Log channels via `wevtutil`, or import forensic `.evtx`,
   CSV (Sysmon-friendly column aliasing) and JSON exports.
2. **Normalize** — every event gets a stable shape (`ts`, `channel`, `event_id`, users, IPs,
   process, commandline, raw `data`, SHA-256 evidence fingerprint).
3. **Correlate** — 40 rule pack (MITRE ATT&CK technique mapping) detects kill-chain behaviour:
   credential theft, lateral movement, persistence, defense evasion, discovery, escalation, impact.
4. **Timeline** — events are bucketed into the 9-stage intrusion timeline with phase banding,
   intel-cluster detection and activity surge windows.
5. **Comply** — built-in controls mapped to **ISO/IEC 27001**, **NIST CSF** and **OWASP Top 10 (2021)**.
6. **Report** — download an executive HTML report (risk gauge, phase band, MITRE heat grid,
   campaign clusters, compliance matrices, full audit chain) plus CSV/JSON case exports with
   SHA-256 integrity sidecars.

## Security posture

- Serves a hardened UI on **127.0.0.1 only**, on a random port, behind a single-use session token.
- Strict CSP / `X-Content-Type-Options` / download headers · path-traversal guard · 100 MB upload cap.
- Every action (start, collect, import, analyze, report download, denied requests, shutdown)
  is appended to an **append-only, hash-chained audit trail** (JSONL with SHA-256 chain).
- UI can be run from a **portable `.exe`** with no admin rights and no installation.

See `docs/architecture.md` (design reference), `docs/security.md` (threat model),
`docs/SECURITY_COMPLIANCE.md` (framework mapping), `docs/USER_GUIDE.md` (usage) and
`docs/memory.md` (agent/developer memory) for details.

## Quick start

### Portable exe (recommended for responders)

```
dist\WELIntrusionCorrelationSuite.exe
```

Runs from anywhere (USB stick, analysis box). A browser tab opens to the local dashboard.
Idle for 30 minutes and it exits cleanly itself. Session/audit data lands next to the exe in
`welics_case_data\`.

Optional automation overrides (env vars): `WELICS_PORT` and `WELICS_TOKEN`.

### From source

Requires Python 3.9+ (no third-party packages).

```powershell
python app\main.py
# or, for a fixed URL during debugging:
$env:WELICS_PORT = 8765; $env:WELICS_TOKEN = "0123456789abcdef0123456789abcdef"
python app\main.py
```

### Build the exe

```powershell
.\build.ps1          # requires: pip install pyinstaller
```

Produces `dist\WELIntrusionCorrelationSuite.exe` (~9 MB) plus a `.sha256` manifest.

## Test suite

```powershell
python tests\run_tests.py        # engine: ingestion, rules, correlation, reports, audit chain
python tests\server_smoke.py     # live HTTP server + REST + downloads
python tests\exe_smoke.py        # frozen .exe end-to-end (build first)
```

## Project layout

```
app/
  main.py            entrypoint (portable bootstrap, idle watchdog, browser launch)
  server.py          hardened localhost HTTPServer + REST API + report/export endpoints
  events.py          wevtutil collection, evtx/csv/json import, normalization
  rules_registry.py  40 detection rules, MITRE-mapped (R-001..R-040)
  rules.py           rule engine + match operators
  correlate.py       timeline phases, intel clusters, spikes, risk scoring, MITRE matrix
  compliance.py      ISO 27001 / NIST CSF / OWASP Top 10 mappings + coverage
  audit.py           hash-chained append-only audit trail
  report.py          HTML executive report + CSV/JSON export generators
  web/               dashboard UI (index.html, style.css, app.js) - zero dependencies
tests/               engine, HTTP smoke and exe smoke suites + synthetic case dataset
docs/                security/compliance and user guides
build.ps1            PyInstaller one-file build script
dist/                built portable exe + SHA-256 manifest
samples/             sample generated HTML report
```

## Version

1.0.0 — part of the Windows Event Log correlation & intrusion timeline project.