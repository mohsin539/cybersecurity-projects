# State — Web App Fuzzer (current project status)

Snapshot of the project as of 2026-09-19. Update this file as the project evolves.

---

## 1. What exists

```
ARCHITECTURE.md        System architecture (layers, components, deployment topologies)
FRAMEWORK_MAPPING.md   Traceability: OWASP 2025, NIST SP 800-53/800-218, ISO 27001:2022
security.md            This file is the security posture (see section list)
state.md               This file
memory.md              Developer memory/conventions for future sessions
requirements.txt       Build tool pin (PyInstaller); runtime = stdlib only
build.bat              One-click portable .exe build
main.py                Entry point (launches GUI)
app/
  core/
    models.py          Endpoint/Parameter/FuzzCase/Finding dataclasses
    framemap.py        Module metadata -> OWASP/NIST/ISO/SSDF + CWE severity
    payloads.py        Payload corpora (sqli, xss, ssti, traversal, ssrf, cmdi, header, errors, boundary, auth)
    discovery.py       HTML crawl (links + forms), param extraction, same-host scope
    http_client.py     stdlib urllib client (cookie jar, proxy, TLS, scope merge)
    detectors.py       Oracle + differential detection per module
    engine.py          ScanConfig + Engine (plan, thread pool, rate limit, audit log)
    reporter.py        JSON + HTML evidence reports (traceability records)
  gui/app.py           Tkinter GUI (5 tabs: Target & Scope, Modules, Run Scan, Findings, Report & Export)
dist/WebAppFuzzer.exe  Portable single-file build (built with PyInstaller 6.22, ~12 MB)
smoke_test.py          Local vulnerable test app + assertion-driven core test
test_report.py         Report/JSON/HTML + audit log test against smoke app
```

Runtime artifacts created by the app next to the exe (portable): `data/fuzzer_config.json`,
`data/audit/audit.jsonl`, `data/reports/*`.

## 2. Feature status

| Capability | Status |
|---|---|
| Crawl GET/POST endpoints + extract query/form params | DONE |
| Fuzz modules: sqli, xss, ssti, traversal, ssrf, cmdi, header, errors, boundary, auth | DONE (payload sets + detectors) |
| Differential + oracle detection, confidence, severity | DONE |
| Framework mapping on every finding (OWASP 2025 / NIST / ISO / SSDF) | DONE |
| Deterministic seeds, max budgets, concurrency, politeness delay | DONE |
| Audit log (append-only JSONL) | DONE |
| JSON + HTML evidence reports | DONE |
| GUI: target config, module selection, live progress/stop, findings table+detail, export | DONE |
| Config save/load | DONE |
| Portable .exe (onefile, windowed) | DONE |
| DOM/headless-browser fuzzing | PLANNED (not built) |
| WebSocket/GraphQL/gRPC protocol adapters | PLANNED (not built) |
| OOB collaborator (SSRF DNS callback) | PLANNED (not built; detection is response-based) |
| CI gate / SARIF / Jira/DefectDojo push | PLANNED (not built) |

## 3. Verification performed

- `python smoke_test.py` — PASS: 34 findings across xss, sqli, traversal, errors, boundary on a local vulnerable app; asserts module coverage + OWASP mapping.
- `python test_report.py` — PASS: HTML (12 KB) + JSON (20 KB) exports render; ~175 audit lines written with run/event structure.
- GUI construct test — PASS: all 5 notebook tabs build; Tk 8.6.
- `python -m PyInstaller ... --onefile --windowed` — BUILD OK.
- FINAL exe verification — LAUNCH OK: GUI window titled "Web App Fuzzer", responding, ~39 MB working set; no `startup_error.log` written.
- Fixed during this phase: `main.py` imported `BASE_DIR` (a name that does not exist in `app.gui.app`), which crashed the frozen exe at startup. Import corrected, and `main.py` now also writes `startup_error.log` next to the exe on any launch failure.

Note on monitoring the frozen exe: PyInstaller `--onefile --windowed` runs as two processes — a title-less bootloader plus the real Tk process (window title "Web App Fuzzer"). Check the Tk process (`MainWindowTitle`), not the bootloader PID, when verifying launch.

## 4. Known limitations

- Crawler is regex/HTML-parser based: no JavaScript rendering, no SPA deep-crawl, no WebSocket frames.
- Detection is response-based only (no out-of-band). Time-based SQLi needs the app to delay; tested threshold 1.5 s.
- `auth` module is minimal (status-difference heuristic on protected endpoints).
- Header-injection findings depend on the target echoing injected response headers.
- Reports contain raw response evidence — treat as confidential (see security.md).
- Credentials stored by "Save config" are plaintext on disk (documented warning; keep empty if sensitive).
- Onefile exe unpacks to `%TEMP%` at each launch; slower cold start, standard PyInstaller behavior.

## 5. How to run

Portable exe:
```
dist\WebAppFuzzer.exe
```
From source:
```
python main.py
```
Rebuild:
```
build.bat
```
Tests:
```
python smoke_test.py
python test_report.py
```

## 6. Next steps (see ARCHITECTURE.md roadmap M1-M5)

1. Dedup/correlate duplicate findings (same module+param collapse with payload list).
2. Headless browser module (Playwright) for DOM XSS + SPA crawl.
3. Out-of-band collaborator for SSRF time/body-free detection.
4. Scan gates + SARIF export for CI.
5. Policy-per-target config (severity thresholds, SLA fields) for ISO A.8.8 tracking.
6. SBOM/SCA fingerprinting of target dependencies (OWASP A03 module).