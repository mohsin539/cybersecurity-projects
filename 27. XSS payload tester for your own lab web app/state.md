# State — XSS Payload Tester (current project status)

Snapshot of the portable GUI project as of 2026-09-20. Update this file as the project evolves.

---

## 1. What exists

```
(parent folder "27. XSS payload tester for your own lab web app")
xtester/                     Companion FastAPI + Playwright lab/scanner (separate project)
ARCHITECTURE.md              System architecture (GUI .exe solution + companion)
security.md                  Security posture (this project, portable GUI)
state.md                     This file
memory.md                    Developer memory/conventions for future sessions
requirements.txt             Build tool pin (PyInstaller); runtime = stdlib only
build.bat                    One-click portable .exe build
XssTester.spec               PyInstaller build spec (release)
XssTesterDbg.spec            PyInstaller debug spec
main.py                      Entry point (launches GUI; frozen-aware)
smoke_test.py                Local vulnerable lab app + assertion-driven core test
test_report.py               Report/JSON/HTML + audit log test against the smoke app
app/
  core/
    models.py                ScanConfig/Endpoint/Candidate/ProbeResult/Finding dataclasses
    contexts.py              Injection contexts (HTML/Attr/Script/URL/DOM) + wrappers
    encoders.py              Evasion encoders (html hex/dec, js hex/unicode, url, case mix)
    payloads.py              Vector corpus x strategies -> payload list builder
    framemap.py              Category metadata -> OWASP 2025 / CWE / NIST / ISO / SSDF + severity
    http_client.py           stdlib urllib session (cookies, proxy, TLS, timeouts, scope)
    discovery.py             Same-host crawl + parameter extractor (links + forms)
    detection.py             Response-reflection analysis: verdict + confidence + CSP
    cvss.py                  CVSS v3.1 base score + severity (FIRST spec, reflected XSS)
    remediation.py           Context-aware OWASP XSS Prevention remediation strings
    engine.py                ScanConfig + Engine (discover, plan, execute, detect, audit)
    reporter.py              JSON + HTML evidence reports (traceability records)
  gui/app.py                 Tkinter GUI (5 tabs: Target&Scope, Modules, Run, Findings, Reports)
dist/XssTester.exe           Portable single-file build (PyInstaller, stdlib-only runtime)
```

Runtime artifacts created by the app next to the exe (portable): `data/config.json`,
`data/audit/audit.jsonl`, `data/reports/*`.

## 2. Feature status

| Capability | Status |
|---|---|
| Same-host crawl + query/form parameter extraction (GET + POST) | DONE |
| Payload corpus: basic, event_handler, iframe, scheme, breakout, dom | DONE (vectors × contexts × strategies) |
| Strategy encoders: tagcase, js_keyword, js_hex, js_unicode, html_hex, html_dec, url, double_url, attr_scheme | DONE |
| Response-reflection detection: raw vs encoded, exec signatures, CSP assessment | DONE |
| Verdict EXECUTED/LIKELY/SUSPICIOUS/CLEAN + confidence | DONE |
| CVSS v3.1 scoring + severity + context mapping | DONE |
| Framework mapping on every finding (OWASP 2025 / CWE / NIST / ISO / SSDF) | DONE |
| Deterministic seeds, max budgets, concurrency, politeness delay | DONE |
| Audit log (append-only JSONL) | DONE |
| JSON + HTML evidence reports | DONE |
| GUI: target config, module selection, live progress/stop, findings table+detail, export | DONE |
| Config save/load | DONE |
| Portable .exe (onefile, windowed) | DONE |
| Headless-browser execution proof | NOT in this exe (companion `xtester/backend` covers it) |
| Finding dedup/correlation | PLANNED (not built) |
| Session resume / saved-scan reopen | PLANNED (not built) |
| SARIF export / CI mode | PLANNED (not built) |

## 3. Verification performed

- `python smoke_test.py` — PASS (2026-09-20): 542 findings on vulnerable endpoints (raw reflection, attribute breakout, script breakout, scheme/href, dom, iframe); `/encoded` + `/noreflect` produce zero findings; OWASP=`A05 Injection`, CWE-79, EXECUTED verdict, POST `/msg` form parameter scanned. Two bugs fixed during this pass:
  - `discovery.py` hardcoded form method to GET — `method="post"` forms were never scanned. Now honours the form `method` attribute.
  - `/encoded` false positives from `js_hex`/`js_unicode`/`url`/`double_url` payloads (no HTML-escapable chars → echoed verbatim). `detection._escape_style()` now downgrades these to CLEAN unless a decoding context exists.
- `python test_report.py` — PASS: HTML (485 KB) + JSON (817 KB) exports render; audit log 1370 lines with run/event structure.
- GUI construct test — PASS: all 5 notebook tabs build; Tk 8.6/clam theme.
- `python -m PyInstaller --onefile --windowed` (XssTester.spec) — BUILD OK (12.7 MB `dist\XssTester.exe`).
- FINAL exe verification — LAUNCH OK: Tk process window titled "XssTester", responsive; no `startup_error.log` written.

Note on monitoring the frozen exe: PyInstaller `--onefile --windowed` runs as two processes — a title-less bootloader plus the real Tk process (window title "XssTester"). Check the Tk process (`MainWindowTitle`), not the bootloader PID, when verifying launch.

## 4. Known limitations

- Crawler is `html.parser`-based: no JavaScript rendering, no SPA deep-crawl.
- Detection is **response-based only** (no browser): verdicts are triage evidence; manual PoC browser check is still required before acting.
- Beacon/exfil vectors (`fetch(...)`, `new Image().src=...`) are intentionally excluded from corpus expansion because there is no out-of-band callback in the desktop tool.
- Encoded reflections are reported CLEAN (good sign). Escape-syntax echoes (`\xNN`/`\uNNNN`/`%HH`) are also CLEAN unless a JS/URL decoding context exists; a naive double-encode or JSON-context edge case can still be missed.
- Auth cookie/header stored by "Save config" are plaintext on disk (documented warning; keep empty if sensitive).
- Onefile exe unpacks to `%TEMP%` at each launch; slower cold start, standard PyInstaller behavior.

## 5. How to run

Portable exe:
```
dist\XssTester.exe
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

## 6. Next steps (see ARCHITECTURE.md roadmap M1-M4)

1. Dedup/correlate duplicate findings (same category+context+param collapse with payload list).
2. Headless Playwright "confirm execution" mode (reuse `xtester/backend` engine) for execution-proof verdicts.
3. Request-map / captured-session import so labelled-lab flows can be PHP-like bootstrapped.
4. Scan profiles + SARIF export for CI.
5. Retest tracking (SSDF RV.1) — "patch-n-reverify" workflow in the GUI.