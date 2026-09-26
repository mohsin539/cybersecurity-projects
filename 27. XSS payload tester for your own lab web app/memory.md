# Memory — XSS Payload Tester (developer memory bank)

Fast-reference for future sessions: architecture decisions, conventions, implementation gotchas, and how to extend the tool. Read this plus `state.md` and `ARCHITECTURE.md` before modifying code.

---

## 1. Project identity

- Portable **desktop XSS tester** for **your own lab web app** (OWASP Top 10:2025-aligned), delivered as a single-file Windows `.exe`.
- Primary controls: NIST SP 800-53 **SI-10/SI-15**, ISO 27001:2022 **A.8.29/A.8.28**, NIST SSDF **PW.8.2/RV.1**.
- Companion: `xtester/` FastAPI + Playwright scanner (lab + execution-proven headless verdicts). This repo is the **response-reflection** portable variant — do NOT confuse the two engines.
- Standards versions in force (2026): OWASP Top 10:2025 (this project set maps Injection to **"A05 Injection"** — keep that exact label for consistency with siblings), ISO/IEC 27001:2022 Annex A (A.8 cluster = secure dev), NIST SSDF SP 800-218 v1.1, FIRST CVSS v3.1.

## 2. Conventions

- **Runtime = Python 3.12 stdlib only** (urllib, tkinter, json, threading, html.parser, re, http.server). Deliberate: keeps the onefile exe small, offline, dependency-free. Do NOT add third-party runtime deps without strong reason; if you must (e.g., Playwright), update `security.md` supply-chain notes and rebuild.
- **No code comments** in `app/` per project rule; use descriptive names + these docs.
- Package layout: `app/core/*` (headless logic, no GUI imports), `app/gui/app.py` (Tkinter only; imports core, never the reverse).
- Dataclasses in `models.py` for all records; JSON via `vars(f)` (reporter) or explicit serialisers.
- Every payload category MUST carry metadata in `framemap.MODULES` (title, owasp, cwes, nist, iso, ssdf, severity, remediation) — findings embed it; report traceability depends on it.
- `build_candidates` payload expansion: categories × vectors × contexts × strategies. Beacon vectors are skipped when no beacon base is given (desktop tool never provides one).

## 3. How a scan flows (understand before editing)

`GUI -> Engine.run`:
1. `Discovery.crawl(seed)` -> `Endpoint(method,url,params)` from same-host links + forms.
2. `Engine._plan(endpoints)` -> `List[Candidate]`: for each enabled category, expand via `payloads.build_candidates(...)` and cross with each endpoint param; cap at `max_payloads` payloads per category and `max_requests` total.
3. Baseline per (endpoint,param): benign token request; endpoints with 5xx baselines are skipped.
4. Workers (`ThreadPoolExecutor`, `concurrency`): send candidate (payload URL-encoded into the target param), run `detection.analyze(...)`, build `Finding` (with CVSS + framework mappings), `on_finding` callback -> GUI.
5. Politeness = `time.sleep(delay_ms/1000)` per completed case; `engine.stop()` checked between cases.
6. Audit events appended to `data/audit/audit.jsonl`.

## 4. Adding a new payload category (recipe)

1. `payloads.py`: add vectors to `VECTORS` (template with `{TOKEN}`; `contexts` tuple of spec names) and/or a strategy to `STRATEGIES` (label, context kinds, transformer). Vectors carry a `category` — the module key.
2. `framemap.py`: add category metadata (owasp/cwes/nist/iso/ssdf/severity/remediation).
3. `detection.py`: extend `EXEC_SIGNATURES` (regex, label) if the new category introduces new execution markers; add explicit signatures per category name to `_category_signatures`.
4. GUI: nothing to change — modules tab auto-renders from `MODULES`.
5. Test: add a vulnerable endpoint to `smoke_test.py` VulnHandler covering the category; run `python smoke_test.py` and `python test_report.py`.

## 5. Gotchas learned (verify again if touched)

- `urllib.request.OpenerDirector.open()` on Python 3.12 does **not** accept a `context=` kwarg. Custom TLS trust is wired via `HTTPSHandler(context=ctx)` at `build_opener` time (`http_client.Session.__init__`).
- `HTTPError` bodies: urllib raises for 4xx/5xx; you MUST `exc.read()` to keep the response body or reflection detection silently dies (see `http_client.Session.request`).
- `Session.request` returns **4-tuples `(status, body, headers, seconds)`**; any unpacking mismatch breaks discovery silently (wrapped in try/except) — symptom: "0 endpoints, 1 urls found", zero cases.
- URL merge re-encodes ALL query params (`_merge_query`): values like `"><img…` go out percent-encoded and the server decodes once before reflection. Payload checks use the **decoded payload string** against the **decoded response body** — never compare the URL-encoded form.
- Baseline skip: endpoints whose baseline status >= 500 are skipped.
- Encoded-reflection check: `html.escape` of the payload and entity encoders from `encoders.py` must be tested against the *same* string form the app reflects (some apps HTML-escape before reflection; url-decode first).
- CSP downgrade only multiplies confidence (base `* 0.6`); it does not flip a raw-reflection finding to CLEAN — server-side encoding is the decider.
- `data/` + config/reports/audit live under `base_dir()` = exe folder when frozen (`sys.frozen`), else project root. GUI demo runs of the exe create `dist/data/`; clean it before redistributing.
- Frozen exe checks: PyInstaller `--onefile --windowed` = TWO processes (bootloader + Tk child). Verify the child via `MainWindowTitle`, not the `Start-Process` PID. `sys.stdout`/`sys.stderr` are `None` in windowed mode — `main.py` redirects them to `os.devnull` and wraps startup in try/except writing `startup_error.log` next to the exe. Re-check `main.py` imports after refactors.
- OWASP label: use exactly `"A05 Injection"` (siblings use the same) — keep consistency across findings, framemap, and tests.
- Escape-syntax payloads (`js_hex` `\xNN`, `js_unicode` `\uNNNN`, `url`/`double_url` `%HH`) contain **no HTML-escapable chars**, so an app that only HTML-escapes echoes them verbatim (raw look, harmless). `detection._escape_style()` classifies these and downgrades to CLEAN unless a decoding context exists (`<script`/`on*= ` for js style; `href/src/action/poster/data=` for url style). When adding a strictly-HTLM-escaping "safe" lab endpoint, re-verify these strategy familes stay CLEAN.
- Form parsing: `_LinkParser` stores `(action, method, names)` and `crawl()` must honour the form's `method` attribute. A hardcoded GET here silently skipped POST endpoints entirely (classic silent bug — symptom: POST findings never appear). When adding form handling changes, assert against a `method="post"` form like `/msg`.` in smoke_test.py.

## 6. Key files to touch for the most common changes

| Change | File |
|---|---|
| New vector / strategy | `app/core/payloads.py` |
| New encoder / evasion transform | `app/core/encoders.py` |
| New context wrapper | `app/core/contexts.py` |
| Detection / verdict / confidence | `app/core/detection.py` |
| CVSS / severity tuning | `app/core/cvss.py` |
| New framework mapping | `app/core/framemap.py` |
| Crawl / param extraction | `app/core/discovery.py` |
| HTTP/TLS/proxy/cookie behaviour | `app/core/http_client.py` |
| Scan orchestration, budgets, audit | `app/core/engine.py` |
| Report formats | `app/core/reporter.py` |
| GUI layout/tabs | `app/gui/app.py` |
| Rebuild exe | `build.bat` |
| Regression tests | `smoke_test.py`, `test_report.py` |

## 7. Testing checklist (after any change)

- `python smoke_test.py` (vulnerable + safe endpoints, module coverage, OWASP mapping)
- `python test_report.py` (exports + audit log structure)
- GUI construct: `python -c "from app.gui.app import App; a=App(); a.update(); a.destroy()"`
- Rebuild: `build.bat`; sanity launch: start exe, observe it stays alive, kill.