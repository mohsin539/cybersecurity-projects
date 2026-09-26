# Memory — Web App Fuzzer (developer memory bank)

Fast-reference for future sessions: architecture decisions, conventions, implementation gotchas, and how to extend the tool. Read this plus `state.md` and `ARCHITECTURE.md` before modifying code.

---

## 1. Project identity

- Input-validation **DAST fuzzer** (OWASP Top 10:2025-aligned) with a portable desktop GUI.
- Primary controls: NIST SP 800-53 **SI-10**, ISO 27001:2022 **A.8.29/A.8.28**, NIST SSDF PW.8.2/RV.1.
- Two deploy modes documented (in-CI gate / standalone); the shipped artifact is the standalone portable exe.
- Standards versions in force (2026): OWASP Top 10:2025 (A01-A10, released Nov 2025, finalized Jan 2026; SSRF folded into A01; new A03 supply chain, A10 exception handling), ISO/IEC 27001:2022 Annex A (93 controls, A.8 cluster = secure dev), NIST SSDF SP 800-218 v1.1.

## 2. Conventions

- **Runtime = Python 3.12 stdlib only** (urllib, tkinter, json, threading, html.parser, regex). Deliberate: keeps the 12 MB onefile portable and dependency-free. Do not add third-party runtime deps without strong reason; if you must (e.g., Playwright), update `security.md` supply-chain notes and rebuild.
- **No code comments** in `app/` per project rule; use descriptive names + these docs.
- Package layout: `app/core/*` (headless logic, no GUI imports), `app/gui/app.py` (Tkinter only; imports core, never the reverse).
- Dataclasses in `models.py` for all records; JSON (de)serialization via `vars(f)`.
- Determinism: engine uses `random.Random(seed)`; per-case markers from `new_marker()`.
- Every module MUST carry metadata in `framemap.py` `MODULES` (title, owasp, cwes, nist, iso, ssdf, severity, remediation) — findings embed it; report traceability depends on it.

## 3. How a scan flows (understand before editing)

`GUI -> Engine.run` ->
1. `Discovery.crawl(seed)` -> `Endpoint(method,url,params)` list (GET query params from URLs + form inputs).
2. `Engine._plan(endpoints)` -> `List[FuzzCase]` (module x payload x endpoint x param), capped at `max_requests`. Payload `{marker}` substituted with a random token.
3. Workers (ThreadPoolExecutor, `concurrency`) per case: build baseline (same URL, target param removed) once per URL; send case; `detectors.detect(...)`; on hit build `Finding` with framework mappings; `on_finding` callback -> GUI.
4. Rate limit = `time.sleep(delay_ms/1000)` per completed case; `engine.stop()` checked between cases.
5. Audit events appended to `data/audit/audit.jsonl` (JSONL, append-only).

## 4. Adding a new fuzz module (recipe)

1. `payloads.py`: add key to `_REGISTRY` with `(payload_id, template)` tuples; use `{marker}` placeholders for reflection/execution detection. Update `_SQL_ERROR_RE`/`_STACK_RE`/marker lists if the class introduces new signature patterns.
2. `framemap.py`: add module metadata (owasp/cwes/nist/iso/ssdf/severity/remediation) — the traceability report reads this.
3. `detectors.py`: add a `module == "..."` branch returning `Optional[Tuple[severity, confidence, evidence_dict]]`. Baseline dict keys: status/body/headers/time; actual same.
4. GUI: nothing to change — modules tab auto-renders from `MODULES`.
5. Test: add a vulnerable endpoint to `smoke_test.py` VulnHandler and cover in the `by_module` assertion; run `python smoke_test.py` and `python test_report.py`.

## 5. Gotchas learned (verify again if touched)

- `urllib.request.OpenerDirector.open()` on Python 3.12 does **not** accept a `context=` kwarg. Custom TLS trust is wired via `HTTPSHandler(context=ctx)` at `build_opener` time (see `http_client.Session.__init__`).
- `HTTPError` bodies: urllib raises for 4xx/5xx; you MUST `exc.read()` to keep the response body or stack-trace/verbose-error detection silently dies (fixed already).
- `Session.get`/`request` return 4-tuples `(status, body, headers_dict, seconds)`. Any unpacking mismatch breaks discovery silently (it is wrapped in try/except) — symptom: "0 endpoints, 1 urls found", zero cases.
- URL merges (`_merge_query`) re-encode ALL query params — values like `../../etc/passwd` go out percent-encoded (`%2F`); server-side `parse_qs` decodes once. Test servers in `smoke_test.py` must key the param they read to the param the fuzz case targets (`id` vs `file` vs `name` vs `p`).
- Baseline skip rule: endpoints whose baseline is 5xx are skipped entirely. Test apps for the `errors` module must respond 200 on baseline (`?p=1`) and 5xx on malformed input.
- Detector thresholds: SQLi time-based fires at `>= 1.5s` delta; keep enough margin for slow CI machines.
- `data/` + config/reports/audit are written under `base_dir()` = exe folder when frozen (`sys.frozen`), or project root when run from source. GUI demo runs of the exe create `dist/data/`; clean it before redistributing.
- Frozen exe checks: PyInstaller `--onefile --windowed` = TWO processes (bootloader + Tk child). Verify the child via `MainWindowTitle`, not the `Start-Process` PID. `sys.stdout`/`sys.stderr` are `None` in windowed mode — `main.py` redirects them to `os.devnull` and wraps startup in try/except writing `startup_error.log` next to the exe. A missing symbol imported in `main.py` crashes the frozen app but never surfaces in console mode — re-check `main.py` imports after refactors.

## 6. Key files to touch for the most common changes

| Change | File |
|---|---|
| New payload | `app/core/payloads.py` |
| New detection logic / severity | `app/core/detectors.py` |
| New framework mapping | `app/core/framemap.py` |
| Crawl / param extraction | `app/core/discovery.py` |
| HTTP/TLS/proxy behaviour | `app/core/http_client.py` |
| Scan orchestration, budgets, audit | `app/core/engine.py` |
| Report formats | `app/core/reporter.py` |
| GUI layout/tabs | `app/gui/app.py` |
| Rebuild exe | `build.bat` |
| Regression tests | `smoke_test.py`, `test_report.py` |

## 7. Testing checklist (after any change)

- `python smoke_test.py` (module coverage + OWASP mapping assertions)
- `python test_report.py` (exports + audit log structure)
- GUI construct: `python -c "from app.gui.app import App; a=App(); a.update(); a.destroy()"`
- Rebuild: `build.bat`; sanity launch: start exe, observe it stays alive, kill.