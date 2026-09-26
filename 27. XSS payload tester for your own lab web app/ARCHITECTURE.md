# XSS Payload Tester (Portable GUI) — System Architecture

**Document version:** 1.0
**Standards baseline:** OWASP Top 10:2025 · NIST SP 800-218 (SSDF v1.1) · NIST SP 800-53 Rev 5 · NIST SP 800-115 · ISO/IEC 27001:2022 Annex A
**Scope:** the portable, GUI-based, single-file `.exe` tester for your own lab web application; companion to the `xtester/` server/lab project.

---

## 1. Purpose & Scope

The **XSS Payload Tester** is a desktop (GUI) dynamic testing tool that injects a curated corpus of Cross-Site Scripting (XSS) payloads — raw, filter-evasion encoded, and context-targeted — into every parameter of a target web application (typically your own deliberately-vulnerable lab app) and grades how the app reflects and processes them.

It answers one question: **for every input parameter that the app reflects back, is the reflection safely encoded for the context it lands in, or can a browser be made to execute attacker-controlled script?**

Operating mode delivered here:

- **Standalone portable GUI** — a double-click `.exe` (no installation) used by the owner of the lab app against `http://localhost:PORT/...` targets with an explicit authorization note.

> Note on tooling: the same lab (`xtester/lab`) also has a FastAPI + Playwright headless-browser scanner (`xtester/backend`). This repository's portable GUI is the **response-reflection-based** variant: it trades headless-browser execution proof for a zero-dependency, single-file, dependency-free desktop artifact that runs anywhere (OWASP ASVS style: triage evidence, not proof of exploitability).

Governance requirement: every finding, payload category, and report must be traceable to OWASP Top 10:2025, NIST (SSDF / SP 800-53 / SP 800-115), and ISO/IEC 27001:2022 controls so tool output doubles as compliance evidence for the lab owner.

---

## 2. Design Goals & Guiding Principles

| Principle | Meaning in this system |
|---|---|
| **Own the XSS surface** | The tool is specialized: it does not replace general vuln scanners; it owns the reflected/client-side injection surface (NIST SP 800-53 SI-15 / SI-10 domain). |
| **Portable first** | Runtime is Python 3.12 **standard library only** (tkinter, urllib, json, threading, html.parser, re). No third-party runtime dependency keeps the onefile `.exe` small, offline, and runnable from a USB stick. |
| **Coverage by OWASP Top 10:2025** | Each payload category maps to OWASP Injection (A05:2025, per the numbering used by the sibling tooling in this project set) and its CWEs. |
| **Evidence-ready output** | Every finding stores the exact probe URL (PoC), the payload sent, observed reflection (raw/encoded), CSP header state, CVSS v3.1 score, and control mappings (ISO A.8.29, SSDF PW.8.2). |
| **Safe by design** | The tester is itself built with secure coding (SSDF PW.5, ISO A.8.28); it never stores plaintext secrets in reports, and it enforces an authorization note + scope prompt before scanning. |
| **Non-destructive & polite** | Configurable delay/concurrency, bounded request budgets, timeouts; detection is entirely response-based — no out-of-band callbacks to external infrastructure (ISO A.8.34). |
| **Deterministic, auditable runs** | Per-run token, bounded corpus, capped request counts, and an append-only audit log for evidence and incident reconstruction (ISO A.8.32, A.8.15). |
| **Honest verdicts** | Because there is no browser, findings carry a verdict (EXECUTED / LIKELY / SUSPICIOUS / CLEAN), a 0-1 confidence, and the raw evidence so an analyst confirms before acting (SSDF PW.8.2 / RV.1). |

---

## 3. Reference Architecture

```
 +----------------------------------------------------------------------+
 |                         PRESENTATION LAYER                           |
 |   Tkinter GUI (XssTester.exe, onefile --windowed, no install)         |
 |   Target & Scope | Modules/Payloads | Run Scan | Findings | Reports   |
 +--------------------------------------+-------------------------------+
                                        |
                                        v
 +----------------------------------------------------------------------+
 |                         ENGINE LAYER (app.core)                      |
 |  Discovery (crawl params)  ->  Planner (payloads x contexts x params)|
 |  ->  Executor (thread pool, rate limit, stop, TLS/proxy/cookie)      |
 |  ->  Detector (reflection analysis, verdict + confidence, CSP)       |
 |  ->  Rater (CVSS v3.1 base score + severity)                         |
 |  ->  Auditor (append-only JSONL evidence trail)                       |
 +----------------------------------------------------------------------+
                                        |
                +---------------------------+--------------------------+
                v                           v                          v
 +-----------------------------+  +--------------------+  +---------------------------+
 |   PAYLOAD CORPUS            |  |   REFLECTION        |  |  GOVERNANCE METADATA       |
 |  vectors x strategies       |  |   ANALYSIS          |  |  framemap: category ->     |
 |  x contexts (OWASP XSS      |  |  raw vs encoded,    |  |  OWASP 2025 / CWE / NIST   |
 |  Filter Evasion cheat       |  |  exec signatures,   |  |  / ISO / SSDF / severity   |
 |  sheet families) + encoders |  |  CSP assessment     |  |  + context remediation     |
 +-----------------------------+  +--------------------+  +---------------------------+
                                        |
                                        v
                         STORAGE (portable, next to the exe)
                         data/config.json, data/audit/audit.jsonl,
                         data/reports/*.json|html
```

Cross-cutting concerns: audit & security logging (ISO A.8.15, OWASP A09), secrets handling (auth material held in memory, never in reports), supply-chain hygiene (stdlib-only runtime; PyInstaller build-time pinned), and scope/politeness controls.

---

## 4. Core Components

### 4.1 GUI (Tkinter, `app/gui/app.py`)
- **Target & Scope tab** — target URL, auth cookie, auth header, extra headers, crawl page budget, per-category payload budget, request cap, concurrency, politeness delay, timeout, proxy, TLS verification toggle, deterministic seed, and a mandatory **authorization note**.
- **Modules / Payloads tab** — one checkbox per payload category, auto-rendered from `framemap.MODULES` with the OWASP mapping shown.
- **Run Scan tab** — Start/Stop, progress bar (`done/total`), and a live log that mirrors the immutable audit trail.
- **Findings tab** — sortable table (severity, category, vector, context, strategy, verdict, CVSS, URL, param, confidence) plus an evidence/remediation detail pane.
- **Report & Export tab** — HTML and JSON evidence exports, config save/load, summary.

### 4.2 Discovery (`app/core/discovery.py`)
- Fetches the seed page, collects same-host links (capped at `max_pages`), extracts query-string parameters from discovered URLs and `<input>`/`<textarea>`/`<select>` names from `<form>` elements (GET + POST), and builds an `Endpoint` list. Baseline-reflective parameters become the injection surface.

### 4.3 Payload Corpus (`app/core/payloads.py`, `app/core/contexts.py`, `app/core/encoders.py`)
- **Vectors**: OWASP XSS Filter Evasion families — `<script>`, event handlers (`img onerror`, `svg onload`, `body onload`, `details/ontoggle`, `input autofocus/onfocus`), `iframe srcdoc`, `javascript:` href, attribute breakouts, script-string breakouts, DOM clobbering.
- **Contexts** (labelled for reporting/remediation): HTML element, double/single/unquoted attribute, href/URL, `<script>` string, DOM `innerHTML` sink.
- **Strategies/encoders**: raw, tag case-mix, JS keyword (`\u0061lert`), JS hex/unicode escapes, HTML hex/decimal entity encoding, single/double URL encoding, attribute `javascript:` entity scheme. These are **test fixtures for your own lab app** — they encode the way browsers and naive WAF filters normalize input. They are never used on anything the tool itself renders.
- **Budgeting**: bounded candidate list (`max_payloads`) and total request cap (`max_requests`).

### 4.4 HTTP Client (`app/core/http_client.py`)
- Stdlib `urllib` session with cookie jar, `ProxyHandler`, configurable TLS verification (`HTTPSHandler(context=...)`), timeouts, custom User-Agent, auth/extra headers, and a scope guard. Returns `(status, body, headers, seconds)` for every request; 4xx/5xx bodies are preserved via `HTTPError.read()`.

### 4.5 Detector (`app/core/detection.py`)
Response-reflection analysis (no browser — documented honesty policy):
1. **Raw reflection** — is the full payload present verbatim in the response body?
2. **Encoded reflection** — is an escaped form present (`&lt;script&gt;`, entity-encoded, etc.)? That is evidence of mitigation.
3. **Execution signatures** — within the reflected window, look for `<script`, `on<event>=`, `javascript:`, `alert(`, `fetch(`, `document.write`/`innerHTML`, `new Image` — signatures that would fire in a browser.
4. **CSP assessment** — parse `Content-Security-Policy`; a strict policy (no `unsafe-inline`) downgrades confidence.
5. Verdict `EXECUTED / LIKELY / SUSPICIOUS / CLEAN` + 0-1 confidence per OWASP ASVS v4.0.3 V5.1 evidence model.

### 4.6 Rater & Reporting (`app/core/cvss.py`, `app/core/reporter.py`, `app/core/remediation.py`)
- **CVSS v3.1** base score per FIRST specification; defaults model reflected XSS (`AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`), scope/risk-adjusted per context (`dom` → scope U).
- **Findings** carry CWE, OWASP/NIST/ISO/SSDF mappings, severity, confidence, evidence, PoC URL, and context-specific remediation from the OWASP XSS Prevention Cheat Sheet.
- **Reports** export JSON and evidence-tabular HTML with full traceability records.

### 4.7 Engine (`app/core/engine.py`)
- Orchestrates `discover -> plan -> execute -> detect -> report`, with a `ThreadPoolExecutor`, politeness delay, stop event, per-scan run id, and append-only JSONL audit (`scan_start`, `request`, `finding`, `scan_end`).

---

## 5. Scan Lifecycle (data flow)

```
1. CONFIGURE  Target, auth, budgets, seed, authorization note.
2. DISCOVER   Crawl seed page (same-host, capped) -> endpoints + parameters.
3. PLAN       categories x vectors x contexts x strategies x endpoints x params,
              capped by max_payloads / max_requests; one scan token.
4. EXECUTE    Thread pool sends one request per candidate (URL-encoded payloads),
              polite delay, stop-check, per-request audit.
5. DETECT     Compare response for raw/encoded reflection + exec signatures + CSP.
6. RATE       CVSS v3.1 base score + severity + confidence per verdict.
7. REPORT     Findings -> GUI table; HTML/JSON evidence export; audit trail closed.
8. RETEST     After a fix, re-run same categories to confirm closure (SSDF RV.1).
```

---

## 6. Quality Controls

- **Portability** — runtime stdlib only; the frozen `.exe` is a single file that unpacks to `%TEMP%` at launch (standard PyInstaller behavior) and writes state next to itself (*portable*).
- **Budgets** — max pages, max payloads, max requests, timeouts; no infinite loops or floods (ISO A.8.34).
- **Politeness** — default delay 100 ms + configurable concurrency (1-16).
- **Determinism** — one random token per run; seeds recorded for reproducibility.
- **Honesty** — response-based detection means findings are triage evidence; the GUI labels verdicts and confidence so the operator verifies in a real browser (`vt` — the lab app renders the PoC).
- **Authorization** — an authorization note is collected before every scan and embedded in every exported report.

---

## 7. Data Model (high level)

- `ScanConfig` — url, auth material, budgets, concurrency, delay, timeout, proxy, verify_tls, seed, modules (categories), notes.
- `Endpoint` / `Parameter` — discovery results (method, url, param name/location/value).
- `Payload` — vector × context × strategy expanded injection string (with token).
- `Candidate` — payload + endpoint + param + proof URL (the PoC) + scan metadata.
- `ProbeResult` — verdict, confidence, status, raw/encoded reflection flags, observations.
- `Finding` — severity, CVSS vector/score, verdict, confidence, category, context, evidence, mappings, remediation, PoC.
- Audit events — JSONL records of scan/request/finding lifecycle.

---

## 8. Platform Security (the tester protects itself)

Because this tool generates attack traffic and can hold auth material, it applies the same standards it enforces:

- **Secure coding of the tool** (SSDF PW.5, ISO A.8.28): all GUI inputs validated; reports HTML-escape all payload content before rendering; no eval of payloads anywhere in the tool.
- **Secrets** — auth cookie/header live in memory only; never written to audit trail, reports, or findings. "Save config" stores them plaintext locally **with a documented warning** (keep empty when sensitive).
- **Least privilege** — run the exe as a normal user; no admin rights required; no writes outside its own `data/` directory.
- **Supply chain (OWASP A03)** — runtime imports only the Python standard library; the onefile exe embeds a reproducible stdlib build; PyInstaller pinned `>=6,<7`; verify `Get-FileHash` on distribution.
- **Scope** — the crawler stays on the seed host; the operator declares the authorized target up-front.
- **Logging** — audit trail captures what was sent (URL, payload id, status) for reconstruction (ISO A.8.15, OWASP A09).

---

## 9. Deployment Topologies

### 9.1 Portable desktop (delivered)
`XssTester.exe` → run anywhere; creates `data/` (config, audit, reports) next to the exe. Targeted at local lab apps (`http://127.0.0.1:PORT`).

### 9.2 Source mode
- `python main.py` — from a checkout with Python 3.12.
- `python smoke_test.py` / `python test_report.py` — self-contained regression against a temporary local vulnerable app.
- `build.bat` — one-click rebuild of the portable exe.

### 9.3 Server lab (companion, not part of this exe)
The `xtester/` FastAPI + Playwright scanner remains available when headless-browser execution proof is required (see `xtester/docs`). The two are complementary: portable triage vs. execution-proven verdicts.

---

## 10. Technology Stack

| Layer | Choice | Notes |
|---|---|---|
| Language | Python 3.12 | stdlib-only runtime (`tkinter`, `urllib`, `json`, `threading`, `html.parser`, `re`) |
| GUI | Tkinter / ttk | ships with CPython; no install; clam theme |
| HTTP | urllib | cookiejar, proxy, custom TLS context, timeouts |
| Packaging | PyInstaller 6.x | onefile + windowed |
| Reports | JSON + self-contained HTML | traceability + evidence, no external assets |
| Target | Authorized lab web app | html.parser discovery, response-reflection detection |

---

## 11. Implementation Roadmap

- **M1 (Foundation)** — config, discovery, corpus (vectors × contexts × strategies), response detection, engine, audit, reports. *(DONE — this release)*
- **M2 (Persistence & UX)** — finding dedup/correlation, saved-session resume, export formats, Polish GUI.
- **M3 (Advanced detection)** — Playwright headless split for execution proof, DOM-sink crawling, request-map (*burp-style*) import, auth-flow capture.
- **M4 (Ops)** — scan profiles, CLI mode for CI, SARIF export, retest tracking.

---

## 12. References

- OWASP Top 10:2025 — https://owasp.org/Top10/2025/
- OWASP XSS Filter Evasion Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html
- OWASP XSS Prevention Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
- OWASP ASVS v4.0.3 (V5.1 XSS verification) — https://owasp.org/www-project-application-security-verification-standard/
- NIST SP 800-218 (SSDF v1.1) — https://csrc.nist.gov/pubs/sp/800/218/final
- NIST SP 800-53 Rev 5 (SI-10, SI-15, CA-8) — https://csrc.nist.gov/pubs/sp/800/53/r5/
- NIST SP 800-115 — https://csrc.nist.gov/pubs/sp/800/115/final
- ISO/IEC 27001:2022 Annex A — https://www.iso.org/standard/27001
- FIRST CVSS v3.1 — https://www.first.org/cvss/specification-document