# Browser Artifact Extractor — Project State

**Document status:** published · **Last update:** 2026-09-21 · **Snapshot of:** `v1.0.0`

This file records *current* project state: what is implemented, what has been
tested and verified, known limitations, and the forward roadmap. It is updated on
every material change; the version/date line is the revision marker.

---

## 1. Feature status

| Feature | Status | Verified on |
|---|---|---|
| Browser discovery (Chromium family) | ✅ Implemented | Chrome, Edge, Firefox (dev host); Brave/Opera/Vivaldi/others per config |
| Browser discovery (Firefox) | ✅ Implemented | 1 Firefox profile (dev host) |
| History extraction | ✅ Implemented | Chrome, Edge, Firefox |
| Downloads extraction | ✅ Implemented | Chrome, Edge, Firefox |
| Cookies extraction | ✅ Implemented | Firefox (decrypted); Chrome/Edge blocked pending lock (see §4) |
| Cookie decryption (v10/v11 AES-GCM + DPAPI) | ✅ Implemented | Unit-verified via `load_master_key`/`decrypt_value` |
| v20 App-Bound detection | ✅ Implemented | Returns `v20_appbound` status |
| Bookmarks extraction | ✅ Implemented | Chrome, Edge, Firefox |
| Autofill / form data | ✅ Implemented | Chrome, Edge, Firefox |
| Saved logins | ✅ Implemented | Chromium metadata (+opt-in decrypt); Firefox NSS-flagged |
| Search terms | ✅ Implemented | Chrome, Edge, Firefox |
| Cache (Simple Cache keys/URLs, cache2 scan) | ✅ Implemented | Chrome, Edge, Firefox |
| Locked-file acquisition ladder (shared/backup/VSS) | ✅ Implemented | Live-lock degradation tested on this host |
| SHA-256 evidence manifest + HMAC option | ✅ Implemented | `evidence_manifest_*.json` produced |
| Hash-chained audit log + `verify()` | ✅ Implemented | `Audit chain: VALID` on every run |
| Compliance catalogue (20 controls) | ✅ Implemented | In-app + in-report; 100% coverage flag |
| Reports: HTML / CSV / JSON / XML / XLSX / PDF / MD | ✅ Implemented | All produced in CLI, GUI, and .exe runs |
| Auto-export on GUI scan | ✅ Implemented | `BAE_Output/scan_<ID>/` refreshed per scan |
| GUI: dashboard, tables, nav, export dialog, verify | ✅ Implemented | GUI smoke + threaded scan tests |
| CLI headless mode | ✅ Implemented | `--cli` on source and packaged `-CLI.exe` |
| Portable one-file executables | ✅ Implemented | Both built, launched, ran scans |

---

## 2. Verification record (development host)

Host: `mohsinIT-PC` · Windows 11 (10.0.26200) · Python 3.12.7 ·
`cryptography 50.0.1 / openpyxl 3.1.5 / reportlab 4.2.5 / PyInstaller 6.22.3`

| Run | Channel | Limit/flag | Records | Elapsed | Audit chain | Coverage |
|---|---|---|---|---|---|---|
| T1 early integration | source CLI | 40 | 712 | 1.3 s | VALID | 20/20 |
| T2 decrypt-on | source CLI | 40 --decrypt | 712 | 3.9 s | VALID | 20/20 |
| T3 post-winio ladder | source CLI | 30 --decrypt | 607 | — | VALID | 20/20 |
| T4 GUI full flow | source GUI | 25 (auto) | 548 | — | VALID | 20/20 |
| T5 packaged CLI .exe | `-CLI.exe` | 15 | 428 | 0.64 s | VALID | 20/20 |
| T6 final rebuild | `-CLI.exe` | 10 | 316 | — | VALID | 20/20 |

Static checks: `python -m pyflakes core sec report ui main.py build_portable.py`
→ **clean**; `python -m compileall` → **clean**; GUI smoke (12 views, 8 tables,
discovery + scan + auto-export) → **PASS**; packaged GUI exe launch/close → **PASS**.

Export integrity spot-checks: XLSX re-opened via openpyxl (9 sheets incl. Summary);
XML record count == total records (428); HTML contains escaped values and tables;
CSV folder emits 9 files.

---

## 3. Artifact inventory (current build)

```
dist/
├── BrowserArtifactExtractor.exe       29.4 MB  GUI, windowed, one-file
└── BrowserArtifactExtractor-CLI.exe   29.4 MB  console, one-file
```

Runtime footprint on disk (source tree): ~250 KB code; build requirements ~150 MB
environment is not shipped (exe is self-contained).

---

## 4. Known limitations & open defects

| # | Limitation | Status / workaround |
|---|---|---|
| L1 | Chrome/Edge `Cookies` DB is exclusively locked while browser runs; non-elevated runs skip it with a warning | **By design.** Elevate for VSS, or close the browser. (Windows `ERROR_SHARING_VIOLATION` 32) |
| L2 | Chromium v20 App-Bound cookies cannot be decrypted outside the browser's service | Reported `v20_appbound`; metadata still captured |
| L3 | Firefox `logins.json` values are NSS-encrypted; not decrypted | Fields surfaced; no key exposure |
| L4 | Live SQLite + concurrent WAL writes can produce a slightly stale copy | WAL sidecars are copied; acknowledged best-effort |
| L5 | PDF tables capped at 800 rows; HTML/CSV unlimited | Print pragmatics; full data in CSV/JSON/XLSX |
| L6 | VSS path requires elevation and `powershell.exe` present | Automatic when admin; otherwise clear message |
| L7 | No automated CI/test harness checked in | Manual smoke suite; see roadmap R1 |
| L8 | One-file exe may trigger AV heuristics | README troubleshooting; `--onedir` fallback |
| L9 | Login/test history profiles (`System Profile`, `Guest Profile`) may be listed | Harmless; filterable in profile list |
| L10 | Cache recovery is header/URL-based, not a byte-exact cache forensic parser | Enumerates files + keys/URLs + metadata |

---

## 5. Configuration & default behaviour catalogue

| Setting | Default | Location |
|---|---|---|
| Categories collected | all 8 | `ScanOptions.categories`, UI checkboxes |
| Decrypt secrets | **off** | `ScanOptions.decrypt_secrets` / `--decrypt` |
| Recover cache URLs | on | `extract_cache_urls` |
| Max records / category | 0 = unlimited | `--max-records`, UI spinbox |
| Audit severity floor | INFO | `AuditLogger(severity_floor=...)` |
| Actor (audit + reports) | `$env:USERNAME` / CLI `--operator` | `AuditLogger.actor` |
| Output root | `BAE_Output/` beside binary (or cwd for CLI default) | `ui.app.base_dir()` / `run_cli` |
| Audit log path | `BAE_Output/logs/audit_<date>.jsonl` (GUI) | `App.__init__` |
| Report auto-save | `BAE_Output/scan_<scan_id>/` | `App._on_complete` |

---

## 6. Roadmap

| ID | Item | Priority | Notes |
|---|---|---|---|
| R1 | Checked-in automated test suite (`unittest`/`pytest`) covering extractors on synthetic SQLite fixtures | High | Enable regression safety before next feature work |
| R2 | Optional VSS module hardening + integration test | Medium | Elevation-only; guardrail against hanging PowerShell |
| R3 | `pip-audit` gate in build script | Medium | Supply-chain assurance (OWASP A06) |
| R4 | Package signing (Authenticode) guidance | Medium | Reduces AV false positives |
| R5 | `key4.db`/NSS master-password-less logins decryption | Low | Cross-platform scope creep; assess later |
| R6 | `--dedupe`, `--since`, `--domain` filter flags | Low | Analyst productivity |
| R7 | Localisations (i18n) of GUI strings | Low | Not requested; architecture is `*`hold-friendly* |
| R8 | Export `--target {evidence,redacted}` mode | Medium | Automates masking for non-decrypt production reports |

---

## 7. Change log (state-relevant)

| Date | Change |
|---|---|
| 2026-09-21 | v1.0.0 initial delivery: engine, security layer, exporters, GUI, packaging. Locked-file ladder fixed shared-read failures (WinError 32) by consolidating into `core/winio`. Pyflakes clean; both .exe built and exercised. |
| (next) | ... append here |