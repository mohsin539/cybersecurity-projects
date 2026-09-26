# State: API Call Sequence Visualizer for a Sample's Behavior

**Document ID:** ACSV-STATE-001
**Version:** 1.0
**Classification:** Internal
**Date:** 2026-09-22

---

## 1. Purpose

This document records the **current implementation state** of the ACSV project.
It is the single source of truth for *what exists, what is stubbed, and what is
pending* at build time. It pairs with `architecture.md` (design intent) and
`security.md` (security/compliance posture). Persistently updated as the
codebase evolves.

---

## 2. Decision Log (Stack)

| Decision | Choice | Rationale / Notes |
|----------|--------|-------------------|
| Runtime | **Python 3.12.7** (CPython, win32) | Present on system; no Rust/cargo toolchain available. |
| GUI | **PySide6 6.11.2** | Rich native widgets; fastest path to colorful dark-cyber UI. |
| Packaging | **PyInstaller 6.22.3** `--onefile --windowed` | Portable single `.exe` per G1. |
| Report PDF | **fpdf2 2.8.8** | Pure-Python, offline, deterministic. |
| Event store | **SQLite (WAL)** | Single-file ACID store; `data/acsv.db`. |
| Secrets | **DPAPI** (`CryptProtectData`, flag 0 = user-bound) | Data-at-rest key protection (ISO A.8.24). |
| Audit chain | HMAC-SHA256 over `prev_hash \|\| canonical_payload`, JSONL + SQLite mirror | Tamper-evident append-only log. |
| Config | **TOML** policy, validated with deep-merge fallback to embedded defaults | Fail-closed on invalid policy. |
| Tests | **pytest 8.4.2** | 31 tests, all passing. |

---

## 3. Repository Layout (implemented)

```
.
├── architecture.md            # design intent (ACSV-ARCH-001)
├── security.md                # security & compliance posture      (this project)
├── state.md                   # implementation state               (this document)
├── memory.md                  # persistent engineering knowledge   (this project)
├── build.ps1                  # PyInstaller onefile build (pytest gate)
├── requirements.txt
├── policies/
│   └── default.toml           # default hardened policy (redaction, retention, limits)
├── schemas/                   # reserved: JSON Schemas (events/reports/audit)
├── templates/                 # reserved: report templates (currently code-embedded)
├── data/                      # portable-mode data dir (runtime; may be empty)
├── acsv/                      # application package
│   ├── app.py                 # entry: run GUI (QApplication)
│   ├── cli.py                 # entry: headless CLI (demo/report/audit/repl)
│   ├── __main__.py            # python -m acsv support
│   ├── version.py, config.py, crypto.py, registry.py, redaction.py,
│   ├── store.py, audit.py, compliance.py, services.py, intake.py
│   ├── capture/               # runner.py, generator.py, importer.py, etw.py
│   ├── analysis/              # engine.py, graph.py
│   ├── report/                # engine.py, exports.py
│   └── ui/                    # theme.py, main_window.py, widgets.py,
│                              # dashboard, capture, timeline, heatmap,
│                              # graph_view, report_studio, compliance_console,
│                              # audit_viewer, settings_view
└── tests/                     # conftest.py, test_audit, test_capture,
                               # test_intake, test_report  (31 passed)
```

---

## 4. Functionality Status

| Feature | Status | Notes |
|---------|--------|-------|
| Sample intake (register virtual sample) | **Implemented** | SHA-256, metadata; `AcsvIntake`. |
| Capture runner (offline replay of synthetic trace) | **Implemented** | `CaptureRunner.create_session / run_trace`; writes events with seq + integrity. |
| Live ETW capture | **Stub** | `acsv/capture/etw.py` raises `NotImplementedError`; reserved v1.1 (needs native sidecar). |
| User-mode hook engine (IAT/EAT) | **Reserved** | Requires native library; not in v1.0 Python build. |
| Importer (Procmon/API-Monitor JSON/XML) | **Implemented** | `capture/importer.py` parses structured trace files. |
| Analysis engine | **Implemented** | Stats, top APIs, threads, categories, statuses, findings, high-value ops. |
| Call graph builder | **Implemented** | Directed edges, weights, chain detection (CreateRemoteThread injection family). |
| Reports | **Implemented** | JSON / HTML / CSV / PDF / STIX 2.1; report SHA-256; download flow. |
| Report hashing / integrity | **Implemented** | `IntegrityService.canonical_bytes` normalizes tuples/int-keys (JSON round-trip). |
| Audit service | **Implemented** | Hash-chained JSONL + SQLite mirror; verify chain; export; rotate secrets. |
| Compliance mapping | **Implemented** | ISO 27001 / NIST CSF+800-53 / OWASP Top 10 tables; coverage matrix + summary. |
| Redaction | **Implemented** | Value-preserving quote-safe redaction (see `memory.md`); email/SSN patterns. |
| GUI — main window, theme, dashboard | **Implemented** | Dark-cyber theme (`ui/theme.py`), sidebar nav to 9 pages. |
| GUI — capture, timeline, heatmap, graph | **Implemented** | Swimlane timeline, heatmap brush, graph view. |
| GUI — report studio, compliance, audit viewer, settings | **Implemented** | Report format picker + download, coverage heatmap, audit verify/export/rotate, settings. |
| Portable vs managed data dir | **Implemented** | `./data` wins if present; else `%LOCALAPPDATA%\ACSV`; env `ACSV_DATA` override. |
| Auth / RBAC | **Reserved** (scaffold only) | Local single-actor identity recorded in audit; RBAC in v1.1. |

---

## 5. Test Status

| Suite | Result |
|-------|--------|
| `tests/test_audit.py` | PASS (hash chain, redaction, secret rotation, tamper detect) |
| `tests/test_capture.py` | PASS (session lifecycle, sequence integrity) |
| `tests/test_intake.py` | PASS (sample registration, hashing, duplicates) |
| `tests/test_report.py` | PASS (document build, JSON/PDF/HTML/STIX exports, hashes) |
| **Total** | **31 passed, 0 failed** (run: `python -m pytest tests -q`) |

---

## 6. Pending / Next Steps

1. [x] **Package portable `.exe`** — `build.ps1` (see §7). Entry point is `launcher.py` (frozen as top-level script; fixes relative-import crash). `data/icon.ico` generated.
2. [x] Smoke-test CLI: `python -m acsv demo --events 600`, `python -m acsv report --fmt pdf`, `python -m acsv audit-verify`.
3. [x] Smoke-test GUI: `python -m acsv` (launch, load demo session, open timeline/heatmap/graph, generate + download PDF report, check Audit Viewer).
4. [x] Provide a real `data/icon.ico` (build only, `build.ps1 --icon`).
5. [ ] (v1.1) Audit Viewer full UI, RBAC, live ETW sidecar.

---

## 7. Build Procedure (current)

```powershell
# in project root
python -m pytest tests -q        # gate: must be all-green
powershell -ExecutionPolicy Bypass -File .\build.ps1
# output: dist\ACSV.exe (onefile, windowed; entry point launcher.py)
# portable mode: run with a writable .\data next to the exe
```

---

## 8. Runtime Data Locations

| Mode | Location |
|------|----------|
| Portable (default in repo) | `./data/` next to app (`acsv.db`, `secrets.enc`, `audit.jsonl`, `audit.db`) |
| Managed | `%LOCALAPPDATA%\ACSV\` |
| Override | env `ACSV_DATA` |

---

## 9. Reserved Design (documented, not yet built)

- **Live capture** (ETW/hooks) — v1.1 native sidecar; schema and `parent_seq` already in place.
- **RBAC / peer review / SIEM streaming** — architecture §8.2; audit action vocabulary already includes roles-ready groups.
- **Artifact vault content-addressing** — vault schema reserved; `pack_file_digest` helper exists in `crypto.py`.
- **Signature of reports (Ed25519)** — DPAPI keystore hook present; activation gated by `sign_reports` policy.

*End of state document.*