# STATE.md — SentinelGraph

Tracks the **current state** of the build — what exists, what is verified, what is pending. Update this file whenever the system changes.

**Last updated:** 2026-09-20 · Build state: **Re-scan diffing + ITSM ticket exports + signing pipeline shipped; 37/37 backend tests; 28/28 Chrome E2E; exe re-verified live**

## 1. Working State (verified)

| Area | State | Evidence |
|---|---|---|
| Backend API (FastAPI) | ✅ 15+ endpoints live | E2E smoke: all 200s |
| Auth (JWT + RBAC) | ✅ Working | 12/12 tests; auditor 403 on mutations verified |
| Graph engine (in-memory) | ✅ CORP.LAB seed loads | 32 nodes / 40+ edges on boot |
| Neo4j store | ✅ Code complete, optional | `SG_NEO4J_ENABLED=true` (not integration-tested in this session) |
| Attack-path engine | ✅ BFS + risk + blast radius | helpdesk → Tier-0 path risk 89.0 |
| Findings engine | ✅ 19 rules fire (incl. ADCS ESC1–ESC9, constrained delegation, RBCD) | 15 findings on seed; ESC + delegation rule IDs verified in tests |
| Compliance mapper | ✅ 6 frameworks | OWASP 90 · ISO 95 · CSF 96.7 · 800-53 93.3 · PCI 97.7 · CIS 94.1 |
| Audit trail | ✅ Append-only | admin/auditor `/audit` returns events |
| Frontend (React+TS+Tailwind) | ✅ Built to `backend/static` | strict `tsc` clean; vite build green |
| SPA served same-origin | ✅ | `GET /` → 200 text/html |
| Tests | ✅ 13/13 backend passing | `python -m pytest tests/ -q` |
| Chrome E2E (puppeteer-core) | ✅ 25/25 checks | `cd e2e && node verify.js`; screenshots in `e2e/artifacts/` |
| Attack-path simulation via UI | ✅ | helpdesk → Tier-0: blast radius 84.7/100, "DOMAIN COMPROMISE POSSIBLE" flagged |
| What-if remediation simulator | ✅ API + UI | DCSync fix: risk −25, 1 critical removed; store never mutated (test-verified) |
| PDF/CSV GRC exports | ✅ | /reports/findings & /reports/compliance; PDF opens, CSV Excel-safe |
| **Portable SentinelGraph.exe** | ✅ **Built & verified** | PyInstaller onefile ~30.3 MB; re-verified with rescan diff (18 new → 0 new), Jira CSV, %LOCALAPPDATA% baseline |
| Scheduled re-scan + diff | ✅ API + UI + scheduler | `analysis/rescan.py`; baseline JSON survives restarts; SG_RESCAN_INTERVAL_MIN or admin interval API |
| Jira/ServiceNow ticket export | ✅ | `/reports/tickets/{jira|servicenow}?sev_min=`; importer-compatible headers; dedupe via External/Correlation ID |
| Code-signing pipeline | ✅ script, no cert on this machine | `tools/sign_exe.py` (signtool/osslsigncode, SHA-256 + RFC3161); `tools/release.py` gates releases |

## 2. How to Run

```bash
# Option A — dev (two terminals)
cd backend && python -m pip install -r requirements.txt
SG_JWT_SECRET=$(python -c "import secrets;print(secrets.token_urlsafe(48))") python -m uvicorn app.main:app --port 8000
cd frontend && npm install && npm run dev          # http://localhost:5173

# Option B — single origin (already built)
cd backend && SG_JWT_SECRET=... python -m uvicorn app.main:app --port 8000
# open http://localhost:8000
```

Lab accounts: `admin/ChangeMe!Lab2024`, `analyst/Analyst!Lab2024`, `auditor/Auditor!Lab2024`.

## 3. Known Gaps / Pending

| Item | Status | Next step |
|---|---|---|
| Portable .exe packaging | ✅ `SentinelGraph.spec` + frozen-safe static paths; exe in `backend/dist/` | Rebuild after UI changes: `npm run build` then `pyinstaller SentinelGraph.spec --noconfirm` |
| Docker artifacts | Spec'd, not yet committed | Add `Dockerfile` + `compose.yaml` |
| Signing certificate | not available in this environment | Set SG_CODESIGN_PFX/PASSWORD (or --pfx) with Windows SDK signtool or osslsigncode; `tools/release.py` then signs+verifies automatically |
| MFA evidence | partial in compliance | Wire real IdP/SSO |
| SIEM streaming | audit prints JSON lines | Add Splunk/Sentinel shipper |
| SharpHound v2 edges (cert bundling, DPAPI) | not implemented | Extend `importer._map_ace` + edge kinds |
| Neo4j integration test | pending | CI service container |

## 4. Verification Log (this session)

- `python -m pytest tests/ -q` → **37 passed** (adds: rescan diff unit+API, baseline persistence, RBAC on rescan, ticket CSV shapes, sev filter, 422s).
- Headless-Chrome E2E → **28/28** (adds: rescan diff panel + scheduler status, ticket export buttons).
- **Portable exe re-verified live:** scan 1 = 18 new / scan 2 = 0 new / 18 unchanged; Jira CSV headers correct; baseline written to data dir; scheduler status reported; process stopped cleanly.
- Signing gate validated: refuses to sign without cert + tooling (exit 2) — CI-safe.
- Earlier session: `api.login()` token-persistence bug caught by browser testing and fixed; rate-limiter test isolation; seed flag fix; compliance catalog typos.

### What-if engine notes
- `FilteredStore` view filters edges / overrides props; live store provably unmutated (`test_what_if_never_mutates_store`).
- Simulator uses **uncapped** `risk_raw` (risk_index caps at 100 and would hide single-fix deltas).
- Roadmap auto-orders critical→low; cumulative steps reported per finding.
