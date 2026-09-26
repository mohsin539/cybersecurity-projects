# MEMORY.md — SentinelGraph

Durable context for any agent or engineer resuming work on this project. Read this first.

## 1. Project Identity

- **What:** BloodHound-style Active Directory attack path visualizer with continuous compliance posture mapping.
- **Who it's for:** Bank security teams (SOC, red/purple team, GRC) operating **lab domains** or importing authorized SharpHound collections.
- **Stack:** FastAPI + in-memory/Neo4j graph · React 18 + TypeScript + Tailwind + Cytoscape.js.
- **Name:** SentinelGraph (app title: "SentinelGraph AD Attack Path Visualizer", v1.0.0).

## 2. Design Decisions (do not revisit without cause)

1. **Storage-agnostic graph core.** Everything consumes the `GraphStore` interface (`backend/app/graph/store.py`). In-memory for lab; Neo4j optional via `SG_NEO4J_ENABLED`. Engines never import a concrete store.
2. **Single-origin UI.** Vite builds into `backend/static`; FastAPI serves the SPA. No CORS in production profile; token stays in memory (never localStorage) to cap XSS blast radius.
3. **Lab profile vs production profile.** `SG_ENVIRONMENT=lab` enables `/api/docs` + localhost CORS; `production` disables both. Config validator enforces JWT secret ≥32 chars.
4. **Evidence-based compliance.** Controls declare evidence types (`tiering|graph|rbac|crypto|audit|validation`); the mapper computes pass/partial/fail at request time — no static checklists.
5. **BloodHound-compatible semantics.** Edge kinds mirror SharpHound edges (DCSync, GenericAll, Owns, …) so imported collections land natively.
6. **Tier-0 as first-class lens.** Microsoft Enterprise Access Model tiering drives scoring bonuses, exposure views, and the F-TIER/F-SESS findings.
7. **Fail-closed security.** Unknown node kind/edge kind raises; import rules that throw are skipped without killing the scan; errors never leak internals.

## 3. Key Files Map

```
backend/
  app/
    core/       config.py (env, secret validator) · security.py (JWT/RBAC)
                audit.py (append-only) · rate_limit.py · headers.py (CSP…) · errors.py
    graph/      model.py (Node/Edge/kinds/weights) · store.py (interface+memory)
                neo4j_store.py · lab_seed.py (CORP.LAB) · importer.py (SharpHound ETL)
    analysis/   tiers.py (Tier-0 classify) · engine.py (paths/blast/choke/exposure)
    findings/   rules.py (10 rules → MITRE ATT&CK)
    compliance/ catalogs.py (6 frameworks) · mapper.py (evidence→status)
    api/        routes_auth.py · routes_core.py · deps.py (rate limits)
    main.py     wiring, SPA mount, lifecycle audit
  tests/test_api.py        12 tests
  static/                  built frontend (vite output)
frontend/
  src/api.ts               typed client, token in memory
  src/components/          Login · Dashboard · Explorer · GraphView · Compliance · AuditView
  src/App.tsx              shell + RBAC-scoped tabs + finding modal
ARCHITECTURE.md  SECURITY.md  STATE.md  MEMORY.md  README.md
```

## 4. Domain Model Cheatsheet

- Node id format: `kind:name` (e.g. `user:svc_sql`, `group:domain_admins`, `computer:dc01`).
- 15 edge kinds; weights in `model.EDGE_WEIGHTS` (DCSync 1.0 → GPLink 0.2). `member_of`/`has_session` weights resolve contextually.
- Tier-0: domain nodes, DC computers, Tier-0-named groups + their members (propagated twice for nesting).
- Path score: `40·avg(weight) + 30/(1+0.35·(hops−1)) + 25·[T0 target] + 10·[user source]`, cap 100.
- Blast radius risk: `45·[T0 reachable] + 8·min(T0,5) + 2·√reachable`, cap 100.

## 5. Run & Test

```bash
cd backend && python -m pip install -r requirements.txt && python -m pytest tests/ -q
SG_JWT_SECRET=<48+ chars> python -m uvicorn app.main:app --port 8000   # UI at /
cd frontend && npm install && npm run build    # rebuilds backend/static
```

Lab accounts: admin/ChangeMe!Lab2024 · analyst/Analyst!Lab2024 · auditor/Auditor!Lab2024 (roles: full / read+seed / read-only).

## 6. Gotchas

- `python-multipart` is required (file upload) but easy to forget in fresh envs.
- **ADCS model:** `ca`/`cert_template` node kinds; `enroll|autoenroll|manage_certificates|manage_ca|published_on` edges; ESC1–ESC9 rules read template **props** (client_auth, enrollee_supplies_subject, any_purpose, vulnerable_template_acl, no_security_extension) + `_esc_enrollment_eligibility()` (one nesting level). ESC5/ESC7 need the seeded `generic_all`→CA and `manage_certificates`→CA edges.
- **Constrained delegation vs RBCD:** both use `allowed_to_delegate` edges distinguished by `props.delegation` (`"constrained"` vs `"rbcd"`) — rules F-DELEG-002/003; F-DELEG-004 flags write-ACEs on computers (RBCD attribute primitive).
- **UI verification:** use `e2e/verify.js` (puppeteer-core + installed Chrome, `window.__sg_cy` handle in GraphView for canvas node selection). CSS `text-transform: uppercase` means `innerText` returns "RISK INDEX" — keep text assertions case-insensitive. Fresh servers have ~5 audit events; the "Paths (N)" panel and "Blast radius" labels are uppercase-styled.
- **Login token pitfall:** `api.login()` must `setToken(r.access_token)` — curl tests mask a missing store because they pass the header manually.
- **Exe build chain (do in this order):** `npm run build` (frontend → backend/static) → `pyinstaller SentinelGraph.spec --noconfirm` (in backend/) → test exe from a **neutral CWD**. `main._static_root()` handles `sys._MEIPASS`; console stays visible on purpose; UPX off (AV flags). Env knobs: `SG_HOST/SG_PORT`; fresh session secret per launch by design.
- **What-if engine:** simulates via `FilteredStore` (edge filter + prop override); uses `findings_summary()['risk_raw']` (uncapped) because `risk_index` saturates at 100. MITIGATIONS map in `analysis/whatif.py` must stay in sync with rule ids in `findings/rules.py`.
- **PDF exports:** reportlab; US-Letter landscape canvases in `reports/exporters.py`; CSV is UTF-8-BOM + formula-injection-safe (`_csv_safe`). Downloads go through `downloadApiFile()` (bearer in header, blob + object URL) — never plain links (token is memory-only).
- **Re-scan diffing:** `analysis/rescan.py`; snapshot = per-rule fingerprint (sha256 of id/severity/category/mitre/sorted affected ids). Baseline JSON via `_data_dir()`: SG_DATA_DIR > (frozen → %LOCALAPPDATA%/SentinelGraph) > ./data. Scheduler thread honors `settings.rescan_interval_minutes` (SG_RESCAN_INTERVAL_MIN; admin can POST /interval; 0=off). An old server still holding the port makes new code look broken (405/SPA-on-API) — check `netstat -ano | grep LISTEN` after restarting.
- **Ticket exports:** `reports/tickets.py` — Jira (Summary/Description/Issue Type/Priority/Labels/External ID) and ServiceNow (Short description/…/Correlation ID); External/Correlation ID = finding id so ITSM imports dedupe; `sev_min=critical|high|…` filter.
- **Signing:** `tools/sign_exe.py` (signtool preferred, osslsigncode fallback; SHA-256 + RFC3161 /tr, never /t; refuses without cert → exit 2). `tools/release.py` = npm build → pytest → pyinstaller → sign (or --skip-sign warning) → smoke-launch. Needs PFX + Windows SDK, which dev machines typically lack.
- Rate limiter is in-process and per-tests needs `rate_limit.clear()` (autouse fixture exists).
- Unconstrained delegation flag lives on the **computer node** props (`unconstrained: true`), not the edge.
- `frontend/node_modules` is Windows-path heavy; always run npm from `frontend/`.
- Cytoscape style keys must be quoted strings ('shadow-blur'), not bare identifiers.
- Importer rejects files >512 MB and entries >2M by design (DoS cap) — don't "fix" that.
