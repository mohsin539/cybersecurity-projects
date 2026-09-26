# memory.md — Project Memory (Reservation Document)

Status: Active · Maintainer: on every contribution · Purpose: persistent cross-session memory for humans and agents

> **Reservation rule**: every non-trivial contribution updates `memory.md` in the same change set. Read this file first when resuming work. Conflicts between docs and `memory.md` resolve in favor of `memory.md` until docs are reconciled (then update `memory.md` to avoid drift).

---

## 1. Project snapshot

- **What**: SOC Alert Triage Dashboard — severity scoring + alert deduplication, GUI/web based.
- **Form**: Zero-dependency Node.js (≥18) web application: `node server.js` → http://localhost:8080. No npm install, no build step, no external packages. Chosen because the workstation has Node 24 and Python 3.12 but **no Go toolchain**.
- **Authoritative design docs**: `01`–`07` + `adr/`. Implementation-level security: `security.md`. State semantics: `state.md`. This file: cross-session memory.

## 2. Architecture decisions (current truth)

| Decision | Value | Rationale |
|---|---|---|
| Runtime | Node.js stdlib only (`http`, `crypto`, `fs`) | portability, zero supply-chain surface (OWASP A06 by construction) |
| Auth | demo login (no password), server-side session cookie | demo-scope; prod path documented in security.md A07 |
| Storage | `data/store.json` snapshot, loaded at boot, saved after each mutation | simple portability; PostgreSQL is the design target (03) |
| Audit | in-memory hash chain per tenant + JSONL export | implements AU-9/AU-10 posture for demo; WORM is prod target |
| Dedup | exact key only (SHA-256 over tenant/rule/entities/window-bucket); `fuzzy` enum reserved | fuzzy (MinHash/pgvector) deferred, state reserved in `state.md` §5 |
| Scoring | deterministic 8-factor model, fixed ML adjustment 0 | ADR-002; golden vector in `02` §4.2 must reproduce score 97 |

## 3. Key implementation facts

- **server.js** (~600 lines): routing, auth/sessions, RBAC/ABAC middleware, scoring engine, dedup engine, audit chain, kill switches, static file host, JSONL audit export. All security-relevant helpers (timing-safe compare, entity canonicalization, HTML escape on client) flagged with `// SECURITY:` comments.
- **public/index.html + app.js + styles.css**: SPA, strict CSP served by server (`default-src 'self'`), all rendering via `textContent` (no innerHTML), fetch wrapper auto-sends `X-CSRF-Token`, queue table, alert detail with factor breakdown + dedup tree, audit view with verify button, config view for soc.lead/admin.
- **Demo data**: seeded per tenant `t1`: users `analyst@t1` (tier1), `lead@t1` (soc.lead), `auditor@t1` (auditor); alerts incl. `FIN-DB-001` credential-access scenario (golden vector), plus duplicates and cross-tenant tenant `t2` isolation demo.
- **Ports/env**: `PORT` env var (default 8080), `DATA_FILE` env var (default `data/store.json`).

## 4. Test & verification history

- End-to-end smoke test via curl (documented in security.md §8): login → CSRF → queue (tenant-filtered) → ingest duplicate → dedup link verified → disposition → audit verify → invariant check → tenant-spoof rejection → CSRF rejection.
- Golden vector: seeded FIN-DB-001 scenario computes score 97/band critical when run with default weights (from `02` §4.2). If weights changed via config, new `scoreVersion` is recorded.

## 5. Open items / next steps (reserved)

1. Fuzzy dedup module (state reserved, see `state.md` §5).
2. ML overlay switch wiring (`mlAdjustment` currently fixed 0).
3. SOAR webhook emitter (B5 boundary) — reserved endpoint shape in `state.md` §5.
4. Feedback webhook with HMAC verification (T07).
5. TLS termination guidance / `Secure` cookie behind reverse proxy.
6. Windows packaging: `triage.bat` wrapper or pkg-style single-exe build (optional).

## 6. Session log (append-only)

| Date | Session | Notes |
|---|---|---|
| 2026-09-19 | 1 | Architecture docs 01–07 + ADRs authored (see repo). |
| 2026-09-19 | 2 | Implemented server.js + SPA + security.md + state.md + memory.md; smoke-tested E2E. |
| 2026-09-19 | 3 | Fixed logout CSRF bypass (moved behind CSRF middleware). Fail-closed boot integrity verified: tampered audit chain ⇒ server refuses to start. |
| 2026-09-19 | 4 | Launch-fix session: (1) root cause of "not launching" = stale background instance holding :8080 → EADDRINUSE on every new start; server now prints clear guidance + `triage.bat` auto-clears the port; (2) fixed frontend TypeError `row.append(...).addEventListener` (append returns undefined) that broke alert-detail render when duplicates exist; (3) fixed golden-vector drift — implementation f3 credential-access was 0.9, doc 02 §4.2 specifies 0.8; aligned code to spec, score now 97 exactly; (4) test_e2e.sh is now self-contained (own server :8081 + throwaway store, trap cleanup) so it never pollutes the user's store; 26/26 green. |

> Rule: append a row per working session; never delete rows (this file is itself append-only in spirit).
