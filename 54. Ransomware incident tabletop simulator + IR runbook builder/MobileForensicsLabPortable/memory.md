# 🧠 Persistent Memory — MobileForensicsLabPortable

> Purpose: **reservation of context** across sessions/projects. Read before continuing work.

## 1. Project identity

- **Name:** MobileForensicsLabPortable ("MFL")
- **Location:** `…\54. Ransomware incident tabletop simulator + IR runbook builder\MobileForensicsLabPortable`
- **Architecture source:** sibling `architecture.md` (layered: presentation → service → data,
  governance overlay: audit chain + compliance engine; report downloads + comprehensive audit formats).
- **Stack:** Python 3.12 · Flask 3.1 · SQLite (single-file portable) · server-side Jinja
- **Runtime facts:** Windows, no git repo, Python + Flask 3.1.3 verified installed.
  Run: `run.bat` → http://127.0.0.1:5000 → login `admin / admin123!`.

## 2. Architecture decisions (ADR)

| ADR | Decision | Why |
|---|---|---|
| ADR-1 | Single portable Flask app (no containers) | Matches "portable lab" brief; zero infra, local-first |
| ADR-2 | SQLite + parameterised queries; JSONB-free | Portable; OWASP A03 fully covered |
| ADR-3 | Compliance *view* open to staff; **exports** restricted | Auditors must read posture, writes stay privileged |
| ADR-4 | Audit via append-only table, SHA-256 `prev_hash` chain, secret keyed | Tamper-evidence without a blockchain/HSM dependency |
| ADR-5 | Reports = HTML/JSON/CSV/XML with `Content-SHA256` | Zero extra deps; PDF deferred to print pipeline |
| ADR-6 | Bootstrap creates `admin` user idempotently | Deterministic first-run; password change is Step-1 hardening |
| ADR-7 | RBAC roles: `admin`, `examiner`, `auditor` | Mirrors real lab separations of duty |

## 3. Conventions (ALWAYS follow)

- **No comments in code unless asked.** (User's global rule.)
- Every DB call is parameterised: `cur = db.execute(sql, args)` — never f-string SQL.
- Every state change MUST fire `audit(app, actor_id, actor_role, ACTION, subject_type, subject_id, context, severity)`.
  Register new action strings in `mfl/audit.py → ACTIONS` **or it raises ValueError**.
- New privileged routes MUST use `@login_required` + `@role_required(...)` from `mfl/security.py`.
- Templates: extend `base.html`; keep panel styling via existing CSS classes (`card`, `tag tag-*`, grid/dots).
- `g_user_id()` / `g_user_role()` live in `mfl/security.py` (NOT in route modules).
- Report/export endpoints set `Content-SHA256`, `no-store`, `X-Robots-Tag: noindex`.
- Tests live outside repo (temp dir) or in `tests/` if introduced; run before delivery.

## 4. Verified facts from last session (2026-09-22)

- Smoke test PASSED: login, case/evidence/custody/artifact CRUD, all 4 report formats,
  audit export, chain integrity, RBAC 403.
- Crawl test PASSED: all 21 GET routes render 200.
- Bugs fixed late in session: `init_audit` secret-key encoding; `_case_bundle` case_id join;
  report bundle JSON (case is single dict not list); ADR of role helpers to security.py.

## 5. Recurring patterns (copy from these)

- **Add audited mutation:** copy a route from `cases.py` (create) → insert → `audit(...)` → redirect+flash.
- **Add control:** extend `CONTROLS` list in `mfl/compliance.py` with `(ref, framework, control, capability, audit_actions)`.
- **Add action:** append to `ACTIONS` in `mfl/audit.py`.
- **Add export:** mirror `mfl/routes/reports.py` pattern (generate → `_send` + sha256 header).

## 6. Open loops & where they live

| Loop | File anchor | Plan |
|---|---|---|
| DB-backed login lockout | `mfl/security.py` `_fail_tracker` | Replace dict w/ table, window TTL |
| PDF/DOCX | `mfl/reports.py` | Add optional libs behind try/except |
| SIEM shipping | `mfl/routes/audit.py` export | Webhook/CEF format |
| Packaging exe | `app.py` | PyInstaller spec in backlog |

## 7. Security reminders (reserved for future sessions)

- Default bootstrap creds are the #1 risk — flag first-login password change.
- Keep `security.md §5` hardening checklist enforced; never weaken it silently.
- If DB migrates: keep `prev_hash`/`hash` NOT NULL; migration must re-link the chain.