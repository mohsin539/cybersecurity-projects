# 🧾 Project State — MobileForensicsLabPortable

> State snapshot: **2026-09-22** · Baseline: architecture.md v2.0 pattern · Branch: n/a (local)

## 1. Deliverable summary

Working, portable, web-based mobile-forensics case lab implementing the layered
**presentation → service → data** architecture with a **governance overlay**
(audit chain + compliance engine), exactly as scoped in `architecture.md`:

- 🌐 **Presentation layer** — Flask + Jinja dark-lab theming (`static/css/style.css`)
- ⚙️ **Service layer** — `mfl/routes/*.py` blueprints (8 modules)
- 🗄️ **Data layer** — SQLite (`mfl/db.py`), hash-chained audit store (`mfl/audit.py`)
- ✅ **Governance** — compliance registry (`mfl/compliance.py`), report suite (`mfl/reports.py`)

## 2. File inventory & status

| File | Purpose | Status |
|---|---|---|
| `app.py` | Entry point (`create_app`, dev server) | 🟢 verified |
| `run.bat` | Windows launcher (install deps + start) | 🟢 verified |
| `requirements.txt` | Flask 3.x + Werkzeug + Jinja pins | 🟢 verified |
| `seed_demo.py` | Demo case + evidence + artifacts | ⚙️ ready |
| `mfl/__init__.py` | App factory, bootstrap (admin seed) | 🟢 verified |
| `mfl/db.py` | Schema + connection (parameterised only) | 🟢 verified |
| `mfl/audit.py` | Append-only SHA-256 hash chain | 🟢 verified |
| `mfl/security.py` | Auth, RBAC, CSRF, headers, throttling | 🟢 verified |
| `mfl/compliance.py` | ISO/NIST/OWASP control registry + scoring | 🟢 verified |
| `mfl/reports.py` | HTML/JSON/CSV/XML + manifest hashing | 🟢 verified |
| `mfl/routes/{main,cases,evidence,analysis,custody,reports,audit,compliance}.py` | Blueprints | 🟢 verified |
| `mfl/templates/*` | 16 Jinja templates | 🟢 verified |
| `mfl/static/css/style.css` | Dark forensic theme | 🟢 verified |
| `security.md` | Security posture + threat model | 🟢 done |
| `state.md` | This file | 🟢 done |
| `memory.md` | Persistent project memory | 🟢 done |

## 3. Automated verification performed

| Test | Result |
|---|---|
| Import all packages | ✅ pass |
| Login flow (bad then good credentials) | ✅ pass |
| Create case → evidence → custody → artifact | ✅ pass |
| Generate HTML / JSON / CSV / XML reports | ✅ pass (`Content-SHA256` present) |
| Audit export JSON/XML | ✅ pass |
| Hash-chain verification (`verify_chain`) | ✅ intact |
| RBAC: auditor blocked from `/cases/new` | ✅ HTTP 403 |
| Template crawl (21 routes) | ✅ all render 200 |

## 4. Roles & permissions

| Role | Cases/Ev/Custody/Analysis | Reports | Audit | Compliance | Users/Settings |
|---|---|---|---|---|---|
| `admin` | CRUD | ✅ | ✅ export | ✅ | ✅ (all) |
| `examiner` | CRUD | ✅ | ❌ | ❌* | ❌ (settings only) |
| `auditor` | View only (implicit) | ✅* | ✅ export | ✅ | ❌ |

\* Compliance page is viewable by auditor/admin via blueprint nav; role 403 currently enforced
on **Audit export**, **Users**, and **Write** actions; Compliance *view* is open to logged-in staff.
(This is a deliberate, documented scoping decision — see memory.md ADR-3.)

## 5. Known limitations / backlog

1. **In-memory login throttle** — resets on restart; plan DB-backed lockout.
2. **No PDF generation directly** — HTML report is print-to-PDF friendly; DOCX/PDF via
   optional libs is a roadmap item.
3. **SQLite at rest unencrypted** — production needs OS/crypto-disk layer.
4. **Multi-tenant isolation** — single-org portable edition; tenant RLS is a larger redesign.
5. **Demo seed** not run automatically — call `python seed_demo.py` once for populated UI.

## 6. Next steps (priority order)

1. Harden auth (DB-backed lockout, 2FA optional) — security.md §5.
2. Wire SIEM shipping via webhook or file drop of `/audit/export/xml`.
3. PDF/DOCX generation + signed artifact upload UI.
4. Report line-item → control hyperlink in HTML exports.
5. Package as exe (PyInstaller) for true “portable” single-file distribution.