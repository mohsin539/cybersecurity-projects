# 🏦 Compliance Automation Suite

**ISO 27001 · Bangladesh Bank ICT Guidelines 2015 · NIST CSF 2.0 · OWASP Top 10 2021**
*Control Mapper & GRC Reporting Platform — one evidence point in → compliant across every framework out.*

---

## What's inside

| Artefact | Purpose |
|---|---|
| `architecture.md` | Reference design (control mapper, layers, security, deployment, reports) |
| `security.md` | Security architecture — RBAC, hash-chained audit, WORM vault, OWASP/ISO/NIST mapping |
| `state.md` | System state — data model, state machines, scoring formulas, snapshot |
| `memory.md` | Decisions log (ADR), gotchas, verification commands, handoff context |
| `backend/` | Runable FastAPI suite — engines, REST API, seeded data, tests |
| `backend/app/static/` | Single-page dashboard (no build step, no CDN) |

## Features
- 🧬 **Control Mapper** — canonical `category` maps ISO ↔ BB ICT ↔ NIST CSF ↔ OWASP with overlap de-duplication
- 📊 **Live Dashboard** — per-framework compliance scores, risk tiers, SLA, heatmaps
- 📡 **Assessment engine** — AUTO/HYBRID runs scoped to any framework
- 🎯 **Risk engine** — CVSS-weighted register, auto-escalation to SLA-tracked tickets
- 🗃️ **Evidence Vault** — WORM storage, SHA-256 chains, auditor evidence packs
- 📥 **Reports** — PDF · DOCX · XLSX · CSV · JSON downloads + evidence ZIP
- 🔐 **Security** — PBKDF2 passwords, JWT, 6-role RBAC, append-only hash-chained audit log (verified by tests)

---

## Quick start (Windows PowerShell)

```powershell
# 1. Install dependencies
cd backend
python -m pip install -r requirements.txt

# 2. (Re)seed the database
python -c "from app.seed import seed; seed(force=True)"

# 3. Run
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000

# 4. Open
#    http://127.0.0.1:8000   → dashboard
#    http://127.0.0.1:8000/docs → interactive API
```

## Demo accounts

| Login | Password | Role |
|---|---|---|
| `admin` | `Admin@12345` | SUPER_ADMIN |
| `ciso` | `Ciso@12345` | CISO |
| `auditor` | `Audit@12345` | ASSESSOR |
| `owner` | `Owner@12345` | CONTROL_OWNER |
| `regulator` | `Regul@12345` | REGULATOR (read-only — tests confirm 403 on writes) |

> ⚠️ Dev credentials only. Rotate via `POST /auth/users` (SUPER_ADMIN) and set `CAS_SECRET_KEY` env var for any non-demo run.

## Tests

```powershell
cd backend
python -m pytest tests -q        # 14 integration tests (auth, RBAC, reports, chains)
```

## Structure

```
backend/
├─ app/
│  ├─ main.py            FastAPI app + lifespan
│  ├─ database.py        SQLite (WAL, FK on) + naive_utcnow()
│  ├─ models.py          ORM: users, frameworks, controls, mappings, assets,
│  │                     scans, evidence(links), assessments, risks, tickets, audit
│  ├─ security.py        PBKDF2, JWT, RBAC _require_, hash-chained audit
│  ├─ seed.py            4 frameworks · 56 controls · 57 mappings · assets · risks · users
│  ├─ engines/
│  │  ├─ mapper.py       canonical mapping, matrix, gaps, overlap dedupe
│  │  ├─ assessment.py   auto/hybrid runs, decisions
│  │  ├─ risk.py         CVSS scoring, escalation, SLA metrics
│  │  └─ evidence.py     WORM vault, chain verify, zip packs
│  ├─ reports/generator.py  PDF/DOCX/XLSX/CSV/JSON/ZIP renderers
│  ├─ routers/           auth · dashboard · controls · assets · assessments · evidence · risk · reports · audit
│  └─ static/            index.html · styles.css · app.js (SPA)
├─ data/                 compliance.db · vault/ · exports/   (generated, git-ignored)
└─ tests/test_api.py     14 integration tests
```

## Key API endpoints

| Method | Path | Purpose |
|---|---|---|
| POST | `/auth/login` | Get JWT |
| GET | `/dashboard/summary` | KPIs + framework matrix + risk |
| GET | `/controls`, `/controls/matrix` | Control catalogue, compliance matrix |
| POST | `/controls/mapping` | Apply canonical mapping |
| POST | `/assessments` | Run AUTO/HYBRID assessment |
| POST | `/evidence/upload` | WORM evidence store |
| GET | `/evidence/integrity`, `/audit/verify` | Tamper-evidence chain checks |
| GET | `/reports/download?report=&fmt=` | PDF/DOCX/XLSX/JSON exports |
| GET | `/reports/csv?report=` | CSV exports |
| GET | `/evidence/pack` | Auditor evidence ZIP + MANIFEST.json |
| POST | `/risk/escalate` | High/critical → SLA tickets |

---

*Built per `architecture.md`. See `security.md`, `state.md`, `memory.md` for the reserved deep-dive docs.*