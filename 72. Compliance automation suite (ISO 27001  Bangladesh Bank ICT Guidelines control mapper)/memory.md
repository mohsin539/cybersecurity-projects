# 🧠 Memory.md — Working Memory, Decisions & Agent Context

> **Reserved & maintained as the project's memory/decisions ledger (ADR-style).** Captures intent, constraints, decisions, gotchas, and hand-off context for any future agent or maintainer working on this suite.

---

## 1. Project Intent (the "why")

> "One evidence point in → compliant positioning across every framework out."

Build a **GRC (Governance, Risk & Compliance) automation suite** that maps controls across four+ regimes — **ISO/IEC 27001:2022, Bangladesh Bank ICT Guidelines 2015, NIST CSF 2.0, OWASP Top 10 2021** (PCI-DSS optional future) — and produces auditor/regulator-ready reports in **PDF · DOCX · XLSX · CSV · JSON (+ evidence ZIP)**. Reference blueprint: `architecture.md`.

---

## 2. Decisions Log (ADR)

| # | Decision | Rationale | Status |
|---|---|---|---|
| D1 | **Build as runnable full-stack demo** (FastAPI + SQLite + vanilla-JS SPA) | The architecture describes production scale (PostgreSQL/Neo4j/K8s); a runnable vertical slice proves behaviour | ✅ implemented |
| D2 | **Naive UTC timestamps everywhere** | SQLite + SQLAlchemy store naive datetimes; tz-aware vs naive comparisons crashed (`TypeError`) | ✅ fixed (see §4) |
| D3 | **SHA-256 hash-chained audit & evidence ledger** | Tamper-evidence for ISO A.8.15 / OWASP A09 without external infra | ✅ implemented |
| D4 | **Canonical `category` as mapping key** | CCO intent-matching across heterogeneous control numbering (A.8.24 ↔ CH-14 ↔ PR.DS-1 ↔ A02) | ✅ implemented |
| D5 | **RBAC `require()` FastAPI dependency per route** | Deny-by-default; regulator read-only verified by test | ✅ implemented |
| D6 | **Latest assessment wins for compliance_matrix** | Report engines read the newest COMPLETED/REVIEWED assessment per framework | ✅ implemented |
| D7 | **Auto-escalation: CRITICAL/HIGH OPEN risks → tickets** | Ops-friendly SLA loop; SLA defaults 24/72/168h | ✅ implemented |
| D8 | **WORM by convention (no update/delete evidence endpoints)** | Simplest honest immutability in demo scope | ✅ implemented |
| D9 | **SQLite as dev store; Postgres swap documented** | Zero-config startup for the masterclass; `state.md` records target | ✅ (documented) |
| D10 | **CI gate = `pytest` + integrity/chain checks** | 16 tests lock behaviour; vault + audit chain verify endpoints included | ✅ passing |
| D11 | **BB ICT F&R Return generator** | Regulator-ready quarterly return (`/reports/download?report=bb_fr`) — multi-sheet XLSX (cover/chapter/control/evidence/findings), CSV, PDF; closes architecture §9 catalogue gap | ✅ implemented |
| D12 | **Report downloads gated on `report:read`** | Permits read-only roles (ASSESSOR/REGULATOR/VIEWER) to export the F&R return & evidence packs per §12 while write endpoints stay guarded | ✅ implemented |

---

## 3. Architecture vs Implementation Map

| architecture.md item | Implementation |
|---|---|
| Control Mapper Engine §5 | `backend/app/engines/mapper.py` |
| Risk Engine §4.3 | `backend/app/engines/risk.py` |
| Assessment Engine | `backend/app/engines/assessment.py` |
| Evidence Vault §4.4 | `backend/app/engines/evidence.py` |
| Reporting §9 | `backend/app/reports/generator.py` |
| BB ICT F&R Return (Quarterly) §9 | `backend/app/reports/generator.py::build_bb_fr_return` — Cover/Chapter/Control/Evidence/Findings sheets |
| Security §8 | `backend/app/security.py` |
| API routers | `backend/app/routers/*` |
| RBAC matrix §12 | `ROLE_PERMISSIONS` in security.py + mirrored in `static/app.js` |
| Dashboard KPIs §14 | `routers/dashboard.py` + `static/app.js::renderDashboard` |
| Data model §6 | `backend/app/models.py`, `state.md` |

---

## 4. Gotchas & Lessons Learned (do not re-break)

1. **Naive vs aware datetimes** — always use `naive_utcnow()` (`database.py`). A tz-aware `datetime.now(timezone.utc)` compared against a DB-read naive value throws `TypeError: can't compare offset-naive and offset-aware datetimes`.
2. **Audit row hash must embed the stored timestamp.** Compute `ts` once, use it both in the chain payload and as `created_at`, otherwise `/audit/verify` fails on the very rows it just wrote.
3. **JWT secret ≥ 32 bytes** — PyJWT warns `InsecureKeyLengthWarning` and the message is noisy in CI.
4. **SQLite strips tzinfo** — store naive; serialize `.isoformat()` for APIs.
5. **`set` of dicts is unhashable** — mapping graph nodes need a `dict keyed by id` (`routers/controls.py::mapping_graph`).
6. **`return` can silently vanish in large-edits** — `compliance_matrix` returned `None` after an edit and dashboard 500'd (`matrix["overall"]`). Always re-run pytest after edits.
7. **`db.add(x).attr = y` is a pyflakes-style foot-gun** — `db.add()` returns `None`; the accidental `.collect`/`.tier =` chains crashed seed. Prefer explicit assignment then `db.add`.
8. **Background Start-Job dies with the shell session** — for persistent dev server use `Start-Process -WindowStyle Hidden` or `uvicorn` in its own terminal.
9. **Auth header is the only auth channel in the SPA** — no cookies; downloads use `fetch → Blob → <a download>` since `window.location` can't carry the bearer token.
10. **StaticFiles mount at `/`** must be registered *after* all API routers so `/auth/...` etc. win the routing table.

---

## 5. Demo Accounts (dev only — rotate for any real use)

| Username | Password | Role |
|---|---|---|
| `admin` | `Admin@12345` | SUPER_ADMIN |
| `ciso` | `Ciso@12345` | CISO |
| `auditor` | `Audit@12345` | ASSESSOR |
| `owner` | `Owner@12345` | CONTROL_OWNER |
| `regulator` | `Regul@12345` | REGULATOR (read-only) |

---

## 6. Verification Commands (the "memory")

```powershell
# from backend/
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000          # run suite
python -m pytest tests -q                                           # 14 tests gate
python -c "from app.seed import seed; seed(force=True)"              # reset + reseed
python -c "from fastapi.testclient import TestClient;\
from app.main import app; c=TestClient(app);\
r=c.post('/auth/login',json={'username':'ciso','password':'Ciso@12345'});\
print(c.get('/dashboard/summary',headers={'Authorization':'Bearer '+r.json()['token']}).status_code)"
```

---

## 7. Open Threads / Next Steps

- [ ] **AI-assisted mapping (P3)** — LLM suggestions human-approved, same `ControlMapping` table
- [ ] **ALEMBIC migrations** instead of drop/recreate
- [ ] **PostgreSQL swap** + RLS for true multi-tenancy
- [ ] **OIDC/Keycloak** SSO+MFA replacement of demo passwords
- [ ] **ZIP audit-pack** with signed manifest consumption guide
- [ ] PCI-DSS 4.0 framework pack (architecture.md marks 9/12)

---

## 8. Handoff Note

If you pick this suite up: **start from `architecture.md`** (design), **`state.md`** (data/state), and this file (decisions/context). Verify with §6 commands before changing anything, then extend with another pytest per new behaviour. Keep `security.md` in sync with any auth/vault/RBAC change — it is the reviewer-facing security story.

> **Doc status:** Reserved & living — append a new ADR row for every architectural decision.