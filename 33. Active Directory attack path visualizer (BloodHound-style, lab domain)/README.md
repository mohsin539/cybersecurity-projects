# SentinelGraph — AD Attack Path Visualizer (Lab)

BloodHound-style Active Directory attack-path analysis with a bank-grade compliance layer: **OWASP Top 10 2021 · ISO/IEC 27001:2022 · NIST CSF 2.0 · NIST 800-53 r5 · PCI DSS 4.0 · CIS Controls v8**.

![tabs](https://img.shields.io/badge/ui-Dashboard%20·%20Explorer%20·%20Compliance%20·%20Audit-22d3ee) ![tests](https://img.shields.io/badge/tests-12%2F12%20passing-34d399)

## Quick Start

### Single-origin (recommended)
```bash
cd backend
python -m pip install -r requirements.txt -r requirements-frontend-notneeded.txt 2>/dev/null || python -m pip install -r requirements.txt
set SG_JWT_SECRET=change-me-to-a-48-char-random-secret-value-abc123   # PowerShell: $env:SG_JWT_SECRET="..."
python -m uvicorn app.main:app --port 8000
# open http://localhost:8000  → sign in
```

### Dev mode with hot reload
```bash
# terminal 1
cd backend && SG_JWT_SECRET=... python -m uvicorn app.main:app --port 8000 --reload
# terminal 2
cd frontend && npm install && npm run dev   # http://localhost:5173 (proxies /api)
```

**Lab accounts** (demo only — production federates to IdP with MFA):

| User | Password | Role |
|---|---|---|
| `admin` | `ChangeMe!Lab2024` | full control + audit view |
| `analyst` | `Analyst!Lab2024` | analysis + seed/import |
| `auditor` | `Auditor!Lab2024` | read-only + audit view |

## What You Get

- **Dashboard** — risk index, choke points ("fix first"), tier distribution, findings feed with MITRE ATT&CK tags.
- **Graph Explorer** — interactive Cytoscape map; click any principal → attack paths with risk scores, blast radius, Tier-0 impact callouts.
- **Compliance** — live per-framework scores (~90 controls) computed from runtime evidence, with per-control drill-down.
- **Audit Trail** — append-only record of logins, seeds, imports, analyses (admin/auditor).

The bundled **CORP.LAB** seed domain plants 9 realistic bank weaknesses (kerberoastable SQL service account, helpdesk reset on Tier-0, non-DA DCSync, unconstrained delegation, GPP cpassword, …) so every view is immediately meaningful.

## Import Your Own Lab Collection

SharpHound ZIP or bloodhound-python JSON (≤512 MB):

```bash
curl -X POST http://localhost:8000/api/v1/graph/import \
  -H "Authorization: Bearer $TOKEN" -F "file=@20240919_sharphound.zip"
```

Or use the seeded lab domain (default) — `POST /api/v1/graph/seed {"reset": true}` (admin/analyst).

## API Overview (JWT bearer, `/api/v1`)

| Method & Path | Role | Purpose |
|---|---|---|
| `POST /auth/login` | — | rate-limited login (5/min) |
| `GET /graph`, `GET /graph/stats` | any | graph data / counts |
| `POST /graph/seed`, `POST /graph/import` | analyst+ | load demo or real collection |
| `POST /analysis/paths` | any | attack paths + blast radius for a source |
| `GET /analysis/choke-points` | any | highest-leverage principals |
| `GET /analysis/tier0-exposure` | any | who can reach each Tier-0 asset |
| `GET /findings` | any | misconfigurations + ATT&CK + remediation |
| `GET /compliance` | any | 6-framework posture |
| `GET /audit` | admin/auditor | audit trail |

Interactive docs at `/api/docs` (lab profile only).

## Portable EXE (Windows lab laptop)

The app is designed to run as a single portable binary: FastAPI serves both API and UI on `127.0.0.1:8000` with the in-memory graph — no database, no admin rights.

```powershell
pip install pyinstaller
pyinstaller --name SentinelGraph --onefile --add-data "static;static" ^
  --collect-all app --collect-all uvicorn --collect-all jose run.py
```

`run.py` (create next to `app/`):

```python
import os
os.environ.setdefault("SG_ENVIRONMENT", "lab")
import secrets, uvicorn
os.environ.setdefault("SG_JWT_SECRET", secrets.token_urlsafe(48))  # per-run session secret
from app.main import app
uvicorn.run(app, host="127.0.0.1", port=8000, log_level="info")
```

Build the frontend first (`cd frontend && npm run build`) so `backend/static` ships inside the exe. Distribute `dist/SentinelGraph.exe`; each launch generates a fresh session secret (tokens intentionally don't survive restarts).

## Repository Layout

```
ARCHITECTURE.md      full architecture (data model, engines, compliance, security design)
SECURITY.md          threat model, OWASP matrix, hardening checklist
STATE.md             verified feature state + gaps
MEMORY.md            agent/engineer context for resuming work
backend/             FastAPI app, engines, tests (12/12 passing)
frontend/            React+TS+Tailwind SPA (builds into backend/static)
```

## Optional: Neo4j backend

```bash
SG_NEO4J_ENABLED=true SG_NEO4J_URI=bolt://localhost:7687 SG_NEO4J_PASSWORD=... python -m uvicorn app.main:app
```

## License & Scope

Internal lab tooling. Defensive analysis only; no exploitation capabilities. Run collection tools only against domains you are authorized to assess.
