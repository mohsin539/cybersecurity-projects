# Social Engineering Awareness Simulator (SEAS)

Internal phishing / social-engineering test platform for Bangladeshi banks.
FastAPI + React (Vite + TypeScript). OWASP Top 10, NIST CSF 2.0, ISO 27001:2022
design guidance; reports export to `.xlsx`, `.csv` and `.html`.

## Layout

```
backend/                 FastAPI app (auth, campaigns, tracking, reports, audit)
  app/main.py            entry, security headers, CORS, serve_frontend()
  app/models.py          ORM entities (16 tables incl. audit chain + consent)
  app/security.py        PBKDF2 600k hashing, JWT, login rate limiter
  app/services/          delivery simulator, SE-Index scoring, xlsx/csv/html exporters
  tests/smoke.py         end-to-end API test — must end SMOKE TEST PASSED
frontend/                React + Vite + TS console (Dashboard, Campaigns, Targets, Training, Reports, Audit)
docs/                    architecture.html/.md, topology.mmd, security.md, state.md, memory.md
```

## Run (dev)

Backend:

```
cd backend
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -u tests\smoke.py        # end-to-end check
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --port 8000
```

Frontend (auto-built UI also served by backend at `/` if `frontend/dist` exists):

```
cd frontend
npm install
npm run dev        # http://localhost:5173 (proxies /api and /t to :8000)
npm run build      # strict tsc + vite, outputs dist/
```

## Seeded demo access

| role    | username | password |
|---|---|---|
| admin   | admin    | Admin@12345 |
| security| security | Security@12345 |
| hr      | hr       | HR@12345678 |
| auditor | auditor  | Audit@12345 |

API docs: `http://localhost:8000/docs`