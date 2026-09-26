# State — NTM 0.2.0

Snapshot written by the assistant at the end of the current working session.
Use this file to see exactly where the build stands; the "verified" claims
below were re-checked live during this session, not assumed.

## What exists (verified on disk this session)

| Path | Purpose | Status |
|---|---|---|
| `requirements.txt` | fastapi, uvicorn, pydantic (FastAPI pulls rest) | present |
| `ARCHITECTURE.md` | full system design + standards mapping | present |
| `security.md` | threat model + OWASP/NIST/ISO control map | present |
| `state.md` | this file | present |
| `memory.md` | durable project memory for future sessions | present |
| `app/__init__.py` | package marker | present |
| `app/config.py` → `CFG` | env-driven settings (db path, secret, lock params) | present |
| `app/db.py` | sqlite schema + helpers (`init_db`, `q`, `q1`, `run`, `upsert_job`, `get_job`, user fns) | present |
| `app/util.py` | b64/sign/totp/pbkdf2/hash/time helpers | present |
| `app/audit.py` | hash-chained audit (`AUDIT.append/verify/tail`) | present |
| `app/auth.py` | PBKDF2 + TOTP + bearer tokens + RBAC (`authenticate`, `verify_token`, `get_claims`, `require_roles`) | present |
| `app/scope.py` | CIDR parsing, RFC1918 deny list, `validate_ip`, `in_scope` | present |
| `app/snmp.py` | SNMPv2c collector (UDP, ASN.1 BER) | present |
| `app/arp.py` | ARP cache parsing/table collection | present |
| `app/traceroute.py` | traceroute/ICMP path collection | present |
| `app/engine.py` | job orchestration (`launch_sim_scan`, `get_job`, runner thread) | present |
| `app/main.py` | FastAPI app: login, logout, scan/sim, jobs/{id}, topology, inventory, export, audit, health | present · imports clean (probed: 14 routes) |
| `ui/index.html` / `app.js` / `style.css` | single-page UI (login + dashboard + topology + inventory + audit) | present |

## Verified this session (live probes, no assumptions)

- `app.main` imports without error; 14 routes register.
- Every `CFG.*` reference in main.py resolves to a real config field
  (probe output showed all resolved; `browser_origin` was the one that
  previously didn't — now derived from `host`/`port`, `wsgi_secure` from
  `session_secret` availability — see `main.py` edits).
- Module surfaces (db/auth/audit/engine/util) dumped live; main.py only calls
  functions that exist (no phantom names — earlier `main.py` referenced
  `CFG.browser_origin`/`CFG.wsgi_secure` which did not exist; fixed).
- E2E sim smoke passed:
  `db.init_db()` → `launch_sim_scan("10.30.0.0/16", agent="sim-ok", budget_items=6000)`:
  job reached `done`, 42 observations persisted, `AUDIT.verify()=={'ok':True}`.
- DB schema live-inspected (`PROBE_SCHEMA` runs): tables `users, settings,
  sanitized_*, scopes, jobs, observations(→devices+links)` as designed.

## Not yet done (next-session backlog)

- [ ] Wire UI buttons for TOTP enrollment / password reset (endpoints exist in
      `auth` surface: `enroll_totp`, `confirm_totp`, `set_password`; no UI).
- [ ] Redis/shared rate-limiter for multi-worker deploys (currently in-memory).
- [ ] Signed binary/exe build step (PyInstaller onefile) — `build_exe.ps1`
      template lives in EXTENDED_DOCS section; actually runner logic exists but
      the .ps1 was not written this session. **Create `build_exe.ps1`.**
- [ ] `run.bat` launcher for one-click start. **Create.**
- [ ] README.md with quickstart. **Create.**

## How to run

```
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt
.venv\Scripts\python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open http://127.0.0.1:8000 — sign in (default admin created by
`db.ensure_default_admin` on first boot; creds documented in config/ARCHITECTURE).

## How to test

```
python -X utf8 -c "from app import db, engine, audit; db.init_db(); ...
```
or drive the API layer via the FastAPI TestClient / a probe that boots uvicorn
(see probe_e2e usage pattern — note: TestClient requires `httpx`; if using the
starlette TestClient you must `pip install httpx` first).

## Environment caveats (PowerShell)

- PowerShell 5.1 here: **no heredocs**, `rg`/`grep` limited; always prefer
  writing a `.py` probe file to disk then running it (never inline `python -c`
  for multi-line code).
- Windows: use `-X utf8` for python and read/write paths with the exact
  `(SNMP + ARP + traceroute)` spelling.
