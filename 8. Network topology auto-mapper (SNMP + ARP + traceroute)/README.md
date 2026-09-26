# 8. Network Topology Auto-Mapper (SNMP + ARP + traceroute)

Pure-Python (3.12) network **topology auto-mapper**: discovers a network,
builds a link topology (L2/L3), inventories every device, and trails every
change through a tamper-evident audit chain — wrapped in a small FastAPI web
app with role-based access control (viewer/operator/admin), TOTP 2FA, and
RBAC scoped to the standards in `security.md` (OWASP Top 10:2025, NIST CSF
2.0, ISO/IEC 27001:2022).

`ARCHITECTURE.md`  → how it fits together (layers, DB, API contract, threat map)
`security.md`      → threat model + what each module does about it
`state.md`         → what is actually built & verified, what's left
`memory.md`        → durable project-memory cheat sheet for the next session

## Quickstart (dev, PowerShell / Windows)

```powershell
# create venv once
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt

# boot the API (FastAPI app "app.main:app")
python -X utf8 -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open http://127.0.0.1:8000 — the UI (login → dashboard → scan → topology →
inventory → audit) is served at `/`. API docs at `/docs`.

Default admin is created on first boot (`app.db.ensure_default_admin()`).
Change the password on first login; TOTP enrollment UI is the next-milestone
item (endpoints already exist: `POST /api/auth/totp/enroll` · `/confirm`).

## One-click / packaged builds

- `run.bat` — venv + install + uvicorn in one double-click.
- `build_exe.ps1` — PyInstaller onefile `dist\network-topo-mapper.exe` with
  the UI bundled; run `powershell -ExecutionPolicy Bypass -File build_exe.ps1`.
  Add `ui` data via `--add-data` in that script if the UI isn't auto-included.

## Quick tour of the API (all JSON; bearer token via `Authorization: Bearer`)

```
POST /api/login                        {username, password, code?}  -> token
POST /api/logout
POST /api/scan/sim                     {scope: "10.0.0.0/16", budget?} -> job id
GET  /api/jobs/{job_id}                job status + progress
GET  /api/topology                     nodes + links (viewers get MACs redacted)
GET  /api/inventory                    device inventory
GET  /api/audit                        audit-chain tail + verify()
GET  /api/export?fmt=json|graphml      topology export
GET  /api/health
```

## Tests

Backend contract smoke (started a job, finished, 42 observations persisted,
audit chain verified) lives in `contract_smoke.py` — run with `python
contract_smoke.py`. See `state.md` §"How to test" for the exact command list.

## Layout

```
app/       Python package (db, auth, audit, engine, scope, snmp, arp,
           traceroute, util, config, main)
ui/        single-page front-end (index.html, app.js, style.css)
data/      sqlite DB + audit chain (created at runtime; never committed)
```

## License / ethics

Lab tool. You are responsible for scoping scans to networks you own or are
explicitly authorized to probe (see `scope.py` deny-list + `security.md`).
