# Project memory — NTM (network topology auto-mapper)

Durable memory for any future session. This is the *single source of truth*
for orientation; read `state.md` and `security.md` for status and threat model.

## Identity

- Project folder: `8. Network topology auto-mapper (SNMP + ARP + traceroute)`
- Task: auto-discover layer-2/3 topology with SNMP, ARP, traceroute; expose
  topology, inventory, audit via a small FastAPI web app; security by design
  (OWASP Top 10:2025, NIST CSF 2.0, ISO 27001:2022 mappings in ARCHITECTURE.md).
- Stack: Python 3.12 + stdlib(sqlite3, hashlib, ipaddress, base64, hmac) +
  FastAPI/uvicorn/pydantic v2. No scapy/pysnmp — everything hand-rolled to
  keep the dependency surface small and auditable.

## Directories & files

```
<root>/
  app/
    __init__.py   config.py  db.py      util.py
    audit.py      auth.py    scope.py
    snmp.py       arp.py     traceroute.py   engine.py    main.py
  ui/             index.html  app.js   style.css
  ARCHITECTURE.md security.md state.md memory.md README.md?  requirements.txt
```

## Architectural invariants (do not regress)

1. **scope gating is server-side and allow-list only.** Never feed an
   arbitrary host/IP list from the UI straight into a collector. `ScanBody.scope`
   → `scope.parse_cidr` → each candidate IP `validate_ip` + `in_scope`.
2. **All /api/* need a valid claim** via `get_claims`/`Depends`; admin concerns
   use `require_roles(...)`. Viewer role ⇒ MAC redacted in responses.
3. **Audit is hash-chained + append-only** (`audit.AUDIT`). `verify()` must stay
   `{'ok': True}` for the demo. Appending must happen on every mutation.
4. **No phantom names.** Every function referenced must exist; before editing,
   dump the module surface (`dir(mod)` + `inspect.signature`) and match.
   This session's #1 recurring bug: main.py referencing `CFG.browser_origin`/
   `CFG.wsgi_secure` that didn't exist.
5. **stdbuf-free logging; no print-based protocol.** If a probe prints nothing,
   check for import failure first (module-level `SyntaxError`/`AttributeError`.
6. Windows/PowerShell: no heredocs. Write `.py` probe files, run them.

## Verified API / module contracts (from live probes)

### db
- `db.init_db()` inits schema.
- `db.q(sql, params=()) -> list[dict]`, `db.q1(...)->dict|None`, `db.run(...)`
- `db.upsert_job(job)`, `db.get_job(job_id)`, `db.get_conn()`
- user mgmt: `get_user`, `create_user`, `list_users`, `ensure_default_admin`,
  `set_password`? (via auth.set_password), `update_user`

### auth (probe-verified export list)
```
authenticate (username, password, code='')  raises AuthenticateError
issue_token? -> token       (see surface dump; names confirmed: authenticate,
confirm_totp, create_user, enroll_totp, get_claims, hash_password, issue_token,
new_salt, pbkdf2, require_roles, set_password, sig_valid, sign, verify_token)
```

### audit
`AUDIT.append(actor, action, target='', detail=None, level='info')`,
`AUDIT.tail(n)`, `AUDIT.verify() -> {'ok':bool, 'broken_at':int|None}`

### engine
`launch_sim_scan(scope, agent='sim', budget_items=6000) -> job_id;  get_job(job_id)`

### main (FastAPI app `app.main.app`) — 14 routes
- `GET  /`                      serves ui/index.html
- `POST /api/login`             body {username,password,code}
- `POST /api/logout`
- `POST /api/scan/sim`          body {scope, budget}  (role: operator/admin)
- `GET  /api/jobs/{job_id}`
- `GET  /api/topology`, `/api/inventory`, `/api/audit`, `/api/export`, `/api/health`
- (docs at /docs)

## Default credentials / bootstrapping

- `db.ensure_default_admin()` creates the first admin on empty DB. See
  config.py defaults; change passwords on first login. TOTP is off by default
  (see security.md §12; enrollment endpoints present, UI next milestone).

## Next actions (highest leverage, in order)

1. `build_exe.ps1` (PyInstaller onefile) + `run.bat` + `README.md` quickstart.
2. Wire TOTP-enroll + password-change into the UI with admin-role gate.
3. Re-verify audit chain after any change: run the sim smoke → job done +
   `AUDIT.verify()=={'ok':True}`.

## Environment quirks to remember forever

- PowerShell 5.1: **no heredocs**, no `<<`. Multi-line python → write file, run.
- Path spelling must match `(SNMP + ARP + traceroute)` exactly.
- `python -X utf8 -c "..."` for one liners but keep them single-line.
- If server probe returns *nothing*, suspect import-time failure in app.main —
  run `python -X utf8 -c "import app.main"` first.
