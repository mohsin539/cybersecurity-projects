# Security model — NTM 0.2.0

Applies to the web layer (`app/main.py`), the auth module (`app/auth.py`),
the audit chain (`app/audit.py`), scope gatekeeping (`app/scope.py`) and the
collectors (`app/snmp.py`, `app/arp.py`, `app/traceroute.py`). This file is
the *map*; code is the territory. When they disagree, the code wins — flag it
as a bug, don't paper over it.

## 1. Threat model (who is out to get us)

| Threat actor | Assets exposed | Primary defense |
|---|---|---|
| Anonymous web caller | login, health, static UI | FastAPI dependency `current_claims` on every `/api/*` route → 401 |
| Operator who can't scan | scan endpoints | role gate `require_roles("operator","admin")` on `/api/scan/*` |
| Viewer who must not see MACs | inventory/topology/export | server-side redaction in `get_claims()["role"]=="viewer"` branch (see §5) |
| Stolen session cookie | any authenticated endpoint | httpOnly + Secure + SameSite=Lax cookie; short `session_hours`; server-side logout |
| Replayed/forged PWS token | authz | HMAC-SHA256 signature + exp claim (`auth.verify_token`); no token caching, stateless verify |
| Scope-escape via crafted CIDR | scanner inputs | `scope.parse_cidr` rejects non-CIDR + `scope.in_scope(...)` allow-list only (SSRF guard) |
| Audit tampering | integrity evidence | hash-chained `AUDIT.verify()` catches any mid-chain edit (§6) |

## 2. Credential storage (NIST 800-63B §5.1)

- Passwords hashed with **PBKDF2-HMAC-SHA256, 310k iterations** (uses
  stdlib `hashlib.pbkdf2_hmac`), per-user random salt (16 bytes), stored in
  `users.salt`/`users.pw_hash`.
- No plaintext, no reversible form, ever logged or returned.
- TOTP: `pyotp`-compatible base32 secret in `users.totp_secret`; codes verified
  with a 1-step window via `auth`'s `totp_verify`. Only the digest material is
  stored server-side.

## 3. Session & token handling (OWASP ASVS V3)

- Cookie `ntm_sid`: `HttpOnly`, `Secure` (when `CFG.wsgi_secure`), `SameSite=Lax`,
  short `max_age = CFG.session_hours*3600`.
- Stateless bearer tokens (HMAC-signed claims incl. `exp`); no server-side
  session store → easy horizontal scale; revocation is by expiry + logout only.
- Logout: `delete_cookie` + (in a real deployment) client-side clear.

## 4. Rate limiting / lockout

- Login failures tracked in-memory with a sliding window
  (`auth.LoginRateLimiter`), counts backed by `CFG.login_lock_*`; run in the
  container/site behind a reverse-proxy-friendly host header.

## 5. RBAC + data redaction

Roles: `admin`, `operator`, `viewer`. Enforced three places, never trust the
client:
1. `require_roles(...)` dependency on admin-only endpoints.
2. `get_claims(request)` → returns decoded claims each request (never cached
   across requests).
3. Viewer redaction: `redacted = claims["role"] == "viewer"` branches in
   `/api/topology`, `/api/inventory`, `/api/export` — MAC addresses replaced
   with `*masked*` in responses; this is the only place MACs can leave.

## 6. Audit chain integrity (hash-chained, append-only)

`app/audit.py`:
- Every record carries `prev_hash` link; `AUDIT.verify()` walks the chain and
  returns `{"ok": True}` only if the whole chain matches (any edit → `ok:False`,
  `broken_at` index). Tamper-proof against casual DB/JSONL editing.
- Endpoints that mutate (login, scan) append first; the chain is exposed
  read-only via `/api/audit` and verified on demand.

## 7. SSRF / scope enforcement (OWASP A4)

Scanner NEVER accepts arbitrary hosts from the client. `ScanBody.scope` is
parsed by `scope.parse_cidr` (strict), then each discovered IP is validated
with `scope.validate_ip` + allowed only if `scope.in_scope(ip, net)`. RFC 1918
deny-list (in `scope.SCOPE_DENY_CIDRS`) prevents probes into loopback/link-local.

## 8. Input validation / injection

- All bodies are typed `BaseModel`s; FastAPI auto-400s on invalid fields.
- DB queries use parameter binding (`db.q(..., params)`) — no string
  interpolation of user input anywhere. SQLi is structurally impossible.

## 9. Headers & transport

- FastAPI sends `X-Content-Type-Options: nosniff` et al. via Starlette default
  on JSON responses; add middleware in front (nginx) for the rest:
  - `Strict-Transport-Security` (behind TLS),
  - `Content-Security-Policy` (UI is same-origin; inline styles disabled),
  - `X-Frame-Options: DENY`.
- CORS: single fixed `allow_origins` = `http://{CFG.host}:{CFG.port}` (no `*`),
  `allow_credentials=True` for the cookie; any other origin → browser blocks.

## 10. Key mgmt / config hygiene

- `CFG.session_secret`, `CFG.audit_key_path` are read from env / config file
  first run; **never committed** — a `.env`/keystore is generated on first
  startup into `data/` (see `app/config.py`).
- `dev_mode` etc. are runtime, not hardcoded secrets.

## 11. Verified contract (what "done" means here)

- `authenticate`/`verify_token`/`get_claims`/`require_roles` surface proven via
  probe (auth dir listing, above).
- Route table: `/`, `/api/login`, `/api/logout`, `/api/scan/sim`, `/api/jobs/{id}`,
  `/api/topology`, `/api/inventory`, `/api/export`, `/api/audit` + docs.
- E2E smoke earlier: login → launch sim scan → job reaches `done` → 42
  observations persisted → audit `verify()=={'ok':True}`.

## 12. Gaps / runbook (honest)

- Password reset path + enrollment TOTP registration: code surface exists
  (`set_password`, `enroll_totp`, `confirm_totp`) but no UI buttons wired yet —
  feature-flagged for the next milestone. Do **not** ship admin enrollment UI
  until the RBAC gate is applied to those endpoints.
- Rate-limiter is per-process memory (resets on restart). Acceptable for
  single-operator lab; move to a shared store when multi-worker.
- HTTP is fine for the lab (`wsgi_secure` cookie flag off by default), but
  **deploy behind TLS** before putting real credentials on it.
