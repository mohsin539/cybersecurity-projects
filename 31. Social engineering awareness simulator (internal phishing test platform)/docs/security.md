# SEAS — Security Design (security.md)

Reserved design document for the Social Engineering Awareness Simulator (SEAS),
an internal phishing test platform for Bangladeshi banks.

Scope: confidentiality, integrity, availability and evidence for the simulation
lifecycle (consent → campaign → lure → tracking → risk → training → report).
Compliance drivers: **Bangladesh Bank ICT Security Guidelines**, **OWASP Top 10 (2021)**,
**NIST CSF 2.0**, **ISO/IEC 27001:2022 Annex A**.

## 1. Security Objectives

| Objective | Mechanism in this build |
|---|---|
| Confidentiality | JWT access tokens, RBAC, hashed passwords (PBKDF2-HMAC-SHA256, 600k iterations), masked PII in API traces and exports |
| Integrity | Tamper-evident hash chain over all audit events; signed report download tokens |
| Availability | Stateless API with SQLite default (Postgres-ready), thread-based delivery simulation, rate limiting on login |
| Evidence | Every state change writes an immutable, chained `AuditLog` row (`app/services/audit.py`) |

## 2. Assets & Data Classification

| Asset | Class | Protection |
|---|---|---|
| Employee PII (name, phone, email, branch, grade) | Confidential | Masked in submit events; `password` fields never stored |
| Phishing credential dumps | Highly Confidential | Captured transiently, hashed (SHA-256), **not persisted**; only SE-Index is credited |
| Campaign strategy / lure templates | Internal | RBAC `admin`/`security` only; audit trail |
| Report bundles (.xlsx/.csv/.html) | Confidential | Saved server-side; access via short-lived signed token |
| Audit chain | Highly Confidential | Append-only service, hash-linked rows |

## 3. OWASP Top 10 (2021) → Implementation Map

| OWASP A- | Risk in SEAS | Control in code |
|---|---|---|
| A01 Broken Access Control | Analyst vs admin; auditor must not approve | `app/deps.py:require_roles(...)` + per-route role gates on every router; launch gated to `admin` |
| A02 Cryptographic Failures | Credentials, tokens, DB at rest | PBKDF2 600k round SHA-256; JWT HS256 with env secret; real secrets never committed |
| A03 Injection | SQL, HTML, headers | SQLAlchemy 2.0 ORM bound parameters; export HTML escaping; no string-built SQL in app code |
| A04 Insecure Design | Fake-login page could leak | Submit stores only salted hash + event; never a plaintext password; landing pages are seed-owned HTML |
| A05 Security Misconfiguration | Default creds, open CORS | Seed users only via `create_all`; CORS restricted; HSTS + `X-Phish-Security` headers middleware in `app/main.py` |
| A06 Vulnerable Components | Python/JS deps | Pinned `requirements.txt` + npm lockfile; run `pip-audit` / `npm audit` pre-deploy |
| A07 Identification & Auth Failures | Weak login, brute force | 8-fail/60s sliding-window rate limiter in `app/security.py` login bridge |
| A08 Software & Data Integrity | Report tampering | HMAC-signed download tokens (expiry 15 min) in `app/routers/reports.py`; report bundles hashed into audit chain |
| A09 Security Logging & Monitoring | Missing evidence | Every mutating action logged via `require_roles`-wrapped audit service with chained hashes |
| A10 SSRF | Lure redirect abuse | Tracking redirect targets are internal token-mapped URLs, never user-supplied hosts |

## 4. NIST CSF 2.0 Functions

- **Govern**: RBAC model, role-separation for campaign approval (admin + security dual sign-off), retention policy.
- **Identify**: SE-Index 0–100 identifies at-risk employees; do-not-phish (`opt_out`) individuals excluded.
- **Protect**: PBKDF2 hashing, JWT, HSTS, rate limiting, hashed credential handling.
- **Detect**: Open-pixel, click and submit events give live visibility into phish-prone behavior.
- **Respond**: `REPORTED` path = staff who recognized the lure; immediate feedback loop.
- **Recover**: Re-training cohorts auto-assigned for at-risk profiles (`/api/v1/training/auto-assign`).

## 5. ISO 27001:2022 Annex A mappings (subset)

| Control | Application |
|---|---|
| A.5.15 Access Control | RBAC roles: admin, security, hr, analyst, auditor |
| A.6.8 Security of coding | ORM everywhere, no raw SQL string interpolation |
| A.8.2 Information classification | PII vs campaign strategy separation above |
| A.8.10/8.11/8.12 Vulnerabilities | Pinned deps + pre-deploy audit scans |
| A.8.12 Data leakage prevention | Credentials hashed; downloads are token-bound |
| A.8.16 Monitoring | Audit hash chain, dashboard telemetry |
| A.7.13 Asset handling | Consent records + opt-out per employee |

## 6. Transport & Headers

`app/main.py` middleware emits (in addition to FastAPI defaults):

```
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: no-referrer
X-Phish-Security: protected-simulation-frame
```

TLS terminates at the ingress gateway (bank requirement); the app itself is served
behind that terminator in production.

## 7. Secrets Handling

- `.env` is never committed; `.env.example` documents variable names only.
- `JWT_SECRET`, `SIGN_SECRET`, `DB` all read from environment via `app/config.py`.
- Report signing keys are rolled via env restart; tokens are HMAC-signed and expiring.
- No secrets in code, seed data uses clearly-labelled demo passwords.

## 8. Data Residency & Retention (Bangladesh)

- Data stored on premises (SQLite default → Postgres on bank-managed host).
- Raw credential values are never written to disk or export files; exports contain
  masked usernames and per-employee SE-Index only.
- Retention flags: audit chain retained per regulatory window; lure artifacts
  (templates/landing pages) archived after campaign close.

## 9. Security Checklist / Pre-Deploy

1. Run `pip-audit` on backend, `npm audit` on frontend.
2. Pin CORS `allow_origins` to the exact console origin.
3. Generate fresh `.env` secrets; rotate quarterly.
4. Set `LOGIN_RATE` limits per branch-size; enable CAPTCHA at high watermarks.
5. Verify audit chain with the included smoke test (`backend/tests/smoke.py`, `SMOKE TEST PASSED`).
6. Test `opt_out` excludes individuals end-to-end before a real drill.