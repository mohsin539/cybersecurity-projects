# 🛡️ Security Posture — MobileForensicsLabPortable

> Version 1.0.0 · Status: **Implemented & verified** · Owner: CISO (reference copy for reservations/audits)

This document records the security controls implemented **in this codebase**, mapped to
ISO/IEC 27001:2022 Annex A, NIST CSF 2.0, NIST SP 800-53 Rev 5 and OWASP Top 10 (2021).
An executable Statement of Applicability is generated live in-app at **Compliance → Dashboard**,
and the tamper-evident trail it depends on is verifiable at **Audit → Verify chain**.

---

## 1. Executive summary

MobileForensicsLabPortable ships as a **single-portable Flask application** (Python, SQLite).
It is designed as a **zero-trust, defence-in-depth** evidence lab console:

| Area | Control | Status |
|---|---|---|
| Authentication | Session cookies, PBKDF2 password hashing, login throttling | ✅ Implemented |
| Authorization | RBAC (admin / examiner / auditor), deny-by-default | ✅ Implemented |
| Integrity | SHA-256 evidence hashing + hash-chained audit log (WORM-style) | ✅ Implemented |
| Web | CSRF tokens, security headers, parameterised SQL, autoescaping | ✅ Implemented |
| Monitoring | Every action emitted to immutable audit trail + exports | ✅ Implemented |

---

## 2. OWASP Top 10 (2021) coverage

| ID | Risk | Implementation |
|---|---|---|
| **A01** | Broken Access Control | `role_required()` decorator on every sensitive route (`mfl/security.py`); restricted modules: Audit, Compliance, Users, Chain-verify. Verified: auditor gets **403** on `/cases/new` (`smoke_test`). |
| **A02** | Cryptographic Failures | TLS expected at reverse-proxy; at-rest hashing (SHA-256); passwords PBKDF2 via `werkzeug`; secret key from env or CSPRNG. |
| **A03** | Injection | **Every** DB call uses parameterised queries (`mfl/db.py`). Jinja autoescape on; `escape()` used in generated HTML reports. |
| **A04** | Insecure Design | STRIDE review documented (see §4); threat modeling per new module. |
| **A05** | Sec. Misconfiguration | Secure headers + CSP + `X-Frame-Options: DENY`; opaque error pages (no stack trace exposure); `$_SESSION`-style settings no debug default. |
| **A06** | Vulnerable Components | Pin `requirements.txt`; run `pip-audit`/`pip check` before release (annotated in CI gate below). |
| **A07** | Identification/Auth Failures | Login throttling (5 attempts/IP, in-memory), session lifetime 45 min, cookies `HttpOnly` + `SameSite=Lax` + optional `Secure`. |
| **A08** | Software & Data Integrity | CSRF on all state changes; downloads carry `Content-SHA256` header; audit chain tamper-evident. |
| **A09** | Logging & Monitoring Failures | Structured audit events, append-only, SIEM-exportable (JSON/XML/CSV). Verify with `verify_chain()`. |
| **A10** | SSRF | **No server-side URL retrieval anywhere in the codebase.** Download links are own-origin responses. |

---

## 3. ISO 27001:2022 (Annex A) mapping — implemented

| Clause | Control | Where |
|---|---|---|
| 5.9 | Asset inventory | Evidence & case registry (case → evidence items) |
| 5.15 | Access control | RBAC + `role_required` + `login_required` |
| 8.2 | Privileged access | Role-gated admin module; restricted audit export (admin/auditor) |
| 8.15 | Logging | `audit_events` table, append-only API model |
| 8.16 | Monitoring | `verify_chain()` run in-app; alert on integrity break |
| 8.24 | Cryptography use | SHA-256 evidence + chain; PBKDF2 passwords |
| 8.28 | Secure coding | Parameterised queries, autoescape, CSP |
| 8.31/8.33 | Backup / testing | SQLite file is portable & copyable; DR step documented (§7) |

> Full interactive matrix is rendered in-app: **Compliance → Control registry → evidence mapping**.

---

## 4. Threat model (STRIDE)

| Element | Threat | Mitigation |
|---|---|---|
| Login/User | Spoofing | PBKDF2 hashes, throttled attempts, session mutation |
| Case/Evidence | Tampering | SHA-256 hashes + audit events on every write |
| Audit store | Repudiation | Hash chain (`prev_hash → hash`), secret-keyed, WORM-style |
| Report export | Info disclosure | Role checks, `no-store`, `X-Robots-Tag: noindex` |
| Forms (all) | CSRF | Per-session token enforced on POST/PUT/PATCH/DELETE |
| Upload | Mass file/DoS | `MAX_CONTENT_LENGTH` cap (default 25 MB); no file persistence |

**Residual risks**
- In-memory login throttle resets on restart → replace with DB-backed lockout for appliance/hosted deployment.
- CSRF header check relies on same-origin `X-CSRF-Token` from app scripts; forms always embed the token.
- SQLite file at rest is **not encrypted**; encryption-in-rest requires OS-level (BitLocker/LUKS) in production.

---

## 5. Hardening checklist (production)

- [ ] Set a strong `MFL_SECRET` (env var) and keep it secret.
- [ ] Change bootstrap admin password (`admin / admin123!`) on first login.
- [ ] Enable `MFL_COOKIE_SECURE=1` behind HTTPS.
- [ ] Put behind TLS-terminating reverse proxy (nginx/Caddy); keep CSP headers active.
- [ ] Replace in-memory rate limiter with DB-backed version for multiple instances.
- [ ] Run `pip-audit` + `python -m pip check` in CI; rotate dependencies quarterly.
- [ ] Back up `instance/mfl.db` regularly; restore-test annually (RTO ≤ 4 h).
- [ ] Record audits to a central SIEM via `/audit/export/xml`.

---

## 6. Authorized use & boundaries

- This tool is a **case-management + integrity layer** around a forensics lab, not a
  device-imaging tool. Acquisition hashes are user-supplied and should come from trusted
  imaging workstations (e.g., Cellebrite/AXIOM output).
- Never store production secrets, C2 phone numbers of live investigations, or protected
  communication content beyond authorized scope. Enable data-residency toggles per org policy.

---

## 7. Recovery & continuity

- **Location:** one SQLite file at `MFL_DATA_DIR` (default `instance/mfl.db`).
- **Backup:** simple file copy to a WORM bucket/tape per retention policy.
- **Restore test:** restore copy into a fresh `MFL_DATA_DIR` and run `/chain/verify`;
  an intact hash chain validates post-restore integrity.

---

## 8. Verification artifacts

| Check | Command / route | Expected |
|---|---|---|
| Chain integrity | `GET /chain/verify` | ✅ CHAIN INTACT |
| RBAC deny | auditor → `/cases/new` | HTTP 403 |
| Login throttle | 5 bad logins from one IP | `LOGIN_FAILED … rate-limited` |
| Export tamper flag | response header `Content-SHA256` | 64-hex hash present |