# 🔐 Security.md — Security Architecture of the Compliance Automation Suite

> **Reserved & maintained as the authoritative security reference.** Mirrors `architecture.md` §8 and the *actual* implementation in `backend/app/security.py`, the evidence vault, and the audit chain.

---

## 1. Security Posture at a Glance

| Domain | Measure | Framework Proof-Point |
|---|---|---|
| Authentication | JWT (HS256) · PBKDF2-HMAC-SHA256 (210k iters) | ISO A.8.5 · NIST IA-5 · OWASP A07 |
| Session | 30-min access token, sliding refresh | NIST IA-2 · ISO A.8.2 |
| Authorization | Role-Based Access Control (6 roles) | ISO A.9.1.2 · NIST AC-2 · OWASP A01 |
| Audit | Append-only, SHA-256 hash-chained ledger | ISO A.8.15 · BB Ch-14 · OWASP A09 |
| Evidence | WORM immutable vault + SHA-256 per artefact | ISO A.8.16 · BB Ch-03 |
| Password storage | PBKDF2-HMAC-SHA256 with per-user salt | NIST SP 800-63B · ISO A.8.5 |
| Transport | TLS 1.3 / mTLS in mesh (deployment) | ISO A.8.20 · NIST SC-8 |
| Secrets | `CAS_SECRET_KEY` env override (32+ bytes) | ISO A.8.24 · NIST SC-13 |
| Input handling | FastAPI/Pydantic validation, upload allow-list | OWASP A03 · OWASP A04 |

---

## 2. Authentication (`backend/app/security.py`)

### 2.1 Password Hashing
- **Algorithm:** PBKDF2-HMAC-SHA256, 210,000 iterations, 16-byte per-user random salt.
- Stored as `pbkdf2$<salt_b64>$<digest_b64>` — never plaintext, never reversible.
- Constant-time comparison via `hmac.compare_digest` (mitigates timing attacks).

```python
def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 210_000)
    return f"pbkdf2${base64.b64encode(salt).decode()}${base64.b64encode(digest).decode()}"
```

### 2.2 JWT Session Tokens
- HS256 signed with `CAS_SECRET_KEY` (production must inject via environment; key ≥ 32 bytes).
- Payload: `sub` (user id), `username`, `role`, `iat`, `exp` (30 minutes).
- Expired/invalid tokens are rejected by `decode_token` with 401.

### 2.3 Login Controls
- Successful sign-ins write a **hash-chained audit event** (`LOGIN_SUCCESS`) with source IP.
- Disabled accounts can never authenticate (`is_active` guard).

---

## 3. Authorization — RBAC Matrix

Implemented in `ROLE_PERMISSIONS` (`security.py`) and enforced per-endpoint via `require(permission)`.

| Role | Permissions |
|---|---|
| `SUPER_ADMIN` | `*` (wildcard) |
| `CISO` | map:write, assess:write, risk:write, evidence:write, remediation:write, report:write/read, dashboard:read, audit:read, asset:write, user:read |
| `CONTROL_OWNER` | evidence:write, assess:read, report:read, dashboard:read, remediation:write |
| `ASSESSOR` | assess:write, evidence:read, report:read, dashboard:read, audit:read |
| `REGULATOR` | dashboard:read, report:read, evidence:read (read-only for Bangladesh Bank examiners) |
| `VIEWER` | dashboard:read, report:read |

Verified by test: **regulator is denied `POST /assessments` (403)** while read endpoints succeed.
Report downloads (`/reports/download`, `/reports/csv`) require `report:read` — available to read-only roles
(ASSESSOR / REGULATOR / VIEWER) so Bangladesh Bank examiners can pull the F&R return and evidence packs without write access.
The frontend mirrors this matrix and hides/disable write actions the user's role cannot perform.

---

## 4. Tamper-Evident Audit Trail

Every state-changing API call appends to `audit_logs` (ISO A.8.15 / BB Ch-14 / OWASP A09).

### 4.1 Hash Chain
- Each row stores `prev_hash` (hash of the previous row) + `row_hash`:
  `SHA256( actor | role | action | entity | entity_id | detail_json | ip | prev_hash | created_at )`
- The chain begins from a fixed **GENESIS** block.
- `GET /audit/verify` and `GET /evidence/integrity` recompute the chain and flag any tampering.

### 4.2 Evidential Value
- Chain verification is exercised in the test suite (`test_integrity_verification`).
- Regulator/auditor role can *read* the log but never mutate or truncate it.

---

## 5. WORM Evidence Vault (`backend/app/engines/evidence.py`)

| Property | Implementation |
|---|---|
| **Write-Once-Read-Many** | `worm_locked=True`; payload + meta marker written once to `data/vault/` |
| **Integrity** | Every artefact stored with its SHA-256 digest; digest recomputed on upload |
| **Chain** | Vault hash chain `SHA256(id|title|artefact_type|sha256|created_at|prev)` |
| **Allow-list** | pdf, docx, xlsx, csv, json, txt, png, jpg, log, zip — ≤ 25 MB |
| **Linkage** | One artefact → many controls (`EvidenceLink`) enabling overlap de-dup |
| **Auditor pack** | ZIP export with `MANIFEST.json` listing every artefact + SHA-256 |

Refusing to store an artefact without a SHA-256 digest prevents unverifiable records (OWASP A08 integrity).

---

## 6. OWASP Top 10 → Implementation Evidence

| # | OWASP 2021 | Where it is handled in the code |
|---|---|---|
| A01 | Broken Access Control | `require()` RBAC dependency on every router; role matrix; hidden admin nav |
| A02 | Cryptographic Failures | PBKDF2 passwords, HS256 JWT, SHA-256 chains, ≥32-byte secret |
| A03 | Injection | SQLAlchemy ORM (parameterised), Pydantic payload parsing |
| A04 | Insecure Design | Layered engine separation, deny-by-default permissions |
| A05 | Misconfiguration | CORS allow-list configurable, WORM flags explicit |
| A06 | Vulnerable Components | `requirements.txt` pinned; trivy/checkov gates in CI roadmap |
| A07 | AuthN failures | 210k-iter PBKDF2, account disable, token expiry, login audit |
| A08 | Integrity | Hash-chained audit + vault, refuse unverified evidence |
| A09 | Logging & Monitoring | `audit()` on every write; `/audit` & `/audit/verify` endpoints |
| A10 | SSRF | No raw server-side URL fetching in the suite; consumer-controlled |

---

## 7. ISO 27001 / NIST CSF → Self-Assessment of the Implementation

| Control | Status in Suite | Evidence file |
|---|---|---|
| ISO A.5.1 policies | ✅ `Setting`+docs | `state.md`, this file |
| ISO A.8.2 access rights | ✅ RBAC | `security.py` |
| ISO A.8.5 authentication | ✅ PBKDF2+MFA flag | `security.py`, `User.mfa_enabled` |
| ISO A.8.15/16 logging & monitoring | ✅ hash chain | `security.py::audit`, `routers/audit.py` |
| ISO A.8.24 cryptography | ✅ hashing+JWT | `security.py` |
| ISO A.5.30/BBC Ch-18 BC | ⚠️ documented RTO/RPO | `architecture.md` §11 |
| NIST PR.DS-6 integrity | ✅ chains | `engines/evidence.py` |
| NIST DE.CM-1 monitoring | ✅ audit verify endpoint | `routers/audit.py` |

---

## 8. Threat Model (STRIDE) — Demo scope

| Threat | Mitigation |
|---|---|
| **S**poofing identity | PBKDF2 + JWT expiry + disabled-account guard |
| **T**ampering | hash-chained audit & evidence vault |
| **R**epudiation | append-only audit log with row hashes |
| **I**nformation disclosure | least-privilege RBAC; evidence read-only for REGULATOR |
| **D**enial of service | rate limiting on gateway (deployment); upload size caps |
| **E**levation of privilege | per-role permission checks; only SUPER_ADMIN creates users |

---

## 9. Production Hardening Checklist (roadmap)

- [ ] Enforce HTTPS/TLS 1.3 + HSTS; terminate at WAF/ALB
- [ ] Replace dev secret with KMS-managed key (env `CAS_SECRET_KEY`)
- [ ] Swap SQLite → PostgreSQL w/ encryption at rest (RDS/Azure SQL)
- [ ] Move vault to S3 Object Lock (WORM) or Azure Blob immutability
- [ ] Keycloak OIDC for SSO/MFA to replace demo-password login
- [ ] SIEM forwarding of audit rows (CEF) + SOAR runbooks
- [ ] Containerise with signed images (Cosign) and scan SBOM in CI
- [ ] Add rate limiting + account lockout module (DDoS/brute force)

> **Doc status:** Reserved & living — updated alongside any security change in `backend/app/security.py`, the vault, or RBAC matrix.