# SECURITY.md — SentinelGraph

Security documentation, threat model, and hardening guide.
Posture targets: **OWASP Top 10 2021 (mitigated), OWASP ASVS L1–L2, ISO/IEC 27001:2022 Annex A, NIST CSF 2.0, NIST SP 800-53 r5, PCI DSS 4.0, CIS Controls v8.**

## 1. Scope & Intended Use

SentinelGraph is a **defensive** analysis tool for **authorized lab domains** and imported SharpHound collections. It performs no exploitation. Operators are responsible for authorization before collecting data from any domain they do not own.

**Data classification:** imported collections and the in-memory graph contain sensitive directory metadata → handle as **Confidential / Internal-Restricted** per bank data classification policy (ISO A.5.12/A.5.13, PCI 3.x scoping).

## 2. Threat Model (STRIDE summary)

| Threat | Vector | Mitigation in this build |
|---|---|---|
| Spoofing | Stolen bearer tokens, brute-force login | 15-min JWT TTL, rate-limited login (5/min), constant-time credential compare, bcrypt/PBKDF2 hashing |
| Tampering | Audit-trail modification, collection import tampering | Append-only in-process audit; importer caps + schema validation; ZIP/JSON parse isolation |
| Repudiation | "Who ran this analysis?" | Every auth/seed/import/analysis action recorded with actor, timestamp, outcome (ISO A.8.15, PCI 10.2.1) |
| Information disclosure | Stack traces, verbose errors, docs exposure | Uniform error envelope; `/api/docs` only in lab profile; security headers incl. CSP, nosniff, DENY framing |
| Denial of service | Import bombs, path-analysis floods | 512 MB archive cap, 2M-entry cap, bounded BFS depth/limit, API rate limit 120/min |
| Elevation of privilege | Auditor calling mutating endpoints | Server-side RBAC on every route (auditor = read-only), 403 verified in tests |

## 3. OWASP Top 10 2021 — Mitigation Matrix

| Risk | Mitigation | Where |
|---|---|---|
| A01 Broken Access Control | Role checks in dependencies, deny-by-default routes, Tier-0 model analysis | `app/core/security.py`, `app/api/*` |
| A02 Cryptographic Failures | bcrypt cost ≥ default OWASP; PBKDF2-600k fallback; JWT HS256 with ≥32-char secret enforced by config validator | `app/core/security.py`, `config.py` |
| A03 Injection | Pydantic models on every body; parameterized Cypher in Neo4j store; no dynamic SQL/Cypher from user text | `app/api/*`, `neo4j_store.py` |
| A04 Insecure Design | Tiered RBAC, read-only auditor, lab/prod profile separation, threat model in this doc | design |
| A05 Security Misconfiguration | Secure defaults; CSP; docs off in prod; strict import caps | `headers.py`, `main.py`, `importer.py` |
| A06 Vulnerable Components | Pinned dependencies (`requirements.txt`, lockfile); SBOM via `pip freeze` / `npm ls` | manifests |
| A07 Auth Failures | Rate limiting, short TTL, no persistent token storage client-side (memory only) | `rate_limit.py`, `api.ts` |
| A08 Data Integrity Failures | Append-only audit; import schema validation; unsigned-ZIP rejection on parse failure | `audit.py`, `importer.py` |
| A09 Logging & Monitoring Failures | Structured JSON audit events with severity; SIEM-ready line format; login-failure alerting | `audit.py`, `deps.py` |
| A10 SSRF | No user-supplied URL fetching anywhere in the codebase | — |

## 4. Framework Control Mapping (evidence-backed)

The compliance engine (`app/compliance/`) maps runtime evidence → control status for:

- **ISO/IEC 27001:2022** — A.5.15/16/17/18, A.8.2, A.8.5, A.8.9, A.8.15/16, A.8.24, A.8.25/28/29, A.8.32
- **NIST CSF 2.0** — GV.PO/RM, ID.AM, PR.AA-01/03/05, PR.PS, DE.CM/AE, RS.MA, RC.RP
- **NIST SP 800-53 r5** — AC-2/3/6(1), AU-2/3/6/9, IA-2/5, CM-2/6/7, SI-2/4
- **PCI DSS 4.0** — 2.2.x, 4.2.1, 7.2.x, 8.2.x, 8.3.x, 8.6.x, 10.2/10.3/10.4, 11.3/11.5, 12.3/12.5
- **CIS Controls v8** — 1, 3, 4, 5.2/5.4, 6.1/6.8, 8, 13, 16, 17

`partial` statuses in lab mode are expected where MFA (PCI 8.2.4) and SIEM retention (PCI 10.3) require production integrations.

## 5. Hardening Checklist (production deployment)

1. Set `SG_JWT_SECRET` (≥32 chars, from vault/KMS; rotate quarterly — PCI 8.6.x).
2. Set `SG_ENVIRONMENT=production` (disables /api/docs, CORS).
3. Terminate TLS 1.2+ at gateway; keep HSTS (PCI 4.2.1).
4. Bind lab exe to `127.0.0.1` (default); never expose raw lab instance.
5. Replace lab USERS dict with LDAPS/IdP federation + MFA (NIST 800-63B AAL2+, PCI 8.2.4).
6. Stream audit JSON to SIEM; WORM-retain 12 months online + 12 offline (PCI 10.3/10.5).
7. Encrypt collections at rest; auto-purge after analysis window.
8. Run `pip audit` / `npm audit` in CI; pin and SBOM-tag releases (A06, CIS 16).
9. Quarterly access review of platform accounts (PCI 7.2.5, ISO A.5.18).

## 6. Vulnerability Reporting

Internal tool: report to the security engineering channel; include reproduction steps and lab-only evidence. Do not test against production forests. Accepted reports are triaged under the bank's standard IR SLAs (NIST CSF RS.*).
