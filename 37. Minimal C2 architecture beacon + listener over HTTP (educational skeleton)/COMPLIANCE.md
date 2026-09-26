# Compliance &amp; Security Mapping — C2 Study Lab

This skeleton proactively maps its security controls to three widely used
frameworks so the lab doubles as a governance/awareness exercise:

- **ISO/IEC 27001:2022** (Annex A controls)
- **NIST** Cybersecurity Framework (CSF 2.0) + SP 800-53 control families
- **OWASP Top 10 (2021)** — web application security

> Status legend: &#9989; in place &middot; &#9888;&#65039; partially / deployment note

---

## 1. ISO/IEC 27001:2022 (Annex A)

| Control | Description | Implementation | Status |
|---|---|---|---|
| A.5.15 | Access control | Two principals (`beacon` / `console`) with distinct bearer tokens; constant-time comparison in `authn.py` | &#9989; |
| A.5.33 | Physical / lab isolation of test systems | Documented "authorized lab use only" boundary in README + GUI footer | &#9888;&#65039; |
| A.8.10 | Information deletion / data minimization | Registry is volatile (in-memory); beacon sends only minimal system metadata | &#9989; |
| A.8.24 | Use of cryptography | Application-layer Fernet AEAD encryption of every payload in `crypto.py` | &#9989; |
| A.8.28 | Secure coding | Allowlist-only task execution (pure Python, no `subprocess`), input size caps, no `eval` | &#9989; |
| A.8.29 | Security testing in development | Headless demo (`python src/main.py --demo`) exercises listener+beacon+reports end-to-end | &#9989; |
| A.12.4.1 | Event logging | Structured JSONL audit trail (`audit.jsonl`) + rotating session logs | &#9989; |
| A.12.4.3 | Log protection | Append-only file writer; logs excluded from repository hygiene docs | &#9989; |
| A.12.7 | Evidence collection | Report engine exports `.xlsx` / `.csv` / `.html` for review | &#9989; |
| A.18.1 | Compliance with policies/regulations | Control mapping (this file) shipped with the codebase | &#9989; |

---

## 2. NIST (CSF 2.0 + SP 800-53)

| Function / Family | Control | Implementation | Status |
|---|---|---|---|
| **Identify** — ID.AM | Asset inventory | `registry.py` keeps live beacon inventory (ID, host, OS, IP, last seen) | &#9989; |
| **Protect** — AC (Access Control) | `AC-7` unsuccessful logons / `AC-3` enforcement | 401 + audit on every failed token; distinct principals | &#9989; |
| **Protect** — SC (System &amp; Communications Protection) | `SC-8` transmission confidentiality &amp; integrity | Fernet AEAD payload encryption; deploy behind TLS/HTTPS for full parity | &#9888;&#65039; |
| **Protect** — IA (Identification &amp; Authentication) | `IA-5` authenticator management | Secrets derived from env/kms-capable config (defaults are lab-only) | &#9888;&#65039; |
| **Detect** — AU (Audit &amp; Accountability) | `AU-6` audit review | Live audit table in GUI + `.html` report | &#9989; |
| **Detect** — AU | `AU-2` event types | Every action is audited (checkin, enqueue, result, auth.failure, listener lifecycle) | &#9989; |
| **Respond** — IR | `IR-4` incident handling | Rate limiting throttles abuse; failed auth is distinguishable from legit traffic in audit trail | &#9989; |
| **Recover** — CP | Business continuity | Registry block-graph is volatile; reports provide externalized evidence to rebuild state | &#9888;&#65039; |

---

## 3. OWASP Top 10 (2021)

| Category | How the skeleton addresses it | Status |
|---|---|---|
| **A01 Broken Access Control** | Every protected route requires a valid bearer token; role separation (beacon vs console); unauthorized → `401` + audited | &#9989; |
| **A02 Cryptographic Failures** | All payloads wrapped in Fernet (AEAD); `no-store` cache headers; no secrets in logs; key via env/derived, never logged | &#9989; |
| **A03 Injection** | No SQL; no shell; task params are schema-validated; JSON parsing enclosed and verified | &#9989; |
| **A04 Insecure Design** | Minimal attack surface: 2 POST + 3 GET endpoints, allowlisted task names rejected server-agnostically | &#9989; |
| **A05 Security Misconfiguration** | Secure defaults (localhost bind, generated lab keys), explicit content-type/size validation, no default admin creds | &#9888;&#65039; |
| **A06 Vulnerable Components** | stdlib HTTP server (curated), pinned `cryptography` / `openpyxl` requirements | &#9989; |
| **A07 Identification &amp; Authentication Failures** | Constant-time `hmac.compare_digest`, per-IP sliding-window rate limiting | &#9989; |
| **A08 Software &amp; Data Integrity Failures** | AEAD ciphertext tamper detection; status is always reported and audited | &#9989; |
| **A09 Security Logging &amp; Monitoring Failures** | Append-only JSONL audit + rotating `session.log` + live GUI console | &#9989; |
| **A10 SSRFish / Server-side requests** | Beacon URL is fixed by operator config; listener performs no outbound requests | &#9989; |

---

## Evidence artifacts

| Artifact | Purpose | Framework value |
|---|---|---|
| `logs/audit.jsonl` | Append-only event trail | ISO A.12.4, NIST AU-2/AU-3 |
| `logs/session.log` | Rotating operational log | ISO A.12.4, OWASP A09 |
| `reports/C2StudyLab_report.xlsx` | Summary + tables, auto-filtered | ISO A.12.7 evidence |
| `reports/beacons.csv` `tasks.csv` `events.csv` | Machine-readable evidence | ISO A.12.7, NIST AU-6 |
| `reports/C2StudyLab_report.html` | Colorful human-readable dashboard | ISO A.18, audit review |

## Policy notes for production use

1. **Transport**: terminate with **TLS** at the listener (reverse proxy / self-signed cert in lab) so that C2 control-channel traffic matches `SC-8`/A.8.24 expectations end-to-end.
2. **Secrets**: rotate tokens &amp; the Fernet key; inject via environment variables or a KMS (`C2_BEACON_TOKEN`, `C2_CONSOLE_TOKEN`, `C2_FERNET_KEY`).
3. **Environment**: keep beacons inside an isolated lab VLAN with the console; the current registry is volatile.
4. **Authorization**: retention of audit logs and reports should align with your organization's records policy (ISO A.18.1).