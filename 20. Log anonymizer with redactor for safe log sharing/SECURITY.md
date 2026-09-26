# Security Architecture - Log Anonymizer with Redactor

This document describes the security controls implemented in the desktop GUI and server-side engine, mapped directly to **OWASP Top 10 (2021)**, **NIST CSF 2.0 / SP 800-53 R5**, **ISO 27001:2022 Annex A**, GDPR, HIPAA and PCI-DSS.

---

## 1. OWASP Top 10 (2021) Mapping

| #   | Weakness                           | Control                                                                                   |
|-----|------------------------------------|-------------------------------------------------------------------------------------------|
| A01 | Broken Access Control              | Policy engine: default-deny (no PII class can reach an export destination unless explicitly permitted); session passphrase gate on sensitive operations |
| A02 | Cryptographic Failures             | Windows DPAPI (AES-256) for state salt; Fernet AES-128-CBC + HMAC-SHA256 for encrypted exports; HMAC-SHA256 salted hashing of originals (never stored) |
| A03 | Injection                          | `InputValidator`: strips null bytes, control characters, enforces size limits; all log lines validated before detection |
| A04 | Insecure Design                    | Secure-by-default policy: only `SAFE` and `LOW` data classes permitted by default; all other classes force `FULL_REDACT` |
| A05 | Security Misconfiguration          | No secrets stored in plaintext; state/memory files integrity-tagged; secure defaults (no debug logging, no raw values persisted) |
| A06 | Vulnerable Components              | Pinned core dependencies in `pyproject.toml`; vendored PyInstaller build excludes unused packages (`fastapi`, `uvicorn`, `httpx`) |
| A07 | Identification & Auth Failures     | Optional session passphrase (PBKDF2/scrypt-hashed) gates settings, export and salt reveal |
| A08 | Software/Data Integrity Failures   | Append-only audit chain (sequence-prefixed Merkle-anchored records); integrity-tagged state and memory files (SHA-256 MAC) |
| A09 | Security Logging & Monitoring      | Every redaction action appended to the tamper-evident audit trail; chain root recomputed on startup (verify anomalies) |
| A10 | Server-Side Request Forgery        | Not applicable: desktop tool makes no outbound requests from log content |

---

## 2. NIST CSF 2.0 / SP 800-53 R5 Controls

| Function | Subcontrol | Implementation |
|----------|------------|----------------|
| Govern (GV.OC) | Risk Management Strategy | STRIDE threat model + risk register in ARCHITECTURE.md; residual risk documented per component |
| Identify (ID.AM) | Asset Management | Data classification schema (SAFE / LOW / MEDIUM / HIGH / CRITICAL); memory tracks files by path + safe metadata |
| Identify (ID.RA) | Risk Assessment | 14-item risk register with severity, residual risk and mitigation status |
| Protect (PR.AC) | Access Control | Policy RBAC (default-deny); passphrase gate on state, export and salt reveal |
| Protect (PR.DS) | Data Security | 7 redaction strategies; DPAPI encryption at rest; k-anonymity generalization suppression |
| Protect (PR.PT) | Protective Technology | Input validation; maximum line length; batch size caps; UI origin validation |
| Detect (DE.CM) | Continuous Monitoring | Chain root recomputed on app launch; any discrepancy shown as MISMATCH in status bar |
| Detect (DE.AE) | Adversarial Analysis | Chain anomaly detection flags when rebuild root differs from expected |
| Respond (RS.RP) | Incident Response | Response playbooks in section 9 of ARCHITECTURE.md |
| Recover (RC.RP) | Recovery Plan Execution | Audit chain replay from disk; state corruption falls back to secure defaults |

---

## 3. ISO 27001:2022 Annex A Controls

| Control | Description | How implemented |
|---------|-------------|-----------------|
| A.5.15 | Access control / segregation | Default-deny policy; optional passphrase lock on sensitive actions |
| A.8.2  | Labelling of information | Classification badge per entity type displayed in legend and dashboard |
| A.8.3  | Handling of assets | Original logs never stored; only redacted output + salted hashes retained |
| A.8.11 | Data masking | 7 strategies: full redact, partial mask, tokenize, pseudonymize, generalize, date-shift, contextual |
| A.8.12 | Prevention of data leakage | Luhn validation for card numbers; contextual detector suppresses false positives |
| A.8.15 | Logging | Append-only audit trail with sequence-anchored hash chain |
| A.8.16 | Monitoring activities | `verify_chain()` runs automatically on GUI startup; manual verify available |
| A.8.24 | Use of cryptography | DPAPI (AES-256, OS-managed keys); Fernet (AES-128-CBC + HMAC-SHA256); HMAC-SHA256 |
| A.8.28 | Secure coding | 75 passing tests; ruff lint clean; no eval/exec; safe deserialization |
| A.8.29 | Security testing | Tests cover negative cases (Luhn invalid, DPAPI wrong entropy, chain tampering) |

---

## 4. Cryptographic Controls

| Function | Algorithm | Purpose | Key Source |
|----------|-----------|---------|------------|
| State encryption | AES-256 (DPAPI) | Protect token salt at rest | Windows user logon credentials (no app key) |
| Export encryption | AES-128-CBC + HMAC-SHA256 (Fernet) | Encrypted redacted output (.enc) | scrypt(password, salt) → 32-byte key |
| Original value storage | HMAC-SHA256 (salted) | Audit trail hash of original values | Token salt + per-tenant nonce |
| Redacted value storage | SHA-256 | Audit trail hash of redacted values | None (deterministic) |
| Chain integrity | HMAC chain (SHA-256) | Tamper-evident append-only audit | Build from record sequence fields |
| State file integrity | SHA-256 | Detect state corruption | USAGE_PREFIX + payload |
| Memory file integrity | SHA-256 | Detect memory corruption | MEMORY_PREFIX + payload |

---

## 5. Data Retention and Deletion (GDPR Art. 17)

| What | Where | Retained | Erasable |
|------|-------|----------|----------|
| Token salt | DPAPI-encrypted in state.json | Until explicit forget | `Settings > Erase Memory / Forget State` |
| Recent file paths | memory.json (cleartext paths) | Up to 20 most recent | `Settings > Erase Memory` |
| Custom rules | memory.json (DPAPI-wrapped section) | Until user removes | `Settings > Erase Memory` |
| Entity stats | memory.json (fingerprinted keys) | Until user erases | `Settings > Erase Memory` |
| Audit trail records | data/audit/*.json | Append-only, retained per policy | Manual admin deletion only |
| Original log values | Never stored | N/A | N/A |
| Session passphrase hash | state.json (cleartext scrypt hash) | Until session is locked | `Settings > Erase Memory / Forget State` |

---

## 6. Threat Model Summary (STRIDE)

| Category | Threat | Mitigation |
|----------|--------|------------|
| **S**poofing | Forged audit records | Chain root recomputation; append-only storage; timestamp + event ID |
| **T**ampering | Modified audit records | SHA-256 integrity tag in state/memory; chain hash mismatch detection |
| **R**epudiation | Denying a redaction | All actions logged with immutable sequence, timestamp and hash |
| **I**nformation Disclosure | Original log leakage | Originals never stored; only salted HMAC retained |
| **D**enial of Service | Large file exhaustion | `max_line_length` and `preview_lines` limits; batch cap |
| **E**levation of Privilege | State file manipulation | DPAPI user-bound encryption; SHA-256 integrity tag; atomic write (temp+rename) |

---

## 7. Encrypted Export Format (.enc)

```
Offset  Length  Description
0       8       Magic header: LAC1-ENC\x01
8       16      Random salt for scrypt KDF
24      ...     Fernet token (AES-128-CBC + HMAC-SHA256)
```

Decryption is only possible with the password supplied at export time. The 16-byte random salt ensures unique keys per export and prevents rainbow table attacks (ISO A.8.24).

---

## 8. Building the Secure Desktop Binary

```powershell
# Build the .exe (requires Python 3.10+, PyInstaller, cryptography)
.\build_gui.ps1

# Output: dist\LogAnonymizer.exe
# The .exe bundles:
#   - tkinter (GUI framework)
#   - ctypes/crypt32 (DPAPI via Windows OS)
#   - cryptography (Fernet export)
#   - All engine modules (detection, redaction, audit, policy)
```

The build script runs the full test suite before packaging. If any test fails, the build aborts.

---

## 9. Incident Response

| Scenario | Action |
|----------|--------|
| Audit chain MISMATCH detected at startup | Stop: do not process any logs; alert user; investigate data/audit files for tampering |
| State file corruption | Load secure defaults; offer to rebuild from scratch |
| Export password forgotten | The encrypted .enc file cannot be recovered; re-export from source logs |
| Suspected original value leakage | Verify no `*_hash` fields in audit records contain cleartext (they use HMAC); purge data/audit if doubt |
| GUI settings tampered | `state.json` integrity tag prevents undetected modification; reload from save |

---

## 10. Testing

| Area | What is tested | Count |
|------|----------------|-------|
| Detection | Pattern matcher, contextual refinement, Luhn validation, false-positive suppression | 16 |
| Redaction | All 7 strategies, overlap merging, empty input, right-to-left replacement | 14 |
| Security | Audit trail integrity, chain tampering, input validation, DPAPI roundtrip | 12 |
| Service | End-to-end pipeline, policy loading, anomaly detection | 5 |
| GUI State | Save/load roundtrip, DPAPI protection, integrity tags, truncation detection | 10 |
| GUI Memory | Path-only storage, sanitization, fingerprinted stats, rule roundtrip, forget_all | 9 |
| GUI Scanner | Detection highlighting, encrypted export (Fernet), chain verification, evidence report | 7 |
| **Total** | | **75** |

Run the full suite:

```bash
py -m pytest tests -q
py -m ruff check src tests
py -m ruff format src tests
```