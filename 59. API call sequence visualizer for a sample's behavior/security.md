# Security: API Call Sequence Visualizer for a Sample's Behavior

**Document ID:** ACSV-SEC-001
**Version:** 1.0
**Classification:** Internal — Security Sensitive
**Date:** 2026-09-22
**Related:** `architecture.md` (§9 Security & Compliance Framework Integration), `state.md`

---

## 1. Scope

This document records the **security posture** of ACSV as implemented today,
the ISO 27001 / NIST / OWASP Top 10 mapping evidence, the built-in controls,
remaining gaps, and the self-test that validates the security claims.

ACSV is an offline-first, portable, GUI + CLI tool that ingests **untrusted
sample behavior data**, analyzes it, and produces tamper-evident reports.
The threat model treats the *capture data and rendered reports* as untrusted
input to the parser and renderers.

---

## 2. Control Implementation Evidence

### 2.1 Cryptographic controls (ISO A.8.24 / OWASP A02)

| Control | Implementation | File(s) |
|---------|----------------|---------|
| SHA-256 content hashing | Report files hashed; sample hashes; `pack_file_digest` | `acsv/crypto.py` |
| Deterministic canonical JSON | `canonical_bytes` normalizes tuples/int-keys via JSON round-trip → chain stable | `acsv/crypto.py` |
| HMAC-SHA256 audit chaining | `entry_hash = HMAC-SHA256(prev_hash \|\| payload)` | `acsv/crypto.py:48`, `acsv/audit.py` |
| DPAPI secret-at-rest | `CryptProtectData` flag 0 (current user), entropy `ACSV-v1`; `LocalFree` argtypes fixed for x64 | `acsv/crypto.py:157` |
| Key rotation | `DPAPIStore.rotate_secrets`; audit event `SECRETS_ROTATED` | `acsv/crypto.py:147`, `acsv/audit.py`, `acsv/ui/audit_viewer.py` |
| No MD5/SHA1 as integrity | Only SHA-256/HMAC-256 used | — |
| TLS mandate (future network) | No network surface enabled by default; TLS 1.3 reserved for v2.0 | `architecture.md` §9.3 A02 |

### 2.2 Tamper-evident audit log (ISO A.5.33 / A.8.15, OWASP A09/A08)

- Append-only `audit.jsonl` + `audit.db` mirror; **append after a tampered tail terminates the chain** (fail-closed) — `acsv/audit.py`.
- Every sensitive action is audited. Action vocabulary (implemented):
  `SESSION_START, SAMPLE_INTAKE, CAPTURE_START, CAPTURE_END, REPORT_CREATE,
  REPORT_DOWNLOAD, REPORT_DELETE, POLICY_LOAD, POLICY_CHANGE, ACCESS_NAV,
  INTEGRITY_VERIFY, AUDIT_EXPORT, SECRETS_ROTATED, FAILED_ACCESS`.
- Include-integrity: every chain entry carries the previous hash; verification recomputes the whole chain — `audit verify` CLI and Audit Viewer button.
- Export to `audit-YYYYMM.jsonl` with manifest hash.

### 2.3 Input handling / injection (OWASP A03)

- SQLite accessed **only via parameterized queries** (`acsv/store.py`, prepared statements). No string-built SQL.
- Report HTML is generated from the package's own template with **escaped values**; no user/sample-controlled template execution.
- No shell execution of sample-derived strings anywhere in the codebase (`policy.hooks` reserved, not executed).
- Redaction runs **before persistence** on API args; redaction engine is quote-safe (preserves JSON validity after masking).

### 2.4 Redaction & PII (ISO A.5.34)

- Active patterns (see `memory.md` for the regex design):
  - Key-value secrets: `authorization|password|passwd|pwd|secret|token|bearer|api_key` → value masked `[REDACTED]`, JSON kept valid.
  - Email addresses; SSNs (xxx-xx-xxxx).
- `redact_json` is a **deep transform**; nested structures and lists are redacted too; trivial data (ints/bools/None) untouched.
- Policy may extend `redact_patterns` in `policies/default.toml`.

### 2.5 Path handling / traversal (OWASP A01/A03)

- All report save paths canonicalized + `resolve()`d; extraction/destination is guarded against traversal (`acsv/report/exports.py`).
- Data dir resolved via validated `base_dir`; portable mode auto-detected.

### 2.6 Least privilege & isolation (ISO A.8.2, NIST AC-6, OWASP A04)

- **No automatic sample execution.** v1.0 operates on **offline replays** of synthetic/imported traces; live capture requires an explicit elevated sandbox run (reserved v1.1).
- UI/reporting runs unelevated; secrets sealed with DPAPI (user-bound).
- Single-actor session identity is recorded in audit entries (actor = OS user) — A.8.5 baseline.

### 2.7 Configuring/tamper resistance of policy (ISO A.8.9/A.5.1)

- Policy load **fails closed**: malformed/missing TOML → embedded defaults with audit `POLICY_LOAD` warning; unknown keys rejected.
- Policy snapshot hash embedded in every session (`session.policy_hash`) and report (`policy_snapshot`, `integrity.policy_hash`).

---

## 3. Framework Alignment Matrix (executable evidence)

The **Compliance Console (GUI)** and report section **Compliance Mapping** expose
`coverage_summary()` + `coverage_matrix()` from `acsv/compliance.py`:

- **ISO/IEC 27001:2022** — Annex A control table across A.5/A.7/A.8 domains.
- **NIST** — CSF 2.0 functions (GOVERN/IDENTIFY/PROTECT/DETECT/RESPOND/RECOVER) plus SP 800-53 Rev.5 controls (AC-2/3/6, AU-2/3/9/11, CM-2/6, CP-9, IA-2, IR-4/5, RA-5, SA-11/15, SC-28, SI-4, SR-3/4).
- **OWASP Top 10 (2021)** — A01–A10 risk mapping with implemented mitigations.
- Coverage model: every top-level framework key has `{"rows": [...], "summary": {...}}`; summary includes `total`, `implemented`, `partial`, `reserved`, coverage %.

Reports carry the matrix, so downloaded evidence includes its own compliance statement (hash-sealed at the report level).

---

## 4. Threat Model (STRIDE) — current status

| Threat | Asset | Status in v1.0 |
|--------|-------|----------------|
| Tampering | Event store / audit / report | **Mitigated**: hash chains; report SHA-256; verification commands. |
| Repudiation | Analyst actions | **Mitigated**: append-only audit with actor + action + hash. |
| Information disclosure | Sample contents / PII in args | **Mitigated**: policy-driven redaction pre-persist; DPAPI; classification banner. |
| Denial of service | Capture runaway | Partial: event caps + session timeouts in policy (live capture reserved v1.1). |
| Elevation of privilege | Sample escaping sandbox | **Design only** (v1.1 native). v1.0 never executes the sample — offline replay. |
| Spoofing | Forged report / IPC peer | Partial: report hashes; Ed25519 signing hook reserved; IPC none in v1.0. |

---

## 5. Security Self-Test (one command)

```powershell
python -m pytest tests -q
```

Covers: chain verification & tamper detection, secret rotation, redaction
(full + fallback), intake hashing (dedupe), session/sequence integrity, report
hash + canonical-round-trip equality, PDF/HTML no-render-crash, STIX structure.

---

## 6. Remaining Security Work (gaps)

1. **Code scanning** (SAST: Semgrep/CodeQL) in CI; dependency audit (`pip-audit`) and SBOM (CycloneDX).
2. **Authenticode signing** of the built `ACSV.exe`; published SHA-256 alongside release.
3. **RBAC + OIDC/MFA-ready identity** (v1.1) — currently single OS-actor identity.
4. **Encryption at rest of the event DB** (NIST SC-28) — currently full-disk/DPAPI only for secrets; consider SQLCipher.
5. **Live-capture isolation** (VM/Windows Sandbox AppContainer) — reserved v1.1.
6. **Fuzzing** of importer/parser entry points (event PML/XML/JSON, config loader).
7. **HTML report CSP hardening review** before exposing file-based viewer to non-technical users.

---

## 7. Secure Baseline (what ACSV does NOT do)

- No telemetry, no phone-home, no remote updates, no cloud by default.
- No auto-execution of dropped files; no shell interpolation of untrusted data.
- No write of plaintext secrets to disk (DPAPI only).
- No MD5/SHA-1 used for any integrity decision.

*End of security document.*