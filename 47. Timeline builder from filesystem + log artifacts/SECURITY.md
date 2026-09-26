# Security & Compliance - TimelineBuilder

TimelineBuilder is a portable forensic timeline builder. It treats evidence and log
input as **untrusted** and is engineered to align with ISO/IEC 27001:2022, NIST
SP 800-53 / SP 800-61 / SP 800-86 and the OWASP Top 10 (2021).

This document is the control-to-framework evidence map. It is intended to be read
alongside `ARCHITECTURE.html`.

---

## 1. Threat Model

| Threat | Vector | Mitigation (implementation) |
|---|---|---|
| Evidence tampering | Modification of source files | Read-only collection; SHA-256 per artifact; evidence manifests (`security/integrity.py`) |
| Repudiation | Analyst denies performing an action | Append-only hash-chained audit log (`security/audit.py`) |
| Path traversal | Crafted source paths (`..\..\`) | `ensure_within()` + `validate_source_path()` reject escapes (`security/validation.py`) |
| Injection via filenames/log content | `<script>` in log lines or file names | HTML escaping in report/exporter (`export/html_exporter.py`), filename sanitization |
| Resource exhaustion (DoS) | Giant files, deep trees, event floods | `max_depth`, `max_events`, `log_max_file_bytes`, chunked hashing, cancellable worker |
| Sensitive data at rest | Case store on removable media | Optional AES (Fernet) + PBKDF2-HMAC-SHA256, 600k iterations (`security/crypto.py`) |
| Exfiltration | Hidden network calls | No sockets opened anywhere; fully offline |
| Malicious log parser input | Malformed EVTX/JSON/CSV | Defensive parsing, per-file error isolation, bounded previews |

---

## 2. Implemented Controls

### 2.1 Cryptographic integrity
- SHA-256 hashing for files and exported artifacts (`security/hashing.py`).
- Evidence manifest generation and verification (`build_manifest` / `verify_manifest`).

### 2.2 Tamper-evident logging
- Each audit record contains `prev_hash` and `hash = SHA256(prev_hash | canonical(record))`.
- Genesis link is `0 * 64`; `verify_audit_chain()` validates linkage, hashes and sequence.
- Records are appended and `fsync`-ed; the log is never rewritten in place.

### 2.3 Input validation & safe paths
- Rejects null bytes, empty/oversized paths.
- Resolves and confines paths to an allowed base (`ensure_within`).
- Sanitizes filenames for downstream use (`sanitize_filename`).

### 2.4 Least privilege
- Evidence is opened read-only; no writes to source locations.
- Symbolic links are not followed unless explicitly enabled.
- No elevation, services or drivers; runs as the invoking user.

### 2.5 Data protection at rest
- Optional case encryption: `MAGIC || salt(16) || Fernet(AES-CBC + HMAC)`.
- Key derivation: PBKDF2-HMAC-SHA256, 600,000 iterations, 32-byte key.

### 2.6 Safe rendering
- All event/source strings pass through `html.escape` before templating.

---

## 3. Framework Mapping

### 3.1 ISO/IEC 27001:2022 (Annex A)

| Theme | Controls | Implementation |
|---|---|---|
| Cryptography | A.8.24 | SHA-256 integrity, AES case encryption |
| Collection of evidence | A.5.28 | Manifests, read-only acquisition, audit chain |
| Logging & monitoring | A.8.15, A.8.16 | Hash-chained audit log, audit-chain status in GUI/CLI |
| Storage media | A.7.10 | Optional encrypted case store for removable media |
| Access control | A.5.15, A.8.2 | Least privilege, read-only sources |
| Secure coding | A.8.28, A.8.26 | Validation, escaping, bounded resources |
| Capacity management | A.8.6 | Event/file/depth limits |
| Technical vulnerability mgmt | A.8.8 | Pinned requirements, dependency review |
| Network security | A.8.20 | No network egress |
| Segregation of duties | A.5.3 | Explicit user-driven actions, audit actor identity |

### 3.2 NIST

| Publication / Control | Relevance | Implementation |
|---|---|---|
| SP 800-53 AU-2/AU-3/AU-9 | Audit events, content, protection | Hash-chained structured audit records |
| SP 800-53 SI-7 | Software/firmware/info integrity | SHA-256 hashing + manifests |
| SP 800-53 SI-10 | Input validation | `security/validation.py` |
| SP 800-53 SC-13/SC-28 | Cryptographic protection, at-rest | Fernet AES + PBKDF2 |
| SP 800-53 SC-7 | Boundary protection | No network egress |
| SP 800-53 AC-6 | Least privilege | Read-only collection |
| SP 800-86 | Forensic techniques | Provenance, integrity, normalized timeline |
| SP 800-61 | Incident handling lifecycle | Detect (correlation/severity) -> Analyze (timeline) -> Respond (export) |

### 3.3 OWASP Top 10 (2021)

| Risk | Status | Notes |
|---|---|---|
| A01 Broken Access Control | Mitigated | Path confinement, least privilege |
| A02 Cryptographic Failures | Mitigated | Modern primitives; no home-grown crypto in production paths |
| A03 Injection | Mitigated | Input validation + HTML escaping of all output |
| A04 Insecure Design | Mitigated | Explicit threat model and defense-in-depth |
| A05 Security Misconfiguration | Mitigated | No admin/services; minimal defaults; bounds enforced |
| A06 Vulnerable & Outdated Components | Monitored | Pinned dependencies; audit on upgrade |
| A07 Identification & Authentication Failures | N/A (local tool) | Optional PBKDF2 passphrase for encrypted cases |
| A08 Software & Data Integrity Failures | Mitigated | SHA-256 manifests, signed-build capable |
| A09 Security Logging & Monitoring Failures | Mitigated | Comprehensive, tamper-evident audit trail |
| A10 SSRF | Removed | No outbound network functionality |

---

## 4. Secure Development Practices

- **Testing**: `python -m unittest discover -s tests` - security, collectors and pipeline suites.
- **Reproducible builds**: `build.ps1` produces `dist\TimelineBuilder.exe` plus `SHA256SUMS.txt`.
- **Dependencies**: `requirements.txt` pins the runtime set; keep `cryptography`/PySide6 current.
- **Code signing (recommended)**: add `signtool` to `build.ps1` in production to protect the binary's integrity and provenance.

---

## 5. Reporting a Vulnerability

Report suspected issues privately to the maintainer with reproduction steps and
affected version (`TimelineBuilder --version`). Do not open public issues for
unpatched vulnerabilities.
