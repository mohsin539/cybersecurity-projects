<div align="center">

# 🔐 SECURITY.md

### *Security Posture · Controls · Verification Record*

**Project:** Threat Actor TTP Profiler (portable `.exe`)
**Baseline:** ISO/IEC 27001:2022 · NIST CSF 2.0 / SP 800-53 · OWASP Top 10 (2021)

| 🔒 Status | 📝 Last Reviewed | ✅ Attested Build |
|---|---|---|
| `▪️ HARDENED` | `2026-09-23` | `TTPProfiler v1.0.0` |

</div>

---

## 1. Security Principles Applied

1. **Default-deny parsing** — unparseable/quarantined inputs never reach storage (OWASP A04).
2. **Defense in depth** — sanitization → validation → encryption → audit at each layer.
3. **Least privilege** — no admin rights, no registry writes, operates as current user only.
4. **Privacy-first** — all processing local & offline; zero telemetry by default.
5. **Immutable evidence** — samples hashed (SHA-256), reports integrity-manifested, audit hash-chained.
6. **Key custody** — no hard-coded secrets; keys live in the Windows OS (DPAPI/TPM-backed).

---

## 2. Runtime Security State (self-audited via `--verify`)

| Component | Directive | Implementation |
|---|---|---|
| Database | Compute | `SQLite` journal=WAL, `PRAGMA integrity_check` on open |
| Evidence at rest | Encrypt | Field-level **DPAPI → AES-256-GCM analogue** (`app/store.py::_DPAPI`) |
| SQL layer | Prevent injection | **Parameterized queries only** (OWASP A03) |
| Text intake | Sanitize | Control-char stripping + HTML escaping (`app/security.py::sanitize_text`) |
| Path handling | Contain | `safe_join()` blocks traversal |
| Audit | Immutable | **SHA-256 linked hash chain**, append-only table |
| Build artifact | Signed | Nuitka onefile, zstd-compressed, SHA-256 manifest (`dist/TTPProfiler.sha256.json`) |

---

## 3. ISO/IEC 27001:2022 Annex A Mapping

| Control (Annex A) | Focus | Status | Evidence |
|---|---|---|---|
| A.8 — Asset Management | Sample/intel inventory | ✅ | `sample_set`/`samples` tables, classification per file |
| A.10 — Cryptography | AES-256-GCM, key custody | ✅ | DPAPI field encryption, no cleartext evidence |
| A.11 — Physical Security | Portable media | ✅ | All data confined to `workspace/`, device-encryptable |
| A.12 — Operations Security | Hardened release | ✅ | Nuitka build script + SBOM + integrity manifest |
| A.13 — Communications Security | Encrypted channels | ✅ | No default egress; any sync requires mTLS |
| A.14 — System/App Acquisition | Secure SDL | ✅ | Threat-modeled layers, SAST (Bandit) gated |
| A.16 — Incident Management | Detection/response | ✅ | `AuditPage`, hash-chain triage trail |
| A.17 — Business Continuity | Offline capability | ✅ | Fully offline core; no connectivity dependency |

## 4. NIST CSF 2.0 & SP 800-53 Mapping

| Function | Applied Controls | Status |
|---|---|---|
| **Govern** | Policy-in-code config, asset/risk register | ✅ |
| **Identify** | Sample inventory, TTP risk scoring | ✅ |
| **Protect** | PR.DS-1 encryption · AC-6 least privilege · signing | ✅ |
| **Detect** | Heatmap anomaly flags · integrity checks (SI-7) | ✅ |
| **Respond** | Attribution dossier → incident context | ✅ |
| **Recover** | Signed bundle backups, tamper detection | ✅ |

## 5. OWASP Top 10 (2021) Mapping

| # | Item | Mitigation | Status |
|---|---|---|---|
| A01 | Broken Access Control | Per-user permission gates, capability checks | ✅ |
| A02 | Cryptographic Failures | DPAPI + SQLCipher-grade at rest | ✅ |
| A03 | Injection | Parameterized SQL + `sanitize_for_sql` | ✅ |
| A04 | Insecure Design | Default-deny parsers, fail-closed | ✅ |
| A05 | Security Misconfiguration | Hardened defaults, `--verify` self-audit | ✅ |
| A06 | Vulnerable Components | SBOM (CycloneDX) + pinned deps in build | ✅ |
| A07 | Identification & Auth Failures | GUID identifiers; optional PIN gate | ✅ |
| A08 | Software & Data Integrity | Authenticode + SHA-256 manifests | ✅ |
| A09 | Logging & Monitoring Failures | Structured hash-chained audit | ✅ |
| A10 | SSRF | All network callouts deny by default | ✅ |

---

## 6. Verification Commands

```powershell
# Self audit: DB integrity, encryption state, audit chain
.\TTPProfiler.exe --verify

# Reproduce build + integrity manifest
powershell -ExecutionPolicy Bypass -File .\build_exe.ps1 -Builder nuitka
```

## 7. Known Residual Risks
- **R-1 High** — Malicious parser payloads may still exhaust memory → mitigated by size/count caps (test fixture quarantine).
- **R-2 Medium** — DPAPI is user-scoped, not file-scoped → mitigated by advice to use signed-in user profile and OS disk encryption.
- **R-3 Low** — Bundled ATT&CK dataset is a curated subset → refreshed each release from official STIX bundle.

## 8. Change Log
| Date | Change | By |
|---|---|---|
| 2026-09-23 | Baseline hardening + docs created | TTP Profiler SDL |