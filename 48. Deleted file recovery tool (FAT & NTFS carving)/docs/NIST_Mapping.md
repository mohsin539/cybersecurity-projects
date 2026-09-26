# NIST Framework Mapping — RecovPro Secure (CSF 2.0 + SP 800-53)

RecovPro Secure is a read-only evidence-capture tool used inside an incident
response / forensic review. This mapping covers the NIST Cybersecurity
Framework v2.0 functions and the most relevant SP 800-53 rev. 5 controls.

## NIST CSF 2.0

| Function | Outcome | Implementation |
|---|---|---|
| **GOVERN (GV)** | Policy, roles, security requirements | `SECURITY.md` policy, ethical-use statement, vulnerability process; least-privilege runtime via `asInvoker` manifest (GV.OC, GV.PO) |
| **IDENTIFY (ID)** | Asset & threat understanding | Volume/drive/image inventory in UI and `enum_volumes`/`probe_physical_drives`; MBR/GPT partition parsing; carving signature database sized to bounded threat model (ID.AM, ID.RA) |
| **PROTECT (PR)** | Guard integrity & confidentiality | Read-only IO discipline; AES-256-GCM + PBKDF2-600k encrypted export; SHA-256 vault manifest; path traversal sanitization; hash-chained audit (PR.DS, PR.PS, PR.AA) |
| **DETECT (DE)** | Identify anomalies during use | Structural plausibility gates + bounds reject malformed disk images; self-test *is* the change detector for the engine (DE.CM) |
| **RESPOND (RS)** | Analysis & containment | Recovery candidates are fingerprinted and exported encrypted with auditable provenance; bounded carve caps prevent memory exhaustion during response (RS.MA) |
| **RECOVER (RC)** | Restoration & continuity | Vault `verify_all()` confirms artifact integrity before reuse; encrypted `.bundle` restores cleanly (RC.RP, RC.RR) |

## NIST SP 800-53 rev 5 (selected)

| Control | Description | Implementation |
|---|---|---|
| **AC-3 / AC-6** | Access enforcement / least privilege | No elevation requested by the app (`asInvoker`); admin-only probe paths gated by `is_elevated()` |
| **AU-2 / AU-6 / AU-11** | Audit events / review / retention | `AuditLogger` writes structured events for scan and vault actions; hash chain + tail root supports later review & retention (files retain until operator deletes) |
| **AU-7** | Audit reduction & report generation | CSV / JSON / HTML exports from structured scan results; SHA-256 per artifact |
| **CM-6/CM-8** | Configuration & asset inventory | Single `requirements.txt` pins; reproducible PyInstaller `.spec`; sources inventoried at open |
| **CP-9** | System backup | Vault + optional AES-256-GCM encrypted bundle is the operator’s portable backup format |
| **SA-4/SA-11** | Acquisition / developer testing | 4-phase engine self-test is a mandatory pre-ship build gate; synthetic-media fixtures only |
| **SI-7** | Software & info integrity | Vault manifest integrity checks (`verify_all`); audit hash chain; SHA-256 on every recovered artifact |
| **SC-8** | Transmission confidentiality | Data exchanged via encrypted bundle (AES-256-GCM) rather than cleartext (SC-8 / SC-28) |
| **SC-13** | Cryptographic protection | Industry-standard primitives via `cryptography` (AES-256-GCM, PBKDF2-HMAC-SHA256 600k) |
| **SC-28** | Protection of information at rest | Encrypted `.bundle`; vault files integrity-protected by SHA-256 manifest |
| **SI-10** | Input validation | Offsets/sizes clamped in `ReadOnlySource`; carve bounds constants; path sanitization on all writes |

## Rationale notes

- **Why no telemetry/network:** designs map to strict confidentiality controls
  (AU privacy, SC data transmission); the tool is intentionally offline.
- **Why bounded carving:** directly serves *availability* objectives in CSF "PR.DS" and
  SP 800-53 SI-7 by preventing hostile images from exhausting memory.
- **Why hash-first:** SI-7/SC-28 confidence that evidence was not altered between
  capture and analysis.