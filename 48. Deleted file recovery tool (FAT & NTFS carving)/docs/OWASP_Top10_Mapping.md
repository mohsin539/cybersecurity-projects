# OWASP Top 10 (2021) Mapping — RecovPro Secure

RecovPro Secure is an offline desktop forensic utility; web-class exposure does
not apply directly. The table records how each OWASP Top 10 (2021) category is
addressed or deliberately bounded.

| # | Category | Relevance & control |
|---|---|---|
| **A01** Broken Access Control | **High relevance.** Every path, source selector and export writes under operator control. Controls: `is_elevated()` gates physical-drive access; vault confinement + `safe_name`/`is_unsafe_path` prevent writes outside the vault; `ReadOnlySource` never issues writes to scanned media. |
| **A02** Cryptographic Failures | Control: recovered vault bundle uses **AES-256-GCM** (authenticated) with random nonce; keys derived from passphrase via **PBKDF2-HMAC-SHA256, 600 000 iterations**, random 32-byte salt; integrity anchored by **SHA-256** manifest + hash-chained audit. No plaintext dumping of secrets: recovered files are stored only in the operator’s vault. |
| **A03** Injection | Not applicable to a local GUI; the only "query" surfaces are filters (group/ext) built from a fixed allow-list and passed to structured code, never a shell or SQL. Direct file byte streams are never executed—carved data is treated as inert bytes. |
| **A04** Insecure Design | Controls: bounded carve windows (`PROBE_STEP`, `MAX_ARTIFACT`, `FOOTERLESS_MAX`) defeat memory-exhaustion-by-hostile-image; maximum artifact cap 512 MiB; self-test shipped as a release gate; threat model documented (`docs/`, `SECURITY.md`). |
| **A05** Security Misconfiguration | Controls: exact dependency pins; UAC `asInvoker` (no implicit admin); read-only-by-construction IO; no network access / no telemetry; single reproducible packaging spec. |
| **A06** Vulnerable & Outdated Components | Controls: `requirements.txt` pins (`PySide6`, `cryptography`, `Pillow`); PyInstaller bundles at build time; the upgrade/report loop is the SECURITY.md vulnerability process. |
| **A07** Identification & Authentication Failures | N/A for a local utility; the one interactive secret is the **export-bundle passphrase**, enforced by PBKDF2 + AES-GCM so offline brute-force is cost-prohibitive. |
| **A08** Software & Data Integrity Failures | Controls: SHA-256 per recovered artifact; `verify_all()` vault manifest check before reuse; `verify_chain()` before trusting audit logs; hash chaining prevents silent log modification. |
| **A09** Security Logging & Monitoring Failures | Controls: structured audit log (JSONL) with per-record SHA-256 chain + tail root; logs cover scan open, carving, vault store, bundle export; no sensitive file contents are ever logged. |
| **A10** Server-Side Request Forgery | N/A — the tool performs no outbound requests of any kind (no network stack used at runtime). |

## Residual risk (declared)

- **Social/legal:** the operator’s authorization to examine a volume is the
  strongest control; technical controls cannot substitute for consent.
- **Overwrite (forensic reality):** bytes already reused by the filesystem
  cannot be recovered; the `$Bitmap` gate and FAT free-cluster heuristics
  explicitly report such candidates as `overwritten`, never silently importing
  wrong data.
- **Adversarial images:** bounded probing caps worst-case work, but a
  pathological image may still return many low-confidence carves — operators
  should re-validate by extension detector and BYTE-level signature.