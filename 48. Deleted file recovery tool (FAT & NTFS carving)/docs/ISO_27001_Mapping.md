# ISO/IEC 27001 Mapping — RecovPro Secure

This document maps the controls the product implements to relevant
ISO/IEC 27001:2022 Annex A objectives. It is a **design-compliance statement**,
not a certification claim.

| Annex A control | Objective | Implementation in RecovPro Secure |
|---|---|---|
| **5.4** Management responsibilities | Security roles & responsibilities | Documented operator instructions in SECURITY.md; ethical-use statement in README |
| **5.6** Contact with authorities / **6.8** reporting | Incident handling & reporting | Vulnerability-reporting process with response SLA in SECURITY.md (5 business days) |
| **6.7** Threat intelligence | Understand threats before response | Free-space scanning bounded against hostile disks; PLAUSIBILITY gates + MAX_ARTIFACT caps documented in `app/core/carver.py` |
| **7.2.1** Competence & lab management | Testing prior to release | 4-phase read-only self-test (`app/main.py --selftest`) that is a build gate; synthetic media builders in `app/tests/builders.py` |
| **8.8** Management of technical vulnerabilities | Patch & regression control | Pinned dependencies (`requirements.txt`); deterministic PyInstaller `.spec`; self-test regression suite |
| **8.9** Information security configuration management | Least-functional config | UAC `asInvoker` manifest —application never requests elevation; physical-drive access only when the operator already runs elevated |
| **8.12** Prevention of information leakage | No data leaks to third parties | No telemetry, no network calls, no upgrade checkers; exports only on operator action (CSV/JSON/HTML/encrypted bundle) |
| **8.15** Logging | Tamper-evident evidence | `audit.jsonl` hash chain + `audit.tail.sha256` root; `verify_chain()` before trusting logs |
| **8.24/8.25** Use of cryptography / lifecycle | Protect confidentiality & integrity | AES-256-GCM + PBKDF2-HMAC-SHA256 (600k iters) for bundle export; SHA-256 for vault manifest and per-artifact fingerprinting; SHA-256 hash chain for audit |
| **8.28** Secure coding | Secure development lifecycle | Path-traversal sanitization (`safe_name`/`is_unsafe_path`), input clamps in `ReadOnlySource`, bounds in carver, faults fail closed with clear errors |
| **8.33** Test information | Protect test data | Self-test fixtures are synthetic (temp `recovpro_test_*.img`), never real media; reporters asked to reproduce against synthetic images only |
| **8.34** Protection of info systems during audit/testing | Isolation during assurance | Engine opens sources `GENERIC_READ` + share flags, never writes; vault confinement for all outputs |

## Evidence checklist

To substantiate each claim, the following artifacts ship with the codebase:

- `app/core/disk.py` — read-only handle discipline + clamps.
- `app/security/audit.py` — hash-chained log + `verify_chain()`.
- `app/security/vault.py` — SHA-256 manifest + AES-256-GCM bundle export/restore.
- `app/security/sanitize.py` — path traversal hardening.
- `app/tests/smoke.py` — the executable self-test gate.
- `packaging/RecovPro.manifest` — `asInvoker` execution level.
- `packaging/RecovPro.spec` — reproducible bundle config.