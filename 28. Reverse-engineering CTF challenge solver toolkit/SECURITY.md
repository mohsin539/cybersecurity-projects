# Security Policy — REkt

**Version:** 1.0 · **Last reviewed:** 2026-09-19 · **Owner:** Architecture WG
This document is part of the shipped product (ARCHITECTURE.md §11.4).

## 1. Supported versions

| Version | Supported | Notes |
|---|---|---|
| 1.0.x | ✅ | Current release |
| < 1.0 | ❌ | Re-download the verified current build |

## 2. Reporting a vulnerability

- Use **GitHub Private Vulnerability Reporting** (Security tab) — do **not** open public issues for security bugs.
- We acknowledge within **72 hours**, triage within **7 days**, and coordinate a fix within **90 days** (NIST SSDF RV.1/RV.2).
- Please include: affected version (`rekt.exe --version`), reproduction steps, and impact assessment. Sample files are not required — hashes suffice.

## 3. Security posture (what we enforce)

| Invariant | Where enforced | Control |
|---|---|---|
| Network egress denied inside sandbox children, always | `sandbox/policy.py` (`Policy.allow_network` rejects True), `sandbox/child.py` (socket null-route) | OWASP A01, NIST AC-3 |
| No shell ever spawned; argv-list only | `sandbox/runner.py` (`Popen` w/o `shell=True`), bandit S-rules in CI | OWASP A03 |
| Writes confined to job scratch | child `open()` guard + Policy invariant | OWASP A01, ISO A.8.9 |
| Sample bytes never parsed in the GUI process | JobService → disposable child with Job Object caps | NIST SC-3 |
| Plugins: signed allow-list; unsigned needs per-session Developer Mode + audit | `application/plugins.py`, `platform/trust.py` (Ed25519) | OWASP A08, ISO A.8.30 |
| Audit log tamper-evident (hash-chained) and verified at boot | `platform/audit.py` | NIST AU-9 |
| Telemetry impossible, not just off | `Config.validate()` raises if `telemetry_enabled` | OWASP A09, GDPR-friendly |
| No PII or sample content in logs — hashes only | audit appenders | OWASP A09 |
| EXEC-class actions require per-session explicit consent | `sandbox/policy.py::check_consent` | OWASP A01 |
| Executable builds: windowed, onedir, no UPX, reproducible from `rekt.spec` | `rekt.spec`, `scripts/build_exe.py` | NIST SSDF PS.2 |

## 4. Known limitations (honest disclosure)

1. **User-mode sandbox ≠ VM.** A determined sample might attempt sandbox escape via kernel exploits. REkt v1.x is designed for CTF/educational binaries, not live malware analysis. The GUI warns on launch; a VM-based runner is on the roadmap (ARCHITECTURE.md §13).
2. **Plugin code runs in-process.** Signed plugins are trusted code; unsigned plugins under Developer Mode run with your user rights. The allow-list default mitigates this.
3. **Windows Job Objects** enforce memory/CPU caps, but not kernel-level syscall filtering (no seccomp equivalent). UI restrictions + handle limiting reduce exposure.
4. **Update channel is offline by default** (`update_check_url=""`). If enabled later, it must be TLS 1.3 + pinned + signature-checked before any file swap.

## 5. Hardening guidance for operators

- Run REkt from a **standard user account** (never admin) — it needs nothing elevated.
- Prefer the portable `--data-dir` on non-system storage; delete it to remove all state.
- Keep `unsigned_plugins_allowed=false` and Developer Mode off unless reviewing plugin code.
- Use **File → Verify audit log** after any session you may need to attest.
- Sample drop location: REkt copies samples into its content-addressed store; originals are never modified.

## 6. Vulnerability disclosure timeline

| Stage | Target |
|---|---|
| Acknowledgment | ≤ 72 h |
| Triage + severity (CVSS 3.1) | ≤ 7 d |
| Fix released (HIGH/Critical) | ≤ 30 d |
| Fix released (Medium/Low) | ≤ 90 d |
| Public advisory (GHSA) | after fix ships |

## 7. Credits

Security researchers who responsibly disclose will be credited (opt-in) in release notes and `THIRD-PARTY-NOTICES.md`-adjacent `AUTHORS-SEC.md`.
