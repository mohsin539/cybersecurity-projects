# security.md — Security & Compliance Reference

> **Scope:** portscanner v1.0 (Python implementation of `architecture.md`)
> **Frameworks:** ISO/IEC 27001:2022 (Annex A), NIST SP 800-53 Rev.5, OWASP Top 10 (2021)
> ⚠️ **Authorized use only.** Scanning systems without written permission may be illegal.

---

## 1. Threat Model

| # | Threat | Vector | Primary controls |
|---|--------|--------|------------------|
| T1 | Unauthorized scanning (tool misuse) | User scans third-party systems | Authorization gate (C1), audit log (C2) |
| T2 | Terminal escape / output injection | Malicious service banners (`\x1b[...`) | Sanitization (C3) |
| T3 | Path traversal | `--output ../../etc/cron.d/x` | safe_output_path (C4) |
| T4 | Resource exhaustion / self-DoS | Huge CIDR, runaway workers | Hard caps (C5) |
| T5 | Credential leakage in reports/logs | Proxy creds in env/config | Redaction (C6) |
| T6 | Tampering with scan evidence | WAL/report modification | 0600 perms, SHA-256 integrity (C7) |
| T7 | Injection via targets/ports config | `; rm -rf`, oversized strings | Charset + length validation (C8) |
| T8 | Privilege abuse | Raw-socket engines run unnecessarily | Privilege isolation + pre-check (C9) |
| T9 | Recon of the scanner itself | Predictable probe timing/ISN | Jitter + randomized ISN (C10) |
| T10 | Vulnerable dependencies | supply-chain | Stdlib-only core; pinned optional scapy (C11) |

---

## 2. Implemented Controls (code-referenced)

| ID | Control | Implementation | Verified by |
|----|---------|----------------|-------------|
| C1 | **Authorization gate** — non-private targets require typed confirmation phrase or `--yes`; refusals audited; raw scan types additionally require explicit authorization | `security.authorization_gate`, `config.validate` | `test_authorization_gate_*`, `test_raw_scan_requires_authorization` |
| C2 | **Audit logging** — append-only, who/when/what, redacted, bounded line length | `security._audit`, `audit.log` (~/.portscanner/, 0600) | smoke run (CLI e2e) |
| C3 | **Output sanitization** — ANSI/CSI strip, control-char escape, 256 B banner cap | `security.sanitize_text` | `test_sanitize_strips_terminal_escapes` |
| C4 | **Path traversal guard** — resolved output must stay in project or ~/.portscanner | `security.safe_output_path` | `test_safe_output_path_blocks_traversal` |
| C5 | **Resource caps** — targets ≤ 4096, expansion ≤ 2^20, workers ≤ 2048, ports ≤ 65535, bounded queues, per-host in-flight cap | `config.py`, `resolver.MAX_EXPANSION`, `scheduler` | `test_parse_ports_rejects_garbage` |
| C6 | **Secret redaction** — env secret keys replaced in all log/report text | `security.redact` | code review / manual |
| C7 | **Evidence integrity** — WAL default 0600 (POSIX), `sha256_of_file` for chain-of-custody | `store.close`, `security.sha256_of_file` | manual |
| C8 | **Input validation** — target charset allow-list, port-spec strict regex, DNS via stdlib parser (no regex parsing of IPs) | `config._validate_target_string`, `config.parse_ports` | `test_validate_rejects_bad_targets` |
| C9 | **Privilege isolation** — raw sockets only in `engines/raw.py`; admin pre-check in GUI label + engine probe; fail-fast before packets | `engines/raw._is_admin`, `gui` | `test_raw_scan_requires_authorization` |
| C10 | **Scan hygiene** — configurable jitter, per-host fairness cap, adaptive rate back-off, random-ish ISN, RST teardown | `ratelimit.py`, `scheduler`, `engines/raw` | manual |
| C11 | **Dependency minimization** — zero runtime deps; scapy optional + privilege-gated | `pyproject.toml` | manual |

---

## 3. ISO/IEC 27001:2022 — Annex A Mapping

| Annex A Control | Title | Implementation here |
|---|---|---|
| A.5.1 | Policies for information security | This document + README safety section |
| A.5.17 | Authentication information | Secrets never logged (`redact`), `PublicConfig` strips sensitive fields |
| A.6.3 | Information security awareness | Legal notice at startup, GUI warning label, epilog in `--help` |
| A.8.2 | Privileged access rights | Raw-socket engines require admin; capability pre-checked, never assumed |
| A.8.5 | Secure authentication | N/A (no accounts) — local user context only |
| A.8.8 | Management of technical vulnerabilities | Tool purpose; gated by explicit authorization (C1) |
| A.8.9 | Configuration management | Immutable frozen `Config`; no global mutable state |
| A.8.10 | Information deletion | WAL/reports are user-owned files; documented as sensitive (C7) |
| A.8.12 | Data leakage prevention | Banner truncation + sanitization before persistence (C3) |
| A.8.13 | Information backup | WAL doubles as crash-recovery artifact (`--resume`) |
| A.8.15 | Logging | Append-only audit trail (C2) |
| A.8.16 | Monitoring activities | Event bus counters; rate controller observes network feedback |
| A.8.24 | Use of cryptography | SHA-256 for integrity references (C7); no custom crypto |
| A.8.25 | Secure development lifecycle | Threat model (§1), tests §4, minimal deps (C11) |
| A.8.29 | Security testing | Unit + smoke suite; controls verified by named tests (§2) |
| A.8.32 | Change management | `state.md` records change history + verification steps |

## 4. NIST SP 800-53 Rev.5 Mapping

| Control | Family | Implementation here |
|---|---|---|
| AC-3 | Access Enforcement | Authorization gate before any packet (C1) |
| AC-4 | Information Flow Control | Output path containment (C4) |
| AC-6 | Least Privilege | Connect/UDP need zero privilege; raw isolated (C9) |
| AC-21 | Information Sharing | Redaction of credentials in shared reports (C6) |
| AU-2 / AU-3 | Event Logging / Content | Audit log: timestamp, user, event, redacted detail (C2) |
| AU-9 | Protection of Audit Info | 0600 perms, append-only usage pattern (C2/C7) |
| AU-11 | Audit Record Retention | File-based, user-managed; format documented here |
| CM-7 | Least Functionality | Only requested features execute; no telemetry |
| IA-4 | Identifier Management | Local username via `getpass.getuser()` for audit |
| SA-15 | Development Process | Architecture → controls → tests traceability (§2) |
| SC-5 | Denial of Service Protection | Hard caps + bounded queues + rate limiter (C5) |
| SC-10 | Network Disconnect | RST teardown, bounded socket lifetime, timeouts (C5/C10) |
| SI-7 | Software/Info Integrity | SHA-256 integrity helper; WAL tamper-evident by perms (C7) |
| SI-10 | Information Input Validation | Strict config validation, charset allow-lists (C8) |
| SI-11 | Error Handling | Errors become events/warnings; never silent; scan continues |

## 5. OWASP Top 10 (2021) Mapping

| OWASP Risk | Relevant because | Mitigation here |
|---|---|---|
| **A01 Broken Access Control** | `--output` file writes | Path containment (C4), no exec/search on outputs |
| **A02 Cryptographic Failures** | evidence integrity | SHA-256 integrity refs (C7); TLS fingerprint-only (no weak custom crypto) |
| **A03 Injection** | target strings, banners in terminal | Charset validation (C8), ANSI-strip (C3); DNS via stdlib parser |
| **A04 Insecure Design** | resource abuse | Rate limiter, hard caps, bounded queues (C5); authorization by design (C1) |
| **A05 Security Misconfiguration** | unsafe defaults | Safe defaults (connect scan, rate-capped); dangerous modes require explicit flags; validation fail-fast |
| **A06 Vulnerable Components** | supply chain | Zero runtime dependencies (C11) |
| **A07 Auth Failures** | N/A (no auth) | No accounts/sessions exist |
| **A08 Integrity Failures** | WAL/report tampering | 0600 perms, integrity hashing (C7) |
| **A09 Logging Failures** | misuse invisible | Audit every start/stop/authz decision (C2) |
| **A10 SSRF** | scanner fetches banners | It *is* a network tool — scope enforced by authorization gate (C1); no URL fetching beyond probe payloads |

---

## 6. Data Protection

| Artifact | Location | Sensitivity | Protection |
|---|---|---|---|
| Audit log | `~/.portscanner/audit.log` | internal | 0600 (POSIX), redacted content |
| WAL | `./scan.wal` | internal | 0600 on close (POSIX); delete after use |
| Reports | user-specified | internal | path-contained; treat as confidential |
| Banner excerpts | inside reports | external-derived | truncated 256 B, sanitized, no auto-execution |

## 7. Secure Defaults Summary

- Scan type: `connect` (unprivileged, fully logged by targets — honest by design)
- Rate: bounded by workers; per-host ≤ 32 in-flight
- Authorization: **required** for non-private targets and **all** raw scans
- Output: stdout, no file writes without explicit `--output`
- Banner handling: sanitize → truncate → store

## 8. Verification & Change Control

- Full suite: `py -m unittest discover -s tests -v` (11 tests, green on 2026-09-12)
- E2E smoke: `py -m portscanner 127.0.0.1 -p 80,443,445,3389 --yes` — audit log entries produced
- Any control change requires: threat-model row update (§1), control row (§2), test, and `state.md` entry.
