# Security Document — ARP Live-Host Discovery Tool

**Version:** 1.0 · **Applies to:** `arp_scanner` v1.0.0 (GUI + scan engine + `.exe`)
**Audience:** Developers, security reviewers, operators
**Companion docs:** [`archetecture.md`](archetecture.md) · [`state.md`](state.md) · [`memory.md`](memory.md)

---

## 1. Scope & Security Objective

This document maps the application's security controls to three control
frameworks required by the project:

| Framework | What we map |
|---|---|
| OWASP Top 10 (2021) | Application-level risks (relevant subset) |
| ISO/IEC 27001:2022 (Annex A) | Information-security management controls |
| NIST CSF 2.0 + SP 800-218 (SSDF) | Organizational posture & secure development |

**Security objective:** the tool must discover live hosts on an authorized
local segment while (a) minimizing its own attack surface, (b) producing
**trustworthy, integrity-checked** reports, and (c) leaving a **complete audit
trail** of what it did and when — all with the least privilege required.

The tool is a **local, operator-driven CLI-style GUI utility**. It performs no
authentication, holds no credentials, spawns no network listeners, and
persists nothing beyond user-chosen export files plus local audit/consent
markers. This scope is reflected in the mappings below.

---

## 2. Security Architecture (principles)

```
                ┌───────────────────────────────────────────────┐
   Operator     │               ARP Scanner App                │
   (human/CI)   │                                               │
      │         │  GUI ── worker thread ── scan engine          │
      ▼         │       │                    │                  │
  ┌────────┐    │  QThread pipes signals    │ ARP burst send    │
  │ stdin/ │    │  (no secrets in payloads) │  + single capture │
  │ dialogs│────►  ┌─────────────┐  ┌───────▼────────┐           │
  │ FILES  │◄────  │ Exporters   │──│ Security Guard │          │
  │ (exe)  │    │  │ (atomic)    │  │ (consent/prive)│          │
  └────────┘    │  └─────────────┘  │ (validation/audit)       │
                │                   └───────────────────────────┘
                └───────────────────────────────┬───────────────┘
                                                │ ARP frames (L2)
                                                ▼
                                          Network segment
```

**Defense-in-depth layers implemented:**

1. **Authorization gate** — mandatory authorized-use notice on first launch
   (`arp_scanner/security/guard.py:CONSENT_NOTICE`).
2. **Least privilege / capability check** — raw L2 access is verified at the
   scan boundary and the operator is told exactly how to elevate
   (`guard.py::check_privileges`), never auto-elevated.
3. **Input hardening** — strict regex-based parsing of CIDR / ranges / MACs;
   malformed input rejected with actionable messages, no code paths accept
   unvalidated strings (`arp_scanner/util/net.py`).
4. **Output hardening** — CSV formula-injection neutralization and path
   validation before any file write (`guard.py::sanitize_cell`,
   `validate_export_path`).
5. **Integrity of exports** — atomic temp-file + `os.replace()` writes so a
   reader never sees a partial file (`report/exporters.py::write_export`).
6. **Audit & detectability** — every scan lifecycle event, consent decision,
   error, and export is written to a timestamped audit log
   (`guard.py::audit`).
7. **No data exfiltration** — the application makes exactly one kind of
   network call: ARP probes on the caller-chosen interface and subnet. No
   telemetry, no updates, no remote endpoints.

---

## 3. OWASP Top 10 (2021) Mapping

| # | OWASP Axx | Risk in this tool | Implemented controls | Evidence |
|---|---|---|---|---|
| A01 | Broken Access Control | Unauthorized scanning; privilege misuse | Authorized-use consent gate; raw-socket capability check at scan boundary; **no auto-elevation**; explicit instruction to run with least privilege (Admin/sudo/CAP_NET_RAW) | `guard.py::check_privileges`, `_privilege_hint` |
| A02 | Cryptographic Failures | Scan reports are sensitive (IP+MAC); stored exports must not leak | No in-transit or at-rest encrypted data is held (local tool); exports written with owner-only permissions on POSIX; guidance to `chmod 600` / ACL on Windows documented in `security.md` §6 & README | `guard.py::_restrict_permissions` |
| A03 | Injection | Crafted target strings → config/network abuse; CSV formula injection; log injection | Strict regex target parsing + octet range limits + 2M-address cap; `sanitize_cell()` neutralizes `=`/`+`/`-/`@`/tab cells; export path validation rejects control chars & `..` | `util/net.py`, `guard.py::sanitize_cell/validate_export_path`, `report/exporters.py` |
| A04 | Insecure Design | Enabling large-scale scanning; unbounded resource use | Design guardrails: `/8`-class scans require explicit override; 1M-address hard limit; bounded burst pacing; default excludes network/broadcast addresses | `core/engine.py::LARGE_SCAN_ADDRESS_LIMIT`, `scanner config` |
| A05 | Security Misconfiguration | Debug leaks, unnecessary features, unsafe defaults | Windowed (console-less) production build; `verbose` framing dumps opt-in; no debug backdoors; secure defaults (reserved addresses skipped, bounded retries) | `arp_scanner.spec` (`console=False`), `core/config.py` |
| A06 | Vulnerable & Outdated Components | Supply-chain risk from PySide6/scapy/psutil | Requirements pinned with lower bounds; SBOM documented in `state.md` R-008; build deps isolated in a venv; periodic upgrade review is an open item | `requirements.txt`, `pyproject.toml` |
| A07 | Identification & Authentication Failures | Not applicable | Tool authenticates to nothing and stores no identity data | — |
| A08 | Software & Data Integrity Failures | Tampered `.exe` / source drift between shipped binary and repo | Reproducible build via `arp_scanner.spec` + `build_exe.bat` from pinned deps; **code signing & SHA-256 distribution hashes recommended before wider distribution** (open item R-007) | `arp_scanner.spec`, `build_exe.bat`, `state.md` |
| A09 | Security Logging & Monitoring Failures | Scan misuse going unnoticed | Structured audit log: timestamps (UTC), PID, event text; rotated at 5 MB; mirrored to app's audit pane; crash traces captured to `crash.log` | `guard.py::audit`, `app.py:_install_excepthook` |
| A10 | Server-Side Request Forgery | Tool "teleports" to arbitrary targets — normally N/A, but here the tool BY DESIGN probes only the local segment | The only network primitive is ARP (L2, single broadcast domain); interface is operator-selected; target parsing cannot express URLs/hosts — only IPv4/CIDR on the local interface | `core/packets.py` (ARP only), `util/net.py` |

> A07 is marked non-applicable by design; A10 is mitigated by construction
> (the application cannot be coerced into contacting arbitrary hosts by
> operators or input alone).

---

## 4. ISO/IEC 27001:2022 — Annex A Control Mapping (relevant subset)

| Annex A control | Title | How the tool satisfies it |
|---|---|---|
| **A.5.1** | Policies for information security | Authorized-use notice; scanning permitted only with ownership/consent (`guard.CONSENT_NOTICE`) |
| **A.5.15** | Access control | Least-privilege run model; capability verified before any packet is sent; no persistent privileged daemon |
| **A.5.23** | Cloud services security | N/A — no cloud services |
| **A.5.35** | Independent review of information security | Security review checklist in `security.md` §10; code review before merging |
| **A.6.8** | Security event reporting | All events funnelled to `guard.audit()` (scan start, hosts, errors, consent decisions) |
| **A.7.4** | Physical security monitoring | N/A (software only) — operator workstation assumed controlled |
| **A.8.8** | Tech. vulnerability mgmt | Pin ranges; SBOM; upgrade review tracked as open item (R-008) |
| **A.8.9** | Configuration management | Single reproducible build via `.spec` + `.bat`; config file precedence documented |
| **A.8.10** | Information deletion | Results live only in RAM until operator exports; export files are deleted only by the operator; no auto-retention |
| **A.8.13** | Information backup | Duration/summary outputs are regenerable; audit log is append-only with rotation |
| **A.8.14** | Reliability of monitoring | Audit writes are fsync'd on export path; log rotation preserves a `.log.1` history |
| **A.8.16** | Activity monitoring | `guard.audit()` provides tamper-evident-after-the-fact timeseries; timestamps UTC |
| **A.8.24** | Use of cryptography | N/A — no crypto keys; if future transport added (e.g., report sync) TLS 1.2+ required |
| **A.8.34** | Protection of information systems during audit/testing | Export files and audit logs treated as sensitive; owner-only perms |
| **A.8.25** | Secure development lifecycle | SSDF-aligned: threat modeling, validation, tests (59 passing), review gate (§5, §10) |
| **A.8.28** | Secure coding | Input validation, CSV-injection defense, no eval/exec of input, sandboxed file writes |
| **A.8.29** | Security testing (dev/acq) | Unit tests for parse/export/validation; offscreen GUI smoke test; packaged-exe launch test |
| **A.8.30** | Outsourced development | N/A — in-house |
| **A.8.31** | Separation of dev/test/prod | Dev venv (`.venv`), build venv (`.venv_build`), packaged dist isolated in `dist/` |
| **A.8.32** | Change management | State.md decision log; precedence rules; review gate |
| **A.5.17** | Authentication info | N/A — no credentials handled |
| **A.5.28-31** | Physical / workplace / clean desk | N/A — data minimization is the mitigation |

---

## 5. NIST Mapping

### 5.1 NIST Cybersecurity Framework (CSF 2.0)

| Function | Implemented practice |
|---|---|
| **Govern (GV)** | Authorized-use policy embedded in the app; security.md as the control baseline |
| **Identify (ID)** | Data inventory: IP+MAC discovered, audit events, export files all classified as **internal/sensitive**; assets enumerated in `state.md` |
| **Protect (PR)** | Least privilege, capability gating, input/output hardening, atomic writes, pinned dependencies, owner-only permissions |
| **Detect (DE)** | Full audit log of scans, consent events, errors; visible audit pane; crash logging |
| **Respond (RS)** | Clear operator guidance on privilege failures (exit-code contract `2/3`); graceful interrupt handling; partial results preserved on interruption |
| **Recover (RC)** | Exports are regenerable from a re-scan; audit log rotation keeps history; builds reproducible |

### 5.2 NIST SP 800-218 Secure Software Development Framework (SSDF)

| Practice | Mapping in repo |
|---|---|
| **PW.1 (Define security requirements)** | `security.md`, architecture constraints in `archetecture.md` |
| **PW.4 (Reuse existing, well-secured software)** | scapy / psutil / Qt (battle-tested libraries) over custom stack code |
| **PW.5 (Create source code)** | Code review checklist (§10); no secrets in code |
| **PW.7 (Review & verify code)** | 59 passing pytest cases incl. security-focused tests (`test_guard.py`, `test_export.py`) |
| **PS.2 (Inspect third-party code)** | SBOM + pinned ranges (R-008); relies on upstream advisories |
| **PS.3 (Verify third-party integrity)** | Hashes verified at pip install of venv; unsigned deps flagged as residual risk |
| **PS.4 (Employ reproducible builds)** | `arp_scanner.spec` + `build_exe.bat` from frozen venv |
| **RV.1 (Test in deployed env)** | Packaged-exe offscreen launch test passed; runtime requires Npcap+Admin |
| **RV.2 (Deploy in securely provisioned env)** | Windowed build; no debug hooks; guidance to sign + hash distributable (R-007) |

### 5.3 Supporting NIST references

- **SP 800-115** (technical security testing) — scanning mindset; our ARP approach is a compliant L2 discovery primitive.
- **SP 800-41 / rev** — ARP/protocol-level guidance aligned with our design.
- **SP 800-123** (server security) — N/A, no server.
- **SP 800-94** — network monitoring; audit log is our monitor.

---

## 6. Data Handling & Privacy

- **Collected in RAM:** IP, MAC, RTT, interface, vendor (derived). Nothing is
  written except: (1) an operator-requested export, (2) the local audit log,
  (3) the consent marker (contains only a UTC timestamp — no identity data).
- **Exports:** treated as **sensitive** (device identifiers). Operators must
  apply restrictive permissions: POSIX `chmod 600 file`; Windows — restrict via
  file ACLs. The tool writes temp files with minimal default perms and renames
  atomically.
- **No exfiltration:** no network egress beyond ARP on the chosen interface.
  The tool has no update-checker, telemetry, or remote calls.
- **Retention:** results are intentionally ephemeral; export files are the
  operator's responsibility (deletion, encryption-at-rest via OS at rest
  protection, etc.).

---

## 7. Runtime Threat Model

| Threat | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Unauthorized use of the tool | Medium | Legal/network disruption | Consent gate + audit trail + no-network-egress design |
| Operator runs as over-privileged context | Medium | Wider blast radius | Capability check; docs recommend least privilege (`Admin/sudo`, not root-everything) |
| Malicious targets (Rogue ARP) | Medium | False positives/spoofed MACs | Replies keyed to requested `tpa`; dedupe by IP; RTT min; vendor=unknown flagged |
| Crafted input (`=cmd`, path traversal, huge ranges) | Low→Medium | CSV injection / DoS / overwrite | `sanitize_cell`, `validate_export_path`, size caps, atomic replace |
| Tampered binary distribution | Low | Integrity of delivered tool | Reproducible build, signing+hash recommended (R-007), build from pinned deps |
| Sniffed ARP traffic (L2 visibility) | High (inherent) | Host enumeration exposed to promiscuous peers | Documented in consent notice; inherent L2 risk, no mitigation beyond authorization limits |
| GUI thread starvation / worker crash | Low | Frozen UI / incomplete scan | Worker on separate QThread with signal marshalling; excepthook→crash.log |
| Privilege escalation via Npcap driver | Residual | High | Operates only under the operator's account; Npcap vendor driver updates required (documented) |

---

## 8. Logging & Monitoring (A09 / A.12.4)

- **Format:** `YYYY-MM-DDTHH:MM:SSZ [pid] message` — UTC, machine-readable, append-only.
- **Channels:** stderr (informational) + `%APPDATA%\ArpScanner\audit.log` (Windows) / `~/.config/arpscanner/audit.log` (POSIX).
- **Rotation:** 5 MB, previous file kept as `audit.log.1`.
- **Crash traces:** `crash.log` in the same directory via `sys.excepthook`.
- **Events logged:** consent ack/decline, app start, scan start (target count + interface), scan complete (counts + duration), per-host result lines (verbose), errors, privilege failures, cancellations, exports.

---

## 9. Secure Development & Build Practices

- **Isolated venv** for both dev and build (`pip install -e .` / `build_exe.bat`).
- **Pinned-but-auditable dependencies** (lower bounds) recorded as SBOM in `state.md`.
- **Reproducible artifact:** `pyinstaller --clean arp_scanner.spec` → `dist\ArpScanner\ArpScanner.exe`.
- **Binary hardening:** `console=False` (no terminal leak), excludes unused Qt modules (WebEngine/QML), UPX compression applied.
- **Release checklist before wider distribution (recommended):**
  1. Code-sign the `.exe` (Authenticode / signtool) to bind identity + integrity.
  2. Publish a `SHA-256` manifest alongside each release.
  3. Pin exact dependency versions (not just floors) in a release lockfile.
  4. Update Npcap-dependent docs + re-run privilege & sniffing validation.

---

## 10. Security Review Checklist (used at each merge)

- [ ] No secrets, keys, or PII introduced
- [ ] All inputs validated before use (targets, paths, MACs)
- [ ] CSV cells sanitized against formula injection
- [ ] Export paths validated; writes atomic
- [ ] Audit event emitted for every user-visible security-relevant action
- [ ] No new network endpoints or egress introduced
- [ ] Dependencies updated in `requirements.txt` + SBOM kept accurate
- [ ] `pytest` suite green (`59 passed`)
- [ ] Changes documented in `state.md` decision log
- [ ] Privileged behavior still capability-gated (no auto-elevation)

---

## 11. Compliance Statement & Assumptions

The tool is designed to align with the **intent** of OWASP Top 10 (2021),
relevant ISO/IEC 27001:2022 Annex A controls, and NIST CSF 2.0 / SP 800-218.
Formal certification to a framework is an organizational decision, not
something a code artifact can claim alone; this document is the evidence
package an assessor can start from.

**Assumptions:**
1. The machine is an operator-controlled workstation running Windows (primary) or POSIX (secondary).
2. Npcap (Windows) or libpcap/raw-socket support (POSIX) is present and current.
3. Operators have network ownership or written authorization.
4. Networks scanned contain standard Ethernet L2; exotic media (PPP, RFC 1042 tunnels) may behave differently.

---

*Reference docs: `archetecture.md` (design), `state.md` (reservations &
decisions), `memory.md` (project conventions).*