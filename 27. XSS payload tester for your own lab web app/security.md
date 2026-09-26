# Security — XSS Payload Tester (portable GUI)

Security and safety posture of the portable XSS testing tool, aligned with OWASP Top 10:2025, NIST SP 800-53/800-218, and ISO/IEC 27001:2022 Annex A. Read before use.

---

## 1. Authorization is mandatory

This tool generates attack traffic. Use it **only against systems you are authorized to test** — by design its intended target is **your own lab web application**.

- A formal authorization gate is part of the workflow: record the system owner, date range, and allowed hosts in the **Authorization note** field before scanning (mirrors ISO A.8.29 acceptance criteria and NIST SP 800-115 planning phase).
- The GUI shows an explicit warning banner and the tool sends a scanning User-Agent (`XssTester/1.0 ... authorized security-testing only`).
- The tool does **not** enforce legal authorization by itself. Enforcing authorization is the operator's obligation.

## 2. Data handling

| Data | Where it lives | Handling |
|---|---|---|
| Target URL / config | `data/config.json` on **Save config** | Store is plaintext JSON. If it contains auth material, keep it private and delete after use. |
| Auth cookie / auth header | GUI memory only | Held in session memory during the scan; **never** written to audit trail, findings, or reports. Recommendation: use throwaway test credentials (least privilege, ISO A.5.15). |
| Scan findings / evidence | `data/reports/*.json|html` | Evidence includes raw response text which may contain **sensitive application data** — responses to payloads are echoed by the lab app. Treat reports as confidential (ISO A.8.12/A.8.13). |
| Audit trail | `data/audit/audit.jsonl` | Append-only JSONL: scan start/stop, requests (URL, payload id, status), findings, operator events. Used for evidence and incident reconstruction (ISO A.8.15, NIST AU-2/6/12, OWASP A09). |

Recommendations:
- Encrypt the `data/` folder if it must persist (BitLocker / EFS) — ISO A.8.12/A.8.13.
- Run scans against staging/QA copies of the app first.
- Never scan systems outside the lab scope you own.

## 3. Built-in safety controls (protects the target and the operator)

- **Scope**: crawling stays on the seed host (same-host-only). No link is followed off the declared target.
- **Politeness**: configurable delay between requests (ms) + concurrency cap (1-16). Defaults avoid flooding the target (ISO A.8.34).
- **Non-destructive default**: payloads are read/modify reflection probes; there is no destructive or state-changing module (no file deletion, no account lockout, no mail triggers).
- **Timeouts**: all requests bounded (`timeout` field); max pages / max payloads / max requests budgets prevent runaway runs.
- **No out-of-band callbacks**: detection is response-based; nothing contacts external infrastructure (no DNS/HTTP collaborator).
- **TLS**: certificate verification is ON by default; disable only for local self-signed lab targets and understand the trust implications.
- **Payload quarantine**: payload strings are embedded in reports only after HTML-escaping; the tool never executes parsed payload content.

## 4. The tool protects itself

- **Dependency surface** — runtime uses only the Python 3.12 standard library. No third-party runtime imports. PyInstaller (build-time only) pinned `>=6,<7`.
- **Secrets hygiene** — credentials never appear in reports, findings, or the audit log.
- **Least privilege** — run the exe as a normal, non-admin user; do not copy it into protected directories.
- **Supply chain (OWASP A03)** — the shipped exe embeds a reproducible stdlib build; regenerate and verify the checksum (`Get-FileHash XssTester.exe`) when distributing.

## 5. Detection quality & limitations (avoid false assurance)

- Detection is **response-reflection-based and heuristic**: no browser renders the page. A *raw reflection* with execution signatures is graded EXECUTED/LIKELY/SUSPICIOUS, but **browser confirmation is still required** before relying on a finding — open the PoC URL manually (the lab app renders it).
- Confidence (0-1), the observed reflection form (raw/encoded), and CSP header state are captured so an analyst can verify before scheduling remediation (SSDF PW.8.2 / RV.1, ISO A.8.29).
- Encoded reflection = evidence of mitigation; the detector reports CLEAN in that case rather than a false EXECUTED.
- CSP does not block all XSS in every browser mix; a strict CSP downgrades but does not zero a finding — server-side encoding is the fix for reflected XSS.
- Re-test after a fix: re-run the same categories against the patched lab app and confirm the finding disappears (SSDF RV.1; ISO A.8.8 closure).

## 6. Incident response notes

- On any unintended impact during a scan: stop the scan (Stop button), preserve `data/audit/audit.jsonl` and the most recent report (forensic evidence), reproduce with a single payload, and notify the lab owner.
- The audit log's `scan_start`, `request`, and `finding` entries give a precise reconstruction of what was sent and when.

## 7. Control mapping (evidence)

| Framework | Where the tool produces evidence |
|---|---|
| OWASP Top 10:2025 | Every finding carries an OWASP category (A05 Injection family per this project set's numbering) + CWE ids (CWE-79 primary) |
| NIST SP 800-218 (SSDF) | PW.5 (its own secure code), PW.7.2 / PW.8.2 (triage + testing records), RV.1 (re-test) |
| NIST SP 800-53 | SI-10 (input validation) / SI-15 (output encoding) primary; CA-8, SA-11 supporting |
| ISO/IEC 27001:2022 | A.8.8 (vuln register), A.8.25/A.8.26/A.8.27/A.8.28/A.8.29 (SDLC), A.8.15 (audit), A.8.34 (test protection) |

## 8. Report security

- HTML/JSON reports embed response evidence. Store in a protected folder, not on shared web roots.
- Reports include the `authorization_note` entered, making the authorized scope explicit in the artifact.
- Redact report content before sharing externally if it contains third-party or production-like data (ISO 5.x supplier/sanitisation considerations).

---

References: OWASP Top 10:2025 · OWASP XSS Prevention & Filter Evasion Cheat Sheets · OWASP ASVS v4.0.3 (V5.1) · NIST SP 800-115 · NIST SP 800-53 Rev 5 (SI-10/SI-15) · NIST SP 800-218 (SSDF v1.1) · ISO/IEC 27001:2022 Annex A · FIRST CVSS v3.1.