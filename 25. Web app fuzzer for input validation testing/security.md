# Security — Web App Fuzzer (portable GUI)

Security and safety posture of the portable tool, aligned with OWASP Top 10:2025, NIST SP 800-53/800-218, and ISO/IEC 27001:2022 Annex A. Read before use.

---

## 1. Authorization is mandatory

This tool generates attack traffic. Use it **only against systems you are authorized to test**.

- A legal/formal authorization gate is part of the workflow: record the system owner, date range, and allowed hosts in the **Authorization note** field before scanning (mirrors ISO A.8.29 acceptance criteria and NIST SP 800-115 planning phase).
- The tool marks the UI with an explicit warning banner and a scanning User-Agent (`WebAppFuzzer/1.0 ... authorized security-testing only`).
- It does **not** enforce technical authorization by itself. Enforcing legal authorization is the operator's obligation.

## 2. Data handling

| Data | Where it lives | Handling |
|---|---|---|
| Auth cookie / auth header / extra headers | GUI fields; written to `data/fuzzer_config.json` on **Save config** | Stored in **plaintext on the local disk** if you save config. Never share the config file; delete it after use, or keep the field empty. Credentials are held in memory only during the scan and are **not written to reports or the audit log**. |
| Scan findings / evidence | `data/reports/*.json|html` | Evidence includes response bodies that may contain **sensitive application data**. Treat reports as confidential (ISO A.8.12/A.8.13, classification + controlled distribution). |
| Audit trail | `data/audit/audit.jsonl` | Immutable append-only JSONL: scan start/stop, requests (URL, module, payload id), findings with severity/confidence, operator events. Used for evidence and incident reconstruction (ISO A.8.15, NIST AU-2/6/12, OWASP A09). |

Recommendations:
- Do **not** store production credentials in saved configs. Use throwaway test accounts (least privilege, ISO A.5.15).
- Encrypt the `data/` folder if it must persist (e.g., BitLocker / EFS) — see ISO A.8.12, A.8.13.
- Run scans against staging/QA copies of the application first; only scan production with explicit senior approval and a reduced (passive-first) payload profile.

## 3. Built-in safety controls (defends the target and the operator)

- **Scope**: scanning is limited to the endpoints discovered from the target seed. The crawler stays on the seed host by default (same-host-only).
- **Politeness**: configurable delay between requests (ms) + concurrency cap (1-16). Defaults avoid flooding the target (ISO A.8.34 protection of systems during testing).
- **Non-destructive default**: payloads are read/modify probes. Destructive or state-changing flows are not built in. Data-before/after integrity checks remain the operator's responsibility.
- **Timeouts**: all requests bounded (`timeout` field); no infinite crawls (max pages + max requests budgets).
- **No out-of-band callbacks**: detection is response-based; no DNS/HTTP collaborator infrastructure is contacted (nothing leaves the target conversation except the intended requests).
- **TLS**: certificate verification is ON by default; disable only for local self-signed test targets and understand the trust implications.

## 4. The tool protects itself

- **Dependency surface**: runtime uses only the Python 3.12 standard library (`urllib`, `tkinter`, `json`). No third-party runtime imports. PyInstaller (build-time only) is pinned `>=6,<7`.
- **Secrets hygiene**: credentials never appear in reports, findings, or the audit log.
- **Least privilege**: run the exe as a normal, non-admin user; do not copy it into protected directories.
- **Supply chain (OWASP A03)**: the shipped exe contains a reproducible stdlib build; regenerate and verify the checksum (`Get-FileHash WebAppFuzzer.exe`) when distributing.

## 5. Detection quality & limitations (avoid false assurance)

- Findings are **heuristic** (signature + differential + timing). They are evidence for triage (NIST SSDF PW.8.2 / RV.1, ISO A.8.29), **not** proof of exploitability.
- Confidence is reported (0-1) and all raw evidence is captured for analyst verification before remediation is scheduled.
- Re-test after a fix: re-run with the same modules against the patched build and confirm the finding disappears (NIST SSDF RV.1; ISO A.8.8 closure SLA).

## 6. Incident response notes

- On any unintended impact during a scan: stop the scan (Stop button), preserve `data/audit/audit.jsonl` and the most recent report (forensic evidence), reproduce with a single payload, and notify the system owner.
- The audit log's `scan_start`, `request`, and `finding` entries give a precise reconstruction of what was sent and when.

## 7. Control mapping (evidence)

| Framework | Where the tool produces evidence |
|---|---|
| OWASP Top 10:2025 | Each finding carries its OWASP category (A01-A10:2025) + CWE ids |
| NIST SP 800-218 (SSDF) | PW.5 (its own secure code), PW.7.2 / PW.8.2 (triage + testing records), RV.1 (re-test) |
| NIST SP 800-53 | SI-10 (information input validation) primary; CA-8, SA-11 supporting |
| ISO/IEC 27001:2022 | A.8.8 (vuln register), A.8.25/A.8.26/A.8.27/A.8.28/A.8.29 (SDLC), A.8.15 (audit), A.8.34 (test protection) |

Full traceability tables: `FRAMEWORK_MAPPING.md`.

## 8. Report security

- HTML/JSON reports embed response evidence. Store in a protected share, not on shared web roots.
- Reports include the `authorization_note` you entered, making the authorized scope explicit in the artifact.
- Regenerate/patch or redact reports before sharing externally (e.g., with suppliers) if they contain third-party information (ISO 5.x supplier/sanitisation considerations).