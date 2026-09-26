# Framework & Compliance Mapping — Web App Fuzzer

Companion to `ARCHITECTURE.md`. Each fuzz module, finding, and report is traceable to the frameworks below. The mapping tables are the authoritative source for the **Framework Mapper** component and the **Traceability Report**.

Standards versions referenced:
- **OWASP Top 10:2025** (released Nov 2025, finalized Jan 2026)
- **NIST SP 800-218** — SSDF v1.1 (Secure Software Development Framework)
- **NIST SP 800-53 Rev 5** (security controls)
- **NIST SP 800-115** (Technical Guide to Information Security Testing and Assessment)
- **ISO/IEC 27001:2022** Annex A (93 controls)

---

## 1. OWASP Top 10:2025 — Module Coverage

| OWASP Top 10:2025 | Primary fuzz modules & techniques | Example CWEs |
|---|---|---|
| **A01 Broken Access Control** | Route/path fuzzing (forced browsing), IDOR/object-id mutation, HTTP method fuzzing, header-based access probe (X-Forwarded-For, Host), SSRF probes (CWE-918) against scoped internal hosts / metadata markers | CWE-639, 352, 284, 918 |
| **A02 Security Misconfiguration** | Header hardening checks (CSP, HSTS, X-Frame-Options, CORS), debug/error-page mode detection, default-endpoint probes (`/.env`, backups), TLS/HTTP-strictness probes | CWE-16, 1004, 1021 |
| **A03 Software Supply Chain Failures** | SCA integration: fingerprint exposed dependencies/SBOM matching of target (JS lib signatures, framework banners), version-banner fuzzing | CWE-937, 1388, 345, 926 |
| **A04 Cryptographic Failures** | Cipher/protocol negotiation checks, cookie flags & token entropy inspection, hash-format detection in responses | CWE-327, 331, 319 |
| **A05 Injection** | **Core platform domain**: SQLi, NoSQLi, XSS (reflected/DOM/stored via chained flows), OS command, LDAP, XPath/XQuery, SSTI/expression, XML/XXE, CRLF/header injection — grammar + oracle driven | CWE-79, 89, 77, 78, 94, 611, 917, 730 |
| **A06 Insecure Design** | Business-logic fuzzing (price/quantity/limit tampering), trust-boundary probes, rate-limit bypass checks; feeds threat-model findings | CWE-799, 662, 441 |
| **A07 Authentication Failures** | Session-token entropy/mutation fuzzing, cookie/session mutators, auth-flow parameter tampering, credential-exposure probes, MFA-bypass flows | CWE-287, 384, 307 |
| **A08 Software or Data Integrity Failures** | Deserialization payload probes (Java/JSON/Pickle/YAML), mass-assignment parameter injection, JWT algorithm-confusion probes | CWE-502, 915, 345 |
| **A09 Security Logging & Alerting Failures** | Log-injection payloads (CRLF); verifies injected log visibility and alert hygiene; its own engine stdout/audit feeds SIEM | CWE-117, 778, 223 |
| **A10 Mishandling of Exceptional Conditions** | Error-fuzzing: malformed types, missing/duplicate params, boundary values, unicode — detects stack traces, verbose errors, fail-open branches | CWE-755, 209, 390 |

Supporting OWASP references used for test design: **ASVS v4** (V5 input validation, V14 config), **WSTG** (INPV/ERRV sections), **Secure Coding Practices Quick Reference**.

---

## 2. NIST SP 800-218 (SSDF v1.1) — Practice Mapping

| SSDF practice | How the fuzzer evidences it |
|---|---|
| **PO.3.1** Specify toolchain for secure development | The fuzzer is a documented, approved element of the secure toolchain; its config is versioned. |
| **PW.4** Review software design | Attack-surface builder outputs (fuzz target graph) feed design review against validation requirements. |
| **PW.5** Create source code by secure coding practices | The fuzzer's own code passes SAST; it validates "all inputs, all outputs" per PW.5.1. |
| **PW.7.2** Review/analyze code; record & triage issues | Finding records with triage status feed the development workflow (PW.7.2). |
| **PW.8.1 / PW.8.2** Test executable code | DAST input-validation suite: scoped, designed, executed, and documented per scan. |
| **RV.1** Identify & confirm reported vulnerabilities | Re-test/regression workflow proves remediation and closure of fuzz findings. |
| **RV.2** Analyze root causes | Correlator + remediation-advice engine ties findings to root-cause categories (missing validation, insecure defaults). |
| **PS** group (protect software) | Platform publishes SBOM, signs scan artifacts, enforces provenance for its own releases. |

---

## 3. NIST SP 800-53 Rev 5 & SP 800-115 — Alignment

| Source | Control / phase | Coverage |
|---|---|---|
| SP 800-53 **SI-10** — Information Input Validation | Core home of this tool | Fuzzer coverage is direct evidence that input-validation controls are checked (error checking, bounds, malformed input). |
| SP 800-53 **CA-8** — Penetration Testing | Supporting evidence | Fuzzer output feeds penetration-test records and findings. |
| SP 800-53 **SA-11** — Developer Security Testing & Evaluation | Supporting evidence | In-CI fuzz gates and acceptance criteria map to SA-11 deliverables. |
| SP 800-53 **AU-2 / AU-6 / AU-12**, **SI-3**, **SC-7** | Platform operations | Audit logging, anti-malware/scan sandbox hygiene, boundary + egress control of workers. |
| SP 800-53 **SC-20/21, SC-3/7** | Collaborator infra | OOB SSRF callbacks use approved, isolated infrastructure. |
| SP 800-115 — four-phase methodology | Process alignment | Platform adopts its **planning -> discovery -> attack -> reporting** phases for every scan. |

### SP 800-115 phase correspondence

| SP 800-115 phase | Fuzzer stage |
|---|---|
| Planning | Authorize + scope guard + policy plan (scan lifecycle steps 1-4) |
| Discovery | Crawler, schema import, parameter extraction (step 2-3) |
| Attack | Fuzzing engine + execution (step 5) |
| Reporting | Detection, findings, traceability report (steps 6-9) |

---

## 4. ISO/IEC 27001:2022 Annex A — Control Mapping

| Annex A control | What the fuzzer evidences / satisfies |
|---|---|
| **A.8.8** — Management of technical vulnerabilities | Scan findings feed the vulnerability register, risk-ranked with remediation SLAs and closure tracking. |
| **A.8.25** — Secure development life cycle | Fuzz gates are a defined stage of the SDLC; scans run before release and on change. |
| **A.8.26** — Application security requirements | Fuzz configurations are derived from documented application security requirements per target. |
| **A.8.27** — Secure system architecture & engineering principles | Threat-informed fuzz targets and validation principles (threat modeling) applied in the target graph. |
| **A.8.28** — Secure coding | Verifies the target's input-validation hygiene per the secure coding standard; platform's own code complies. |
| **A.8.29** — Security testing in development and acceptance | DAST suite (SAST adjuncts via SCA) produces acceptance evidence, tool output, and signoff records. |
| **A.8.30** — Outsourced development | Scanning scope covers third-party/outsourced components (OWASP A03 surface). |
| **A.8.31** — Separation of development, test, and production environments | Scan environment policy: staging/QA targets validated; production scans use separate approval + soft payload profile. |
| **A.8.32** — Change management | Every scan is a versioned, auditable change; CI gates and retests leave an approval trail. |
| **A.8.33** — Test information | Fuzz data is scoped and reuse-controlled; records of test data handling are kept. |
| **A.8.34** — Protection of information systems during audit testing | Safety guards, rate limiting, non-destructive defaults, and scope guards protect the target during tests. |
| Supporting platform controls | **A.5.9/5.15-5.18** (asset/inventory, access control, audit), **A.5.21/5.22** (supply chain), **A.8.7/8.9** (malware, config mgmt), **A.8.13** (backup), **A.8.15** (audit logging), **A.8.16/8.17** (monitoring), **A.8.2** (privileged access) |

---

## 5. Finding-to-Control Traceability Report (output spec)

Every finding renders a **Traceability Record**:

```
Finding ID          FUZZ-2026-0042
Module              sqli-boolean-differential
Vulnerability       Blind SQL injection via id parameter
CWE                 CWE-89     CWE-20 (input validation root cause)
OWASP 2025          A05 Injection
NIST SP 800-53      SI-10 (Information Input Validation)
NIST SP 800-218     PW.8.2 (perform testing, document results); RV.1 (confirm & remediate)
ISO 27001:2022      A.8.29 (security testing) ; A.8.28 (secure coding) ; A.8.8 (vuln mgmt)
Severity            High (CVSS 8.6)   Confidence 0.92   Status OPEN
Evidence            req_0042.bin (captured request) / resp_0042.bin / timing_diff.png
Remediation         Parameterized queries; OWASP Query Parameterization Cheat Sheet
SLA (A.8.8)         15 days   Assigned  DevOps-3   Risk Accepted? No
Retest              Scheduled via focused regression run (same seed, module sqli-boolean-*)
```

The report export (PDF/HTML/JSON) aggregates these records into:
1. **OWASP Gap Matrix** — categories with open findings vs covered.
2. **NIST SI-10 Verification Summary** — input-validation surfaces tested and outcomes.
3. **ISO Annex A Evidence Pack** — control-by-control evidence pointers for the auditor.
4. **Remediation SLA board** — for A.8.8 vulnerability-management tracking.

---

## 6. Mapping Integrity & Controls

- **Kept in sync**: the mapping tables are code-backed (YAML + generated docs) so module/CWE mappings are versioned in CI and cannot drift from the fuzzer code (A.8.32).
- **Auditable**: every mapping used in a report links to the exact module version and payload set used (reproducibility).
- **Evolving**: mapping updates track OWASP release cycles (2028-2029 expected), ISO transition deadlines, and NIST revisions as reviewed artifact.