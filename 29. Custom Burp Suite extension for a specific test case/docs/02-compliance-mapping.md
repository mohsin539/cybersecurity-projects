# 02 — Compliance Mapping Matrix

**Goal:** demonstrate how BurpTester's design, behavior, and release pipeline align with
**ISO/IEC 27001:2022**, **NIST SP 800-53 Rev.5**, and **OWASP Top 10:2021**.

> Note on OWASP Top 10: this is a *security testing* tool. The Top 10 matters in two ways:
> **1)** the tool must not *introduce* the Top-10 weaknesses into the analyst environment,
> and **2)** the reference test case **detects** one of them. Both are mapped below.

---

## 1. OWASP Top 10:2021 — "Do no harm" posture

| OWASP Top 10 (2021) | How BurpTester avoids / handles it | Evidence location |
|---|---|---|
| **A01 Broken Access Control** | Runs only inside operator-scoped Burp proxy; loopback IPC bound to `127.0.0.1` with per-run random token; no admin services | `C1`, `ADR-4` (docs/01) |
| **A02 Cryptographic Failures** | No secrets persisted; JWT tests flag weak crypto (alg confusion, `none`) but never *weaken* TLS; bundled JRE from verified upstream | `C10`, ADR-5 |
| **A03 Injection** | Payload budget & allowlist in `SafeExecutionSandbox`; never evaluates raw responses as code; response analysis is parser-bounded | `C9` |
| **A04 Insecure Design** | Fail-closed design reviews in CI; threat modeling per release (docs/03) | Threat model |
| **A05 Security Misconfiguration** | Config profiles schema-validated; unknown schema versions rejected; misconfigured targets surfaced as findings | `C3` |
| **A06 Vulnerable/Outdated Components** | Gradle dependency locking + CycloneDX SBOM + CI vulnerability gate | sbom/, CI |
| **A07 Identification & Auth Failures** | Reference module **detects** broken session/JWT auth (WSTG-SESS-10); itself ships no default backdoor credentials | `JwtTokenTestPack` |
| **A08 Software/Data Integrity Failures** | Signed `.exe` + signed jar (signtool/GSG), release provenance, tamper-evident audit log | docs/04 |
| **A09 Security Logging & Monitoring Failures** | Append-only, hash-chained audit log; findings stream; JSONL ready for SIEM | `C10` |
| **A10 SSRF** | No server-side fetch of analyst URLs; mutations only via operator-forced Burp transport; no client-side SSRF vector | Data flow §5 |

---

## 2. ISO/IEC 27001:2022 — Annex A control mapping (selected)

| Annex A control | Requirement excerpt | BurpTester implementation |
|---|---|---|
| **A.5.1 / A.5.2 / A.5.3** – Policies (security, roles) | Define security roles & responsibilities | `ROLES.md` (analyst, engineer, release-manager identities in CI) |
| **A.5.10** – Info security in cloud/third party | Vet hosted deps | SBOM pins every transitive dependency |
| **A.5.15** – Access control | Least privilege | Analyst runs with their own OS identity; tool never requests elevation |
| **A.5.24** – Info security incident planning | Response to engine crashes / false negatives | Diagnostic journal + crash dump to local logs only |
| **A.7.4** – Physical security (portable media) | Portable media control | `.exe` is a single signed artifact; erasure guidance for thumb drives in docs/04 |
| **A.8.8** – Mgmt of technical vulnerabilities | Patch & track | Gradle dependency lockfile + CI vuln gate (A06) |
| **A.8.9** – Configuration management | Known-good configs | Versioned, schema-validated `profile.json` + change log |
| **A.8.12** – Data leakage prevention | Prevent disclosure outside env | Findings/evidence stay local; opt-in export only |
| **A.8.15** – Logging | Record relevant events | Hash-chained audit trail (anchor starts at build time) |
| **A.8.16** – Monitoring activities | Detect patterns | Findings streams feed local SIEM forwarder |
| **A.8.22** – Web filtering | Control risky destinations | Target scope allowlist enforced pre-mutation |
| **A.8.23** – Web-based systems protection | Protect against attacks | Scanner-role checks only mutate in dry-run boundary |
| **A.8.28** – Secure coding | SDLC controls | Code review + SAST (SpotBugs) + unit tests in CI |
| **A.8.29** – Security testing in development | Test before release | E2E against `vuln-app` fixture in CI |
| **A.8.34** – Protection of information systems during audit | Isolation of security test activity | Isolated Burp project file per run; real time capture |

---

## 3. NIST SP 800-53 Rev.5 — control family mapping (selected)

| Control | Family | Implementation |
|---|---|---|
| **AC-3** Access Enforcement | Access Control | Loopback-only IPC token; per-operator project files |
| **AU-3 / AU-6** Audit Logging & Review | Audit & Accountability | Hash-chained log; review action in incident runbook |
| **CM-2 / CM-6 / CM-7** Baseline & Least Functionality | Configuration | Minimal jlink image; only required JRE modules |
| **CP-9 / PE-3** Backup & physical (media) | Contingency / Physical | Portable media handling & data-erasure SOP in docs/04 |
| **PL-2** Security Planning | Planning | This document set (01–05) |
| **RA-3** Risk Assessment | Risk | Threat model (docs/03) + CVSS-style severity on findings |
| **SA-4 / SA-10** Acquisition & provenance | System & Services | Signed artifacts; SBOM attestation; supply-chain gates |
| **SC-7** Boundary Protection | System & Communications | No external listeners; loopback whitelist; no cloud |
| **SC-8 / SC-13** Confidentiality & crypto | System & Communications | TLS 1.2+ for any export transport; file encryption at rest for evidence |
| **SI-2 / SI-10** Flaw remediation & input validation | System & Information Integrity | Versioned schema validation; dependency scan |
| **SI-11** Error handling | System & Information Integrity | Fail-closed error paths; alerts on unexpected responses |
| **SI-16** Memory protection | System & Information Integrity | Java memory-safe runtime; no JNI where avoidable |

---

## 4. WSTG — test progression mapping (reference module)

| WSTG ID | Test name | BurpTester step |
|---|---|---|
| WSTG-SESS-10 | Testing JWT (JSON Web Tokens) | `JwtTokenTestPack` full chain (see docs/05) |
| WSTG-SESS-09/01 | Session mgmt (baseline coverage) | Supported via future TestPacks; same Finding model |

## 5. How to keep this matrix current

- `docs/02` is versioned; a CI job diffs it against new controls and fails the build if a
  release changes architecture without updating this matrix (enforces **A.8.28** /
  **PL-2** governance).
- The compliance champion approves any change that touches IPC, persistence, or
  mutation policy before merge.