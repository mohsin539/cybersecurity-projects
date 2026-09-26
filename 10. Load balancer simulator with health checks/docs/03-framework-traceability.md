# AegisLB — Framework Traceability

**Compliance & Security-Framework Alignment Matrix**

| Attribute | Value |
|---|---|
| Document ID | AEGIS-LB-TRC-003 |
| Version | 1.0 |
| Classification | Internal / Audit |
| Date | 2026-09-17 |

**Evidence pointer conventions**
- **ARCH** → `01-load-balancer-simulator-architecture.md` (§/§§)
- **SEC** → `02-security-architecture-and-threat-model.md` (§/Nx)
- **TEST** → automated evidence produced in CI (see SEC §9).

All rows are implemented in the architecture unless stated "roadmap".

---

## Table of Contents

1. [How to Read This Matrix](#1-how-to-read-this-matrix)
2. [OWASP Top 10 (2021)](#2-owasp-top-10-2021)
3. [NIST SP 800-207 (Zero Trust)](#3-nist-sp-800-207-zero-trust)
4. [NIST SP 800-53 Rev.5 — Selected Controls](#4-nist-sp-800-53-rev5--selected-controls)
5. [ISO/IEC 27001:2022 Annex A — Statement of Applicability](#5-isoiec-270012022-annex-a--statement-of-applicability)
6. [NIST CSF 2.0 Functions](#6-nist-csf-20-functions)
7. [Cross-Framework Control Conflation](#7-cross-framework-control-conflation)
8. [Evidence Generation Approach](#8-evidence-generation-approach)

---

## 1. How to Read This Matrix

- "**Control**" = the mechanism **architected and enabled by default**.
- "**Evidence**" = where to point an assessor (document section = design
  evidence; TEST = machine-verifiable test evidence).
- "**Status**" = `Implemented` (default-on), `Roadmap` (designed, pending gate),
  `N/A` (not applicable to a simulator — justification given).

---

## 2. OWASP Top 10 (2021)

| ID | Category | Threat in-scope for AegisLB | Control (architected) | Evidence |
|---|---|---|---|---|
| A01 | Broken Access Control | Admin API RBAC failures; cross-scope lateral movement; insecure direct object references (unscoped pool/backend IDs) | ABAC/RBAC via PDP; deny-by-default; object-level checks always bound to `scopeId`; role catalog (SEC §5.3); IDOR tests | ARCH §6.5, §6.6; SEC §3.1, §5.3; TEST (A01) |
| A02 | Cryptographic Failures | Weak TLS, plaintext secrets, weak/protected data | TLS ≥1.3 only, NIST ciphers; ephemeral CA (≤24h); KMS envelope at rest; secrets never in logs/config; key rotation | ARCH §6.6; SEC §6; TEST (SEC-3/7) |
| A03 | Injection | Manifest/path/target injection; shell/YAML/query injection; log injection | Strict JSON-Schema validation, whitelist regex on paths, no eval/exec, parameterized data access, sanitized log emit | ARCH §5.5, §14; SEC §3.1, §4.4; TEST (SEC-4, fuzz) |
| A04 | Insecure Design | Missing threat modeling, unbounded resource use, demo-heavy trust assumptions | STRIDE at design (SEC §3); threat-model gate in CI; rate limits; quotas; fail-closed eligibility; security objectives SO-1..5 | SEC §1, §3, ARCH §13; TEST |
| A05 | Security Misconfiguration | Weak defaults, exposed debug, permissive CORS, default creds | Hardened baselines (CIS), secure defaults, auto-tls, deny-all network default, no debug builds in release; config validation at load | ARCH §9.2, §14; SEC §7; TEST (config-scan) |
| A06 | Vulnerable and Outdated Components | Dependency CVEs, stale images | SCA/SBOM gate, pinned+locked deps, image digest signing & scanning, patching SLA | SEC §9, ARCH §14 (R5); TEST (SEC-8) |
| A07 | Identification & Authentication Failures | Weak human authn, long-lived creds, no lockout, session fixation | OIDC + MFA, ≤30min Bearer tokens, brute-force lockout (≥5), ephemeral workload IDs, credential rotation | ARCH §6.6; SEC §5; TEST (SEC-2) |
| A08 | Software & Data Integrity Failures | Unsigned manifests/artifacts, CI tampering, log tampering | Signed manifests (Ed25519), signed immutable images, tamper-evident audit chain, reproducible hermetic builds | ARCH §6.5, §11.3; SEC §6; TEST (N5,N6) |
| A09 | Security Logging & Monitoring Failures | No correlation, missing alerts, unbounded log growth | Structured logs + content policy, trace correlation, P0–P2 alert catalog, audit chain, retention policies | ARCH §11; SEC §8; TEST |
| A10 | Server-Side Request Forgery | Probe-URI/URL parameter driven off-target fetches; internal exfil | Probe URIs constructed from vetted host allowlist only; `targetPath` regex-restricted (no authority/scheme); egress denied from backends; no user-supplied URLs | ARCH §9.2; SEC §4.4; TEST (N4) |

---

## 3. NIST SP 800-207 (Zero Trust)

### 3.1 Seven Tenets

| Tenet | AegisLB mechanism | Evidence |
|---|---|---|
| 1 | Continuous verification | ≤24h cert rotation; posture claims; PDP re-eval; per-interval probe verification | ARCH §6.6; SEC §2.1 |
| 2 | Limit blast radius | Scope partitions; microsegmentation; auto-quarantine; per-run caps | ARCH §5.2, §12.4; SEC §2.1 |
| 3 | Automate response | Health state machine auto-drain/quarantine; alert escalation; probe rebalance | ARCH §7.2–7.5; SEC §2.1 |
| 4 | All data sources inform | Forwarding + passive + active + posture + config-drift all consulted | ARCH §7.1; SEC §2.1 |
| 5 | Never trust, always verify | mTLS everywhere; PDP deny-by-default; probe tokens | ARCH §4.3; SEC §2, §3 |
| 6 | Least privilege | RBAC/ABAC; JIT elevation; scoped tokens; read-only audit | SEC §5 |
| 7 | Security is everywhere | Threat-model gate; per-component security owner; security tests | SEC §9 |

### 3.2 Five Pillars

| Pillar | Implementation | Evidence |
|---|---|---|
| Identity | SPIFFE SVIDs + OIDC/MFA for humans; short-lived | ARCH §6.6; SEC §5 |
| Devices | Image digest allowlists; attestation for lab hosts | SEC §2.2 |
| Networks | Deny-all policy sets; control/data/obs/probe segmentation; egress allowlists | ARCH §9.2; SEC §7 |
| Applications & Workloads | Minimal images; least-priv accounts; validation fail-closed; audit immutability | SEC §2.2 |
| Data | Classification; AES-256 at rest; mTLS in transit; minimization; deletion APIs | ARCH §10; SEC §2.2 |

### 3.3 Roles (Policy Engine, PE/PDP, PA — policy admin)

| 800-207 role | AegisLB equivalent |
|---|---|
| Policy Engine (PE) | `policy-decision-point` (PDP) — sole decider, deny-by-default |
| Policy Administrator (PA) | `config-service` + `scale-admin` role — policy/config artifacts (signed, versioned, audited) |
| Policy Enforcement Point (PEP) | module-level gateways: admin-api auth filter, in-process PDP shim in each component (T1), service mesh/per-service filter (T2) |

---

## 4. NIST SP 800-53 Rev.5 — Selected Controls

Scope: controls applicable to a self-contained lab system processing
simulated (non-real) data. "Implemented" = designed-in & evidenced.

| Family | Control ID | Applicability & AegisLB evidence |
|---|---|---|
| AC Access Control | AC-2 (Account Mgmt) | Role catalog + lifecycle (SEC §5.3) |
| | AC-3 (Access Enforcement) | PDP enforce all (ARCH §6.6; TEST A01) |
| | AC-4 (Flow Control) | Channel matrix/NetworkPolicies (ARCH §9.2) |
| | AC-6 (Least Privilege) | Roles; no default grants (SEC §5.3) |
| | AC-7 (Unsuccessful Logon Attempts) | Lockout ≥5 (SEC §5.1) |
| | AC-10 (Concurrent Session Control) | Cap per principal (SEC §5.1) |
| | AC-17 (Remote Access) | mTLS only; no plaintext remote admin (ARCH §9.1) |
| | AC-20 (External Sys Usage) | Lab-only; internet egress denied (ARCH §9.2) |
| AT Awareness | AT-2/AT-4 (Awareness/Training) | Teaching simulator; training materials = the sim itself |
| AU Audit | AU-2 (Events) | Event catalog (ARCH §11.2) |
| | AU-3 (Content) | Structured fields; sanitized content (ARCH §11.2) |
| | AU-6 (Review/Analyze) | Alerting + correlation (ARCH §11.4; SEC §10) |
| | AU-8 (Time Stamps) | Clock sync/reference for events (ARCH §11; ISO A8.17) |
| | AU-9 (Protection) | WORM + hash chain + external anchor (ARCH §11.3; N6) |
| | AU-11 (Retention) | Retention policy (ARCH §10) |
| CA Assess | CA-7 (Continuous Monitoring) | Probe/passive/posture pipelines (ARCH §7; SEC §2) |
| | CA-9 (Internal Connections) | Channel matrix audit (SEC §7) |
| CM Config Mgmt | CM-6 (Configuration Settings) | Hardened baselines; auto-tls; validated config load (A05) |
| | CM-7 (Least Functionality) | Minimal images; no debug in release (SEC §2.2) |
| | CM-8 (System Inventory) | SBOM/manifest inventory (SEC §9; A08) |
| CP Contingency | CP-10 (Recovery/Reconstitution) | Manifest restore + replay preservation (SEC §10) |
| IA Identification/Auth | IA-2 (Identification & Auth) | mTLS + OIDC MFA (SEC §5) |
| | IA-3 (Device ID) | Workload SVIDs (SEC §5.2) |
| | IA-5 (Authenticator Mgmt) | Short TTL; rotation; no shared creds (SEC §5/§6) |
| | IA-8/IA-9 (Identity Proofing / Service ID) | SPIFFE identity; PKI (ARCH §6.6) |
| IR Incident Response | IR-4/-5/-6 (Handling/Monitoring/Reporting) | Playbooks, drills (SEC §10) |
| PL Planning | PL-8 (Security Architecture) | This very security design (SEC §1–2) |
| PM Program Mgmt | PM-9/Risk | Risk register (ARCH §15) |
| PS Personnel | PS-7 (Third-Party Personnel) | Operator/student role definitions (SEC §5) |
| RA Risk Assess | RA-3 (Risk Assessment) | STRIDE model; attack narratives (SEC §3–4) |
| SA System Acquisition | SA-10 (Developer Security Testing) | CI gates; SAST/DAST/fuzz (SEC §9) |
| | SA-11 (Secure Dev/Acceptance Test) | DevSecOps gates (ARCH §14) |
| | SA-15 (Dev Process) | Threat-model replay gate (ARCH §14) |
| SC System & Comms | SC-7 (Boundary Protection) | Deny-all egress; probe VLAN (ARCH §9.2) |
| | SC-8/13 (Confidentiality/Integrity in transit) | TLS1.3/mTLS; probe token signing (SEC §6) |
| | SC-12 (Cryptographic Key Establishment) | KMS; PKI hierarchy (SEC §6) |
| | SC-14 (Public Access Protections) | /healthz rate-limited; no exposed admin (ARCH §9) |
| | SC-20/21 (Secure Name/Resolution) | No external resolution in data plane (ARCH §6.3; N4) |
| | SC-28 (Protection at Rest) | AES-256 envelope (SEC §6) |
| SI System & Info Integrity | SI-3 (Malicious Code Protection) | Image scanning + signature (SEC §9) |
| | SI-4 (System Monitoring) | Alerts; metrics; logs (ARCH §11) |
| | SI-7 (Software/Firmware Integrity) | Signed manifests + image digests (ARCH §14) |
| | SI-10 (Info Input Validation) | Schema validation fail-closed (A03; TEST SEC-4) |
| | SI-12 (Information Handling/Retention) | Retention + deletion APIs (ARCH §10) |
| | SI-16 (Memory Protection) | Rust/Go-style memory-safe reference runtime (ARCH guidance) |
| SR Supply Chain | SR-3 (Supply Chain Controls) | Pinned deps; SBOM; signed artifacts (A06/A08) |
| | SR-4 (Provenance) | Hermetic builds; binary hashes recorded (ARCH §14) |
| System-level | Contractor/SSE/DevSecOps | SA-10/11 + AU + SI combined gate chain (ARCH §14) |

Status annotations: all above `Implemented` by design with TEST or design
evidence; controls with no internal relevance (e.g., physical media) are
explicitly out of scope for a software-only simulator (documented in the SoA
record §5 if needed).

---

## 5. ISO/IEC 27001:2022 Annex A — Statement of Applicability

Selected relevant controls (full SoA maintained in audit tooling; excerpts
here). `Impl` = Implemented, `Part` = Partially (roadmap), `No` = N/A.

| Ref | Control (A.…) | Impl | AegisLB evidence |
|---|---|---|---|
| 5.1 | Information security policies | Yes | Security objectives (SEC §1); design policy set |
| 5.3 | Segregation of duties | Yes | Role separation: config vs ops vs audit (SEC §5.3, N6) |
| 5.8 | Info security in project mgmt | Yes | SDLC gates (ARCH §14) |
| 5.15 | Access control rules/rights | Yes | PDP + role catalog (SEC §5) |
| 5.16 | Identity management | Yes | OIDC/MFA + workload SVIDs (SEC §5) |
| 5.17 | Authentication info | Yes | Short-TTL tokens; rotation; lockout (SEC §5.1) |
| 5.18 | Access rights management | Yes | Review cycle incl. revocation scripts |
| 5.24 | Incident response planning | Yes | Playbooks + drills (SEC §10) |
| 5.30 | ICaaS (ICT readiness) | No | N/A (simulator; not business-critical ICT) |
| 5.33 | Protection of records | Yes | Retention + WORM (AU-9; N6) |
| 5.34 | Privacy & protection of PII | Yes | Synthetic identifiers; minimization (ARCH §10) |
| 6.2 | Mobile device policy | No | N/A (no mobile clients) |
| 6.3 | Remote working | No | T3 optional remote lab only; lab-controlled |
| 7.2 | Screening | Yes-arch | Lab operator/student role vetting (policy) |
| 7.12 | Remote/hybrid info tech | No | N/A |
| 8.1 | User endpoint devices | Yes | Image hardening; host attestation (SEC §2.2) |
| 8.2 | Privileged access rights | Yes | JIT elevation; `scale-admin` (SEC §5.3) |
| 8.3 | Information restriction | Yes | Scope partitions; data classification (ARCH §10) |
| 8.5 | Secure authentication | Yes | MFA; mTLS (SEC §5) |
| 8.6 | Capacity management | Yes | Quotas, resource caps (ARCH §13 S1-S3) |
| 8.7 | Protection against malware | Yes | Image + SCA scanning (SEC §9) |
| 8.8 | Technical vulnerability mgmt | Yes | SCA + patch SLA (SEC §9; A06) |
| 8.9 | Configuration mgmt | Yes | Versioned validated config; baselines (A05) |
| 8.10 | Information deletion | Yes | Deletion APIs (ARCH §10) |
| 8.11 | Data masking | Yes | Synthetic data; sanitized alerts (ARCH §10) |
| 8.12 | Data leakage prevention | Yes | Egress denied; content policy on logs (A10) |
| 8.13 | Backup | Yes | Run manifests + audit anchored to durable store |
| 8.14 | Redundancy | Yes-arch | Replica support in T2 (ARCH §13 A1) |
| 8.15 | Logging | Yes | Structured logs + content policy (ARCH §11.2) |
| 8.16 | Monitoring | Yes | P0–P2 alerting (ARCH §11.4) |
| 8.17 | Clock synchronization | Yes | NTP-lab + event timestamps (AU-8) |
| 8.18 | Privileged utility programs | Yes | Admin API only; no root shells in release |
| 8.19 | Software installation | Yes | Allowed-image list; signed images |
| 8.20 | Networks security | Yes | Segmentation + deny-all (ARCH §9.2) |
| 8.21 | Network services | Yes | Channel allowlist (SEC §7) |
| 8.22 | Network segregation | Yes | Probe VLAN; control/data split |
| 8.23 | Web filtering | No | N/A — no outbound web (egress denied) |
| 8.24 | Cryptographic controls | Yes | TLS1.3/mTLS; KMS; rotation (SEC §6) |
| 8.25 | Secure development lifecycle | Yes | Threat model + SAST/DAST/fuzz gates (ARCH §14) |
| 8.26 | Application security testing | Yes | DAST + fuzz; pentest annual |
| 8.27 | Secure system architecture principles | Yes | Zero-trust this document set |
| 8.28 | Secure coding | Yes | OWASP-informed; validation; no eval (A03) |
| 8.29 | Security testing | Yes | SEC §9 matrix |
| 8.30 | Outsourced development | No | N/A (internal) |
| 8.31 | Separation of environments | Yes | Dev/CI/lab separation; gate enforcement (ARCH §14) |
| 8.32 | Change management | Yes | Versioned schema; PR review; audit (ARCH §14) |
| 8.33 | Test information protection | Yes | Synthetic data; masking (8.11) |
| 8.34 | Protection during audit/test | Yes | Read-only audit surface; immutable logs |

---

## 6. NIST CSF 2.0 Functions

For each function and key categories, AegisLB realization and evidence.

### GOVERN (GV)

| Category | Realization | Evidence |
|---|---|---|
| GV.OC (Org Context) | AegisLB mission = realistic LB behavior + security demonstration | ARCH §1–2 |
| GV.RM (Risk Mgmt Strategy) | Risk register; security objectives SO-1..5 | ARCH §15; SEC §1 |
| GV.RM-SC (Supply Chain) | SBOM/signing/pinning; supplier=OSS ecosystem controlled | SEC §9; A06 |
| GV.PO / GV.PO-SC | Information security policy; SDLC gates; security owner per component | ARCH §14; SEC §2.1 tenet 7 |
| GV.OV | Oversight: audit chain, KPIs on alerts/tests | ARCH §11 |
| GV.RR | Roles/Responsibility matrix | SEC §5.3 |

### IDENTIFY (ID)

| Category | Realization | Evidence |
|---|---|---|
| ID.AM (Asset Management) | Component/asset inventory incl. dependencies (SBOM) | ARCH §4.3; SEC §9 |
| ID.RA (Risk Assessment) | STRIDE threat model; 6 attack narratives; likelihood ratings | SEC §3–4 |
| ID.IM (Improvement) | Threat model replayed per change; post-mortems | SEC §10 |
| ID.GV (Governance) | Policy artifacts signed/versioned | ARCH §6.5 |

### PROTECT (PR)

| Category | Realization | Evidence |
|---|---|---|
| PR.AA (Identity Mgmt, Authn, Authz) | OIDC/MFA + mTLS + PDP | SEC §5 |
| PR.AA-SC | Supply-chain identity (artifact signing) | SEC §6 |
| PR.AT (Awareness/Training) | The simulator is a training platform | ARCH §2.1 |
| PR.DS (Data Security) | Encryption at rest/in transit; minimization | SEC §6; ARCH §10 |
| PR.DS-PR (Privacy) | Synthetic IDs; deletion APIs | ARCH §10 |
| PR.PS (Platform Security) | Hardened images; deny-all nets; quotas | SEC §2.2; ARCH §12.4 |
| PR.PS-EP (Endpoint) | Host attestation (lab) | SEC §2.2 |
| PR.PW (Technology Infrastructure Resilience) | Health-check redundancy N-of-M; per-backend capability | ARCH §7 |
| PR.IR (Technology Improvement) | Patching SLA; image rebuild cadence | SEC §9 |

### DETECT (DE)

| Category | Realization | Evidence |
|---|---|---|
| DE.CM (Continuous Monitoring) | Passive + active health channels; metrics/logs | ARCH §7, §11 |
| DE.CM-SC (Supply Chain Monitoring) | CVE alerting; image scan events | SEC §9 |
| DE.AE (Adversarial Analysis) | PDP denial bursts, probe token mismatches, chain-gap detection | ARCH §11.4 |

### RESPOND (RS)

| Category | Realization | Evidence |
|---|---|---|
| RS.MA (Incident Management) | P0 protocols; on-call ownership | SEC §10 |
| RS.CO (Communication) | Escalation policy; alert routing | SEC §10 |
| RS.AN (Analysis) | Decision trace + probe + audit correlation | SEC §10 |
| RS.MI (Mitigation) | Auto-drain/quarantine; identity revocation; token rotation | SEC §10 |
| RS.IM (Improvement) | Post-mortem updates threat model + scenario suite | SEC §10 |

### RECOVER (RC)

| Category | Realization | Evidence |
|---|---|---|
| RC.RP (Recovery Plan) | Manifest-based restore; replay preservation | SEC §10 |
| RC.IM (Improvements) | Restore replayability on known-good manifests | SEC §10 |
| RC.CO (Communications) | Stakeholder updates during recovery | SEC §10 |

---

## 7. Cross-Framework Control Conflation

High-value alignment (single control satisfies multiple frameworks):

| Capability | OWASP | 800-207 | 800-53 | ISO 27001:2022 | CSF 2.0 |
|---|---|---|---|---|---|
| PDP access control | A01 | Tenet 6 | AC-3, AC-6 | 5.15, 5.18, 8.2 | PR.AA |
| mTLS + ephemeral CA | A02, A07 | Tenets 1,5 | IA-2/3, SC-8 | 5.16/5.17, 8.24 | PR.AA, PR.DS |
| Tamper-evident audit | A08, A09 | Tenet 4 | AU-6/9/11 | 5.33, 8.15 | DE.CM, RS.MA |
| Health-check anti-spoof (N-of-M, tokens) | A01, A02 | Tenets 1,4,5 | CA-7, SC-8 | 8.16 | DE.CM, PR.PW |
| SDLC security gates | A04, A06, A08 | Tenet 7 | SA-10/11/15 | 8.25–8.29, 8.31 | GV.RM |
| Egress control / anti-SSRF | A10 | Network pillar | SC-7 | 8.20–8.22 | PR.PS |
| Input validation fail-closed | A03 | Tenet 4 | SI-10 | 8.26, 8.28 | ID.RA |

---

## 8. Evidence Generation Approach

- **Design evidence**: this doc-set (versioned, signed releases).
- **Machine evidence (TEST)**: CI consumes the scenario suite (N1–N6,
  SEC-1..10, A01-A10 test IDs, F1–F6 fidelity, S1–S3 scale) and emits a
  signed JSON attestation with pass/fail per control — that attestation is
  the primary artifact for auditors.
- **Operational evidence**: alert triage records, drone analytics, quarterly
  drills, annual penetration test report, SCA advisory log.
- The 800-53/ISO rows marked `Implemented` map to at least one TEST id; the
  mapping is generated from a control-definition file kept in the repo.

---

## Appendix A — Test-ID Index (summary)

| Test ID | Verifies | Framework tags |
|---|---|---|
| SEC-1..SEC-10 | AuthN, brute-force, secrets, validation, error safety, audit tamper, TLS, SCA, probe anti-spoof, SSRF | OWASP A01/A02/A03/A05/A06/A07/A08/A09/A10; 800-53 AC/SC/SI; 800-207 tenets 1,4,5 |
| A01..A10 | Per-category OWASP control | OWASP |
| F1..F6 | Determinism/fidelity/anti-flap | CSF PR.PW |
| S1..S3 | Scale/resource | ISO 8.6 |
| N1..N6 | Attack narratives (poisoning, flap, admin abuse, SSRF, supply chain, insider) | SEC §4; cross-framework conflation in §7 |

---

*End of traceability document. All matrices approved for audit use by the
Principal Architect, 2026-09-17.*