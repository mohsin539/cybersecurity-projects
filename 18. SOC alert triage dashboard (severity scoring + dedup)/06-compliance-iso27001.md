# 06 — ISO/IEC 27001:2022 Annex A Mapping (All 93 Controls)

Status: Approved v1.0 · Owner: GRC + Security Architecture · Review cadence: annual / Statement of Applicability cycle

---

**Legend**

| Status | Meaning |
|---|---|
| **S** | Satisfied by this architecture (technical design + automated evidence) |
| **P** | Partially satisfied by design; process/procedural evidence required (owner named in SoA) |
| **O** | Organizationally owned / cloud-inherited; system provides supporting evidence only |
| **N/A** | Not applicable — justification and risk acceptance required in SoA |

Applicability judgments below are **inputs to the Statement of Applicability**; the SoA is the authoritative document (owned by GRC) and must record the inclusion/exclusion rationale and risk treatment linkage for every control.

---

## Theme 5 — Organizational controls (37)

| Control | Title | Status | Where satisfied / notes |
|---|---|---|---|
| 5.1 | Policies for information security | P | This doc set = system-level policy; org ISMS policy framework referenced; approved by GV.RR-01 owner |
| 5.2 | Information security roles & responsibilities | S/P | Named owners per container (01 §4); RACI in SoA |
| 5.3 | Segregation of duties | S | soc.lead ≠ detection.eng; 2-person rule for rules/config; dual-auth bulk ops (04 §3 T08) |
| 5.4 | Management responsibilities | P | Competency expectations in team charter |
| 5.5 | Contact with authorities | O | IR plan references CERT/regulator contacts |
| 5.6 | Contact with special interest groups | O | TI community memberships managed by CTI team |
| 5.7 | Threat intelligence | S | TI ingestion + enrichment factors (02 §3); TI source allowlist (04 T10) |
| 5.8 | Information security in project management | P | Security review gate is mandatory project gate (04 §6) |
| 5.9 | Inventory of information & associated assets | S | Data model + flow catalog + SBOM (03 §1, 01 §6) |
| 5.10 | Acceptable use of information assets | O | Org policy; dashboard use banner (AC-8 analog) |
| 5.11 | Return of assets | P | Offboarding via SCIM deprovision + access review evidence |
| 5.12 | Classification of information | S | data_sensitivity attribute drives ABAC (03 §2.2) |
| 5.13 | Labelling of information | S/P | Sensitivity labels in API responses + UI badges; export watermarking |
| 5.14 | Information transfer | S | TLS everywhere, HMAC-signed webhooks, region pinning (04 A02/A10) |
| 5.15 | Access control | S | RBAC+ABAC, default deny, RLS (03 §2, 04 A01) |
| 5.16 | Identity management | S | OIDC identities, SPIFFE for services, UUID identifiers |
| 5.17 | Authentication information | S | No passwords; secrets via KMS; HMAC keys rotated ≤ 90 d |
| 5.18 | Access rights | P | SCIM lifecycle + quarterly access reviews (evidence: review records) |
| 5.19 | Information security in supplier relationships | P | Vendor reviews for IdP/TI/cloud (DPA, SOC 2 attestations) |
| 5.20 | Addressing infosec within supplier agreements | P | DPAs + security schedules |
| 5.21 | Managing infosec in ICT supply chain | S/P | SBOM/SLSA/dependency SLAs (04 A06/A08); vendor tiering in SoA |
| 5.22 | Monitoring/reviewing supplier services | P | TI source verdict monitoring (T10); vendor SLA dashboards |
| 5.23 | Cloud services security | S/P | Shared-responsibility matrix; inherited controls documented; tenant-isolation guarantees (03 §3) |
| 5.24 | Infosec incident management planning | S/P | SP 800-61-aligned IR integration (05 §3); platform is IR tooling |
| 5.25 | Assessment of information security events | S | UEBA, auth anomaly, audit analytics (04 A09) |
| 5.26 | Response to incidents | S/P | SOAR emission with scoped identities; runbooks (07) |
| 5.27 | Learning from incidents | S | Feedback loop F2; post-incident improvement tracking (05 §3.4) |
| 5.28 | Collection of evidence | S | WORM audit chain, evidence export bundles with hash manifests (05 §3.3) |
| 5.29 | Information security during disruption | S | DR strategy, degradation modes (01 §10) |
| 5.30 | ICT readiness for business continuity | S/P | RPO/RTO targets + quarterly drills (evidence: drill reports) |
| 5.31 | Legal, statutory, regulatory, contractual requirements | P | Legal register maintained by GRC; residency pinning supports |
| 5.32 | IP rights | P | License checks in CI (CM-10 analog) |
| 5.33 | Protection of records | S | WORM retention 400 d; retention matrix (03 §5) |
| 5.34 | Privacy and protection of PII | S | Minimization, pseudonymization, crypto-shredding, PII ABAC (03 §4) |
| 5.35 | Independent review of infosec | P | Annual pentest + internal ISMS audit |
| 5.36 | Compliance with policies | S/P | Policy-as-code (OPA) + MR gates + config scanning |
| 5.37 | Documented operating procedures | S | Runbooks (07) versioned in repo |

## Theme 6 — People controls (8)

| Control | Title | Status | Where satisfied / notes |
|---|---|---|---|
| 6.1 | Screening | O | HR process; platform supports least-privilege onboarding |
| 6.2 | Terms & conditions of employment | O | HR |
| 6.3 | Information security awareness & training | P | Role-based training incl. secure coding + analyst privacy; records in LMS |
| 6.4 | Disciplinary process | O | HR |
| 6.5 | Termination/transfer responsibilities | P | Access revocation automation via SCIM (evidence: SLA metric) |
| 6.6 | Confidentiality/NDA | O | HR/legal |
| 6.7 | Remote work | O | IdP conditional access + managed devices |
| 6.8 | Information security event reporting | S | In-product reporting (flag alert, report pipeline anomaly) + security channel; non-retaliation noted |

## Theme 7 — Physical controls (14)

| Control | Title | Status | Where satisfied / notes |
|---|---|---|---|
| 7.1–7.4 | Physical security perimeters / entry / offices / monitoring | O | Cloud provider attestations (ISO 27001/27017, SOC 2); documented in SoA inheritance |
| 7.5 | Protecting against physical threats | O | Cloud provider |
| 7.6 | Working in secure areas | O | N/A for cloud-only; justification in SoA |
| 7.7 | Clear desk & screen | P/O | Auto-lock sessions (30 min idle), screen privacy flags in UI |
| 7.8 | Equipment siting & protection | O | Cloud provider |
| 7.9 | Security of assets off-premises | O/P | Managed-device posture via IdP |
| 7.10 | Storage media | N/A | No removable media in cloud-only architecture; SoA justification |
| 7.11 | Supporting utilities | O | Cloud provider SLAs |
| 7.12 | Cabling security | O | Cloud provider |
| 7.13 | Equipment maintenance | O | Cloud provider |
| 7.14 | Secure disposal/re-use | S/P | Crypto-shredding for tenant deletion; cloud provider decommission attestations |
| 7.15 | Secure disposal/re-use of equipment | O | Cloud provider |

## Theme 8 — Technological controls (34)

| Control | Title | Status | Where satisfied / notes |
|---|---|---|---|
| 8.1 | User endpoint devices | O/P | IdP device posture; no local data persistence in dashboard |
| 8.2 | Privileged access rights | S | WebAuthn step-up, break-glass dual-control, admin audit (04 A07, T08) |
| 8.3 | Information access restriction | S | RBAC+ABAC+RLS stack (03 §2) |
| 8.4 | Access to source code | S | Protected branches, CODEOWNERS incl. security, signed commits |
| 8.5 | Secure authentication | S | MFA all, WebAuthn privileged, no shared accounts |
| 8.6 | Capacity management | S | Capacity model + headroom + rate limits (01 §9) |
| 8.7 | Protection against malware | O/S | Image scanning + allowlists; host EDR inherited |
| 8.8 | Management of technical vulnerabilities | P | SCA/image scanning, patch SLAs, KEV/EPSS awareness (04 A06) |
| 8.9 | Configuration management | S | IaC-only, drift alarms, PSS restricted, CIS scans (04 A05) |
| 8.10 | Information deletion | S | Retention automation, crypto-shredding, raw TTL (03 §4–5) |
| 8.11 | Data masking | S | Masked replays for staging (01 §8); PII pseudonymization (03 §4) |
| 8.12 | Data leakage prevention | S/P | Export controls (dual-auth, watermarking, rate limits); UEBA (T11) |
| 8.13 | Information backup | S | PITR + cross-AZ replicas + replay-from-raw (01 §10.2); quarterly restore drills |
| 8.14 | Redundancy of information processing facilities | S | Multi-AZ, rebuildable derived state (01 §10) |
| 8.15 | Logging | S | Append-only, hash-chained, WORM audit + security telemetry (04 A09) |
| 8.16 | Monitoring activities | S | OTel + security detection pack + UEBA + monitoring-of-monitoring |
| 8.17 | Clock synchronization | S | NTP-synced, UTC normalization, skew flagging (02 §2) |
| 8.18 | Use of privileged utility programs | S | Break-glass vaulted + dual-control + alarmed; no ad-hoc prod shells |
| 8.19 | Installation of software on operational systems | S | Admission control verifies signatures; no manual installs |
| 8.20 | Networks security | S | Default-deny policies, egress proxy, mesh mTLS (04 §2) |
| 8.21 | Security of network services | S | Service mesh identities, audience-bound tokens |
| 8.22 | Segregation of networks | S | Namespace-per-trust-tier, egress isolation (04 A10) |
| 8.23 | Web filtering | O | Org egress controls |
| 8.24 | Use of cryptography | S | Algorithm allowlist, HSM KMS, rotation (04 §5) |
| 8.25 | Secure development life cycle | S | Full secure SDLC gates (04 §6) |
| 8.26 | Application security requirements | S | ASVS-anchored requirements per control (04 §4) |
| 8.27 | Secure system architecture & engineering principles | S | This document set; ADR discipline |
| 8.28 | Secure coding | S | SAST custom rules, lint bans, review gates, fuzzing |
| 8.29 | Security testing in development | S | Unit/property/isolation/DAST/fuzz/chaos (02 §8, 04 §6) |
| 8.30 | Outsourced development | N/A | No outsourced development; SoA justification |
| 8.31 | Separation of dev/test/prod | S | Three environments; prod-only real data; masked staging (01 §8) |
| 8.32 | Change management | S | PR + differential replay + approvals + auto-rollback + audit (01 F3, 02 §4.5) |
| 8.33 | Test information | S | Synthetic dev data; masked staging replays; no prod data in lower envs |
| 8.34 | Protection of IS during audit/testing | S | Read-only auditor role; no audit-data copies outside WORM + SIEM |

---

## Statement of Applicability (SoA) guidance

1. **Every control appears in the SoA** with: applicability decision, implementation owner (RACI), status, and linkage to risk treatment (ISO 27001 §6.1.2–6.1.3) — the tables above are the input, not the artifact.
2. **Inheritance register**: for Theme 7 and cloud-shared controls, record the provider attestation (report name, date, scope) and the residual responsibility.
3. **N/A justifications**: 7.10, 8.30 are expected N/A for this architecture; any additional exclusion requires risk acceptance by the GV.RR-01 role owner and CISO sign-off.
4. **Integration with NIST mapping**: maintain a single crosswalk (control ↔ CSF 2.0 ↔ 800-53 ↔ Annex A) — the compliance doc set is structured so each implementation reference resolves to exactly one authoritative section (avoid duplicate evidence sources).
5. **Certification-readiness notes**: internal audit cycle (semi-annual) + management review feed the same evidence store as the NIST mappings; surveillance audit prep = dry-run of the evidence plan below.

## Audit evidence plan

| Evidence | Source | Frequency | Owner |
|---|---|---|---|
| Access review records | IdP export + role matrix diff | quarterly | Platform owner |
| Training completion | LMS export | semi-annual | People ops |
| Vuln/patch SLA metrics | Scanner + ticketing export | monthly | Eng manager |
| Restore drill report | DR drill artifact | quarterly | SRE |
| Pentest report + remediation | External assessor | annual | Security lead |
| SBOM + provenance samples | CI artifacts | per release (sampled) | Release eng |
| Audit-chain verification logs | Verification job | daily (alert on fail) | Platform SRE |
| Change records w/ approvals | Git + CI logs | sampled | Detection eng |
| ROPA/DPIA updates | GRC docs | semi-annual | GRC |
| Supplier attestations | Vendor portal | annual | GRC |

Evidence is exported to the GRC platform with immutable timestamps; the audit-chain daily verification doubles as evidence-integrity proof (no manual attestation needed for log authenticity).
