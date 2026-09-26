# 05 — NIST Mapping: CSF 2.0, SP 800-53 Rev. 5, SP 800-61

Status: Approved v1.0 · Owner: GRC + Security Architecture · Review cadence: annual or on major change

---

## 1. NIST Cybersecurity Framework 2.0 — full mapping

### GOVERN (GV)
| CSF 2.0 Subcategory | Implementation in this architecture | Evidence |
|---|---|---|
| GV.OC-01/02 (mission, stakeholders) | README purpose & scope; SOC lead + tenants as stakeholders | charter doc |
| GV.OC-03 (legal/regulatory) | Data residency pinning, DPA/ROPA (03 §3–4) | DPA, ROPA |
| GV.OC-04/05 (risk objectives, appetite) | Residual risk register (04 §7); error-budget policy (01 §11) | risk register |
| GV.RM-01/02 (risk mgmt objectives, appetite in decisions) | Fail-open/fail-closed matrix is a *recorded risk decision* per component (01 §10.1, ADR-001) | ADRs |
| GV.RR-01/02 (roles, authority) | Role model incl. soc.lead/detection.eng separation (03 §2.1); named owners per container | role docs |
| GV.RR-03 (resources) | Capacity model + headroom (01 §9) | capacity plan |
| GV.RR-04 (cybersecurity in HR) | Role-based training incl. secure coding; access tied to role lifecycle via SCIM (03 §2.1, 04 §6) | training records |
| GV.PO-01/02 (policy) | This document set is normative; policy-as-code (OPA) makes technical policy enforceable and versioned | policy repo |
| GV.OV-01/03 (strategy performance, comms) | SLO dashboards + error-budget reviews with SOC leads (01 §11) | review minutes |
| GV.SC-01–10 (supply chain) | SBOM/SLSA/sigstore, dependency SLAs, vendor TI allowlist (04 §4 A06/A08) | SBOM, pipeline logs |

### IDENTIFY (ID)
| Subcategory | Implementation | Evidence |
|---|---|---|
| ID.AM-01/02 (hardware/software inventory) | Kubernetes workload inventory, SBOM per service, CMDB integration (enrichment) | SBOM, inventory |
| ID.AM-03/04 (data & service catalog) | Data model (03 §1), data flow catalog (01 §6), ROPA | data catalog |
| ID.AM-05 (prioritized by criticality) | Asset criticality tiers consumed by scoring f2; the platform scores *itself* in CMDB | CMDB export |
| ID.AM-07 (sensitive data) | data_sensitivity attribute, PII flag, field-level encryption (03 §4) | data classification matrix |
| ID.RA-01/02 (vuln, cyber threat intel) | SCA/image scanning; TI enrichment pipeline (02 §3) | scanner reports |
| ID.RA-05–08 (vuln handling, exploits, threats, risk responses) | Patch SLAs, KEV/EPSS factors in scoring (f6), risk register | vuln backlog metrics |
| ID.RA-09 (hardware/software authenticity) | signed images/bundles, admission verification (04 A08) | admission logs |
| ID.RA-10 (vulnerability disclosure) | bug bounty + triage SLA (04 §6) | bounty program |
| ID.IM-01–03 (improvements) | Feedback loop F2, weekly calibration, chaos game days, post-incident actions tracked | improvement backlog |
| ID.IM-04 (incident response plans & other plans affect cybersecurity) | SP 800-61 integration (§3 below) | IR plan |

### PROTECT (PR)
| Subcategory | Implementation | Evidence |
|---|---|---|
| PR.AA-01/02 (identities, credentials) | OIDC SSO, WebAuthn for privileged roles, SPIFFE service identities (04 §4 A07) | IdP config, tests |
| PR.AA-03 (people/relations authenticated) | MFA for all, session mgmt, step-up auth | session policy |
| PR.AA-04 (access decisions) | RBAC+ABAC matrix (03 §2), OPA enforcement, default deny | policy tests |
| PR.AA-05 (least privilege, segmentation) | RLS tenant boundary, namespace segmentation, egress deny-default (04 A01/A05) | network policy |
| PR.DS-01/02 (data at rest/in transit) | TLS 1.3/mTLS, AES-256-GCM, per-tenant DEKs (04 §5) | crypto config |
| PR.DS-09/10 (software/data integrity, dev env protection) | Signed bundles, hash-chained audit, protected CI, isolated runners (04 A08) | pipeline config |
| PR.DS-11 (inputs/outputs) | Schema validation at every boundary, output encoding, export controls (04 A03/A04) | validation tests |
| PR.PS-01 (configuration) | IaC-only, drift alarms, CIS scanning (04 A05) | IaC repo |
| PR.PS-02/03 (software maintenance, patch) | Patch SLAs, Renovate, staged rollouts | patch metrics |
| PR.PS-04 (images pre-approved) | Signed base images, digest pinning, admission control | image registry |
| PR.PS-06 (secure SDLC) | Secure SDLC gates (04 §6) | MR gates |
| PR.IR-01 (networks/environment protected) | WAF, mTLS mesh, default-deny, egress proxy (04 §2) | topology |
| PR.IR-03 (mechanisms for resilience) | Multi-AZ, DLQ/replay, rebuildable derived state (01 §10) | DR drills |

### DETECT (DE)
| Subcategory | Implementation | Evidence |
|---|---|---|
| DE.CM-01/02/03/06/09 (networks, personnel activity, software, service providers, computing hw) | OTel telemetry, UEBA on analyst behavior (T08), auth anomaly detection, vendor risk reviews | dashboards |
| DE.CM-07 (unauthorized software) | image allowlists, admission control | admission logs |
| DE.CM-10 (monitoring of highest-privilege) | Break-glass alarms, dual-auth events, admin step-up audit | alerts |
| DE.AE-02/03/05/06/07/08 (potentially adverse events analyzed) | **The product itself**: normalization, enrichment, scoring, dedup (01–02); audit chain gap alarms (04 A09) | pipeline SLOs |
| DE.AE-08 (adequate baseline) | score-distribution baselining, differential replay on rule change | baseline reports |
| DE.CM-01 alerting integration | SLO burn + security alerts to on-call (07 runbook) | alert routing |

### RESPOND (RS)
| Subcategory | Implementation | Evidence |
|---|---|---|
| RS.MA-01–05 (incident mgmt execution, triage, prioritization, reporting) | SP 800-61 lifecycle integration (§3); severity scoring IS RS.MA-03 support | IR plan, runbook |
| RS.AN-03/04/05/06/07 (forensics, disclosure, correlations, trends, loss) | WORM audit + hash chain, alert trees, export tooling (03 §1), SIEM export | forensics runbook |
| RS.CO-02/03 (public affairs, disclosure) | Comms templates in IR plan (out of system scope, referenced) | IR plan |
| RS.MI-01/02 (containment, eradication) | Emissions to SOAR with scoped, audited machine identities (01 §4, B5) | SOAR logs |
| RC.RP/CO (recovery) — see RECOVER | — | — |

### RECOVER (RC)
| Subcategory | Implementation | Evidence |
|---|---|---|
| RC.RP-01–06 (recovery plan/exec/integrity/restoration/notifications) | DR strategy: PITR, replay-from-raw, RPO 5 min/RTO 60 min (01 §10.2) | drill reports |
| RC.CO-03/04 (recovery communications) | Status page integration, SOC lead comms protocol (07 runbook) | comms templates |

## 2. NIST SP 800-53 Rev. 5 — control matrix (applicable families)

Legend: **S** = satisfied by design (this architecture), **P** = partially satisfied (process evidence required), **OG** = organizationally owned outside this system.

### AC — Access Control
| Control | Status | Implementation |
|---|---|---|
| AC-2 Account Management | P | SCIM lifecycle, quarterly access reviews; org-owned IdP |
| AC-3 Access Enforcement | S | OPA middleware + RLS (03 §2.3, 04 A01) |
| AC-4 Information Flow Enforcement | S | egress proxy allowlist, SSRF controls, region pinning (04 A10, 03 §3) |
| AC-5 Separation of Duties | S/P | 2-person rule for rules/config, dual-auth bulk ops; SOC lead ≠ detection.eng |
| AC-6 Least Privilege | S | per-endpoint scopes, RLS role without bypass, no shared accounts |
| AC-7 Unsuccessful Logon | OG | IdP lockout policies (documented) |
| AC-8 System Use Notification | S | banner on dashboard + API ToS header |
| AC-12 Session Termination | S | 12 h/30 min idle, server-side revocation list (04 A07) |
| AC-16 Security Attributes | S | tenant_id, band, sensitivity, region attributes drive ABAC |
| AC-17/18 Remote/Mobile Access | OG | managed-device posture via IdP conditional access |
| AC-24 Data Access Control | S | ABAC on PII (pii_reader), break-glass dual-auth |

### AT — Awareness & Training
| AT-2/AT-3/AT-4 | P | role-based curriculum incl. secure coding + analyst privacy training; records in LMS |

### AU — Audit & Accountability
| Control | Status | Implementation |
|---|---|---|
| AU-2 Event Selection | S | audit event catalog defined (03 §1) incl. security-relevant subset |
| AU-3 Content of Audit Records | S | who/what/when/why/before/after (03 §1 audit_events) |
| AU-4 Audit Storage Capacity | S | WORM capacity planning + SIEM export (07) |
| AU-5 Response to Audit Failures | S | **fail-closed**: mutating actions blocked if audit write fails (01 §10.1) |
| AU-6 Audit Review/Reporting | S/P | chain verification job daily; SIEM analytics; analyst UEBA |
| AU-7 Reduction & Report Generation | P | SIEM-side aggregation dashboards |
| AU-8 Timestamps | S | NTP-synced, UTC RFC3339, skew flagging (02 §2) |
| AU-9 Protection of Audit Information | S | append-only, REVOKE UPDATE/DELETE, WORM Object Lock, separate credentials |
| AU-10 Non-repudiation | S/P | hash chain + WORM; client-side request signing on roadmap (R1) |
| AU-11 Record Retention | S | 400 days WORM (03 §5) |
| AU-12 Audit Generation | S | synchronous audit emission on every state change |

### CA — Security Assessment
| CA-2/CA-7 | P | annual pentest, continuous SAST/DAST, MR gates, SLO monitoring |
| CA-3 Information Exchange | P | vendor TI allowlist, DPA/ROPA, webhook allowlists |
| CA-9 Internal System Connections | S | service mesh identities, audience-bound tokens |

### CM — Configuration Management
| CM-2 Baseline | S | IaC-only, PSS restricted, CIS benchmarks |
| CM-3/CM-4 Config Change Control / Impact Analysis | S/P | PR + differential replay + 2-person approval + auto-rollback (02 §4.5, 01 F3) |
| CM-5 Access Restrictions for Change | S | CODEOWNERS + protected branches + signed commits |
| CM-6 Configuration Settings | S | hardened baselines as code, drift alarms |
| CM-7 Least Functionality | S | distroless images, egress deny-default, dependency allowlist |
| CM-8 System Component Inventory | S | SBOM + workload inventory (§1 ID.AM) |
| CM-10/11 Software Usage/Restrictions | P | license + provenance checks in CI |

### IA — Identification & Authentication
| IA-2 Identification & Authentication (org users) | S | OIDC + mandatory MFA; WebAuthn for privileged (04 A07) |
| IA-2(1)/(2) MFA to privileged/network | S | WebAuthn required for admin/lead/config roles |
| IA-4 Identifier Management | S | UUIDs, SPIFFE ids; no shared identifiers |
| IA-5 Authenticator Management | P | KMS-held secrets, rotation ≤ 90 d, no local passwords |
| IA-9 Service Authentication | S | mTLS + audience-bound short-lived tokens |

### IR — Incident Response
| IR-1/IR-3/IR-4/IR-5/IR-6/IR-7/IR-8 | S/P | SP 800-61-aligned lifecycle (§3 below); platform alerts integrated into same IR process it supports |
| IR-4(4) Information Correlation | S | alert trees, entity history, case links (02 §5.3, 03 §1) |
| IR-6(1) Reporting to authorities | OG | legal/comms process referenced in IR plan |
| IR-10 Non-Electronic Incident Response | P | printed runbook fallback, break-glass procedures (07) |

### MA / MP / PS / PE
| MA-4 (nonlocal maintenance) | OG | break-glass audited sessions |
| MP-6 Media Sanitization | S/P | crypto-shredding of tenant data (03 §4) |
| PS-7 Third-Party Personnel | OG | HR/contractor process |
| PE family | OG | cloud provider attestations (SOC 2/ISO 27017 inherited controls documented in SoA) |

### SA — System & Services Acquisition
| SA-4/SA-9 | P | vendor TI/IdP/cloud reviews; DPAs |
| SA-8 Security Engineering Principles | S | this document set; secure design review gate |
| SA-10 Developer Config Mgmt | S | signed commits, protected CI, hermetic builds |
| SA-11 Developer Testing & Evaluation | S | test strategy (02 §8, 04 §6) incl. fuzzing + isolation suites |
| SA-15 Development Process | S | secure SDLC (04 §6) |
| SA-22 Unsupported Components | P | EOL tracking (04 A06) |

### SC — System & Communications Protection
| SC-2/3 Separation (security functions/app) | S | namespace/ trust-tier separation, dedicated audit plane |
| SC-5 Denial of Service | S | rate limits, payload budgets, WAF, degradation modes (01 §10) |
| SC-7 Boundary Protection | S | WAF/GW, mesh mTLS, default-deny, egress proxy |
| SC-8 Transmission Confidentiality/Integrity | S | TLS 1.3/mTLS everywhere (04 §5) |
| SC-10 Network Disconnect | S | timeouts, circuit breakers, resumable WS streams |
| SC-12 Key Establishment/Management | S | HSM-backed KMS, rotation, dual control (04 §5) |
| SC-13 Cryptographic Protection | S | algorithm allowlist, no custom crypto |
| SC-15 Collaborative Devices | OG | out of scope |
| SC-16 Transmission of Security Attributes | S | signed tokens carry tenant/band/sensitivity claims |
| SC-22 Architecture Provisioning | S | single hardened DB entry point, no shared service chains |
| SC-23 Session Authenticity | S | WS auth per session, resumable cursors are token-scoped |
| SC-28 Protection of Information at Rest | S | AES-256-GCM, field-level encryption, crypto-shred |
| SC-39 Process Isolation | S | container isolation, PSS restricted, seccomp |

### SI — System & Information Integrity
| SI-2 Flaw Remediation | P | patch SLAs + exception register |
| SI-3 Malicious Code Protection | OG | EDR on hosts; image scanning (S/P) |
| SI-4 System Monitoring | S | OTel + security pack + UEBA; monitoring of monitoring (04 A09) |
| SI-7 Software/Firmware/Information Integrity | S | signatures, hash chains, admission verification, reproducibility checks |
| SI-8 Spam Protection | OG | email gateway (upstream source) |
| SI-10 Information Input Validation | S | schema validation at every boundary (02 §2, 04 A03) |
| SI-11 Error Handling | S | structured errors, no stack traces to clients, DLQs |
| SI-12 Information Handling & Retention | S | retention matrix + minimization (03 §4–5) |
| SI-16 Memory Protection | S | memory-safe languages (Go) on hot path, W^X defaults |

### SR — Supply Chain Risk Management
| SR-3/4/5/6/11 | P | SBOM/SLSA/sigstore, vendor reviews, dependency SLAs, provenance verification (04 A06/A08) |

## 3. NIST SP 800-61 — Incident handling integration

The triage platform both **supports** the organization's IR process and is **subject to** it. Mapping of the four-phase lifecycle:

### 3.1 Preparation
- The platform's core function (scoring + dedup) is itself preparation capacity: queue hygiene reduces incident-finding latency.
- Runbooks (`07`), on-call rotations, and the "secure the security tool" detection pack are pre-positioned per SP 800-61 §3.1.1.
- Tooling: WORM forensics export, alert trees for scope analysis, replayable raw topics for re-analysis after rule fixes.

### 3.2 Detection & Analysis (SP 800-61 §3.2)
| SP 800-61 activity | Platform capability |
|---|---|
| Vector identification | source/rule/tactic normalization (OCSF) |
| Scope (systems, users, networks) | entity trees, variant_entities, 30d entity history |
| Attack signatures/precursors | TI factors (f4), KEV/EPSS (f6), behavioral anomaly (f7) |
| Prioritization (functional/informational impact) | severity bands + asset criticality (f2) + occurrence velocity (f8) — documented, explainable prioritization per SP 800-61's "impact-based prioritization" guidance |
| Correlation | dedup links + entity linking + case linkage |

### 3.3 Containment, Eradication, Recovery (§3.3)
- Platform emits scoped, audited action requests to SOAR (isolate host, disable account); it never executes containment itself (least privilege, B5 boundary).
- Evidence preservation: nothing is deleted by design (non-destructive dedup); WORM audit chain supports chain-of-custody; evidence export bundles (parquet + hash manifest) for legal hold.

### 3.4 Post-Incident Activity (§3.4)
- Dispositions feed the feedback loop (F2) → detection engineering backlog + scoring/dedup calibration — closing the loop SP 800-61 calls "lessons learned".
- Post-incident reviews produce tracked improvement items (ID.IM mapping §1); major incidents trigger threat-model delta review (04 §6).

### 3.5 IR metrics the platform must report (per SP 800-61 §3.4.2)
- MTTD (alert created → first viewed), MTTH (created → dispositioned), false-positive rate per rule family, dedup precision (sampled), score band distribution shift, escalation rate to SOAR. Definitions live in `07`; reported weekly to GV.OV reviews.

## 4. Control tailoring & inheritance

- Cloud provider controls (physical, hypervisor, some network) are **inherited** and documented in the SoA/shared-responsibility matrix with attestations (SOC 2 Type II, ISO 27001/27017/27018).
- Tailoring: AC-7 and PE family are org-owned; compensation for any "not applicable" control is documented with risk acceptance signed by GV.RR-01 role owner.
- Parameterization: AC-12 (session timeouts), AU-11 (400-day retention), SI-2 patch SLAs are set as organization-defined values and enforced technically where possible.
