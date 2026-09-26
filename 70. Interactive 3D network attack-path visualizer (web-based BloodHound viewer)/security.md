# security.md — Security Policy, Controls & Threat Model (PathSphere 3D)

**Version:** 1.0  
**Classification:** Internal Security Reference  
**Aligned To:** ISO/IEC 27001:2022 (Annex A), NIST CSF 2.0 + SP 800-53 Rev. 5, OWASP Top 10 (2021), MITRE ATT&CK, OWASP ASVS L2

---

## 1. Security Objectives

PathSphere 3D ("PathSphere") enforces **Secure by Design (P-01)**, **Zero Trust Data Access (P-02)**, **Defense in Depth (P-03)**, **Least Privilege & Separation of Duties (P-04)**, **Everything is Evidence (P-05)**, and **Scale without Degradation (P-06)**.

Primary security objectives (SO):
- SO-1: Prevent unauthorized access to Active Directory/Entra ID/cloud topology and attack-path findings.
- SO-2: Ensure all security-relevant actions are immutable, attributable, and tamper-evident.
- SO-3: Enforce per-tenant, per-role, attribute-based access control on every graph read/query/export.
- SO-4: Maintain cryptographic integrity of reports, audit events, and configuration artifacts (SBOM, images).
- SO-5: Detect and respond to anomalous access patterns (mass export, off-hours Tier-0 access, burst queries).
- SO-6: Eliminate injection surfaces against the graph engine (Cypher/GraphQL) via allow-listed, parameterized access only.
- SO-7: Achieve audit readiness for ISO/IEC 27001, NIST CSF 2.0, and evidence-grade assurance.

---

## 2. Security Policies

### 2.1 Access Control Policy (ACP)
- **Deny-by-default.** No implicit grants; every request evaluated by OPA (ABAC).
- **Least Privilege:** Minimum scope (tenancy, OU/domain, tags, sensitivity) per role.
- **RBAC:** Roles: `Viewer`, `Analyst`, `Auditor`, `Admin`. Separation of duties: report authors ≠ report approvers.
- **JIT Access:** Privileged elevation time-limited (≤ 1 hour TTL), auto-expire, fully audited.
- **Break-Glass:** Requires pre-approved workflow, auto-ticketing (SOAR), mandatory justification, post-access review.
- **Session Controls:** Short-lived JWT (15 min) + refresh rotation with reuse detection; secure HttpOnly/SameSite=Strict cookies; device binding where feasible.

### 2.2 Data Classification & Handling Policy (DCHP)
| Label | Definition | Handling Requirements |
|---|---|---|
| `Public` | Non-sensitive documentation | No restrictions |
| `Internal` | Operational/config docs | Authenticated access |
| `Confidential` | Topology summaries, findings, reports | ABAC + 4-eyes approval for export; watermark; expiry TTL |
| `Restricted` | Tier-0/crown jewels, raw directory metadata, PII | Pseudonymized by default; "reveal" is audited event; need-to-know + explicit approval |

- **Data Minimization:** Return only fields authorized (field-level authZ).
- **Pseudonymization:** Directory PII masked until explicit, audited reveal.
- **Tenant Isolation:** Logical tenancy enforced at query layer + RLS (Postgres); no cross-tenant graph leakage.

### 2.3 Cryptography Policy (CP)
- **In Transit:** TLS 1.3 only; HSTS preload; mTLS for service-to-service (service mesh); no TLS < 1.3.
- **At Rest:** AES-256-GCM; KMS-managed keys, rotation per policy (90-day recommended), key usage separation.
- **Signing:** Ed25519 for report artifacts and attestation; cosign (Sigstore) for container images/artifacts.
- **Integrity:** SHA-256 for uploads, artifacts, backups; hash-chained audit ledger.
- **Crypto Agility:** Maintain crypto-agility register; deprecate algorithms via documented change control.

### 2.4 Secure Development & SDLC Policy
- **Shift-Left Security:** SAST (Semgrep/CodeQL), SCA (dependabot/renovate + Snyk/Grype), IaC (Checkov/tfsec), secrets scanning (gitleaks), container (Trivy).
- **SBOM:** CycloneDX SBOM generated per build, stored with artifact, signed (cosign).
- **Vulnerability Management:** Critical CVEs ≤ 7-day SLA, High ≤ 14-day, Medium ≤ 30-day; fail gates on Critical.
- **Change Control:** 4-eyes PR reviews, signed commits, GitOps (ArgoCD) with immutable manifests.
- **Threat Modeling:** STRIDE per feature/component; track mitigations; update on design changes.

### 2.5 Audit, Logging & Monitoring Policy
- **Append-Only:** Audit ledger tables non-updatable/non-deletable (DB triggers + WORM archive).
- **Mandatory Fields:** `event_id, ts, actor, role, action, object_type, object_id, tenant, ip, ua, mfa, prev_hash, hash, meta`.
- **Chain Integrity:** `hash(prev_hash || canonical_payload)`; nightly chain-verify + Merkle root anchor; P1 on break.
- **Retention:** Audit/security events 7 years, online 12 months, archive 24 months minimum (immutable). Reports per legal schedule.
- **SIEM:** CEF/JSON over TLS to central SIEM; correlation rules for mass export, off-hours Tier-0 reads, auth spikes, burst queries.
- **Tamper Detection:** Log-integrity monitor + chain-verify alerts.

### 2.6 Incident Response Policy (IRP)
- **Detection:** SIEM alerts + anomaly engine + chain-integrity failures.
- **Triage:** Severity (P0–P4), 15-min acknowledgment for P0/P1.
- **Playbooks:** New-critical-path alert → SOAR containment; data-access anomaly → session revocation + access review.
- **Evidence Preservation:** Forensics-preserve audit chain, WORM copies, request snapshots (read-only).
- **Post-Incident:** Root cause analysis, corrective actions (CAPA), lessons learned, update detection rules.

### 2.7 Data Residency, Privacy & Retention
- **Residency:** Configurable per tenant (region pinning). Collector uploads processed in approved regions.
- **DSAR Support:** Data Subject Access/Deletion requests; report export of audit scope; verified purge with audit trail.
- **PII Handling:** RoPA maintained; "reveal" actions require justification + audited. No PII in application logs.
- **Backup Integrity:** Encrypted backups, integrity hashes verified on restore; PITR tested quarterly.

---

## 3. Security Controls Matrix (Key Implementation)

| Domain | Controls (References) | Implementation | Evidence Artifacts |
|---|---|---|---|
| Identity/Auth | ISO A.5.17/A.8.5 · NIST PR.AA-01/03 · OWASP A07 | Keycloak OIDC, WebAuthn/TOTP, 15-min JWT + rotation+reuse, lockout, JIT, break-glass | Auth logs, MFA coverage, session audits, break-glass tickets |
| Access Control | ISO A.5.15/A.5.18 · NIST PR.AA-05 · OWASP A01 | OPA ABAC on every query, RBAC, field-level authZ, Postgres RLS, deny-by-default | OPA decision logs, role matrix, access reviews, recert records |
| Graph Security | ISO A.8.26 · OWASP A03/A04 | Persisted GraphQL only, parameterized Cypher builders, query budgets (depth/rows/time), tenant isolation | Query audit events, budget violations, persisted query allow-list |
| Data Protection | ISO A.5.33/A.8.24 · NIST PR.DS-01/02/05 | TLS 1.3, AES-256-GCM (KMS), S3 Object Lock (WORM), RLS | TLS scans, key inventory/rotation, object-lock policy |
| Application Sec | ISO A.8.26/A.8.28 · OWASP Top10 | STRIDE, SAST/SCA/DAST/IaC gates, CSP, input validation, error scrubbing | Threat models, pipeline gate reports, SBOM/cosign attestations |
| Supply Chain | ISO A.8.28/A.5.19 · NIST SR-* | SBOM (CycloneDX), cosign-signed images/artifacts, Renovate/Dependabot, signed commits, provenance | SBOMs, attestations, vuln SLAs, dependency review |
| Logging/Audit | ISO A.8.15/A.8.16 · NIST DE.CM | Append-only hash-chained ledger, canonical schema, SIEM stream, nightly chain-verify | Audit chain samples, chain-verify reports, SIEM rule catalog |
| Network | ISO A.8.20 · NIST PR.AA/PR.DS | Service-mesh mTLS, NetworkPolicies, egress allow-list, gateway-only N-S | Mesh cert rotation, netpol audits, egress denies |
| Resilience/DR | ISO A.5.29/A.5.30 · NIST RC.RP | Multi-AZ, PITR (RPO ≤ 15m/RTO ≤ 1h), cross-region WORM, restore drills | DR runbooks, restore drill reports, backups + integrity hashes |
| IR & Compliance | ISO A.5.24–26 · Clauses 9–10 · NIST RS/RC | SOAR playbooks, CAPA, internal audits, evidence bundles | IR timelines, CAPA register, audit evidence packs |

---

## 4. Threat Model (STRIDE Summary)

| Component | STRIDE Threats (Key) | Mitigations | Residual Risk |
|---|---|---|---|
| SPA (WebGL) | **T:** XSS in templates, **I:** tampered client state | CSP, template auto-escape, no raw HTML injection, deep-link validation | Low |
| API Gateway/WAF | **D:** DoS, **S:** spoofed tokens | WAF (OWASP CRS), rate limits, JWT validation (iss/aud/exp/nbf), mTLS | Low |
| Graph Query API | **S/T/I:** Cypher injection, **E:** privilege escalation, **I:** info disclosure | Persisted GraphQL only, parameterized Cypher builders, OPA ABAC, query budgets, field redaction | Low |
| Path Analysis Engine | **D:** unbounded compute, **E:** resource exhaustion | Time/memory governor (≤ 2s), bounded k, async jobs, queue limits, deterministic cache | Low–Med |
| Ingestion Service | **T:** poisoned uploads, **S:** forged collector, **D:** zip bomb | SHA-256 + AV, size/type limits, schema strict, collector cert pinning, quarantine, mTLS/signed JWT | Low |
| Neo4j/Postgres | **E:** excessive read scope, **I:** cross-tenant leakage | Tenant isolation, RLS, least-priv roles, query allow-list, server-side authZ | Low |
| Audit Ledger | **T/I:** tamper/delete, **R:** repudiation | Append-only (triggers), hash-chain (`prev||payload`), WORM archive, nightly chain-verify, Merkle root anchor | Low |
| OPA Policies | **T:** policy tamper, **E:** bypass | Rego in Git (versioned, 4-eyes), signed policy artifacts, decision logged to audit, deny-by-default | Low |
| Object Storage (S3/WORM) | **T/I:** artifact tamper, **D:** loss | Object Lock (WORM), versioning, SSE-KMS, cross-region immutable, integrity hashes + Ed25519 sigs | Low |
| Integrations (SIEM/SOAR) | **S:** forged events, **T:** tampered webhooks | TLS/mTLS, outbound allow-list (anti-SSRF), signed webhooks, allow-listed endpoints, egress proxy | Low |

**Notes:** STRIDE tracked per feature; mitigations mapped to OWASP A01–A10 and Annex A controls.

---

## 5. Security Gates (CI/CD)

| Gate | Tool(s) | Failure Criteria | Enforcement |
|---|---|---|---|
| SAST | Semgrep / CodeQL | High/Critical findings (block on new Critical) | PR gate (required) |
| SCA | Dependabot/Renovate + Grype/Snyk | Critical CVEs (block) | PR/build gate |
| IaC | Checkov / tfsec | High/Critical misconfigs (block) | PR/build gate |
| Secrets | gitleaks / trufflehog | Any secret detected (block) | Pre-commit + PR |
| Container | Trivy / Grype | Critical vulns (block), High (warn/block per policy) | Image build/publish |
| SBOM | CycloneDX + Syft | Missing SBOM (block) | Release gate |
| Signing | cosign (Sigstore) | Unsigned image/artifact (block publish) | Publish gate |
| DAST | OWASP ZAP (auth baseline) | Critical/high exploitable (block release) | Release/nightly |
| License | LicenseFinder/deny | Disallowed licenses (block) | PR gate |

---

## 6. Evidence Requirements (Audit Readiness)

| Evidence Type | Location | Retention | Verification Method |
|---|---|---|---|
| SBOM (CycloneDX) | Artifact registry + release assets | Per release + legal | cosign verify-attestation + SBOM diff |
| Image/Artifact Signatures | Sigstore (cosign) | Indefinite (tied to artifacts) | `cosign verify` / keyless verify |
| Audit Chain (hash-chain) | PostgreSQL (append-only) + S3 WORM | 7y / 12m online / 24m archive | Nightly chain-verify job (recompute + Merkle) |
| Report Signatures (Ed25519) | Report records + artifacts | Per retention schedule | Public `/verify` (SHA-256 + sig) |
| OPA Decision Logs | Audit Ledger (referenced) | 7y | Correlated to query events |
| Access Reviews/Recert | Compliance portal | 7y | Campaign records + approvals |
| Break-Glass Events | Audit Ledger + SOAR | 7y | Full justification + post-review |
| DR Restore Drills | Ops evidence store | 7y | Drill reports + integrity hashes of restored data |
| Pentest Reports + CAPA | `docs/security/` + ticketing | 7y | Track CAPA closure evidence |
| Threat Models | `docs/security/threat-models/` | Per product lifecycle | Versioned + reviewed (4-eyes) |

---

## 7. Security Baselines & Hardening

- **Kubernetes:** PodSecurity (restricted), read-only rootfs, non-root, no privilege escalation, drop ALL capabilities, seccomp/AppArmor, resource limits, NetworkPolicies default-deny.
- **Containers:** CIS-hardened base images, distroless where feasible, minimal attack surface, multi-stage builds, SBOM + vuln scan.
- **Neo4j:** Least-priv DB users, Bolt restricted to internal, auth enabled, query logging for anomalies, no default creds.
- **Postgres:** RLS enabled per tenant, least-priv roles (read/write/append-only), no superuser for app, row-level tenancy.
- **Redis:** Auth enabled, TLS (if external), protected network, no PII stored.
- **S3/WORM:** SSE-KMS, bucket policy deny public, Object Lock compliance mode, versioning, lifecycle to archive.
- **Hosts/Nodes:** CIS benchmarks, automatic patching, EDR, IMDSv2 (cloud), egress allow-list.

---

## 8. Runtime Security & Detection

- **Anomaly Engine (reference):** Detects mass export volume (z-score), off-hours Tier-0 reads, unusual query shapes/depth, burst exports, auth spike from new IP/device.
- **SIEM Correlation Rules (examples):** `ps3d:mass_export`, `ps3d:tier0_offhours`, `ps3d:refresh_reuse_detected`, `ps3d:policy_decision_denied_spike`, `ps3d:audit_chain_break` (P0), `ps3d:break_glass_used`.
- **Runtime Protection:** Falco/tracee rules for shell exec, privilege escalation, unexpected mounts, outbound to non-allow-list.
- **Zero Trust Enforcement:** Continuous access evaluation (token reuse, device posture changes) triggers re-auth where applicable.

---

## 9. Security Contacts & Escalation

| Role | Contact (template) | SLA |
|---|---|---|
| Security Lead | `security@pathsphere.example` | P0/P1 15 min |
| Compliance/Audit Lead | `compliance@pathsphere.example` | Business hours + critical |
| Platform/SRE | `sre@pathsphere.example` | P0 15 min |

---

## 10. Reservation & Security Posture Notes

- **Security Posture (Target):** Residual risk ≤ **Low** across OWASP A01–A10 (A04 Low–Med with compensating approvals).
- **Compliance Readiness:** ISO 27001:2022 Annex A mapped with control→implementation→evidence; NIST CSF 2.0 aligned; OWASP ASVS L2 target.
- **Assurance:** Evidence-first design ("Everything is Evidence", P-05). Hash-chained audit + cryptographically signed reports provide non-repudiation and tamper evidence suitable for internal/external audits.
- **Reservation Strategy (Security):** Deny-by-default, ABAC per request, append-only evidence, tamper-detection (chain-verify), supply-chain attestations (SBOM+cosign), and automated security gates enforce posture continuously.

**Document End**