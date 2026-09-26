# PathSphere 3D — Architecture & Security Blueprint (Comprehensive Report)

**Document Version:** 2.1  
**Solution Name:** Interactive 3D Network Attack-Path Visualizer (Web-Based BloodHound Viewer)  
**Release Status:** Design Blueprint  
**Classification:** Internal Security Architecture Reference

---

## Executive Summary

PathSphere 3D is a web-based attack-path visualization platform that transforms BloodHound-style Active Directory/Entra ID/cloud posture graphs into an interactive, color-coded 3D universe. By combining GPU-accelerated WebGL rendering with a zero-trust microservices backend, the platform makes privilege escalation and lateral movement paths instantly intuitive for Red Teams, SOC analysts, CISOs, and compliance auditors. The architecture embeds security-by-design across every layer and is mapped directly to ISO/IEC 27001:2022 (Annex A), NIST CSF 2.0 + SP 800-53 Rev. 5, OWASP Top 10 (2021), and MITRE ATT&CK.

Key Value Propositions:
- **Speed to insight:** Reduces mean time-to-understand from hours to seconds.
- **Evidence-grade assurance:** Hash-chained, append-only audit ledger with Ed25519-signed reports for audit defensibility.
- **Compliance-ready:** Control-to-evidence traceability across three major frameworks.
- **Scalable performance:** Designed for 250K+ nodes at 60 FPS with < 120 ms API P95 latency.
- **Zero Trust by default:** Every request re-authorized server-side via ABAC (OPA); deny-by-default posture.

---

## 1. Solution Overview

### 1.1 Problem Statement
Traditional 2D BloodHound views degrade at enterprise scale (100K–1M nodes/edges). It is difficult to visualize blast radius, prioritize critical paths, and present risk to non-technical stakeholders. Auditors also require immutable, reproducible evidence of who accessed sensitive topology and when.

### 1.2 Solution
PathSphere 3D renders attack paths as a navigable 3D graph with depth-as-risk, glow-as-criticality, animated edge flows, and hop-by-hop path replay. A hardened API gateway, GraphQL with persisted/parameterized queries, OPA-based ABAC, and a hash-chained audit ledger deliver the control rigor required for regulated environments.

### 1.3 Target Personas
- **Red Team / AD Specialist:** Explores, replays, exports attack paths; validates mitigations.
- **SOC Analyst:** Detects new/critical paths post-change; triages findings.
- **CISO / Executive:** Board-ready heatmaps/trends and compliance posture.
- **Compliance / Auditor:** Read-only, immutable evidence with control mappings and chain verification.

### 1.4 Core Metrics (Design Targets)
| Metric | Target | Notes |
|---|---|---|
| API P95 latency | < 120 ms | Cached subgraphs + bounded queries |
| 3D rendering | 250K+ nodes @ 60 FPS | Instanced meshes, LOD culling, off-thread layout |
| Microservices | 14 | Domain-bound, independently deployable |
| Audit coverage | 100% of security-relevant actions | Append-only, hash-chained |
| Zero Trust | Enforced everywhere | ABAC per query + mesh mTLS |
| Framework mappings | ISO/NIST/OWASP | Control → implementation → evidence |

---

## 2. High-Level Architecture

The platform follows a layered, defense-in-depth model (6 tiers + cross-cutting security). Data flows top-down to the 3D canvas; all requests traverse edge security, gateway authorization, application services, graph intelligence, and persistence.

Tiers:
1. **Presentation (SPA + WebGL):** React + Three.js (R3F), Path Explorer, Report & Audit Console, Admin/Compliance Portal
2. **Edge & API Gateway:** WAF/DDoS/Bot guard, Envoy/Nginx, OIDC + JWT validation, rate-limiting, schema validation
3. **Application Services (14 microservices):** Auth & Identity (Keycloak), Graph Query API (persisted GraphQL), Path Analysis Engine, Ingestion, Report Engine, Audit Ledger, Notification/Workflow, Policy Engine (OPA), Risk Scoring, MITRE Mapper, Delta/Drift, and supporting services
4. **Graph Intelligence:** Attack-path calculator (BFS/Dijkstra/Yen), risk scoring, ATT&CK mapping, delta/drift detection
5. **Data & Persistence:** Neo4j Causal Cluster (graph of record), PostgreSQL HA (users/reports/findings), Redis (cache/sessions/locks/streams), S3/WORM (reports, audit archive)
6. **Integrations:** SharpHound/AzureHound/BloodHound API, Microsoft Entra/AD, SIEM (Splunk/Elastic/Syslog), MITRE ATT&CK/NVD/CVE feeds, SOAR webhooks, Jira/ServiceNow ticketing

Security wrapping: perimeter → network → host → app → data → cryptographic → governance. Every trust boundary terminates TLS, authenticates the caller, and emits an audit event.

---

## 3. Data Flow (7-Stage Pipeline)

| Stage | Component(s) | Description | Security Controls |
|---|---|---|---|
| 1. Collect | SharpHound / AzureHound / Agentless API | Read-only directory/cloud posture snapshots | Collector allow-list, read-only, least privilege |
| 2. Ingest + Validate | Ingestion Service | Upload ZIP/JSON; SHA-256 hash, antivirus (ClamAV), size/type limits, schema strict validation, optional collector signature | Quarantine on anomaly, idempotency, mTLS/signed JWT |
| 3. Normalize → Graph | Ingestion + Neo4j | Merge/dedupe, identity resolution, edge typing, transactional upsert | Parameterized writes, versioned graph snapshot hash |
| 4. Compute Paths | Path Analysis + Risk + ATT&CK Mapper | BFS/Dijkstra, Yen's k-shortest, cycle detection, Tier-0 reachability, risk enrichment, technique tagging | CPU/memory/time ceilings (≤ 2 s), deterministic cache by graph version |
| 5. Serve API | Graph Query API + OPA | Persisted GraphQL/REST; ABAC filter applied server-side; Redis cache; rate limits | Query budget, depth/row caps, tenant isolation, audit on every read |
| 6. Render 3D Universe | SPA (R3F + Worker Layout) | Off-thread force-directed layout, instanced meshes, animated edge flows, semantic color/glow, path replay, snapshots | CSP, SRI, input sanitization, deep-link URL safety |
| 7. Continuous Feedback | Delta/Drift + Notification + Audit + SIEM | Detect new edges/paths → alerts (email/Slack/SOAR) → findings → re-generate reports → append audit events → tickets | Append-only ledger, correlation rules, closed-loop remediation verification |

---

## 4. Component Deep-Dive

| Service | Role | Interfaces | Key Security Controls | Framework Mapping |
|---|---|---|---|---|
| Auth & Identity | OIDC/MFA, sessions, token issuance | `/oauth2/*`, JWKS, introspect | WebAuthn/TOTP, 15-min JWT + refresh rotation + reuse detection, account lockout, session vault | ISO A.5.17/A.8.5 · NIST PR.AA-01/03 · OWASP A07 |
| Graph Query API | Topology access (read-only surface) | GraphQL (persisted queries only), REST | Parameterized Cypher builders, query cost/depth/row caps, per-tenant isolation, result redaction | ISO A.8.26 · NIST PR.DS-05 · OWASP A01/A03 |
| Path Analysis Engine | Attack-path computation | gRPC `ComputePaths`, Redis Streams | Time/memory governor (≤ 2 s), deterministic cache, cycle-safe, bounded k | ISO A.8.26 · OWASP A04 |
| Ingestion Service | Collector intake & normalization | `POST /ingest` (mTLS/signed JWT) | SHA-256 + AV scan, schema strict, quarantine, collector pinning, idempotency | ISO A.5.24–26 · A.8.15 · OWASP A10 guardrails |
| Report Engine | Signed reports (PDF/CSV/JSON/HTML/STIX 2.1) | Job API, template engine | Jinja2 auto-escape, 4-eyes approval (high+), Ed25519 signing, public verify endpoint | ISO A.5.33 · NIST RC/RS |
| Audit Ledger Service | Immutable hash-chained ledger | Internal append API, SIEM stream | Append-only, `hash(prev || payload)`, nightly Merkle root anchor, WORM archive, chain-verify job | ISO A.5.33/A.8.15/A.8.16 · NIST DE.CM |
| Policy Engine (OPA) | ABAC/PBAC decisions | Sidecar `/v1/data/ps3d/allow` (< 5 ms) | Rego in Git (versioned, 4-eyes), decision logged to audit, deny-by-default | ISO A.5.15/18 · A.8.3 · NIST PR.AA-05 · OWASP A01 |
| Notification/Workflow | Alerts & approvals | Redis Streams → SMTP/Slack/Teams/SOAR | Outbound allow-list (anti-SSRF), templated (no raw graph), rate-limited digests | ISO A.5.24–26 · NIST DE.CM-09/RS.MA-02 |
| Risk Scoring + MITRE + Delta/Drift | Enrichment & anomaly detection | gRPC/internal | CVSS + blast radius + dwell weighting, ATT&CK tactic/technique mapping, new-edge anomaly signals | ISO A.5.7 · NIST ID.RA |

---

## 5. 3D Visualization Engine

Stack (bottom→top):
1. **Data Adapter:** Apollo GraphQL client, persisted queries, normalized cache, WebSocket deltas, IndexedDB offline snapshots
2. **Graph Model + Layout Worker:** Off-main-thread 3D force-directed layout (d3-force-3d), semantic clustering by OU/site, LOD decimation > 50K nodes
3. **Scene Composer (R3F):** Instanced meshes (GPU), edge tubes with animated dash flows, bloom/god-rays, raycast picking, camera fly-through
4. **Semantic Color System:** Cyan=users, Violet=groups, Magenta=hosts, Amber=ACL edges, Red=critical path, Lime=hardened/remediated; glow ∝ risk score; depth ∝ tier distance
5. **Interaction:** Hover/tooltips, double-click drill-down, box-select, path pin + replay slider (hop-by-hop), camera bookmarks, PNG/PDF snapshot export, URL-anchored deep links

**Performance Budget:** ≤ 16 ms/frame (60 FPS), frustum culling, texture atlases, half-float buffers, worker-side physics.

**Accessibility:** Keyboard navigation, high-contrast palette, color-blind-safe (shape+pattern), screen-reader node summaries.

---

## 6. Security Architecture — Defense in Depth

7 concentric layers + cross-cutting controls:

| L# | Layer | Controls | Verification |
|---|---|---|---|
| L1 | Edge | WAF (OWASP CRS), DDoS scrubbing, TLS 1.3 termination, HSTS/CSP, bot management | TLS scan, WAF logs, DDoS telemetry |
| L2 | AuthN + ABAC | OIDC/MFA, 15-min JWT + rotation/reuse, OPA per query, request context propagation | Auth audit, policy decision coverage |
| L3 | Network | Service-mesh mTLS (Istio/Linkerd), Kubernetes NetworkPolicies, egress allow-list, north-south via gateway only | Mesh cert rotation, egress deny-by-default audit |
| L4 | Application | Persisted GraphQL, parameterized Cypher, input validation, CSP, SAST/DAST/SCA gates | Pipeline gates, threat-model sign-offs |
| L5 | Data | AES-256-GCM at rest (KMS), RBAC/RLS (Neo4j/Postgres), PITR backups, S3 Object Lock (WORM) | Key rotation, restore drills, backup integrity |
| L6 | Operations | SIEM (correlation), Prometheus/Grafana SLOs, Falco runtime, PAM for admins, EDR, weekly CVSS patching SLA | Alert T&C, patch compliance, runbooks |
| L7 | Governance | ISMS policies, risk register, immutable audit, DR/BCP, compliance evidence bundles | Internal audits (Clause 9), CAPA (Clause 10) |

**Trust Boundaries:** internet→WAF (TB-1), WAF→gateway (TB-2), gateway→services (TB-3, mesh mTLS), services→data (TB-4, private VPC), collector→ingestion (TB-5, mTLS/signature). All emit audit events.

---

## 7. ISO/IEC 27001:2022 — Annex A Mapping (Key Controls)

| Control (A.) | Title | Implementation in PathSphere 3D | Evidence / Artifact | Status |
|---|---|---|---|---|
| A.5.15 | Access control | RBAC + ABAC (OPA) on every graph query/export | OPA decision logs, role matrix, access reviews | Implemented |
| A.5.16 | Identity management | Keycloak, SCIM JML, orphan account detection | SCIM logs, monthly orphan report | Implemented |
| A.5.17 | Authentication info | MFA (WebAuthn/TOTP), no shared UI accounts, Vault secrets (90d rotation) | Vault audit, MFA coverage dashboard | Implemented |
| A.5.18 | Access rights | Quarterly recert, JIT elevation (1h TTL), automated deprovision | Recert campaign records | Implemented |
| A.5.24–26 | Incident planning/management | New-critical-path → SOAR playbook, severity taxonomy, PIR templates | IR runbooks, timelines | Implemented |
| A.5.33 | Protection of records | Reports + audit in S3 Object Lock (WORM), hash-chained ledger | Object-lock policy, chain-verify output | Implemented |
| A.5.34 | Privacy & PII | Classified PII, pseudonymized until audited "reveal", GDPR basis | RoPA, reveal-event audit sample | Implemented |
| A.6.3 | Awareness & training | Role-based paths, phishing-resistant onboarding, security champions | LMS completion records | Partial |
| A.8.2 | Privileged access rights | Tier-0 in PAM/Vault, session recording, break-glass + auto-ticket | PAM session recordings | Implemented |
| A.8.5 | Secure authentication | OIDC+MFA, HttpOnly/SameSite=Strict, 15-min JWT + rotation+reuse detection | Auth baseline, pentest report | Implemented |
| A.8.9 | Config management | GitOps (Helm/Kustomize), immutable CIS images, drift detection | Git history, drift scans | Implemented |
| A.8.15 | Logging | Structured logs (auth/query/export/admin), 12m online / 24m archive, NTP | Log schema, retention policy | Implemented |
| A.8.16 | Monitoring activities | SIEM correlation (mass export, off-hours Tier-0, auth spikes), 24×7 feed | SIEM rule catalog, alert tickets | Implemented |
| A.8.20 | Network security | Private VPC, least-priv SGs, microsegmentation, egress filtering | Network diagram | Implemented |
| A.8.24 | Use of cryptography | TLS 1.3 only, AES-256-GCM at rest, Ed25519 report signatures, crypto agility | TLS scan, key inventory | Implemented |
| A.8.26 | Application security | SDL (STRIDE), SAST/DAST/SCA/IaC, OWASP ASVS L2 target | Pipeline gate reports | Implemented |
| A.8.28 | Secure coding | Semgrep/CodeQL, SCA, IaC scan, 4-eyes PR, signed commits | CI logs, review records | Implemented |
| A.8.31 | Separation of environments | Dev/Staging/Prod isolated; no prod data in lower envs (synthetics only) | VPC/account map | Implemented |

Clauses 4–10: Context/Leadership/Planning/Support/Operation/Performance evaluation/Improvement addressed via ISMS policy, risk register, documented info, operational controls above, internal audit (audit module), and corrective actions (finding workflow).

---

## 8. NIST CSF 2.0 + SP 800-53 Rev. 5 Mapping

| CSF Function | Platform Implementation | Subcategories (representative) | SP 800-53 (key) |
|---|---|---|---|
| **GOVERN (GV)** | ISMS scope, roles, risk register (graph-data risks), supply-chain policy for collectors/deps | GV.OC-01, GV.RM-01, GV.RR-02, GV.SC-01/03 | PM-9, PM-30, SR-3 |
| **IDENTIFY (ID)** | AD/Entra assets as nodes, data-flow docs, NVD + ATT&CK enrichment, lessons learned | ID.AM-01/02/07, ID.RA-01/05, ID.IM-01 | CM-8, RA-3, RA-5, SI-2 |
| **PROTECT (PR)** | OIDC+MFA, ABAC least-priv, TLS1.3+AES-256, Vault secrets, IR plan exercises | PR.AA-01/03/05, PR.DS-01/02/05, PR.PS-01, PR.IR-01/03 | AC-2, AC-6, IA-2, SC-8, SC-13, SC-28 |
| **DETECT (DE)** | SIEM correlation, anomaly engine, log integrity, baselines, alert T&C | DE.CM-01/07/08/09, DE.AE-02/03/06 | AU-2, AU-6, AU-12, SI-4 |
| **RESPOND (RS)** | SOAR playbooks for new paths, severity, stakeholder comms, RCA, improvements | RS.MA-01/02, RS.AN-06/07, RS.CO-02 | IR-4, IR-5, IR-8, CP-9 |
| **RECOVER (RC)** | Multi-AZ HA, Neo4j PITR (RPO ≤ 15 min, RTO ≤ 1 h), cross-region WORM archives, DR game-days | RC.RP-01 | CP-9, CP-10, IR-4 |

---

## 9. OWASP Top 10 (2021) — Mitigations

| OWASP ID | Risk | Attack Scenario | Engineered Mitigation | Residual |
|---|---|---|---|---|
| A01 | Broken Access Control | Cross-tenant graph queries; low-priv user fetches Tier-0 paths | Server-side ABAC (OPA) on every query, persisted GraphQL + field auth, Postgres RLS, deny-by-default, authz tests in CI | Low |
| A02 | Cryptographic Failures | Topology intercepted in transit/stolen from backup | TLS 1.3 only (HSTS preload), AES-256-GCM at rest, KMS rotating keys, no PII in logs, TLS scan | Low |
| A03 | Injection | Cypher injection via search; XSS in report templates | Parameterized Cypher builders only, allow-listed persisted queries, template auto-escaping, CSP, gateway validation | Low |
| A04 | Insecure Design | Unbounded path computation → DoS; export without approval | STRIDE per feature, query cost/time budgets, 4-eyes approval (high+), rate limits, business-logic abuse tests | Low–Med |
| A05 | Security Misconfig | Default creds, exposed Bolt, debug endpoints, verbose traces | IaC scanning (Checkov/tfsec), CIS-hardened images, Vault secrets, config attestation, error scrubbing | Low |
| A06 | Vulnerable Components | Outdated Three.js/React, vulnerable collector deps | Dependabot/Renovate + SCA gate (fail on critical), CycloneDX SBOM per build, cosign-signed images, 7-day critical CVE SLA | Low |
| A07 | Auth Failures | Credential stuffing, session hijack, missing MFA | WebAuthn preferred MFA, lockout + progressive delays, 15-min JWT + rotation with reuse detection, SameSite=Strict cookies, breached-password checks | Low |
| A08 | Software/Data Integrity | Tampered report PDF, poisoned collector upload, unsigned CI artifact | Ed25519-signed reports + verify page, upload hash + optional collector signature, cosign-signed images, GitOps 4-eyes, hash-chained audit ledger | Low |
| A09 | Logging/Monitoring Failures | Silent mass export unnoticed; missing who/what/when | Mandatory audit schema (actor/action/object + prev/next hash), SIEM alerts on export-volume anomaly, log-integrity monitor, alert T&C tests | Low |
| A10 | SSRF | Arbitrary URL fetch → cloud metadata (169.254.169.254) | Outbound allow-list, DNS-rebinding protection, no arbitrary URL fetch (fixed connector endpoints), egress proxy inspection, IMDSv2 + hop-limit | Low |

**Verification Cadence:** DAST + authenticated ZAP baseline per release, annual external pentest, continuous SAST/SCA/IaC gates, OWASP ASVS L2 checklist per milestone, bug-bounty for SaaS.

---

## 10. Reporting Subsystem

| Report Type | Purpose | Formats | Approval/Governance |
|---|---|---|---|
| Executive Risk Summary | Board-ready heatmaps/trends, top 5 paths | PDF (signed), HTML, CSV | Standard workflow; watermark by classification |
| Attack-Path Deep Dive | Full path sets with technique + remediation per hop | PDF/JSON/HTML/STIX 2.1 | Analyst author; high+ may require 4-eyes |
| Tier-0 Exposure Matrix | Who can reach Domain Admins/crown jewels | CSV/JSON/PDF | Scoped to role/ABAC |
| Compliance Evidence Pack | Control → artifact matrix (ISO/NIST/OWASP) | PDF/CSV/JSON | Auditor-friendly, read-only scope |
| Delta/Drift Report | New risky edges since last collection | PDF/CSV/JSON | Event-triggered (auto) |
| Audit Trail Report | User actions, logins, exports over time | CSV/JSON/PDF (signed) | Immutable scope; read-only |

**Delivery:** Cron/event-driven/on-demand → email/portal/S3 presigned/REST/SOAR. Every artifact Ed25519-signed; public `/verify` validates SHA-256 + signature. Report record (Postgres, RLS) stores graph_version hash, author/approver, classification, artifact hash/sig, retention_until, and audit_ref.

---

## 11. Audit & Assurance Subsystem

### 11.1 What is Audited (100% Coverage)
Logins/MFA/lockout/logout, every graph query (actor/object IDs/scope), path compute/exports/reports, ingest uploads (content hash/collector/schema), policy changes, role grants/revocations, admin/break-glass, config/key rotation, retention purges.

### 11.2 Event Schema
Canonical fields: `event_id, ts, actor, role, action, object_type, object_id, tenant, ip, ua, mfa, prev_hash, hash, meta`  
Hash: `hash(prev_hash || canonical_payload)` (SHA-256). Append-only DB triggers reject UPDATE/DELETE.

### 11.3 Integrity & Evidence
- **Append-only ledger:** Tamper-evident chain per event.
- **Nightly chain-verify:** Recomputes full chain + Merkle root anchor; any break raises P1 alert.
- **SIEM streaming:** CEF/JSON over TLS for real-time correlation.
- **WORM archive:** S3 Object Lock for cold storage (ISO A.5.33).
- **Retention:** 12 mo online / 24 mo archive / 7 y for security events (immutable throughout).
- **Auditor role:** Read-only immutable view; chain export requires 4-eyes.

**Report Integrity Chain (Key Point):** Report artifact (SHA-256 + Ed25519 signature) is referenced by an audit event whose hash is chained into the ledger — tampered report breaks the chain; erased chain fails verification; both are SIEM-alerted. This provides court-ready, audit-gradable evidence.

---

## 12. Deployment, Resilience & DR

### 12.1 Topology
- **Ingress:** CDN + WAF → Envoy/Nginx gateway → Keycloak (OIDC/MFA)
- **Application:** Kubernetes (EKS/AKS/GKE), HPA (3–12), mesh mTLS, sidecar OPA, headless Chrome pool for reports, append-only audit writers
- **Data:** Neo4j Causal Cluster (3 cores + 2 read replicas), PostgreSQL HA (primary + 2 sync), Redis Sentinel, OpenSearch/SIEM, Prometheus/Grafana, S3 Object Lock (WORM)
- **DR:** Cross-region passive standby; **RPO ≤ 15 min** (continuous PITR), **RTO ≤ 1 h**, annual DR game-days, WORM archives cross-region replicated

### 12.2 DevSecOps (GitOps)
Git as source of truth: cosign-signed container images, signed OCI Helm charts, ArgoCD sync with auto-rollback on canary failure. Security gates: SAST (Semgrep/CodeQL), SCA, IaC (Checkov/tfsec), container scan (Trivy), DAST baseline (ZAP), SBOM (CycloneDX) per build, 4-eyes PRs, signed commits.

### 12.3 Backups & Integrity
Automated nightly restore drills, pre/post encryption checks, verified integrity hashes for every backup, PITR for graph/relational stores.

---

## 13. Technology Stack

| Layer | Primary | Alternatives | Rationale |
|---|---|---|---|
| 3D Frontend | TypeScript, React 18, Three.js + R3F, d3-force-3d, zustand, Vite | Babylon.js, Cytoscape.js (2D) | WebGL maturity, instancing, composability |
| Backend | NestJS (TS) monorepo, gRPC internal | Go (services), FastAPI (Python) | Real-time WS + shared TS types |
| Graph Store | Neo4j 5 (GDS for path algorithms) | Memgraph, TigerGraph | BloodHound-native Cypher, plugin ecosystem |
| Relational | PostgreSQL 16 | MySQL 8 | RLS, append-only triggers, JSONB |
| Cache/Queue | Redis 7 + Sentinel + Streams | RabbitMQ, Valkey | Low-latency cache + job queues |
| Identity | Keycloak 24 (OIDC, WebAuthn passkeys) | Entra ID, Auth0, Okta | Self-hosted sovereignty, MFA-first |
| Policy | Open Policy Agent (Rego) | Cerbos, Oso | ABAC centralized, fast sidecar |
| Observability | Prometheus, Grafana, OpenTelemetry, OpenSearch | Datadog, ELK | Open standards |
| Security Tools | ZAP, Semgrep, Snyk, Trivy, Checkov, cosign, Vault, Falco | Burp, SonarQube, Prisma/Prisma Cloud | Full SDLC + compliance coverage |
| Deployment | Kubernetes, ArgoCD, Helm, Terraform | Docker Swarm, AWS Lambda | HA, GitOps, autoscaling |

---

## 14. Non-Functional Requirements (SLOs)

| Category | Requirement | Notes |
|---|---|---|
| **Performance** | API P95 < 120 ms; 60 FPS up to 250K nodes; path compute ≤ 2 s (100K graph); report PDF < 30 s | Bounded queries, worker layout, LOD |
| **Availability** | 99.95% monthly (≈22 min); RPO ≤ 15 min; RTO ≤ 1 h | Multi-AZ + cross-region standby |
| **Security** | TLS 1.3; AES-256 at rest; 100% audit coverage; annual pentest; zero critical CVEs at release | Defense-in-depth + SDLC gates |
| **Scalability** | Horizontal (K8s HPA); 50 GB/day ingestion; 10K concurrent analysts; multi-tenant isolation | RLS + tenant-scoped queries |
| **Compliance** | ISO 27001:2022 Annex A mapped; NIST CSF 2.0 aligned; OWASP Top 10 residual ≤ Low; OWASP ASVS L2 | Control→implementation→evidence traceable |
| **Auditability** | Hash-chained ledger, SIEM streaming, evidence bundles, P1 tamper alarms, 7-year retention (immutable) | Court/audit ready |

---

## 15. Implementation Roadmap (Suggested)

| Quarter | Deliverables |
|---|---|
| **Q3** | BloodHound CE data-endpoint parity + AzureHound 2.0 ingestion connectors; persisted GraphQL coverage; chain-verify job in prod; report signing + public verify |
| **Q4** | ML-based "likely next target" prediction (risk-weighted path suggestions); tenant self-service reporting; scheduled evidence packs for ISO audits |
| **Y2** | On-prem appliance mode (air-gapped) with offline compliance packs; FIPS 140-3 cryptographic module alignment path; SBOM attestation + VEX feeds |

---

## 16. Conclusion

PathSphere 3D delivers a visually compelling, security-first evolution of BloodHound for enterprise environments. The blueprint couples GPU-accelerated 3D exploration with rigorous controls: zero-trust authorization (OPA), parameterized graph access, hash-chained immutable audit, and cryptographically signed board-ready reports. With direct mappings to ISO/IEC 27001:2022, NIST CSF 2.0 + SP 800-53 Rev. 5, and OWASP Top 10 (2021), the solution is positioned to satisfy technical, operational, and audit requirements while dramatically reducing time-to-insight for defenders.

**Design Principle:** *"Everything is Evidence"* — every access, export, and administrative action is provably attributable, tamper-evident, and audit-ready by construction.

---

**Document End** — Companion HTML Blueprint: `architecture.html` (colorful, interactive, SVG-rich diagrams)