'use strict';
/**
 * frameworks.js — Framework alignment reference data for the Compliance view.
 *
 * Static, non-sensitive documentation content transcribed from
 * architecture.md §9–§18 so the GUI can render control ↔ code ↔ test mappings
 * without shipping markdown to the browser. No secrets, no PII.
 */

const META = {
  version: '1.0.0',
  name: 'WebXR Security Awareness Training Module',
  classification: 'Internal / Shared',
  alignment: [
    'ISO/IEC 27001:2022',
    'NIST CSF 2.0',
    'NIST SP 800-53 Rev.5',
    'NIST SP 800-207 (Zero Trust)',
    'OWASP Top 10:2021',
    'OWASP ASVS 4.0',
    'W3C WebXR Device API',
    'xAPI 1.0.3 / SCORM / LTI 1.3',
    'WCAG 2.2 AA',
    'GDPR / CCPA',
  ],
  principles: [
    { icon: '🌐', title: 'No-Install, Browser-Native', detail: 'W3C WebXR Device API — runs on Quest, Vive, HoloLens, desktop and mobile with zero app deployment.' },
    { icon: '🔐', title: 'Zero Trust by Design', detail: 'NIST SP 800-207 — every request authenticated, authorized and encrypted; no implicit network trust.' },
    { icon: '🏛️', title: 'Standards-First', detail: 'ISO 27001, NIST CSF, OWASP, SOC 2 and GDPR controls embedded in design, not bolted on.' },
    { icon: '🎓', title: 'Learning-Interoperable', detail: 'xAPI / SCORM / LTI — scores flow into any LMS or HR system.' },
    { icon: '♿', title: 'Inclusive', detail: 'WCAG 2.2 AA plus XR comfort and safety guardrails (XRSI baseline).' },
    { icon: '☁️', title: 'Cloud-Agnostic, Multi-Region', detail: 'Kubernetes-based, data-residency aware (EU / US / APAC).' },
  ],
  personas: [
    { icon: '🧑‍💻', name: 'Trainee / Employee', useCase: 'Take immersive modules, phishing sims, quizzes', access: 'Learner' },
    { icon: '👨‍🏫', name: 'Instructor / L&D', useCase: 'Author scenarios, assign curricula, view class progress', access: 'Author' },
    { icon: '🛡️', name: 'CISO / Security Admin', useCase: 'Campaigns, risk dashboards, audit exports', access: 'Admin' },
    { icon: '🔧', name: 'Platform SRE', useCase: 'Observability, deployments, incident response', access: 'Break-glass (PAM)' },
    { icon: '🏢', name: 'Tenant Admin', useCase: 'User mgmt, branding, policy config per customer', access: 'Tenant-scoped Admin' },
  ],
};

/** ISO/IEC 27001:2022 Annex A — key controls (architecture.md §9.1). */
const ISO27001 = [
  { id: 'A.5.15', title: 'Access control', requirement: 'Define and implement rules for physical and logical access', implementation: 'RBAC + ABAC via PDP, least-privilege service accounts', evidence: 'Policy repo, access review minutes' },
  { id: 'A.5.23', title: 'Cloud services security', requirement: 'Secure acquisition, use, management and exit', implementation: 'CSPM, landing-zone guardrails, shared-responsibility matrix', evidence: 'CSPM reports, DR docs' },
  { id: 'A.6.3', title: 'Awareness & training ⭐', requirement: 'Periodic security education for all staff', implementation: 'The product itself — campaigns, modules, xAPI evidence', evidence: 'Campaign reports, completion exports' },
  { id: 'A.8.2', title: 'Privileged access', requirement: 'Restrict and monitor privileged use', implementation: 'JIT PAM, 2-person break-glass, session recording', evidence: 'PAM logs' },
  { id: 'A.8.5', title: 'Secure authentication', requirement: 'Use secure authentication technology', implementation: 'FIDO2/passkeys for admins, AAL2 baseline', evidence: 'IdP config, policy export' },
  { id: 'A.8.9', title: 'Configuration management', requirement: 'Define and enforce configuration baselines', implementation: 'IaC (Terraform), CIS benchmarks, drift detection', evidence: 'Pipeline runs, drift alerts' },
  { id: 'A.8.12', title: 'Data leakage prevention', requirement: 'Apply DLP to systems and networks', implementation: 'Egress filters, PII tokenization, export watermarks', evidence: 'DLP policy, incident tickets' },
  { id: 'A.8.15', title: 'Logging', requirement: 'Produce, store and protect logs', implementation: 'Centralized OTel → SIEM, hash-chained, WORM', evidence: 'Log retention policy, integrity proofs' },
  { id: 'A.8.16', title: 'Monitoring activities', requirement: 'Detect anomalous behaviour', implementation: 'UEBA, ATT&CK detections, SLO alerts', evidence: 'SIEM dashboards, IR drills' },
  { id: 'A.8.24', title: 'Use of cryptography', requirement: 'Rules for effective crypto use', implementation: 'TLS 1.3, AES-256-GCM, HSM CMK, annual rotation', evidence: 'Crypto inventory, KMS audit' },
  { id: 'A.8.25–29', title: 'Secure development lifecycle', requirement: 'Secure SDLC across design to release', implementation: 'Threat modeling, SAST/DAST/SCA, peer review, signed builds', evidence: 'Review records, scan reports, SBOM' },
  { id: 'A.8.32', title: 'Change management', requirement: 'Controlled, documented changes', implementation: 'GitOps PR flow, CI gates, rollback plan', evidence: 'PR audit trail, CAB minutes' },
];

/** OWASP Top 10:2021 mitigation matrix (architecture.md §11). */
const OWASP = [
  { id: 'A01', risk: 'Broken Access Control', threat: 'Cross-tenant data access; admin API abuse', mitigations: 'Central PDP (deny-by-default), object-level authz, tenant-scoped claims, no client-trusted IDs', verifiedBy: 'DAST authz suite, unit authz tests, pentest' },
  { id: 'A02', risk: 'Cryptographic Failures', threat: 'Weak TLS, exposed PII', mitigations: 'TLS 1.3 only (HSTS preload), AES-256-GCM at rest, field-level encryption, KMS CMK + rotation, no custom crypto', verifiedBy: 'TLS scan (SSL Labs A+), KMS audit trail' },
  { id: 'A03', risk: 'Injection (SQL/NoSQL/XSS)', threat: 'Scenario DSL injection, DOM-XSS in XR app', mitigations: 'Parameterized access, schema-first validation, CSP without unsafe-eval, Trusted Types, output encoding', verifiedBy: 'SAST + DAST, CSP report-only telemetry' },
  { id: 'A04', risk: 'Insecure Design', threat: 'Missing tenant isolation; spoofed scoring', mitigations: 'Threat modeling per epic (STRIDE), ASVS L2 design review, rate-limited submission with server-side recomputation', verifiedBy: 'Design review sign-off, game-theory testing' },
  { id: 'A05', risk: 'Security Misconfiguration', threat: 'Open buckets, debug endpoints, permissive CORS', mitigations: 'IaC-only infra, CIS benchmarks, automated config scanning, secure defaults, strict CORS allowlist', verifiedBy: 'CSPM, tfsec/Checkov, config drift alerts' },
  { id: 'A06', risk: 'Vulnerable & Outdated Components', threat: 'Compromised npm/three.js packages', mitigations: 'SCA blocking gates, SBOM (CycloneDX) per build, pinned digests, private proxy registry, 7-day critical patch SLA', verifiedBy: 'CI gate failures → zero known criticals' },
  { id: 'A07', risk: 'Identification & Auth Failures', threat: 'Credential stuffing on learner portals', mitigations: 'Federated SSO (no local passwords), FIDO2 for admins, breached-password checks, rate limiting + progressive delays, MFA', verifiedBy: 'Load+abuse test, IdP signal dashboards' },
  { id: 'A08', risk: 'Software & Data Integrity Failures', threat: 'Tampered scenario bundles; CI compromise', mitigations: 'Sigstore-signed artifacts, SRI on all assets, scenario-bundle signature verification in client, SLSA L3 provenance, GitOps enforced', verifiedBy: 'cosign verify in admission webhook' },
  { id: 'A09', risk: 'Security Logging & Monitoring Failures', threat: 'Silent breach; missing evidence', mitigations: 'Structured logs → SIEM, hash-chained immutable audit log, alert on authz anomalies, quarterly log-review KPI', verifiedBy: 'Purple-team exercise, MTTR metrics' },
  { id: 'A10', risk: 'SSRF', threat: 'Metadata-service attacks via asset fetcher', mitigations: 'Egress proxy allowlist, IMDSv2 enforced, URL validation (no private CIDRs), DNS rebinding protection', verifiedBy: 'Egress test suite' },
];

/** NIST CSF 2.0 six functions (architecture.md §10.1). */
const NIST_CSF = [
  { fn: 'GV', name: 'Govern', subcategories: 'GV.OC, GV.RM, GV.SC', controls: 'ISMS governance · risk appetite · supply-chain policy · C-SCRM' },
  { fn: 'ID', name: 'Identify', subcategories: 'ID.AM-1..7, ID.RA', controls: 'Asset & data inventory · risk register · vendor tiers' },
  { fn: 'PR', name: 'Protect', subcategories: 'PR.AA, PR.DS, PR.PS, PR.IR', controls: 'MFA/passkeys · encryption · secure SDLC gates · training' },
  { fn: 'DE', name: 'Detect', subcategories: 'DE.CM, DE.AE', controls: 'SIEM correlation · UEBA · CSPM drift · synthetic probes' },
  { fn: 'RS', name: 'Respond', subcategories: 'RS.MA, RS.AN, RS.CO', controls: 'IR playbooks · comms plan · forensics-ready logging' },
  { fn: 'RC', name: 'Recover', subcategories: 'RC.RP, RC.CO', controls: 'RTO 4h / RPO 15min · cross-region failover · lessons learned' },
];

/** NIST SP 800-53 Rev.5 selected families (architecture.md §10.2). */
const NIST_800_53 = [
  { family: 'AC — Access Control', controls: 'AC-2 account mgmt · AC-3 enforced authz · AC-6 least privilege · AC-17 remote access' },
  { family: 'AU — Audit', controls: 'AU-2 events · AU-6 review · AU-9 protection · AU-11 retention (400d)' },
  { family: 'CA — Assessment', controls: 'CA-2 assessments · CA-7 continuous monitoring · CA-8 pen test' },
  { family: 'CM — Configuration', controls: 'CM-2 baselines (CIS) · CM-6 config settings (IaC) · CM-8 inventory (SBOM)' },
  { family: 'IA — Identification & Auth', controls: 'IA-2 MFA · IA-5 authenticator mgmt · IA-9 service identity (SPIFFE)' },
  { family: 'IR — Incident Response', controls: 'IR-4 handling · IR-6 reporting · IR-8 IR plan (tested semi-annually)' },
  { family: 'SA — System Acquisition', controls: 'SA-11 developer testing (SAST/DAST) · SA-12 supply chain (SLSA, SBOM)' },
  { family: 'SC — System & Comms Protection', controls: 'SC-7 boundary protection · SC-8 transmission integrity · SC-13 crypto · SC-28 protection at rest' },
  { family: 'SI — System Integrity', controls: 'SI-2 flaw remediation (SLA) · SI-4 monitoring · SI-7 software integrity · SI-10 input validation' },
];

/** Zero Trust tenets (architecture.md §10.3). */
const ZERO_TRUST = [
  { tenet: 'All data sources & computing services are resources', impl: 'Asset catalog; every endpoint/API is a named resource with policy' },
  { tenet: 'All communication secured regardless of network location', impl: 'mTLS everywhere (mesh), TLS 1.3 externally, no flat network' },
  { tenet: 'Per-session access granted', impl: 'Short-lived tokens, per-request PDP decisions, no standing privileges' },
  { tenet: 'Dynamic policy (identity + device + behaviour)', impl: 'OPA/Cedar rules consuming IdP signals, EDR posture, risk score' },
  { tenet: 'Continuous monitoring of integrity', impl: 'Image signing, drift detection, runtime security (Falco)' },
  { tenet: 'Dynamic authN/authZ before access', impl: 'Risk-based step-up MFA, conditional access patterns' },
];

/** Industry standards matrix (architecture.md §12.1). */
const STANDARDS = [
  { domain: 'XR Platform', standard: 'W3C WebXR Device API 1.0', compliance: 'Standards-based session / immersive-vr / immersive-ar with feature-detect fallbacks (no vendor lock-in)' },
  { domain: 'Authentication', standard: 'W3C WebAuthn L3 / FIDO2', compliance: 'Phishing-resistant admin auth; passkeys supported' },
  { domain: 'Accessibility', standard: 'WCAG 2.2 AA · EN 301 549 · Section 508', compliance: 'Non-VR fallback UI, captions in-VR, keyboard-only admin, contrast tokens, motion-reduction mode' },
  { domain: 'XR Safety', standard: 'XRSI Baseline Recommendations', compliance: 'Comfort settings, session duration nudges, photophobia-safe brightness, no surprise locomotion' },
  { domain: 'Learning Records', standard: 'ADL xAPI 1.0.3', compliance: 'Native LRS; signed statements; SCORM 1.2/2004 adapter for legacy LMS' },
  { domain: 'LMS Interop', standard: 'IMS Global LTI 1.3 / Advantage', compliance: 'Deep-link launch, Names & Roles, Assignment & Grade Services' },
  { domain: 'Secure SDLC', standard: 'NIST SSDF (SP 800-218) · SLSA L3', compliance: 'Provenance-attested builds; SSDF attestation for regulated customers' },
  { domain: 'Cloud Security', standard: 'CSA CCM v4 · ISO 27017/27018', compliance: 'Control mapping in GRC tool; STAR registry entry at Level 2 target' },
  { domain: 'Config Hardening', standard: 'CIS Benchmarks v8', compliance: 'Bench-config as IaC + automated audit (kube-bench)' },
  { domain: 'Threat Modeling', standard: 'STRIDE + MITRE ATT&CK', compliance: 'Per-service TM docs; detections tagged with ATT&CK techniques' },
  { domain: 'Privacy', standard: 'GDPR · UK GDPR · CCPA/CPRA · LGPD · PIPL · DPDP', compliance: 'Data-residency pinning per tenant region; RoPA; DPIA for telemetry; consent-gated analytics' },
  { domain: 'Audit Assurance', standard: 'SOC 2 Type II', compliance: 'Continuous control monitoring; annual audit' },
];

/** Threat model (architecture.md §15). */
const THREATS = [
  { stride: 'Spoofing', scenario: 'Stolen session cookie replays learner identity', component: 'Identity Svc, Gateway', attack: 'T1539 Steal Web Session', countermeasure: 'Short-lived tokens, device binding, anomaly step-up MFA', residual: 'Low' },
  { stride: 'Spoofing', scenario: 'Deepfake voice in vishing sim trains users — attacker abuses same UX', component: 'VR Module', attack: 'T1621 MFA req. gen.', countermeasure: 'Sim content clearly watermarked; rate-limited outbound sims with SPF/DKIM/DMARC markers', residual: 'Low' },
  { stride: 'Tampering', scenario: 'Malicious glTF/JS asset swap on CDN', component: 'CDN, XR client', attack: 'T1195 Supply Chain', countermeasure: 'Signed bundles + SRI, cosign admission, immutable CDN cache', residual: 'Low' },
  { stride: 'Repudiation', scenario: 'Admin denies modifying campaign results', component: 'Campaign Svc', attack: 'T1070 Indicator Removal', countermeasure: 'Hash-chained WORM audit log, 2-person rule for destructive ops', residual: 'Low' },
  { stride: 'Info Disclosure', scenario: 'Cross-tenant read via IDOR on /sessions/{id}', component: 'Progress API', attack: 'T1087 Account Discovery', countermeasure: 'Object-level authz checks + RLS + fuzzed authz tests', residual: 'Medium → tracked' },
  { stride: 'Info Disclosure', scenario: 'XR telemetry leaks gaze data → inferences', component: 'Telemetry Svc', attack: 'T1005 Data from Local System', countermeasure: 'Opt-in consent, k-anonymity (k≥20), no raw biometrics, DPIA', residual: 'Medium → consent UX' },
  { stride: 'Denial of Service', scenario: 'Bot flood on gateway during campaign deadlines', component: 'Edge', attack: 'T1498 Network DoS', countermeasure: 'Anycast DDoS scrubbing, per-tenant rate limits, queue-based campaign dispatch', residual: 'Low' },
  { stride: 'Elevation of Privilege', scenario: 'Compromised pod → cluster admin', component: 'Kubernetes', attack: 'T1610 Deploy Container', countermeasure: 'Default-deny NetworkPolicy, non-root distroless, JIT PAM, no metadata access', residual: 'Low' },
  { stride: 'Elevation of Privilege', scenario: 'Malicious npm package steals build secrets', component: 'CI/CD', attack: 'T1195.002', countermeasure: 'SCA gate, ephemeral runners, OIDC-scoped cloud creds, secretless builds', residual: 'Medium → SLSA L3' },
];

/** Success metrics (architecture.md §18). */
const KPIS = [
  { category: 'Learning', kpi: 'Phishing simulation click rate', target: '↓ 60% in 12 months', icon: '🎯' },
  { category: 'Learning', kpi: 'Time-to-report suspicious events', target: '↓ 50%', icon: '⏱️' },
  { category: 'Engagement', kpi: 'Module completion rate', target: '≥ 85%', icon: '🥽' },
  { category: 'Engagement', kpi: 'Voluntary repeat sessions', target: '≥ 30%', icon: '🔁' },
  { category: 'Security', kpi: 'Critical vulnerabilities older than 7d', target: '0', icon: '🔐' },
  { category: 'Security', kpi: 'MTTR security incidents', target: '< 24h', icon: '⏳' },
  { category: 'Accessibility', kpi: 'WCAG 2.2 AA conformance', target: '100% admin + learner fallback', icon: '♿' },
  { category: 'Compliance', kpi: 'SOC 2 / ISO audit findings', target: '0 major non-conformities', icon: '🏛️' },
  { category: 'Reliability', kpi: 'Platform availability (SLO)', target: '99.9% monthly', icon: '☁️' },
  { category: 'Efficiency', kpi: 'Cost per trained employee', target: '↓ vs classroom baseline', icon: '💰' },
];

/** Compliance roadmap (architecture.md §17). */
const ROADMAP = [
  { phase: 'Phase 1', window: 'Mo 0–6', title: 'ISMS scope & policies', items: ['ISMS charter', 'Risk register', 'DPIA for XR telemetry', 'Threat models', 'SDLC gates'], tone: 'red' },
  { phase: 'Phase 2', window: 'Mo 6–12', title: 'Audit readiness', items: ['ISO 27001 Stage 1+2 audit', 'SOC 2 Type I → II', 'CIS benchmark attestation'], tone: 'orange' },
  { phase: 'Phase 3', window: 'Mo 12–24', title: 'Certification', items: ['ISO 27001 certification', 'SOC 2 Type II report', 'GDPR/DPDP audits', 'VPAT / WCAG'], tone: 'yellow' },
  { phase: 'Phase 4', window: 'Mo 24+', title: 'Expanded assurance', items: ['CSA STAR Level 2', 'FedRAMP Moderate track', 'HIPAA BAA offering'], tone: 'green' },
  { phase: 'Continuous', window: 'Annual+', title: 'Surveillance', items: ['Annual pen test', 'Surveillance audits', 'Control drift monitoring', 'Management review'], tone: 'blue' },
];

module.exports = {
  META,
  ISO27001,
  OWASP,
  NIST_CSF,
  NIST_800_53,
  ZERO_TRUST,
  STANDARDS,
  THREATS,
  KPIS,
  ROADMAP,
};
