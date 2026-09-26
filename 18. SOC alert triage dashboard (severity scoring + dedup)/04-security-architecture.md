# 04 — Security Architecture (Secure by Design)

Status: Approved v1.0 · Owner: Security Architecture · Review cadence: quarterly

---

## 1. Secure-by-design principles (binding)

1. **No trust on ingress** — every request authenticated (human: OIDC + phishing-resistant MFA; service: mTLS/SPIFFE + audience-bound tokens), authorized (RBAC+ABAC), and tenant-scoped at the data layer (RLS) regardless of upstream checks.
2. **Non-destructive by default** — dedup hides, never deletes; dispositions and scores are append-only; "split" restores visibility. Alert loss requires an explicit, dual-authorized, audited purge operation.
3. **Explainability as a security control** — deterministic scores with persisted factor breakdowns make tampering detectable (nightly reproducibility checks double as an integrity control).
4. **Fail-safe defaults, explicit failure modes** — every component's fail-open/fail-closed mode is a documented, tested decision (overview §10.1, ADR-001). Audit is fail-closed.
5. **Economy of mechanism** — one normalization schema (OCSF), one rules language (Rego), one identity fabric; no parallel half-implementations.
6. **Secure the security tool** — the SOC platform is itself a high-value target; it is monitored by the same class of detections it hosts, with a dedicated detections-as-code pack and a named owner.

## 2. Trust boundaries & threats they contain

| # | Boundary | Crossed by | Contained threats |
|---|---|---|---|
| B1 | Internet/enterprise → Edge (WAF, API GW) | analyst browsers, partner webhooks | unauthenticated access, L7 DoS, injection at edge |
| B2 | Edge → Internal services (mesh) | authenticated requests | token replay/lateral movement (mTLS + SPIFFE, audience binding) |
| B3 | Telemetry producers → Collectors | source telemetry | spoofed telemetry, replay floods, malicious payloads (parser attacks) |
| B4 | Services → Data stores | queries | cross-tenant reads (RLS), SQL injection (parameterized only) |
| B5 | Triage plane → Downstream actions (SOAR/case mgmt/notifications) | action emissions | command-injection-into-playbooks, over-privileged automation |
| B6 | CI/CD → Runtime (signed bundles/images) | config, code, models | supply-chain tampering (A06/A08) |
| B7 | Browser → Dashboard | SPA traffic | XSS, clickjacking, CSRF on state-changing routes |

## 3. STRIDE threat model (per element, with mitigations — excerpt of top risks)

| ID | Element | Threat | Impact | Mitigation (control IDs → compliance docs) | Residual |
|---|---|---|---|---|---|
| T01 | Ingest API | Spoofed telemetry source floods queue (DoS) / injects crafted payloads | availability, integrity (false alerts) | mTLS B3, schema validation + parser hardening (fuzzed in CI), per-source rate limits, payload budget caps | Low |
| T02 | Dedup Redis | Attacker or bug poisons exact keys → mass mislinking | integrity of queue | keys tenant-prefixed + SETNX semantics, write scope only to dedup svc (ACL), kill switch (§ 07 runbook), DLQ replay | Low |
| T03 | Scoring rules | Malicious/erroneous rules commit → systematic mis-scoring (safety *and* integrity attack) | high | signed bundles pinned by hash (B6), 2-person rule, differential replay CI gate, nightly reproducibility check (drift = alarm) | Med (insider) |
| T04 | Dashboard SPA | Stored XSS via alert field rendering → analyst session theft | high | strict output encoding, CSP `default-src 'self'` no-inline no-eval, HTML/text-only rendering of free text, Trusted Types; SRI on all assets; dependency allowlist | Low |
| T05 | API | IDOR across tenants (change `tenant_id`/`alert_id`) | confidentiality breach | tenant from token only; RLS backstop; isolation test suite in CI (cross-tenant access must fail) | Low |
| T06 | Audit log | Attacker tampers/erases audit trail | compliance, forensics | WORM (Object Lock compliance mode), hash chain per tenant, real-time SIEM export, fail-closed mutations | Low |
| T07 | Feedback webhook | Replay of stolen feedback HMAC → poison labels | model integrity | timestamp + nonce + replay cache, sender allowlist, schema validation, quarantined (not auto-applied) label changes | Low |
| T08 | Insider | Analyst mass-closes alerts / exfiltrates queue | availability/integrity, confidentiality | ABAC band restrictions, bulk-action rate limits + dual-authorization > 50 alerts/hr, query export watermarking, UEBA on analyst behavior (secondary use of our own telemetry) | Med |
| T09 | ML layer | Adversarial feature manipulation to force band migration | integrity | monotonic constraints, ±10 pt cap, band-crossing forbidden, feature allowlist (no free-text features), anti-gaming server-side features only | Low |
| T10 | Enrichment | Malicious TI data (wrong verdicts) → systematic down/up-scoring | integrity | TI sources allowlisted, verdicts weighted by source reliability, human-visible provenance in explanation, kill switch per TI source | Med |
| T11 | Whole system | Data exfiltration via legit API (mass export) | confidentiality | export endpoints require `exporter` role + dual auth + watermark + rate limit; UEBA alerting on volume anomalies | Med |

STRIDE-per-element completion for all containers is maintained in the threat-model register (link placeholder for repo); the above is the top-risk excerpt reviewed quarterly.

## 4. OWASP Top 10 (2021) — control mapping

> Verification anchors: OWASP ASVS 4.0 chapter/section references in brackets. "Implemented at" cites the concrete component.

### A01:2021 – Broken Access Control
- Tenant scoping: `tenant_id` derived **only** from OIDC claims; request-supplied tenant ignored/rejected. [ASVS V4.1]
- RLS on all tenant tables as data-layer backstop; app role lacks bypass. [V4.2 support]
- Default deny: permission checked per endpoint via policy-as-code (OPA) middleware; new endpoints fail closed until explicitly entitled. [V4.1.2–4.1.3]
- Object-level checks: every `alert_id`/`case_id` access validated against tenant + ABAC (band, PII). [V4.1.1, 4.1.5]
- No direct object references exposed: opaque UUIDs + server-side authorization; no sequential ids in URLs. [V4.3]
- Admin separation: `platform.admin` separate from analyst roles; admin actions require step-up (WebAuthn) and are audited. [V4.1.10-ish]
- Rate limiting per tenant + per actor on mutations and exports; bulk operations dual-authorized. [V4.1.2 rate/throttle]
- Tests: CI isolation suite (cross-tenant must fail), IDOR fuzzing in DAST, ABAC matrix tests. [V4.1.5 verification]

### A02:2021 – Cryptographic Failures
- TLS 1.3 (1.2 minimum, modern ciphers only) everywhere: edge, mesh mTLS, DB, Kafka, Redis. [V9]
- At rest: AES-256-GCM volume + field-level encryption for `raw_original` and PII-flagged payloads; per-tenant DEKs, envelope-encrypted with KMS CMK. [V6.2, V6.3]
- Crypto-shredding for tenant deletion (DEK destruction). [V6.3]
- No custom crypto; algorithms allowlist (no ECB, no SHA1 for security, PBKDF2/Argon2id only for any derived secrets); key rotation ≤ 90 d automated; HSM-backed KMS. [V6.2]
- Internal secrets: external secrets operator, no secrets in env/files/Git; gitleaks in CI. [V6.4-ish support]
- HMAC signing (feedback webhooks) with per-sender keys stored in KMS. [V6.2 support]
- Audit chain uses SHA-256 chaining; signatures for rule bundles use Ed25519. [V6.2 support]

### A03:2021 – Injection
- SQL: parameterized queries only (sqlc/pgx bound params), zero string-built SQL; lint rule blocks raw query builders. [V5.3]
- NoSQL/JSONB: schema-validated documents (JSON Schema at normalizer + API), typed accessors; no dynamic field-name construction. [V5.3.3-ish]
- OS command: none in hot path; any admin tooling must use argv arrays (no shell interpolation); lint-enforced. [V5.2]
- Query/ORM injection into UI: free text rendered as text; no HTML sanitization hacks (no dangerous `innerHTML`); Trusted Types enforced. [V5.1.1, V5.3.1]
- Header/redirect injection: no user input in redirect targets; allowlisted redirects only. [V5.2.4-ish, V5.3.4]
- Log injection: structured JSON logs, newlines/control chars escaped, length caps. [V7.1-ish support]
- Rego/OPA: policies reviewed + fuzzed; policy inputs schema-validated. [V5 support]
- Defense-in-depth: WAF managed rules + per-endpoint payload budgets; DB users follow least privilege (RLS-enforced, no DDL rights at runtime). [V1 support]
- Verification: SAST, DAST, fuzzing of normalizer parsers (corpus from real telemetry), dependency scanning. [V14 support]

### A04:2021 – Insecure Design
- This document set: invariants (README §Non-negotiable), fail-mode matrix (01 §10.1), threat model (§3), ADRs for every irreversible decision.
- Dedup safety: precision-first thresholds, kill switches, shadow mode, canary, bounded aggregation (02 §5.4).
- Scoring governance: bands, monotonicity, ML caps, 2-person rule, reproducibility checks (02 §4.5).
- Threat-modeled workflows: alert lifecycle, feedback loop, config change (F1–F3) each mapped to abuse cases (§3).
- Scale abuse: bounded self-amplification of severity; queue floods degrade to documented modes, not collapse (01 §10).
- Design reviews gate: security architecture review is a merge requirement for new data flows; ADR required for new trust-boundary crossings.

### A05:2021 – Security Misconfiguration
- Hardened bases: distroless/minimal images, non-root, read-only rootfs, dropped capabilities, seccomp RuntimeDefault; Pod Security Standards `restricted`. [V14.1-ish]
- IaC only: Terraform + GitOps; manual console changes drift-detect alarms; no long-lived static keys (workload identity everywhere). [V14.2-ish]
- Default-deny network policies between all namespaces; explicit egress allowlist (deny-by-default egress). [V14.3-ish]
- Config scanning: Checkov/Conftest in CI (CIS benchmarks), TLS config automated checks, CSP report-only → enforced pipeline.
- Separated environments (dev/staging/prod) with prod-only data handling; staging uses masked replays. [V14.1.1-ish]
- Quarterly config review against CIS benchmark + evidence snapshot (see compliance docs).

### A06:2021 – Vulnerable & Outdated Components
- SBOM (CycloneDX) generated per build; provenance attested (SLSA level target 3). [V14.1.4-ish support]
- Dependency allowlist + automatic major-version triage; patch SLAs: critical 72 h, high 7 d, medium 30 d (exception register with compensating controls).
- Continuous scanning (SCA + image scanning + container runtime scanning); alert routing to platform.oncall, not email.
- EOL tracking for runtime/base images; pinned digests everywhere; Renovate with security grouping.
- Frontend: no third-party runtime JS; self-hosted assets with SRI (also mitigates supply-chain XSS).

### A07:2021 – Identification & Authentication Failures
- SSO via corporate IdP (OIDC), mandatory MFA for all; **WebAuthn/FIDO2 required** for privileged roles (admin, soc.lead, detection.eng, service config). [V2.1-ish, V2.5-ish]
- Session management: 12 h max lifetime, 30 min idle timeout for the dashboard, server-side session revocation list, re-auth on role escalation. [V3.3-ish]
- No password storage at all (no local accounts); break-glass accounts exist, vaulted, dual-control, alarm on use. [V2.5 support]
- Service auth: SPIFFE/mTLS, token TTL ≤ 1 h, audience-bound; no wildcard audiences. [V2.x service]
- Credential hygiene: gitleaks, HMAC key rotation ≤ 90 d, webhook replay protection (timestamp+nonce). [V2.2-ish]
- Anomaly detection on auth events (impossible travel for analysts, token misuse patterns) — the platform alerts on its own identity plane.

### A08:2021 – Software & Data Integrity Failures
- Signed commits (enforced), signed releases (Sigstore/cosign), image digest pinning, admission control verifies signatures + SLSA provenance before deploy. [V14.2-ish]
- Rule/model bundles: Ed25519-signed, hash-pinned in deployment; engines verify before load; unsigned/expired ⇒ fail-closed to last-good. [V1 support]
- CI/CD hardening: isolated runners per trust tier, OIDC-based short-lived cloud credentials (no static cloud keys in CI), protected branches + 2-person review, `pull_request_target` forbidden.
- Audit chain (SHA-256 per-entry chaining per tenant) + WORM storage; chain-verification job daily. [V6 support]
- Model artifacts: versioned, hash-locked, provenance recorded (training data window, features) — treated like code.
- Update security: signed manifest, staged rollout with health-gated auto-rollback.

### A09:2021 – Security Logging & Monitoring Failures
- Audit events: every state change (who/what/when/why/before/after), append-only, hash-chained, WORM, real-time SIEM export. [V7.1–V7.3-ish]
- Security telemetry: auth events, privilege changes, config changes, dedup/scoring overrides, export operations, webhook failures — shipped with detection pack ("secure the security tool").
- alerting: SLO burn alerts + security alerts route to on-call with defined triage SLAs (15 min critical).
- Log integrity: chain verification + WORM retention 400 days; clocks NTP-synced; log fields minimized (no payloads, no secrets).
- Protection of logs: separate credentials from app DB role; analysts cannot edit audit store (append-only + RLS); UEBA on analyst behavior (T08/T11).
- Monitoring of the monitoring: heartbeat alerts for pipeline gaps (missing audit chain blocks = alarm).

### A10:2021 – Server-Side Request Forgery (SSRF)
- SSRF surface is small but real: enrichment fetchers (TI, CMDB, IdP), webhook emitter, case-mgmt sync.
- Controls: egress via **proxy with allowlist** (deny-by-default), no user-supplied URLs ever fetched server-side; URL targets are configured, not parameterized by end users. [V9-ish/V12-ish — ASVS 12.6.1]
- Webhook targets: per-tenant registered endpoints, admin-configured only, validated against allowlist of schemes/ports; private/reserved IP ranges + metadata endpoints (169.254.169.254, link-local, ULA) blocked at proxy and via DNS-resolution pinning (re-resolution check before connect).
- Fetchers: response size caps, timeouts, no redirect following across zones, content-type allowlist, disabled file:// and non-HTTP schemes.
- Network: egress-namespace isolation — only the egress proxy namespace has external egress; service→service traffic can't reach it without entitlement.

## 5. Cryptographic & key management summary

| Aspect | Decision |
|---|---|
| Transport | TLS 1.3 preferred, 1.2 floor, HSTS preloaded, internal mesh mTLS (SPIFFE) |
| At rest | AES-256-GCM; field-level for sensitive fields; per-tenant DEK, KMS envelope |
| Signatures | Ed25519 (rule bundles, manifests), Sigstore for artifacts |
| Hashes | SHA-256 (audit chain, dedup keys, integrity checks) |
| Keys | HSM-backed KMS, rotation ≤ 90 d, separation of duties, dual-control for CMK policy changes |
| JWT | RS256/ES256 only, `kid` rotation ≤ 24 h cached, audience + exp + iat validated, no `none`/symmetric shared secrets |

## 6. Secure SDLC

- **Design**: security review gate for new flows; threat model delta per PR touching trust boundaries; ADRs.
- **Code**: mandatory review (CODEOWNERS incl. security owner for authz/crypto/parsers), SAST (Semgrep with custom rules incl. injection/IDOR patterns), secrets scanning, lint rules banning dangerous APIs.
- **Build**: hermetic builds, SBOM + provenance, signed images.
- **Test**: unit + property + isolation suite + DAST (authenticated scans weekly) + normalizer fuzzing (continuous) + chaos drills (fail-mode verification).
- **Deploy**: progressive (canary 1% → 10% → 100%) with SLO + score-distribution gates; admission control verifies signatures; emergency changes require post-hoc review within 24 h (audited).
- **Operate**: vuln SLAs (A06), quarterly access reviews, annual pentest + after every major release; bug bounty (scoped) for the dashboard surface.
- **Measure**: MR security review coverage, time-to-patch, DAST/fuzz findings burn-down, security training completion (role-based, incl. secure coding for engineers and analyst-privacy training).

## 7. Residual risk register (top items, reviewed quarterly)

| ID | Risk | Current treatment | Target |
|---|---|---|---|
| R1 | Insider misuse of triage power | ABAC + dual-auth + UEBA | Add client-side request signing for sensitive ops (roadmap) |
| R2 | TI poisoning | allowlist + reliability weighting | Multi-source verdict quorum (roadmap Q+2) |
| R3 | Supply chain of ML artifacts | versioning + hashes | Full SLSA 3 attestation for models (roadmap) |
| R4 | Long-tail parser attacks on normalizer | fuzzing + payload budgets | Formal grammar validation (exploratory) |
