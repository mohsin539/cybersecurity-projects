# SQL Injection Detection Tool - Comprehensive Architecture

**Tool type:** Defensive-oriented runtime sensor + active vulnerability identification tool that (a) detects SQL injection (SQLi) attacks in live traffic on a per-parameter basis, and (b) identifies application parameters that are actually vulnerable to SQLi - "flags vulnerable params."

**Compliance posture:** Designed, built, and operated to align with ISO/IEC 27001:2022, NIST SP 800-53 Rev.5 and CSF 2.0, OWASP Top 10 (2021), OWASP ASVS v4, and PCI DSS 4.0 (where applicable). The tool itself is validated against the same standards it enforces.

---

## 1. Executive Summary

The tool is a layered, inline-capable security sensor with two synergistic modes:

1. **Detection Mode (passive / IDS):** Inspects live HTTP/HTTPS traffic on a capture, proxy, or agent path; flags SQL injection attempts on a per-parameter basis; and triggers configured response actions (alert, block, quarantine, challenge).
2. **Identification Mode (active / DAST):** Probes approved target application parameters with a controlled, non-destructive payload set to determine which parameters are *actually vulnerable*, producing a prioritized remediation report for engineering teams.

Both modes feed a shared **Risk & Scoring Engine** and a **Correlation Engine**. Every decision is written to an immutable, tamper-evident audit trail suitable as compliance evidence.

The system is designed for low false-positive / low false-negative operation via **five independent detection layers** fused by a confidence-scoring model, with an analyst-in-the-loop tuning feedback mechanism.

---

## 2. Goals and Non-Goals

### 2.1 Goals
- Detect SQLi across all parameter sources (query string, form/JSON/XML bodies, headers, cookies, path segments) including known evasion techniques (encoding, case obfuscation, inline comments, stacked queries, hex blobs).
- Identify the exact parameter (e.g., `?id=`) that is vulnerable, per endpoint, database flavor, and injection type (error-, boolean-, time-, union-, out-of-band-based).
- Emit normalized findings with severity, confidence, evidence, and remediation guidance mapped to CWE-89 / OWASP A03.
- Operate with high precision/low noise via layered detection, baselines, and confidence fusion.
- Produce compliance-ready evidence: audit logs, dashboards, PII redaction, retention, and access controls.
- Align the tool's own SDLC and operations with ISO 27001 / NIST / OWASP / PCI control baselines.

### 2.2 Non-Goals
- Not a replacement for parameterized queries or proper code-level defenses (it is defense-in-depth).
- Not a general web application firewall (WAF): blocking hooks exist but interoperability with existing WAFs/SIEMs is the primary integration path.
- Not a static code analysis tool (SAST), though it emits guidance that maps to SAST findings and accepts baseline SCAs as context.

---

## 3. Governing Frameworks (Source of Truth)

| Framework | Role in this project | Primary alignment |
|---|---|---|
| **OWASP Top 10 (2021)** | Application security posture | A03 (Injection) is the core deliverable; data contributed toward A01, A05, A08, A09 |
| **OWASP ASVS v4.0** | Control-level requirements | V1 (architecture), V5 (validation), V7 (error handling), V8 (logging), V12 (files/resources) |
| **NIST CSF 2.0** | Organizational risk posture | Govern / Identify / Protect / Detect / Respond / Recover |
| **NIST SP 800-53 Rev.5** | System-level control catalog | AC, AT, AU, CA, CM, CP, IA, IR, RA, SA, SC, SI families |
| **ISO/IEC 27001:2022** | ISMS management system | Annex A Controls A.5-A.8 (esp. A.5.15, A.8.23, A.8.28, A.12.4, A.14.2, A.16.1) |
| **PCI DSS 4.0** | Payment card environments (when in scope) | Req. 4, 6.5/6.6, 10, 11, 12 |

A full control-to-implementation matrix appears in **Section 9**.

---

## 4. High-Level Architecture

```
   Traffic Sources                         SQLi DETECTION PLATFORM
                                           
 +----------------+        +----------+   +-----------+   +-----------------------+
 | Mirror/SPAN/TAP|------->|  INGEST  |-->| PARSE &   |-->| DETECTION ENGINE       |
 | (passive)      |        | ADAPTERS |   | NORMALIZE |   | (5 layers, see Sec 6)  |
 +----------------+        +----------+   +-----------+   +-----------+-----------+
 +----------------+           /|   \  \                     |           |
 | Inline Reverse |----------/ |    \  \                    |           |
 | Proxy (active) |             |     \  +--> BASELINES ----+           v
 +----------------+             |      \                 learning  +-----+------+
 +----------------+             |       \                store     | RISK &     |
 | App SDK Agent  |-------------+        \                         | SCORE/     |
 +----------------+                         v                     | FUSION     |
 +----------------+                 +--------------+              +-----+------+
 | SIEM / Logs    |---------------->| CORRELATION  |<-------------------+
 +----------------+                 | ENGINE       |
                                    +--------------+
                                             |
                                             v
                                    +-----------------------+
                                    | RESPONSE ORCHESTRATOR |
                                    | alert*block*quarantine|
                                    +-----------+-----------+
                                                |
                                     +----------+---------+
                                     | DATA & AUDIT LAYER |
                                     | findings, telemetry,|
                                     | redacted payloads   |
                                     +----------+---------+
                                                |
                                                v
                                     +-----------------------+
                                     | ACTIVE SCANNER (DAST) |
                                     | vulnerable param probe|
                                     +-----------------------+
```

### 4.1 Primary data flow
1. A request/response pair is observed or received by an **Ingest Adapter** (tap, inline proxy, SDK agent, log stream).
2. **Parse & Normalize** extracts named parameters, decodes all encoding layers, and produces a canonical `ParameterValue`.
3. **Detection Engine** scores each parameter value against five independent detectors.
4. **Risk & Score Engine** fuses detector outputs with baseline/context modifiers into a confidence + severity verdict.
5. **Response Orchestrator** executes the policy for that verdict (monitor -> flag -> block/quarantine/challenge/report).
6. **Active Scanner** separately tests candidate parameters on approved targets; results merge into the same findings store.
7. All events flow to **Data & Audit Layer** (compliance evidence, redaction-at-rest, retention).

### 4.2 Trust model
- The platform is deployed in a dedicated security segment with egress allow-listing (no unexpected outbound except configured SIEM/webhook and scanner's sandbox beacon domain).
- Ingest adapters are untrusted at the wire; everything arriving is treated as raw input and sanitized before use (defense against log-injection / stored-XSS in the console).
- The Management Console and APIs are separate from the data plane; scanner target changes require privileged, 2-person approval.
---

## 5. Component Deep-Dive

### 5.1 Ingest Adapters (Ingress)
| Adapter | Mode | Notes |
|---|---|---|
| **Inline Reverse Proxy** | active inline | Terminates TLS with managed certs; the only mode that can enforce blocking inline. |
| **Mirror / SPAN / TAP** | passive | For HTTPS, uses pre-imported server private keys or a supported TLS termination/decryption appliance; log-only. |
| **Container / App SDK Agent** | passive hook | Captures parameters at the application boundary with lowest latency overhead; exposes *true application parameter names* rather than raw wire names. |
| **SIEM / Log Stream Ingest** | passive | Consumes proxy/API-gateway logs for offline analysis and correlation. |
| **API / CLI Ingest** | on-demand | Manual replay of captured requests for triage and rule tuning. |

Security controls per adapter: mutual TLS, allow-listing of sources, signed ingest tokens, and per-source rate limiting. Each adapter labels every request with a tamper-evident source identifier.

### 5.2 Parse & Normalize
Responsibilities:
- Parse HTTP/1.1, HTTP/2, and HTTP/3 (QUIC in proxy mode); stream large bodies to bounded buffers.
- Parameter sources: **query string**, **form body**, **JSON / XML / GraphQL**, **multipart**, **cookies**, **headers** (`Referer`, `User-Agent`, `X-Forwarded-For`, custom), and **path segments** (e.g., `/users/{id}`).
- Parameter extraction by name with **type inference** (int, string, UUID, email, date) using OpenAPI/schema hints where available and Active Scanner learning otherwise.
- **Deep normalization pipeline** (evasion defeat):
  - URL-decode (repeated up to N passes), HTML-entity unescape,
  - Hex blobs (`0x41`), unicode escapes (`%u0041`, `\u0041`), percent-encoding variants,
  - Null-byte and backslash handling,
  - Keyword/case folding, whitespace-variant normalization (tabs, newlines, `/**/`, `%20`),
  - Charset detection with a whitelist policy (only permitted charsets are decoded).
- **Redaction hook:** before persistence or onward analysis, PII/sensitive substrings are replaced with tagged digests (Section 8.5).
- Output: canonical `ParameterValue` objects; raw wire copy is never persisted.

### 5.3 Risk & Score Engine (Fusion)
- Each detector emits `(rule_id, weight, confidence, evidence)` per parameter value.
- Overall score = weighted combination of detector confidences, then adjusted by **contextual modifiers**:
  - Baseline deviation (value shape deviates from the learned per-parameter baseline),
  - Correlated session behavior (failed logins + injection probes; multi-stage kill-chain),
  - Target criticality (asset classification feed),
  - Source reputation (IP/ASN/geo reputation feed, configurable).
- Output verdict tiers: `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.
- **Precision controls:** configurable thresholds per deployment; a suppression/learning list for known-benign traffic; analyst dispositions feed model retraining (human-in-the-loop).
- Guardrail: ML layer output is **one fused input, never the sole decision-maker**.

### 5.4 Response Orchestrator
Policy-driven actions (per verdict tier, per target scope):
- **Monitor / Flag** (default posture): tag the parameter and raise a finding.
- **Alert**: webhook, email, SIEM export (CEF/LEEF), SOAR playbook trigger.
- **Block / Reset**: inline-proxy mode only; optionally injects `X-SQLi-Detect: 1.0` headers for application awareness.
- **Challenge / Throttle**: CAPTCHA or rate-limit the offending session/IP.
- **Report / Ticket**: auto-file to engineering backlog for confirmed vulnerable parameters.

All actions roll out in stages `dry-run -> shadow-mode -> enforce` by default; direct enforcement requires an approved change (change-management compliant).

### 5.5 Active Scanner (Vulnerable-Parameter Identification) - the "flags vulnerable params" half
Workflow:
1. **Scope approval gate:** targets must be registered and risk-accepted; staging/QA preferred over production.
2. **Parameter enumeration:** learn parameter names/types from traffic baselines and OpenAPI hints.
3. **Risk-ranked payload selection** from a curated, versioned corpus:
   - error-based (unbalanced quotes, DB error triggers),
   - boolean-based (tautologies `1=1`, contradictions `1=2`, `'a'='a'`),
   - union-based (`UNION SELECT NULL,...` / column-count discovery),
   - time-based blind (`SLEEP(n)`, `BENCHMARK()`, `WAITFOR DELAY '...'`, `pg_sleep`),
   - stacked queries (`;`), out-of-band (DNS/HTTP callback to a sandboxed beacon domain).
4. **Response differential analysis:** baselined vs. injected responses (5xx/DB error strings, response-time delta, page-content diff, OOB beacon hits).
5. **Inference:** confirms vulnerability, DB flavor, injection context (string/int/order-by), and entry point type.
6. **Evidence packaging:** minimal replay payload, sanitized response signature, CWE-89 / OWASP A03 mapping, and remediation guidance (parameterization, escaping, allow-lists).
7. **Safety controls:** global and per-target rate limits, canary queue, staging-first, auto-pause if anomaly thresholds are exceeded (zero DoS effect).

Output: **Vulnerable Parameter Report** per endpoint with priority score = f(severity, reachability, asset criticality, exploitability).

### 5.6 Management Console & APIs
- REST/GraphQL API (OpenAPI-specified, versioned): findings query, policy management, target registration, scanner job control, analyst dispositions, report generation.
- RBAC roles (least-privilege): `viewer`, `analyst`, `operator`, `scanner-admin`, `admin`, `auditor` (read-only + tamper-evident access).
- Dashboards: live alert queue, vulnerable-parameter heatmap by endpoint, detection coverage, detector precision/recall (ROC/PR), compliance report pack.
- All console access requires SSO + MFA; sensitive actions (target approval, policy change to `enforce`, key rotation) require a second approver.

### 5.7 Data & Audit Layer
- Immutable **hash-chained audit log** (each event links to the previous hash) exported in SIEM-friendly format (CEF/JSON).
- **Retention policies** per data class (and GDPR/PCI where applicable): raw findings, digests, audit, reports.
- **Backup + restore** tested on a schedule; encryption at rest and in transit (Section 8.2);
- Monitoring/alerting on storage health, quota, and retention-drain jobs.
---

## 6. Detection Methodologies (Five Layers)

Detectors run independently and are fused by the scoring engine. Layering ensures that evading any single technique still raises signal at other layers.

### 6.1 Layer 1 - Signature / Rule Engine
- Curated, versioned regex corpus (OWASP Core Rule Set-derived plus project-maintained):
  - Tautologies (`1=1`, `1=2`, `'a'='a'`) and `OR`/`AND` chains,
  - `UNION [ALL] SELECT`, `ORDER BY n`, `LIMIT`, `INTO OUTFILE`/`INTO DUMPFILE`,
  - comment markers `--`, `#`, `/* */`,
  - DB keywords: `information_schema`, `@@version`, `DB_NAME()`, `CONCAT()`, `CHAR()`, `CONVERT()`,
  - time/blind primitives: `SLEEP()`, `BENCHMARK()`, `WAITFOR DELAY`, `pg_sleep`,
  - stacked-query delimiters `;`,
  - error-trigger strings (unbalanced quotes/parens),
  - OOB primitives: `LOAD_FILE`, `xp_cmdshell`, `UTL_HTTP`, `sys_exec`.
- Rule metadata: id, DB flavor, injection type, baseline severity, CWE/OWASP mapping, false-positive risk, last-tuned date.
- Lifecycle: versioned rule packs, staged rollout (canary -> all), and a signature-bypass regression suite run in CI.

### 6.2 Layer 2 - Grammar / Tokenizer (SQL-aware)
- Feeds the normalized parameter value into a SQL lexical analyzer (e.g., `sqlparse`-style tokenizer) per DB dialect (MySQL, PostgreSQL, SQL Server, Oracle, SQLite).
- Flags values that lex into a *structurally valid* SQL fragment containing an injection-relevant operator/expression (`SELECT`, `UNION`, `WHERE`, `OR`, `AND`, functions, string literal untermination).
- Significantly reduces false positives for benign text containing words like "select" by requiring token validity + operator presence + structural shape.

### 6.3 Layer 3 - Heuristic Behavioral Detectors
- **Character-profile anomaly:** quote density, semicolon density, `0x` hex blobs, mixed-case encoded keywords, `%`/`_` LIKE metacharacters in unexpected parameters.
- **Type-contract violation:** a parameter baselined as `int` receiving a value containing SQL syntax is a strong signal.
- **Tautology/contradiction patterns:** `' OR 1=1 --`, `1=2` clauses (amplifies boolean-differential detection).
- **Error-based response signature:** DB error substrings in responses (`SQLSTATE`, `ORA-`, `mysql_`, `syntax error at or near`) indicate input reached SQL execution.
- **Obfuscation pyjamas:** `/**/`, `/*! ... */`, interleaved comments inside keywords.

### 6.4 Layer 4 - Machine Learning Classifier (optional, tunable)
- (a) Fast character/token-sequence classifier (gradient boosting on n-grams, or transformer-lite) trained on labeled payload + benign corpora; (b) anomaly scorer over the param-value distribution.
- Guardrails: calibrated thresholds, per-dataset retraining, drift monitoring, human-in-the-loop validation before promotion.
- Deployment: boards only on HIGH-signal parameter profiles; fused with other layers; operator can disable per-target.

### 6.5 Layer 5 - Correlation Engine
- Cross-request / session / IP correlation:
  - Sequential probing matching the **error -> boolean -> union -> time** kill-chain,
  - Response-time deltas indicating time-based blind probing,
  - OOB callback events (DNS/HTTP) matched to request IDs on the sandboxed beacon domain,
  - Cross-endpoint spray (same source, many endpoints, same crafted suffix).
- Produces multi-event findings with higher confidence than single-shot detections and suppresses low-value single hits for low-signal normals.

### 6.6 Evasion Coverage Matrix (enforced by CI tests)
| Evasion technique | Covered by |
|---|---|
| URL/percent encoding (double/triple) | Normalize + Layer 1 |
| Mixed case `SeLeCt` | Case folding + Layer 1 |
| Inline comments `sel/**/ect` | Normalize + Layer 2 |
| Whitespace substitution (`%09`, `%0A`, `/**/`) | Normalize |
| Hex blobs `0x41,CHAR(...)` | Normalize + Layer 1/2 |
| Unicode / UTF-7 / UTF-16 encodings | Charset whitelist + Normalize |
| Null bytes, backslash escapes | Normalize-strip + flag |
| Stacked queries `;` | Layer 1 + Layer 2 |
| Boolean/time differential | Layer 3 + Layer 5 |
| Out-of-band (DNS/HTTP callbacks) | Layer 5 sandbox beacon |

### 6.7 Alert rules examples
| Rule (illustrative) | Injection type | Tiers |
|---|---|---|
| `R-0042: wp-style rules` — `' OR 1=1 --` in any param | boolean | HIGH |
| `R-0087: union enumeration` — `ORDER BY 999--` then `UNION SELECT NULL...` | union combos | HIGH (correlated) |
| `R-0113: time-based blind` — `SLEEP(10)--` with response-time delta > threshold | time | HIGH |
| `R-0029: unterminated quote in int-typed param` | error-based | MEDIUM |
| `R-0160: OOB beacon match` for sandbox domain | OOB | CRITICAL |
---

## 7. Core Data Model

```
Asset         { id, fqdn, env(prod|staging|qa), criticality, owner, is_tls }
Target        { id, asset_id, endpoint, method, auth_level, state(approved|scanned|blacklist) }
Parameter     { id, target_id, name, source(query|body|header|cookie|path),
                inferred_type, baseline_ref, is_sensitive }
Request       { id, ts, adapter_src, method, uri, headers_hash, body_size, src_ip_hash }
ParamValue    { id, request_id, parameter_id, decoded_digest(sha256), encodings_seen, transient_raw }
Finding       { id, request_id, parameter_id, detector_ids[], fused_score, severity,
                verdict(MONITOR|FLAG|BLOCK|QUARANTINE), db_flavor, injection_type,
                evidence_ref, cwe(89), owasp(A03), disposition(pending|tp|fp|duplicate), ts }
VulnParam     { id, target_id, parameter_id, confirmed, db_flavor, context,
                payload_set_labels[], evidence_artifact_ref, remediation, priority_score, ts }
Policy        { id, verdict_to_action_map, scope, rollout_stage(dry_run|shadow|enforce), enabled, owner }
Baseline      { id, parameter_id, ts, stats, model_ref }
AuditEvent    { id, ts, actor, action, object, before, after, prev_hash, chained_hash }
```

Storage rules (compliance-critical):
- **Raw payload values are never persisted.** Only one-way digests (SHA-256 with per-deployment salt) for correlation and redacted blobs.
- Findings retain only approved evidence fragments; PII-bearing evidence requires elevated access and is encrypted separately.
- Retention, backup, and deletion schedules follow the Data Retention matrix (Section 8.6).

---

## 8. Security Architecture of the Tool Itself

The detection platform must *itself* meet the standards it enforces. These are codified controls, validated by the matrix in Section 9.

### 8.1 Identity & Access Management
- Central IdP (SAML/OIDC) SSO; no local password store.
- RBAC (least privilege): roles viewer / analyst / operator / scanner-admin / admin / auditor.
- MFA required for privileged roles; two-person rule for target approval, enforce-policy changes, and key rotation; break-glass accounts with immediate alert + audit.
- Unique per-service service-accounts with per-adapter signing identities; no shared credentials.

### 8.2 Encryption & Key Management
| Data state | Control |
|---|---|
| In transit | TLS 1.2+ (1.3 preferred), HSTS, cipher lock-down; mTLS between services, and to SIEM/webhooks |
| At rest | AES-256-GCM with KMS-managed keys, per-deployment CMK, key rotation <= 90 days, envelope encryption |
| Key management | HSM/KMS, separated key-administrator role, key-use audit logging, crypto-agility migration plan |
| Secrets | Vault-based, ephemeral, injected at runtime; never in code, config, or logs; rotating scanner beacon tokens |

### 8.3 Secure Development Lifecycle (SDLC)
- Threat modeling in design (STRIDE) for every component; abuse-case reviews.
- SAST (Semgrep/CodeQL) + SCA (dependency GHSA/OSV, pinned+locked) + container image scanning in CI; signed artifacts.
- Dependency & rule-pack signing; provenance used for supply-chain integrity.
- `secrets=0` gating: helm/k8s configs scanned for secrets before merge.
- Separate code environments (dev -> staging -> prod); prod deploys only from verified CI pipeline with change approval.

### 8.4 Logging, Monitoring & Incident Response
- Central logging (CloudWatch/ELK/Observability stack) with SIEM forwarding; NTP-synced timestamps; correlation IDs through the pipeline.
- IR playbooks: SQLi detection spike, scanner-behavior anomaly, OOB callback suspicion, secret-rotation incident, console compromise.
- Alerting thresholds and on-call escalation; evidence snapshots preserved per IR process.
- Quarterly tabletop exercises; post-incident reviews feeding detection improvements.

### 8.5 Privacy & Data Protection
- PII/sensitive parameter redaction at ingest; tagged digests only.
- Regional data residency option (deploy-in-region), EU-US data-transfer compliance where applicable.
- DPA/records-of-processing maintained with the ISMS artifact set.
- Right-to-delete / retention erasure jobs documented and executable on request.

### 8.6 Data Retention Matrix (summary)
| Data class | Retention | Disposal |
|---|---|---|
| Raw transient captures | Not stored | N/A |
| Parameter digests | 90 days | Secure delete + validate |
| Findings / Vulnerable Params | 2 years (or policy) | Secure delete + validate |
| Audit events | 2+ years / regulatory | Append-only tamper-evident |
| Scanner evidence artifacts | with parent finding | n/a + anonymize |
| Backups | per RPO/RTO plan | encrypted, aged out |
---

## 9. Compliance Implementation Matrix

> Mapping is control -> where the design satisfies it -> the artifact/evidence that demonstrates it. This document is the "architecture definition" artifact used in ISMS/SSDF/ASV audits.

### 9.1 ISO/IEC 27001:2022 (Annex A, selected)
| Annex A Control | Implementation | Evidence artifact |
|---|---|---|
| A.5.9 Inventory of information | Asset/Target model + data class inventory (Section 7, 8.6) | Data flow diagrams, asset register export |
| A.5.15 Access control | RBAC + SSO/MFA + two-person rule (8.1) | IAM policy, RBAC matrix |
| A.5.16 Identity management |= | Unique identities, per-service accounts | IdP integration config |
| A.5.17 Authentication info | No local passwords; Vault-based secrets (8.2) | Secrets architecture doc |
| A.5.18 Access rights | Role lifecycle reviews, 90-day recertification | Recertification runbook |
| A.5.21 Managing security in ICT supply chain | Signed artifacts, pinned dependencies, provenance (8.3) | SBOM, signing policy |
| A.5.24 / A.5.25 / A.5.27 Incident planning / learning / physical | IR runbooks, post-incident reviews, tabletop tests (8.4) | IR playbook set, exercises log |
| A.5.7 Threat intelligence | Rule packs + scanner payload corpora + reputational feeds (6.1, 5.5) | Threat-intel feeding procedure |
| A.8.2 Privileged access rights | scanner-admin/admin least privilege, MFA, audit | IAM policy |
| A.8.9 Configuration management | Versioned config, IaC, CM baseline, drift alerting | Terraform/K8s configs, CM plan |
| A.8.10 / A.8.11 Information deletion / Data masking | Retention matrix + PII redaction (8.5, 8.6) | Retention/erasure job config |
| A.8.16 Monitoring activities | Full telemetry + SIEM export (8.4) | Monitoring spec, SIEM connector |
| A.8.20/22/23 Network security / segregation / web filtering | Dedicated security segment, egress allow-list, sandbox beacon (4.2) | Network diagram, firewall rules |
| A.8.24 Use of cryptography | TLS 1.2+/AES-256-GCM/KMS rotation (8.2) | Crypto standard + key policy |
| A.8.25/26/27 Secure development / app security / secure architecture | SDL: threat modeling, SAST/SCA, signed deploys (8.3) | SSDF/SDL policy, pipeline config |
| A.8.28 Secure coding | Input validation, sanitization, no raw payload persistence | Coding standard, security tests |
| A.8.29 Security testing | Detection-layer CI tests, evasion suite, pen-test runs | Test reports |
| A.8.31 Separation of development/production | Segregated environments, gated promotion | Environment topology |

### 9.2 NIST SP 800-53 Rev.5 + CSF 2.0 (selected)
| Control (SP 800-53) | CSF 2.0 Function | Implementation |
|---|---|---|
| AC-2/AC-3/AC-6/AC-7 | PR.AA | Account mgmt, access enforcement, least privilege, failed-login throttle (8.1) |
| AU-2/3/6/9/11 | DE.AE | Audit events defined, hash-chained, reviewed, integrity-protected, retained (5.7) |
| CA-7 | DE.CM | Continuous monitoring of pipeline + detectors (8.4) |
| CM-6/CM-8 | PR.PS | Config baselines, component inventory (8.3) |
| IA-2/IA-5 | PR.AA | SSO identities, MFA, authenticator mgmt (8.1, 8.2) |
| IR-4/IR-6 | RS.RP/RS.CO/RS.AN | Incident handling & reporting playbooks (8.4) |
| RA-3/RA-5 | ID.RA | Risk assessment, vuln scanning (6.x) |
| SA-8 | GV.PO | Secure engineering (8.3) |
| SA-10 | PR.PS | Signed/config integrity, provenance (8.3) |
| SC-7 | PR.PT | Boundary protection (4.2) |
| SC-8 | PR.DS | Transmission confidentiality/integrity (8.2) |
| SC-12 | PR.DS | Cryptographic key management (8.2) |
| SC-28 | PR.DS | Protection at rest (8.2) |
| SI-3 | PR.PS | Malware protection on nodes (8.4) |
| SI-4 | DE.CM | System monitoring rules (8.4) |
| SI-7 | PR.DS | Software/file integrity (hash-chained audit, signed deploys) |
| SI-10 | PR.DS | Input validation across all ingest paths (5.2) |
| SI-11 | PR.DS | Error handling that does not leak internals (console, APIs) (6.3) |
| CP-2 | RC.RP | Contingency & recovery plan, tested restore (5.7) |

### 9.3 OWASP Top 10 (2021)
| OWASP | Addressed by |
|---|---|
| A01 Broken Access Control | RBAC, MFA, two-person approvals, per-record ACLs on evidence (8.1) |
| A02 Cryptographic Failures | TLS 1.2+/AES-256-GCM, HSM/KMS, crypto-agility (8.2) |
| A03 Injection | **Core product capability**: 5-layer detection + vulnerable-param identification (6, 5.5) |
| A04 Insecure Design | STRIDE threat modeling, abuse-case reviews, architecture review gate (8.3) |
| A05 Security Misconfiguration | CM-6 baselines, IaC, drift detection, hardening guides (8.3) |
| A06 Vulnerable & Outdated Components | SCA + pinning + SBOM + rolling dependency updates (8.3) |
| A07 Identification & Authentication Failures | IdP SSO, MFA, authN event logging (8.1, 8.4) |
| A08 Software & Data Integrity Failures | Signed artifacts + rule packs, hash-chained audit, provenance (8.3, 5.7) |
| A09 Logging & Monitoring Failures | Structured logging, SIEM forwarding, alerting, IR (8.4) |
| A10 SSRF | Scanner target allow-lists, webhook URL allow-lists, sandbox beacon egress policy (4.2, 5.5) |

### 9.4 PCI DSS 4.0 (when cardholder data is in scope)
| Requirement | How the tool supports compliance |
|---|---|
| Req. 4 | Encrypt transmission - TLS 1.2+ throughout (8.2) |
| Req. 6.5 | Secure coding + these architecture requirements (8.3) |
| Req. 6.6 | **Detect and prevent web-based attacks: the tool is a qualifying control** (5.3, 6.x) |
| Req. 10 | Logging of access to cardholder data posture: audit trail + SIEM (5.7, 8.4) |
| Req. 11 | ASV scans + pen tests incorporate Active Scanner results (5.5) |
| Req. 12 | Policy/ISMS alignment; A.5.x mapping above (9.1) |

### 9.5 NIST CSF 2.0 function summary
| Function | Capability in this design |
|---|---|
| Govern | Risk register, policies, supply-chain policy, RBAC governance (9.1 A.5.x) |
| Identify | Asset/target model, vulnerability identification (7, 5.5) |
| Protect | IAM, encryption, SDLC, config, training (8.x) |
| Detect | 5-layer detection engine, SI-4 monitoring, correlation (6, 5.3) |
| Respond | Verdicts/actions, IR playbooks, SOAR hooks (5.4, 8.4) |
| Recover | Backups, restore tests, contingency plan (5.7, CP-2) |
---

## 10. Threat Model (STRIDE summary)

| Threat | Surface | Mitigation |
|---|---|---|
| Spoofed ingest source / fake traffic | Ingest adapters | mTLS, signed ingest tokens, source allow-lists (5.1) |
| Tampering with findings / audit | DB, audit store | Hash-chained audit, DB ACLs, signed events (5.7) |
| Repudiation of analyst actions | Console/APIs | Audited actions, immutable logs (5.7) |
| Information disclosure (PII in payloads) | Storage, logs | Redaction-at-ingest, digests only, RBAC on evidence (8.5) |
| DoS via crafted traffic | Parse layer | Bounded buffers, streaming, rate limits, resource quotas (5.2) |
| Elevation of privilege | Console/API | RBAC + MFA + two-person rule (8.1) |
| Evasion of detection | Detection engine | 5 independent layers + evasion regression suite (6.x) |
| Scanner abuse (target flooding) | Active Scanner | Approval gate, rate limits, staging-first, canary (5.5) |
| Log injection / stored-XSS in console | Ingest data rendered | Output encoding; sanitize every ingested field (4.2) |
| Supply-chain / dependency compromise | Build pipeline | Pinning, SBOM, signing, provenance (8.3) |
| Secret leakage | Code/config/logs | Vault injection, secrets=0 CI gate, scans (8.2) |
| SSRF from scanner/webhooks | Outbound | Egress allow-list, target allow-list, beacon sandbox (4.2) |

---

## 11. Deployment Topologies

| Topology | Description | Recommended |
|---|---|---|
| **Reverse-proxy inline (perimeter)** | TLS-terminating proxy filters or inspects all app traffic; can block | Production enforcement |
| **Sidecar / service-mesh** | Envoy/Linkerd-style sidecar per workload intercepts traffic | Kubernetes estates, HTTP/2 concise |
| **Passive SPAN/TAP tap** | Mirror feed, detection-modify-only; no touch on traffic path | Zero-latency requirement |
| **App SDK agent (in-process)** | Library captures actual parameter names/values at app boundary | Legacy apps with messy wire formats |
| **Hybrid** | Inline proxy (block HIGH) + passive tap (deep check) + scanner (vuln ID) | Recommended production |

Deployment notes:
- Appliance/k8s manifest with hardcoded resource limits (CPU/mem) per pipeline stage; autoscale on queue depth, not CPU spikes.
- Multi-region/HA: stateless detection + stateful stores replicated; audit log append-only with quorum write.
- Disaster recovery: RPO <= 15 min for findings/audit; RTO <= 4h; restore drills documented (CP-2).

---

## 12. Performance & Scalability

- **Throughput target:** >= 50k RPS per detection instance (passive) with p99 added latency < 1 ms (passive) / < 5 ms (inline).
- **Normalize/caching:** memoized decode results for repeated string fingerprints; regex DFA precompilation per rule pack.
- **Scaling model:** partitions by adapter/src; per-parameter baselines in memory with bounded LRU; Aggregator tier merges per-node correlation.
- **Degraded-mode policy:** if pipeline exceeds latency budget, inline mode fails-open (pass traffic) with alert; passive mode drops lower-severity depths. (Fails-open vs fails-closed is configurable per scope/risk posture.)
- **Capacity testing** run each release (load + soak + evasion-mix) with results published to Ops.

---

## 13. Operations, Observability & Tuning

### 13.1 Observability
- Metrics: detections/sec, per-layer TP/FP/FN, latency, queue depth, scanner job health, scoring distributions.
- Logs: structured (JSON) with correlation IDs; redacted by default; shipped to SIEM.
- Traces: end-to-end span across ingest -> normalize -> detect -> score -> respond.
- Dashboards + SLOs: detection latency, precision floor, uptime per segment.

### 13.2 Tuning loop (human-in-the-loop)
1. Analyst disposition on findings (TP/FP/duplicate) stored and versioned.
2. Weekly precision/recall review per detector.
3. Suppression/learning list for known benign patterns (asset-specific).
4. Feedback trains/validates ML layer; thresholds recalibrated to target precision.
5. Rule-pack and corpus updates follow canary release, rollback-capable.

### 13.3 Change & configuration management
- Config as code (IaC), versioned, peer-reviewed, drift-detected.
- Policy changes follow A.8.9 / CM-6: staged rollout, approval for `enforce`, full audit trail.

---

## 14. Testing & Validation

| Layer | Test approach |
|---|---|
| Detection layers 1-3 | GPU-crafted fixtures + OWASP-Mutillidae / DVWA / Juice Shop lab captures; known TP/FP suites |
| Layer 4 (ML) | Held-out labeled set; precision/recall thresholds; adversarial evasion set |
| Layer 5 correlation | Multi-request attack scripts (error->boolean->union->time, OOB) |
| Evasion suite | Section 6.6 matrix enforced as automated regression in CI |
| Active Scanner | OWASP WebGoat/firing-range lab targets; red/green conflict testing; rate-limit safety tests |
| Fuzz & security | Fuzzing parse layer (HTTP/JSON/XML), negative space; SAST/SCA gates on each merge |
| Compliance evidence | Automated reports exporting Section 9 mapping + evidence links for audit |

**Acceptance criteria (release gate):** precision >= 99.5% on lab positive-set, recall >= 98.5% against evasion suite, p99 inline latency <= 5 ms, zero raw-payload persistence verified, audit hashes verified end-to-end.

---

## 15. Reference Stack (suggested)

| Concern | Suggested |
|---|---|
| Runtime | Go (proxy/ingest) + Python (detection/scoring/ML) or Rust for hot path |
| Parse/normalize | Custom HTTP parser on net/http + `sqlparse`-style tokenizer (per-dialect) |
| Rules | Precompiled RE2 rules; rule packs as signed YAML/JSON versions |
| ML | Gradient boosting / transformer-lite on n-grams; ONNX serving; drift monitor |
| Storage | PostgreSQL (findings/audit) + object store (evidence artifacts, encrypted) |
| Key/secret mgmt | AWS KMS/Vault (or equiv), envelope encryption, ephemeral inject |
| Observability | OpenTelemetry + Prometheus + Grafana; SIEM connector (CEF/JSON) |
| Delivery | Helm/K8s manifests, Terraform, signed container images, SBOM per release |
| CI/CT | GitHub Actions/Jenkins with SAST/SCA/image-scan/evasion-suite gates |

---

## 16. Roadmap (phased)

1. **Phase 0 - Foundation:** architecture review, control baseline, repo & pipeline scaffolding.
2. **Phase 1 - Passive detection (MVP):** inline proxy + parse/normalize + Layers 1-3 + findings API + redaction + audit.
3. **Phase 2 - Correlation & actions:** Layer 5 correlation, orchestration policies, SIEM/SOAR/WAF integrations, shadow-mode.
4. **Phase 3 - Vulnerable-param scanner:** Active Scanner (error/boolean/union/time/OOB), approval gate, remediation reporting.
5. **Phase 4 - ML layer & tuning:** classifiers, feedback loop, drift monitoring.
6. **Phase 5 - Compliance pack:** automated audit-export, retention/erasure jobs, pen-test hardening, ISMS evidence packs.

---

## 17. Document Control
| Item | Value |
|---|---|
| Version | 1.0 |
| Status | Architecture definition (for ISMS/SSDF/ASV evidence packs) |
| Change | v1.0 baseline. Next review after Phase 1 implementation. |

*End of architecture definition.*