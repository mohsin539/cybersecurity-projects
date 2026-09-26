# Web Application Fuzzer for Input Validation Testing — System Architecture

**Document version:** 1.0
**Standards baseline:** OWASP Top 10:2025 · NIST SP 800-218 (SSDF v1.1) · NIST SP 800-53 Rev 5 · NIST SP 800-115 · ISO/IEC 27001:2022
**Companion document:** `FRAMEWORK_MAPPING.md` (full control-to-module traceability tables)

---

## 1. Purpose & Scope

The **Web App Fuzzer** is a dynamic application security testing (DAST) platform that systematically injects malformed, unexpected, and malicious input into every input vector of a web application or API to detect input-validation weaknesses before attackers do.

It answers one core question: **does every input surface of the target validate, constrain, and safely handle anything it receives?**

Operating modes:

- **In-CI/CD** — an automated quality gate that blocks releases containing exploitable input-handling flaws.
- **Standalone** — an on-demand scanner run by security teams against authorized targets, with explicit authorization and scope controls.

Governance requirement: every finding, test module, and report must be traceable to **OWASP Top 10:2025**, **NIST** (SSDF / SP 800-53 / SP 800-115), and **ISO/IEC 27001:2022** controls so that tool output doubles as compliance evidence.

---

## 2. Design Goals & Guiding Principles

| Principle | Meaning in this system |
|---|---|
| **Input validation is the mission** | The fuzzer is specialized: it does not replace general vuln scanning; it owns the input-handling surface (NIST SP 800-53 SI-10 domain). |
| **Coverage by OWASP Top 10:2025** | Each test module maps to one or more OWASP categories and their associated CWEs. |
| **Evidence-ready output** | Every finding stores raw requests/responses, trigger proof, CWE, and control mappings (ISO A.8.29, SSDF PW.8). |
| **Safe by design** | The fuzzer itself follows secure coding (SSDF PW.5, ISO A.8.28); it never stores plaintext secrets and enforces authorization scopes. |
| **Non-destructive & non-disruptive** | Rate limiting, traffic throttling, target sandboxing, and opt-in destructive payloads. |
| **Deterministic, auditable runs** | Scans are reproducible (fixed seed + full request log), satisfying evidence/change control (ISO A.8.32). |
| **Least privilege, isolated workers** | One container per scan; egress policy; no production data-store access (ISO A.8.31). |

---

## 3. Reference Architecture

```
                            +---------------------------------------------------------+
                            |                     CLIENT LAYER                         |
                            |  Web Console (React)  |  CLI (fuzz)  |  REST API         |
                            +--------------+----------------------+-------------------+
                                           |                      |
                                           v                      v
+-------------------------------+  +-------+----------------------+--------------------+
|        AUTH & RBAC            |  |       ORCHESTRATION LAYER    |  GOVERNANCE LAYER  |
|  SSO/JWT | API keys |        |  |  Scan Orchestrator (state    |  Framework Mapper  |
|  scopes (authorize, scan,     |--|  machine) | Job Queue        |  (CWE -> OWASP/    |
|  report) | audit trail        |  |  Scheduler | Policy Engine   |  NIST/ISO) |       |
|  (A.5.15-A.5.18)              |  |  (gates, SLAs) | Scope Guard |  Severity Engine    |
+-------------------------------+  +-------+----------------------+  Evidence Store    |
                                           |                      +--------------------+
                                           v
                                  +-----------------------------------+
                                  |         DISCOVERY LAYER            |
                                  |  Crawler/Spider | API schema       |
                                  |  import (OAS/WSDL/GraphQL) |       |
                                  |  Parameter extractor | Auth/session |
                                  |  adapter | Attack-surface builder  |
                                  +-----------------------------------+
                                           |
                                           v
                                  +-----------------------------------+
                                  |        FUZZING ENGINE             |
                                  |  Generators (mutation / grammar / |
                                  |  template / dictionary) | Payload  |
                                  |  corpus | Injectors (param/header/ |
                                  |  body/JSON/XML/upload/cookie) |    |
                                  |  Protocol adapters (HTTP/WS/       |
                                  |  GraphQL/gRPC) | Encoding adapter  |
                                  +-----------------------------------+
                                           |
                                           v
                                  +-----------------------------------+
                                  |       EXECUTION LAYER             |
                                  |  Isolated worker pool | Headless   |
                                  |  browser (DOM fuzz) | Rate limiter |
                                  |  Safety guards | Proxy recorder    |
                                  +-----------------------------------+
                                           |
                                           v
                                  +-----------------------------------+
                                  |       DETECTION & ANALYSIS        |
                                  |  Response diffing | Oracle matching |
                                  |  (SQL/XSS/XXE/SSTI/SSRF) | Anomaly |
                                  |  detection | Error-info leaker |   |
                                  |  False-positive reducer | Correlator |
                                  +-----------------------------------+
                                           |
                                           v
                                  +-----------------------------------+
                                  |  REPORTING & INTEGRATION          |
                                  |  Traceability report maker |       |
                                  |  Jira/DefectDojo/GitLab pushers |  |
                                  |  SARIF export | Re-test (RV.1)     |
                                  +-----------------------------------+
                                           |
                                           v
                             STORAGE: Postgres (targets, scans, findings,
                             evidence) | Object store (artifacts, HAR, |
                             screenshots) | Redis (queue/cache)        |
```

Cross-cutting concerns: **Audit & Security Logging** (ISO A.8.15, OWASP A09), **Secrets Vault**, **secrets scanning + SBOM of the fuzzer's own repo** (OWASP A03, ISO 5.21/A.8.8), **Observability** (metrics/APM), **Backup & restore** (ISO A.8.13).

---

## 4. Core Components

### 4.1 Client Layer
- **Web Console** — scan creation, target & scope management, live progress, finding triage, evidence review, control-mapping view, compliance report export (PDF/JSON/HTML), user management.
- **CLI** — e.g. `fuzz scan --target https://staging.example.com --policy compliance --exit-code`, CI-native.
- **REST API** — OpenAPI 3.1, versioned; used by console, CLI, and CI.

### 4.2 Authentication & RBAC
- SSO/OIDC or internal IdP; service-to-service via signed, expiring JWTs / scoped API keys.
- Roles: `scan_runner`, `analyst`, `admin`, `compliance_auditor` (read-only + evidence export).
- Mandatory **authorization assertion**: every scan requires a stored authorization ticket (system owner, date range, allowed hosts) — reduces accidental production scans.
- Immutable audit trail of who ran what against which target (ISO A.5.15-A.5.18, NIST AU-2/AU-6).

### 4.3 Orchestration Layer
- **Scan Orchestrator** — finite-state machine driving `queued -> discovery -> fuzzing -> analysis -> reporting -> done/failed/paused`, with checkpoints for resumable, deterministic scans.
- **Job Queue** — priority queue (Celery/RQ on Redis) with dead-letter handling and retries with backoff.
- **Policy Engine** — per-project severity thresholds; maps to remediation SLAs (ISO A.8.8: e.g. critical = 15 days); enforces CI gates (block on critical findings unless risk-accepted with named owner).
- **Scope Guard** — validates every outbound request against an approved allow-list (host, port, path, method); SSRF probes are an opt-in module targeting scoped/internal hosts only, always logged.

### 4.4 Governance Layer
- **Framework Mapper** — maps CWE to OWASP Top 10:2025 category, NIST SSDF task, NIST SP 800-53 control, and ISO 27001:2022 Annex A control. Drives report traceability (see `FRAMEWORK_MAPPING.md`).
- **Severity Engine** — synthesizes CVSS v3.1 base vector from trigger characteristics plus exploitability and target context; assigns a confidence score; analyst override supported.
- **Evidence Store** — immutable, hash-linked records of request/response pairs, timing deltas, and proof-of-trigger artifacts; built for auditor sampling.

### 4.5 Discovery Layer
- **Crawler/Spider** — JS-aware crawling of SPA content; configurable `robots.txt` modes.
- **API schema import** — OpenAPI 3.x, WSDL, GraphQL introspection, gRPC proto; produces exact parameter models (name, type, required, enum, format) for grammar-aware fuzzing.
- **Parameter extractor** — finds query/form/JSON/cookie/header params and reflected value sinks.
- **Auth/session adapter** — pluggable (cookie login, OAuth2, API keys, JWT replay, NTLM); credentials pulled from the Secrets Vault at worker runtime, never written to scan config or logs.
- **Attack-surface builder** — produces the *fuzz target graph*: all (request, parameter, encoding-context, protocol) combinations within configured depth/count budgets.

### 4.6 Fuzzing Engine
- **Generators**
  - *Mutation fuzzing*: bit/byte/char mutators over captured base cases (deterministic seeded PRNG).
  - *Grammar/generation fuzzing*: schema-driven boundaries — number limits, unicode, overflow, format injection.
  - *Template fuzzing*: parameterized templates per vulnerability class — SQLi, NoSQLi, XSS, SSTI, OS command, LDAP, XPath, XXE, deserialization, CRLF/log-injection, SSRF, path traversal, unicode normalization.
  - *Dictionary/corpus fuzzing*: OWASP payload libraries, fuzzDB, polyglot payloads; extensible via YAML.
- **Injectors** — cover all vector locations: query string, path, body (form/JSON/XML/multipart), headers, cookies, GraphQL variables, WebSocket frames, file-upload names/content/metadata.
- **Encoding adapter** — URL, HTML entity, unicode, base64, double-URL-encoding, JSON-escaped; detects reflection context (attribute/script/comment/header) to select appropriate XSS payloads.
- **Protocol adapters** — HTTP/1.1, HTTP/2, WebSocket, GraphQL, gRPC.
- **Stateful fuzzing** — multi-step flows (e.g., add-to-cart then checkout) to reach chained validation weaknesses.

### 4.7 Execution Layer
- **Worker pool** — isolated, disposable containers (one per scan) with restrictive egress.
- **Rate limiter** — token bucket per target host; politeness delays; honours target 429/503 backoff.
- **Safety guards** — request size caps, timeouts, recursion limits; destructive operations disabled by default (`--destructive` opt-in); high-risk payloads flagged.
- **Headless browser** — DOM-level fuzzing for client-side sinks (reflected/DOM XSS) and rendering-based detection in a sandboxed browser profile.
- **Proxy recorder** — captures base traffic (burp-style) so operators can bootstrap fuzz targets from recorded sessions instead of crawling.

### 4.8 Detection & Analysis
- **Differential analysis** — per-payload diffing against a baseline request: status codes, body length/hash, `Set-Cookie` changes, timing deltas, header fingerprints.
- **Oracle matching** — signature + behaviour oracles:
  - *SQLi*: error-text fingerprints, boolean-based inference, time-delay confirmation.
  - *XSS*: reflection detection + rendered-context check in a browser + CSP header assessment.
  - *XXE*: external-entity resolver hit via a scoped DNS/collaborator callback.
  - *SSTI/SR*: polyglot probe evaluation for template engines.
  - *SSRF*: out-of-band callback detection against approved collaborator infrastructure.
- **Error-information leaker** — stack traces, exception classes, debug banners (OWASP A10).
- **False-positive reducer** — re-requests with a benign control; checks whether output was escaped/encoded (encoded = mitigated); records how the app validated.
- **Correlator** — groups duplicate findings and chains multi-step issues (e.g., auth bypass -> broken access control).

### 4.9 Reporting & Integration
- **Finding record** — CWE + OWASP 2025 category + NIST/ISO control mapping, severity, confidence, evidence, remediation guidance (OWASP cheat sheets), affected vector, retest status.
- **Traceability report** — matrix of findings x {OWASP category, NIST control, SSDF task, ISO Annex A control}; the auditor-facing artifact.
- **Integrations** — Jira / ServiceNow / DefectDojo / GitLab; SARIF export for CI; Slack/Teams notifications.
- **Re-test workflow** — fixes are re-scanned via a focused regression run (same seed, same module IDs) to prove closure (SSDF RV.1).

### 4.10 Storage
- **PostgreSQL** — targets, authorizations, scans, findings, retests, policies, audit log.
- **Object storage** — evidence blobs: raw captures, HAR dumps, screenshots, diff snapshots (immutable, hash-linked).
- **Redis** — job queue + ephemeral scan-progress cache.

---

## 5. Scan Lifecycle (data flow)

```
1. AUTHORIZE   Provide target URL + authorization ticket; Scope Guard computes allowed hosts/ports.
2. DISCOVER    Crawler + API schema import + proxy recorder build the attack surface.
3. MODEL       Parameter/vector model built; base requests recorded; baselines cached.
4. PLAN        Policy engine selects module set, depth budget, payload corpus per target type & risk tier.
5. FUZZ        Workers inject payloads per plan; rate-limited; per-request audit captured.
6. DETECT      Differential + oracle + anomaly analysis scores and correlates findings.
7. REPORT      Findings persisted, mapped to frameworks, severity assigned, evidence attached.
8. ACT         CI gate / ticket push / risk-register update; SLAs computed.
9. RETEST      Post-fix regression confirms closure (SSDF RV.1); immutable evidence retained.
```

The pipeline is composable — any stage can run standalone (e.g., `discover` only, `replay` a targeted payload set).

---

## 6. Fuzz-Model Quality Controls

- **Determinism** — all mutation randomness from a seeded PRNG; seed recorded per scan for reproducibility.
- **Budgeting** — configurable limits (max requests/min, max params per endpoint, max depth) to prevent infinite crawls and accidental DoS.
- **Passive-first** — non-invasive probes default; active and out-of-band probing is explicit and logged.
- **Consent gating** — destructive payloads, account-locking risks, and mail-triggering flows are off unless the operator enables them and the policy allows.

---

## 7. Data Model (high level)

- `Target` — url, allowed_hosts, environment, owner, authorization_ticket, risk_tier.
- `Scan` — policy, modules, seed, started/finished, status, commit/branch (CI mode), trigger.
- `Endpoint` / `Parameter` — discovery results (method, path, mime, parameter constraints).
- `FuzzCase` — generated request bytes, vector, payload id, encoded form, seed index.
- `Result` — response status/body/hash/timing, diff vs baseline.
- `Finding` — CWE, OWASP 2025 ids, control mappings, severity, confidence, evidence refs, status, assignee.
- `EvidenceBlob` — immutable, hash-linked artifacts.
- `Policy` — module set, thresholds, SLAs, scope allow-lists.
- `AuditLog` — immutable append-only operator + engine events.

---

## 8. Platform Security (the fuzzer protects itself)

Because this tool generates attack traffic and holds authorization data, it must satisfy the same standards it enforces:

- **Secure coding of the platform** (SSDF PW.5, ISO A.8.28): all console/API inputs validated via framework validators; outputs encoded; SAST + SCA in the fuzzer's own pipeline.
- **Secrets** — never stored in plaintext; external secrets manager (Vault/KMS); credentials injected into scan-worker memory only and masked in logs/reports.
- **Least privilege** — workers run non-root, read-only filesystem, isolated network namespace, no access to production data stores.
- **Supply chain hygiene** — the platform publishes an SBOM and pins dependency hashes (OWASP A03, ISO 5.21/A.8.8).
- **Security logging & alerting** — structured audit logs (OWASP A09, ISO A.8.15) shipped to SIEM; alerts on tool abuse (scan explosion, out-of-scope egress attempts).
- **Change management** — platform config changes flow through versioned PRs and approvals (ISO A.8.32).

---

## 9. Deployment Topologies

### 9.1 In-CI/CD (gate mode)
Scanner container runs as a pipeline stage against an ephemeral pre-production environment; findings are published as SARIF + inline PR comments; the gate blocks merge above a configured severity unless a risk acceptance is filed. Evidence (ISO A.8.29, SA-11) auto-appends to the release record.

### 9.2 Standalone (security team)
Orchestrator + DB hosted on the security infra; workers on-demand (Kubernetes jobs or Nomad). Operators target authorized staging/QA/dev instances; production scans require a separate, higher-privilege approval flow and use reduced/softer payload profiles.

### 9.3 Isolated scan farm (managed/central agents)
Workers deployed inside or near the target network with strict egress via an HTTP(S)-only forward proxy so SSRF/OOB callbacks resolve only to the approved collaborator.

### 9.4 Environment separation requirement (ISO A.8.31)
Scanning environments are logically and physically separated from platform dev environments; the platform's own Dev/Test/Prod use distinct clusters and data stores.

---

## 10. Technology Stack (recommendation)

| Layer | Choice | Notes |
|---|---|---|
| Language | Python 3.12 | Rich fuzzing/parsing ecosystem; async HTTP via httpx |
| Generation | Custom + `grammar`/`hypothesis` reuse | Deterministic seeded mutations |
| Crawling | Playwright (headless Chromium) | SPA + DOM instrumentation |
| HTTP | httpx (async) + HTTP/2; WebSocket via websockets | gRPC via grpcio | — |
| Orchestration | Celery + Redis | Queues, retries, dead-letter |
| API/Console | FastAPI + React | OpenAPI-first |
| Storage | PostgreSQL + MinIO (S3) | Evidence blobs on object store |
| Scan isolation | Docker / containerd + gVisor | One worker container per scan |
| Vault | HashiCorp Vault / cloud KMS | Auth material, never in DB |
| CI integration | GitHub Actions / GitLab CI / Jenkins | SARIF, gates |
| OOB collaborator | Interactsh (self-hosted) or internal DNS+HTTP knocks | Scoped, logged |

---

## 11. Implementation Roadmap

- **M1 (Foundation)** — target/scope model, authz tickets, crawler, baseline capture, determinism, storage, REST API.
- **M2 (Core fuzz)** — mutation + template generators, HTTP/GraphQL admitters, oracle suite (SQLi/XSS/SSTI/XXE), false-positive reducer.
- **M3 (Governance)** — framework mapper (OWASP/NIST/ISO), severity engine, traceability reports, audit log.
- **M4 (Ops)** — CI gate, SARIF, Jira/DefectDojo integration, retest workflow, rate-limit + safety hardening.
- **M5 (Advanced)** — stateful flows, protocol adapters (WebSocket/gRPC), DOM fuzz, collaborator SSRF, policy engine SLAs.

---

## 12. References

- OWASP Top 10:2025 — https://owasp.org/Top10/2025/
- OWASP ASVS & WSTG (test plan cross-reference)
- NIST SP 800-218 (SSDF v1.1) — https://csrc.nist.gov/pubs/sp/800/218/final
- NIST SP 800-53 Rev 5 (SI-10, CA-8, SA-11)
- NIST SP 800-115 (technical security testing methodology)
- ISO/IEC 27001:2022 Annex A (93 controls; A.8.8, A.8.25-A.8.32 cluster)
- OWASP fuzzing/attack payload projects (fuzzDB, OWASP WSTG payloads)