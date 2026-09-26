<div align="center">

# 🔐 **3D CTF SCOREBOARD**
## Security Architecture & Control Specification — v1.0

<br/>

`███████ ██ ██████ ███    ██ ██████ ██  ██████ ███    ███ ██████ ██ ████████ ███████ ██  █████`
`██   ██ ██ ██   ██ ████   ██ ██   ██ ██ ██       ████   ██    ██    ██    ██    ██ ██      ██   ██`
`███████ ██ ██████ ██ ██ █ ██ ██   ██ ██ ██   ███    ██    ██    ██    ██    ██    █████   ███████`
`██      ██ ██   ██ ██  ██  ██ ██   ██ ██    ██    ██    ██    ██    ██    ██    ██      ██   ██`
`██      ██ ██   ██ ██      ██ ██████ ██    ████   ██    ██    ██    ██    ██    ███████ ██   ██`

<br/>

**Fail-Closed · Zero-Trust · Least-Privilege · Evidence-Producing · Adversary-Aware**

<br/>

| | |
|:--|:--|
| 🛡️ **OWASP Top 10:2025** | A01–A10 design-level control coverage |
| ✅ **OWASP ASVS 5.0** | Level 2 requirement-level verification |
| 🏛️ **NIST SP 800-53 Rev. 5** | Moderate-baseline control parameterisation |
| 🏛️ **NIST CSF 2.0** | Govern · Identify · Protect · Detect · Respond · Recover |
| 🧾 **ISO/IEC 27001:2022** | Annex A control implementation evidence |
| 🌍 **GDPR** | Minimisation, DSAR, DPIA, breach notification |

<br/>

`🧱 Binding Controls` · `🧪 Executable Tests` · `🚨 Detection Rules` · `📖 Runbooks` · `⚖️ Risk Acceptance`

</div>

---

<div align="center">

### 🎨 Design Language — Visual Grammar

| Token | Colour | Hex | Usage |
|:--|:--|:--|:--|
| 🟣 Primary | Violet | `#6C5CE7` | Document identity, control families |
| 🟢 Success | Mint | `#06D6A0` | Control implemented, test passing |
| 🔵 Info | Cyan | `#00D2FF` | Data flow, verification, evidence |
| 🟡 Caution | Amber | `#FFD166` | Medium risk, planned, advisory |
| 🟠 Alert | Orange | `#FF9F1C` | High risk, partial, degradation |
| 🔴 Critical | Rose | `#EF476F` | Critical risk, breach, P1, block |
| ⚫ Surface | Obsidian | `#0B0E1A` | Document canvas |
| ◼️ Panel | Slate | `#141A2E` | Component surfaces |
| ⬜ Text | Ghost | `#E8ECF8` | Primary typography |
| ◻️ Muted | Ash | `#8B95B8` | Secondary typography, annotations |

<br/>

**Severity Legend**

🟢 Low &nbsp;·&nbsp; 🟡 Medium &nbsp;·&nbsp; 🟠 High &nbsp;·&nbsp; 🔴 Critical &nbsp;·&nbsp; ⬛ Not Applicable &nbsp;·&nbsp; 🟣 In Progress

**Control Status Legend**

🟢 Enforced &nbsp;·&nbsp; 🟣 In Progress &nbsp;·&nbsp; 🟡 Planned &nbsp;·&nbsp; 🟠 Partial &nbsp;·&nbsp; 🔴 Gap &nbsp;·&nbsp; ⬛ Out of Scope

**Control Family Prefix**

| Prefix | Domain | Colour |
|:--|:--|:--|
| `SEC-IAM` | Identity, authentication, session | 🔵 |
| `SEC-AUTH` | Authorisation, RBAC/ABAC, separation of duties | 🔴 |
| `SEC-APP` | Application hardening, input/output, errors | 🟢 |
| `SEC-CRY` | Cryptography, keys, secrets | 🟣 |
| `SEC-SC` | Software supply chain, build integrity | 🟠 |
| `SEC-DATA` | Data protection, privacy, retention | 🔵 |
| `SEC-AUD` | Audit, logging, detection, alerting | 🔴 |
| `SEC-INFRA` | Infrastructure, network, container, cloud | 🟡 |
| `SEC-EXT` | Third-party, webhook, federation trust | 🔵 |
| `SEC-SDLC` | Process, gates, governance, training | 🟣 |
| `SEC-IR` | Incident response, continuity, recovery | 🟠 |

</div>

---

## 📑 Table of Contents

| § | Section | Family | Badge |
|:--|:--|:--|:--|
| [1](#1--document-control) | Document Control & Approval | 🟣 | 🟣 |
| [2](#2--purpose-scope--the-problem) | Purpose, Scope & The Problem | 🔵 | 🔵 |
| [3](#3--security-principles) | Security Principles | 🟢 | 🟢 |
| [4](#4--posture--adversary-model) | Posture & Adversary Model | 🔴 | 🔴 |
| [5](#5--control-framework--taxonomy) | Control Framework & Taxonomy | 🟣 | 🟣 |
| [6](#6--identity--session-controls) | Identity & Session Controls | 🔵 | 🔵 |
| [7](#7--authorisation--separation-of-duties) | Authorisation & Separation of Duties | 🔴 | 🔴 |
| [8](#8--application-hardening-controls) | Application Hardening Controls | 🟢 | 🟢 |
| [9](#9--cryptography-keys--secrets) | Cryptography, Keys & Secrets | 🟣 | 🟣 |
| [10](#10--software-supply-chain-controls) | Software Supply Chain Controls | 🟠 | 🟠 |
| [11](#11--data-protection--privacy) | Data Protection & Privacy | 🔵 | 🔵 |
| [12](#12--audit-detection--alerting) | Audit, Detection & Alerting | 🔴 | 🔴 |
| [13](#13--infrastructure-network--container-controls) | Infrastructure, Network & Containers | 🟡 | 🟡 |
| [14](#14--third-party--webhook-trust) | Third-Party & Webhook Trust | 🔵 | 🔵 |
| [15](#15--secure-sdlc--release-gates) | Secure SDLC & Release Gates | 🟣 | 🟣 |
| [16](#16--vulnerability--patch-management) | Vulnerability & Patch Management | 🟠 | 🟠 |
| [17](#17--security-testing--verification-catalogue) | Security Testing & Verification Catalogue | 🟢 | 🟢 |
| [18](#18--incident-response--runbooks) | Incident Response & Runbooks | 🔴 | 🔴 |
| [19](#19--exceptions--risk-acceptance) | Exceptions & Risk Acceptance | 🟡 | 🟡 |
| [20](#20--compliance-traceability) | Compliance Traceability | 🟣 | 🟣 |
| [21](#21--security-metrics--kpis) | Security Metrics & KPIs | 🔵 | 🔵 |
| [22](#22--appendices) | Appendices (Control Index, Glossary) | ⬜ | ⬜ |

---

## 1. 🟣 Document Control

| Field | Value | Field | Value |
|:--|:--|:--|:--|
| **Document ID** | `SC3D-SEC-001` | **Version** | 1.0.0 |
| **Status** | 🟣 Approved for build | **Classification** | Internal — Restricted |
| **Owner** | Security Engineering (`security_admin` role) | **Steward** | Lead Referee (business rules) |
| **Parent document** | [`architecture.md`](./architecture.md) | **Companions** | [`state.md`](./state.md) · [`memory.md`](./memory.md) |
| **Classification basis** | Contains attack-surface detail and control weaknesses-by-design | **Review cycle** | Quarterly + on any 🔴 P1 |
| **Approved by** | CISO · Lead Referee · Platform Lead | **Next review** | 90 days from approval |

**Change control**

| Version | Date | Author | Change | Approver |
|:--|:--|:--|:--|:--|
| 0.1 | 2026-09-26 | Security Eng | Initial control catalogue derived from `architecture.md` §10–§14 | — |
| 0.9 | 2026-09-26 | Security Eng | Test catalogue bound to control IDs; SoD assertions added | Lead Referee |
| 1.0 | 2026-09-26 | Security Eng | Approved baseline for Phase 1 build | CISO |

**Normative language**

| Term | Meaning |
|:--|:--|
| 🟢 **MUST** | Mandatory. Absence is a release blocker. |
| 🟡 **SHOULD** | Strongly recommended. Deviation needs a recorded risk acceptance ([§19](#19--exceptions--risk-acceptance)). |
| 🔵 **MAY** | Optional. Engineering discretion. |
| ⬛ **MUST NOT** | Prohibited. Violation is an incident, not a bug. |

> 🧱 **This document is binding.** Every `SEC-*` control is implemented, tested, evidenced, and — where relevant — continuously asserted. A control without an executable test is a wish. A control without an owner is a liability. A control without a detection rule is invisible.

---

## 2. 🔵 Purpose, Scope & The Problem

### 2.1 The Problem This Document Solves

`architecture.md` describes **what** the system is. This document describes **how it refuses to be broken**, in terms an engineer can implement on a Tuesday and an auditor can verify on a Friday.

For a live CTF leaderboard, security is not a compliance appendix. It is the product requirement:

| Product need | Security consequence if unaddressed |
|:--|:--|
| 🏆 The public board must be **correct** | A manipulated leaderboard is a competitive weapon; a wrong winner is a legal and reputational event |
| ⏱️ Scores arrive **in real time** from a third-party platform | Webhook forgery and replay become the primary attack surface |
| 🧑‍💻 Staff administer scores remotely | A single compromised admin account defeats every other control |
| 📊 Reports and evidence are **downloaded** | Exfiltration channel and a data-protection obligation |
| 🧾 The event is **auditable for 7 years** | Tamper-evidence must survive a motivated insider with database access |
| 🌍 Spectators are **anonymous and numerous** | Bots, scrapers, and drive-by attackers at internet scale |

### 2.2 In Scope

| Area | Covered |
|:--|:--|
| 🧑‍💻 Identity | OIDC federation, MFA, session lifecycle, break-glass |
| 🔐 Authorisation | RBAC × resource, ABAC attributes, RLS, two-person integrity |
| 🌐 Web/API surface | Input validation, output encoding, CSP, headers, rate limits, CSRF, CORS |
| 🔑 Cryptography | Transport, at-rest, PII columns, blind index, chain hashing, report signing |
| 📦 Supply chain | SBOM, SCA, SLSA provenance, cosign, dependency allow-list, quarantine |
| 🗄️ Data | Classification, minimisation, retention, legal hold, DSAR, erasure |
| 🧾 Assurance | Audit schema, hash chain, WORM sealing, alerting, evidence packs |
| 🖥️ Infrastructure | Network zones, container hardening, IaC policy, cloud posture |
| 🤝 Third parties | CTF platform webhooks, OIDC/IdP, registry, TSA/transparency log |
| 🔁 Process | Secure SDLC, CI gates, vulnerability management, training, exceptions |

### 2.3 Out of Scope

| Excluded | Reason | Compensating Position |
|:--|:--|:--|
| ⬛ Physical security of the CTF venue | Not operated by us | Venue agreement; device attestation for admin endpoints |
| ⬛ Security of the CTF platform itself | External system | Contracted webhook trust ([§14](#14--third-party--webhook-trust)); reconciliation detects compromise |
| ⬛ Source-IP attribution / prosecution | Requires law enforcement | Evidence packs are court-adjacent artefacts, not legal process |
| ⬛ Cryptographic research / novel primitives | ADR-006: standard crypto only | Crypto-agility config allows future PQC migration ([§9](#9--cryptography-keys--secrets)) |
| ⬛ Marketing-site security | Separate estate | Shared CI standards only |

### 2.4 How to Read This Document

```mermaid
%%{init: {"theme":"base","themeVariables":{"primaryColor":"#6C5CE7","primaryTextColor":"#E8ECF8","primaryBorderColor":"#6C5CE7","lineColor":"#8B95B8","fontFamily":"Inter, sans-serif"}}}%%
flowchart LR
    R["📖 Requirement<br/>OWASP / ISO / NIST"]:::in
    C["🛡️ Control<br/>SEC-* statement"]:::mid
    I["🧱 Implementation<br/>artefact + setting"]:::impl
    T["🧪 Test<br/>T-* case, gate"]:::test
    D["🔍 Detection<br/>AL-* / metric"]:::det
    E["📦 Evidence<br/>collector output"]:::ev
    O["👤 Owner<br/>+ review cadence"]:::own
    R --> C --> I --> T
    I --> D
    T --> E
    D --> E
    C --> O
    O --> R
    classDef in fill:#062B3A,stroke:#00D2FF,color:#E8ECF8
    classDef mid fill:#241A4D,stroke:#6C5CE7,color:#E8ECF8
    classDef impl fill:#06251D,stroke:#06D6A0,color:#E8ECF8
    classDef test fill:#2E2205,stroke:#FFD166,color:#0B0E1A
    classDef det fill:#3A2A05,stroke:#FF9F1C,color:#E8ECF8
    classDef ev fill:#2A1220,stroke:#EF476F,color:#E8ECF8
    classDef own fill:#141A2E,stroke:#8B95B8,color:#E8ECF8
```

> 🔗 Every control in this document is **traceable in both directions**: forward to an implementation artefact and a test, and backward to the requirement that demanded it. A control with no requirement is scope creep; a requirement with no control is a gap. The traceability matrix in [§20](#20--compliance-traceability) closes the loop.

---

## 3. 🟢 Security Principles

The twelve principles below are inherited from [`architecture.md` §4](./architecture.md#4--architecture-principles) and are restated here as **decision rules**. When two controls appear to conflict, these principles break the tie.

| ID | Principle | Decision Rule | Consequence in Practice |
|:--|:--|:--|:--|
| 🟢 **SP-01** | **The server's truth is the only truth** | A client value is never authoritative | The browser renders `rank`; it never computes it. `SC-03` in the coding standard forbids trusting client rank/score/identity. |
| 🟢 **SP-02** | **Deterministic derivation** | Given the same events + model version, the result is reproducible | The scoring engine is pure; no clock, no randomness, no I/O ([`architecture.md` §8.1](./architecture.md#81-why-a-pure-scoring-function-matters-for-audit)). |
| 🟢 **SP-03** | **Audited or not done** | A mutation without an audit record is refused | If the audit store is unavailable, the write fails — availability never outranks accountability. |
| 🟢 **SP-04** | **Fail closed, fail loud** | Ambiguity in a security decision resolves to deny | PDP unreachable ⇒ deny. IdP unreachable ⇒ no anonymous admin. Degradation is explicit, never silent. |
| 🟢 **SP-05** | **Least privilege, time-boxed** | Authority is narrow, scoped, and expires | 8 roles, 34 permissions, event scoping, 1-hour dynamic credentials, 60-minute break-glass. |
| 🟢 **SP-06** | **Two eyes on integrity** | No single human can both change a score and hide it | Two-person integrity on `score.adjust`, `event:freeze`, `role:manage`, `policy:deploy`. |
| 🟢 **SP-07** | **Verify explicitly** | Trust is proven per request, not assumed from network position | mTLS + HMAC + JWT verification + per-request PDP evaluation on every protected call. |
| 🟢 **SP-08** | **Microsegmentation** | Every container gets a deny-by-default egress and ingress policy | 5 network zones; no flat network; lateral reach requires an explicit rule and an audit event. |
| 🟢 **SP-09** | **No client-side secrets** | The browser holds no credential that outlives the request | Session cookie only; tokens in memory; keys never shipped. Irreversible if violated, so it is structurally prevented. |
| 🟢 **SP-10** | **Immutable evidence** | History is append-only and externally anchored | Hash chain + signed Merkle roots in Object Lock + RFC 3161 timestamp. |
| 🟢 **SP-11** | **Degrade gracefully, never silently** | Every degraded state is visible, audited, and reversible | 8 named degradation modes with operator-visible banners and audit events. |
| 🟢 **SP-12** | **Evidence over assertion** | A control is real when a machine produced its proof | Evidence collectors run continuously; quarterly human attestation supplements, never replaces. |

### 3.1 Principle Conflict Resolution Order

When two principles collide, resolve in this order — most restrictive wins, and the conflict is recorded in the risk register ([`architecture.md` §23.1](./architecture.md#231-risk-register)):

```
1. SP-03 Audited or not done      → integrity of evidence
2. SP-04 Fail closed              → safety of the authorisation decision
3. SP-10 Immutable evidence       → non-repudiation
4. SP-06 Two eyes on integrity    → insider resistance
5. SP-05 Least privilege          → blast-radius containment
6. SP-01 / SP-02 Server truth     → correctness of the product
7. SP-11 Graceful degradation     → availability
8. Performance / cost             → last, and only within documented budgets
```

> 📖 **Worked example — the classic availability-vs-audit trade-off.** The audit store becomes unavailable at minute 94 of a live event, 40 minutes before the final freeze. Availability pressure is enormous. **Resolution:** ingest continues (the ingest buffer is a durable queue with 24-hour retention and RPO 0), but all *human* mutations — `score.adjust`, `solve.revert`, `event:phase` — are refused, the board shows a `SAFE MODE` banner, and AL-06-equivalent alerting fires. Rationale: an unaudited manual change during the final hour is exactly the event an auditor will ask about, and the platform can replay ingestion but cannot invent a referee's authority after the fact.

---

## 4. 🔴 Posture & Adversary Model

### 4.1 Threat Actor Posture

The adversary model is inherited verbatim in structure from [`architecture.md` §10.2](./architecture.md#102-threat-actors--attack-surface) and re-expressed as **posture requirements** — what posture each actor forces upon the design.

| Actor | Capability | Forced Posture Requirement | Primary Controls |
|:--|:--|:--|:--|
| 🕷️ **Curious spectator** | Low | Public surface must be boring: no enumeration, no injection, no client-trust | `SEC-APP-01`…`06`, `SEC-AUTH-01`, `SEC-AUTH-04` |
| 🤖 **Botted scraper** | Medium | Volume must be absorbed without degrading the product | `SEC-APP-09`, `SEC-APP-10`, `SEC-INFRA-06` |
| 🎭 **Malicious participant** | Medium | The ingest path must be unforgeable and replay-proof | `SEC-EXT-01`…`06`, `SEC-APP-07` |
| ⚔️ **Organised competitor** | High | Insider and supply-chain paths must be two-person and provenance-verified | `SEC-AUTH-07`, `SEC-SC-01`…`08` |
| 🕳️ **Opportunistic attacker** | Medium | Patch SLAs and segmentation must be real, not aspirational | `SEC-SDLC-05`, `SEC-INFRA-01`…`05` |
| 🧑‍💼 **Malicious insider** | High | Evidence must survive database and host compromise | `SEC-AUD-01`…`07`, `SEC-AUTH-08` |
| 🏛️ **Nation-state / APT** | Very high | Assume pre-positioning; require external anchoring of history | `SEC-AUD-08`, `SEC-CRY-09`, `SEC-DATA-06` |

### 4.2 Attack Surface → Control Map

| Surface | Entry Points | Control Families | Residual Risk |
|:--|:--|:--|:--|
| 🌐 Internet / edge | CDN, WAF, Nginx, SSE | `SEC-INFRA-01`, `SEC-INFRA-06`, `SEC-CRY-01` | 🟡 Volumetric, 0-day in proxy |
| 🎨 Browser | SPA bundle, DOM, WebGL | `SEC-APP-04`…`06`, `SEC-CRY-08` | 🟡 Novel XSS vector; browser CVE |
| ⚙️ API | 40+ REST endpoints, SSE | `SEC-AUTH-01`…`05`, `SEC-APP-01`…`03` | 🟡 BOLA; business-logic flaw |
| ⚫ Webhook | `/webhooks/ctf` | `SEC-EXT-01`…`06` | 🟡 Replay inside the skew window |
| 🗄️ Database | 5432, `net_data` only | `SEC-AUTH-06`, `SEC-DATA-01`, `SEC-AUD-03` | 🟡 Injection in a dependency |
| ⚙️ Container | 18 services | `SEC-INFRA-02`…`05` | 🟡 Container escape |
| 🔧 Supply chain | npm, base images, CI | `SEC-SC-01`…`08` | 🟡 Maintainer compromise |
| ☁️ Cloud control plane | IAM, KMS, S3 | `SEC-CRY-06`, `SEC-DATA-05`, `SEC-AUD-08` | 🟡 Account compromise |
| 🧑 Human | Phishing, social engineering | `SEC-IAM-05`…`08`, `SEC-SDLC-08` | 🟠 Social engineering |

### 4.3 Attack Trees — Top Three

```mermaid
%%{init: {"theme":"base","themeVariables":{"primaryColor":"#EF476F","primaryTextColor":"#E8ECF8","primaryBorderColor":"#EF476F","lineColor":"#8B95B8","fontFamily":"Inter, sans-serif"}}}%%
flowchart TB
    G["🎯 GOAL: put team X at rank 1 without authority"]:::goal
    G --> M1["🕵️ Method 1 · Forge ingestion"]:::m
    G --> M2["🕵️ Method 2 · Steal referee session"]:::m
    G --> M3["🕵️ Method 3 · Corrupt the projection"]:::m
    G --> M4["🕵️ Method 4 · Hide the evidence"]:::m

    M1 --> M1a["❌ Forged webhook signature"]:::x
    M1 --> M1b["❌ Replay inside skew window"]:::x
    M1 --> M1c["❌ Double-apply on retry"]:::x

    M2 --> M2a["❌ Credential stuffing"]:::x
    M2 --> M2b["❌ Phishing-resistant MFA bypass"]:::x
    M2 --> M2c["❌ Session theft / fixation"]:::x
    M2 --> M2d["❌ Step-up not enforced"]:::x

    M3 --> M3a["❌ Client-side rank tampering"]:::x
    M3 --> M3b["❌ Cache poisoning of leaderboard read"]:::x
    M3 --> M3c["❌ Projection drift from event store"]:::x

    M4 --> M4a["❌ UPDATE/DELETE on audit_log"]:::x
    M4 --> M4b["❌ Suppress audit insert"]:::x
    M4 --> M4c["❌ Delete WORM objects"]:::x
    M4 --> M4d["❌ Forge a consistent chain"]:::x

    classDef goal fill:#6C5CE7,stroke:#E8ECF8,stroke-width:3px,color:#E8ECF8
    classDef m fill:#2A1220,stroke:#EF476F,color:#E8ECF8
    classDef x fill:#06251D,stroke:#06D6A0,color:#E8ECF8
```

Each ❌ leaf above is a **negative test** in the verification catalogue ([§17](#17--security-testing--verification-catalogue)). A leaf without a test is an open attack path.

| Method | Blocking Controls | Verification |
|:--|:--|:--|
| Forge ingestion | `SEC-EXT-02` HMAC over raw bytes, `SEC-EXT-03` skew window, `SEC-EXT-05` idempotency key | `T-EXT-01`, `T-EXT-02`, `T-EXT-03` |
| Steal referee session | `SEC-IAM-02` mandatory MFA, `SEC-IAM-06` short sessions, `SEC-IAM-07` revocation, `SEC-AUTH-03` step-up | `T-IAM-04`, `T-IAM-06`, `T-AUTH-05` |
| Corrupt the projection | `SEC-APP-03` server-authoritative scores, `SEC-DATA-04` rebuild-and-compare, `SEC-APP-09` cache purge on mutation | `T-APP-03`, `T-DATA-05` |
| Hide the evidence | `SEC-AUD-03` DB-level immutability rules, `SEC-AUD-04` same-transaction audit, `SEC-AUD-06` WORM Object Lock, `SEC-AUD-08` external anchoring | `T-AUD-01`, `T-AUD-02`, `T-AUD-03`, `T-AUD-04` |

### 4.4 Abuse Cases Carried Forward

The 18 abuse cases (`AB-01`…`AB-18`) defined in [`architecture.md` §13.5](./architecture.md#135-abuse-cases-tested-not-just-documented) are **normative for this document**: each maps to at least one `SEC-*` control and one `T-*` test. The mapping table is maintained in [§20.3](#203-abuse-case-coverage).

---

## 5. 🟣 Control Framework & Taxonomy

### 5.1 Control Record Schema

Every control in this document is a record with fixed fields. A control missing any field is a draft and **cannot be marked 🟢 Enforced**.

| Field | Required | Description |
|:--:|:--:|:--|
| **ID** | ✅ | Stable identifier, `SEC-<FAMILY>-<NN>`. Never reused, never renumbered. |
| **Statement** | ✅ | One normative sentence using MUST / MUST NOT / SHOULD. |
| **Rationale** | ✅ | The threat or requirement it answers, with a link. |
| **Implementation** | ✅ | Concrete artefact, file, setting, or algorithm with parameters. |
| **Verification** | ✅ | The `T-*` test that proves it, and the gate severity. |
| **Detection** | 🟡 | Metric, log field, or `AL-*` rule that reveals violation. |
| **Owner** | ✅ | The role accountable for the control operating. |
| **Cadence** | ✅ | Continuous / per-release / quarterly / annual. |
| **Framework mapping** | ✅ | OWASP 2025, ASVS 5.0, ISO Annex A, NIST 800-53, GDPR. |

### 5.2 Control Lifecycle

```mermaid
%%{init: {"theme":"base","themeVariables":{"primaryColor":"#6C5CE7","primaryTextColor":"#E8ECF8","primaryBorderColor":"#6C5CE7","lineColor":"#8B95B8","fontFamily":"Inter, sans-serif"}}}%%
flowchart LR
    D["🟣 Draft<br/>identified gap"]:::s1
    R["🟡 Reviewed<br/>+ threat modelled"]:::s2
    I["🟠 Implemented<br/>code/config merged"]:::s3
    T["🧪 Tested<br/>T-* passes in CI"]:::s4
    E["🟢 Enforced<br/>+ detection live"]:::s5
    M["🔴 Contested<br/>or regressed"]:::s6
    W["⬛ Retired<br/>superseded / N/A"]:::s7
    D --> R --> I --> T --> E
    E -->|test fails| M
    M -->|fix| I
    M -->|accepted risk| W
    E -->|superseded| W
    classDef s1 fill:#241A4D,stroke:#6C5CE7,color:#E8ECF8
    classDef s2 fill:#2E2205,stroke:#FFD166,color:#0B0E1A
    classDef s3 fill:#3A2A05,stroke:#FF9F1C,color:#E8ECF8
    classDef s4 fill:#062B3A,stroke:#00D2FF,color:#E8ECF8
    classDef s5 fill:#06251D,stroke:#06D6A0,color:#E8ECF8
    classDef s6 fill:#2A1220,stroke:#EF476F,color:#E8ECF8
    classDef s7 fill:#141A2E,stroke:#8B95B8,color:#E8ECF8
```

**Lifecycle rules**

| Rule | Statement |
|:--|:--|
| 🟢 **CL-01** | A control reaches 🟢 Enforced only when its `T-*` test runs in CI **and** its detection signal is live in the SIEM. |
| 🔴 **CL-02** | A regression in an 🟢 control immediately downgrades it to 🔴 Contested and opens a P2 at minimum. |
| 🟡 **CL-03** | Retired controls keep their ID reserved. Reusing an ID for a different control breaks every audit trail that referenced it. |
| 🟢 **CL-04** | The control index in [§22.1](#221-complete-control-index) is generated from the control records, never maintained by hand. |
| 🟡 **CL-05** | Any control whose implementation is deferred to a later roadmap phase is 🔴 Gap with an explicit risk acceptance reference — never silently omitted. |

### 5.3 Control Density by Family

| Family | Controls | Critical | High | Medium | Owner |
|:--|--:|--:|--:|--:|:--|
| 🔵 `SEC-IAM` — Identity & Session | 9 | 3 | 4 | 2 | Security Eng |
| 🔴 `SEC-AUTH` — Authorisation & SoD | 9 | 5 | 3 | 1 | Security Eng |
| 🟢 `SEC-APP` — Application Hardening | 14 | 4 | 6 | 4 | Backend Lead |
| 🟣 `SEC-CRY` — Cryptography & Secrets | 10 | 3 | 4 | 3 | Platform Lead |
| 🟠 `SEC-SC` — Supply Chain | 8 | 2 | 4 | 2 | Platform Lead |
| 🔵 `SEC-DATA` — Data Protection & Privacy | 9 | 2 | 4 | 3 | Data Lead + DPO |
| 🔴 `SEC-AUD` — Audit & Detection | 9 | 4 | 3 | 2 | Security Eng |
| 🟡 `SEC-INFRA` — Infrastructure & Containers | 8 | 2 | 4 | 2 | Platform Lead |
| 🔵 `SEC-EXT` — Third-Party & Webhook Trust | 7 | 3 | 3 | 1 | Platform Lead |
| 🟣 `SEC-SDLC` — Process & Governance | 8 | 1 | 3 | 4 | Security Eng |
| 🟠 `SEC-IR` — Incident Response & Continuity | 6 | 3 | 2 | 1 | Security Eng + Platform |
| **Total** | **97** | **32** | **40** | **25** | — |

### 5.4 Severity Model

| Severity | Definition | Response SLA | Gate behaviour |
|:--|:--|:--:|:--|
| 🔴 **Critical** | Exploitable path to score falsification, evidence destruction, credential/key compromise, or personal-data breach | Patch ≤ 24 h; contain ≤ 1 h | 🔴 Blocks release. Blocks deploy. |
| 🟠 **High** | Materially weakens defence in depth; enables escalation but not direct compromise | Fix ≤ 7 d | 🔴 Blocks release unless risk-accepted with expiry |
| 🟡 **Medium** | Weakens a control's assurance; requires another control to fail first | Fix ≤ 30 d | 🟡 Advisory in CI; tracked |
| 🟢 **Low** | Hardening improvement, best practice, defence in depth | Fix ≤ 90 d | 🟢 Informational |
| ⬛ **N/A** | Not applicable to this deployment; justification recorded | — | Documented in the SoA |

> 🔍 **Severity is assigned by outcome, not by category.** A missing rate limit on the public leaderboard is 🟡; a missing authorisation check on `score.adjust` is 🔴. The CVSS of the underlying weakness is a *tie-breaker*, never the primary input.

---

## 6. 🔵 Identity & Session Controls

**Family objective:** an attacker cannot become, or remain, an authorised human or machine identity — and every identity action leaves an attributable record.

```mermaid
%%{init: {"theme":"base","themeVariables":{"primaryColor":"#00D2FF","primaryTextColor":"#E8ECF8","primaryBorderColor":"#00D2FF","lineColor":"#8B95B8","fontFamily":"Inter, sans-serif"}}}%%
flowchart TB
    subgraph E["🌍 EXTERNAL IDENTITIES"]
        E1["🧑‍💻 Human staff"]:::ext
        E2["🧑‍💻 Participant"]:::ext
        E3["🤖 CTF platform"]:::ext
        E4["👥 Spectator (anonymous)"]:::ext
    end
    subgraph V["🔐 VERIFICATION PLANE"]
        V1["🆔 OIDC Code + PKCE"]:::v
        V2["📱 MFA · WebAuthn/TOTP"]:::v
        V3["🧠 Risk engine"]:::v
        V4["🎫 Session authority"]:::v
    end
    subgraph S["🗄️ SESSION STATE"]
        S1["__Host-sc3 cookie"]:::s
        S2["⚡ Redis denylist"]:::s
        S3["🗄️ Server-side session"]:::s
        S4["🎫 Scoped kiosk token"]:::s
    end
    subgraph G["🛡️ GUARANTEES"]
        G1["✅ No local accounts in steady state"]:::g
        G2["✅ 15 min idle / 8 h absolute"]:::g
        G3["✅ Revocation propagates ≤ 60 s"]:::g
        G4["✅ Break-glass sealed + alerted"]:::g
    end
    E1 --> V1 --> V2 --> V4
    E2 --> V1
    E3 --> V3
    E4 -.->|"never authenticated"| G1
    V4 --> S1 & S2 & S3 & S4
    S --> G2 & G3 & G4
    classDef ext fill:#141A2E,stroke:#8B95B8,color:#E8ECF8
    classDef v fill:#241A4D,stroke:#6C5CE7,color:#E8ECF8
    classDef s fill:#062B3A,stroke:#00D2FF,color:#E8ECF8
    classDef g fill:#06251D,stroke:#06D6A0,color:#E8ECF8
```

### 6.1 Control Catalogue

| ID | Control Statement | Sev | Implementation | Verified by |
|:--|:--|:-:|:--|:--|
| **SEC-IAM-01** | Authentication **MUST** use OIDC Authorization Code with PKCE (`S256`); implicit and password flows **MUST NOT** be enabled | 🔴 | `idp/oidc-client.ts`; `response_type=code`, `code_challenge_method=S256`; `nonce` + `state` both required | `T-IAM-01` 🔴 |
| **SEC-IAM-02** | MFA **MUST** be enforced for every staff role; WebAuthn/FIDO2 preferred, TOTP (RFC 6238) permitted as fallback | 🔴 | IdP policy `mfa_required=true` for all staff groups; `mfaSatisfied` recorded on every session | `T-IAM-02` 🔴 |
| **SEC-IAM-03** | Session cookies **MUST** use the `__Host-` prefix with `Secure`, `HttpOnly`, `Path=/`, no `Domain`, `SameSite=Strict` | 🟠 | `Set-Cookie: __Host-sc3=…; Secure; HttpOnly; Path=/; SameSite=Strict` | `T-IAM-03` 🟠 |
| **SEC-IAM-04** | Sessions **MUST** expire after 15 min idle / 8 h absolute, and 4 h / 5 min idle for `auditor` and `security_admin` | 🟠 | Server-side session store; TTL enforced in Redis **and** asserted in the API gateway | `T-IAM-04` 🟠 |
| **SEC-IAM-05** | Passwords **MUST** be stored as Argon2id (`m=64 MiB, t=3, p=4`); local accounts are break-glass only | 🟠 | Vault sealed break-glass set; `password_encryption` irrelevant (no PG role passwords in cleartext) | `T-IAM-05` 🟠 |
| **SEC-IAM-06** | Brute-force defence **MUST** limit 5 attempts / 15 min per account and per IP, with exponential backoff to 24 h and `🔴` alerting | 🟠 | Rate-limit middleware + risk engine; AL-11 | `T-IAM-06` 🟠 |
| **SEC-IAM-07** | Session revocation **MUST** propagate to API, SSE streams, and cached authorisation within 60 s of a role change, disablement, or `breakglass` event | 🟠 | Redis denylist + full-table sweep; SSE closed with reason `420` | `T-IAM-07` 🔴 |
| **SEC-IAM-08** | Break-glass access **MUST** require two-person authorisation, auto-expire after 60 min, and trigger an immediate P1 | 🔴 | Sealed offline envelope; `breakglass.activated` audit + AL-06; post-hoc CISO review ≤ 24 h | `T-IAM-08` 🔴 |
| **SEC-IAM-09** | Device posture **MUST** be attested for `security_admin` sessions; kiosk displays **MUST** receive scope-limited tokens that cannot reach admin routes | 🟡 | WebAuthn device attestation; `aud=sc3d-kiosk` token with `/api/v1/leaderboard/*` only | `T-IAM-09` 🟡 |

### 6.2 Authentication Hardening Detail

| Concern | Requirement | Reference |
|:--|:--|:--|
| 🧾 Token validation | Verify signature, `iss`, `aud`, `exp`, `nbf`, and `jti`; `kid`-based JWKS resolution with 90-day dual-active rotation | [`architecture.md` §12.2](./architecture.md#122-key-hierarchy--lifecycle) |
| 🎲 Replay defence | `jti` recorded in a Redis replay cache with a 10-minute TTL; reuse is a 🔴 auth failure | SP-07 |
| 🔑 Token storage | Access tokens held **in memory only**; `localStorage` / `sessionStorage` **MUST NOT** be used for any credential | SP-09 |
| 🕵️ Fingerprinting | `userAgentHash` and `ipPrefix` recorded for correlation; raw IP truncated to /24 for GDPR minimisation in the audit explorer | SEC-DATA-04 |
| 🚫 Anonymous admin | If the IdP is unreachable, admin routes **MUST** fail closed; the public board continues | SP-04 |
| 🧾 Recovery codes | 10 single-use codes, Argon2id-hashed, printed once, regeneration audited (`user.mfa.enrolled`) | SEC-IAM-02 |
| 🟡 Password policy | ≥ 16 characters, blocklist check via k-anonymity API, **no** composition rules (NIST 800-63B) | A.5.17 |
| 🔍 Enumeration | Login, recovery, and MFA flows **MUST** return indistinguishable responses for unknown and known principals | `T-IAM-10` 🔴 |

```http
# Session establishment — response header contract
Set-Cookie: __Host-sc3=<256-bit CSPRNG>; Secure; HttpOnly; Path=/; SameSite=Strict
Cache-Control: no-store, max-age=0
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
X-Request-Id: 4bf92f3577b34da6a3ce929d0e0e4736
```

> 🔒 **No client-side secret, ever.** The SPA bundle contains no API key, no signing key, no signing secret. This is a structural property ([SP-09](#3--security-principles)) rather than a policy, because a secret in a published bundle is permanently compromised in every browser cache — an unfixable finding. All privileged operations are cookie-authenticated same-origin calls.

---

## 7. 🔴 Authorisation & Separation of Duties

**Family objective:** every request is authorised by a deny-by-default decision that is recorded, and no single identity can both change a score and erase the proof.

### 7.1 Authorisation Pipeline

```mermaid
%%{init: {"theme":"base","themeVariables":{"primaryColor":"#EF476F","primaryTextColor":"#E8ECF8","primaryBorderColor":"#EF476F","lineColor":"#8B95B8","fontFamily":"Inter, sans-serif"}}}%%
flowchart TB
    R["📨 Request"]:::in
    A1["1️⃣ AuthN<br/>session + exp + revocation"]:::p
    A2["2️⃣ CSRF<br/>double-submit + Origin"]:::p
    A3["3️⃣ Validation<br/>Zod .strict()"]:::p
    A4["4️⃣ Rate limit<br/>+ payload size"]:::p
    A5["5️⃣ PDP evaluate<br/>RBAC ∧ ABAC"]:::p
    A6["6️⃣ Step-up check<br/>SU permissions"]:::p
    A7["7️⃣ Two-person check<br/>2P permissions"]:::p
    A8["8️⃣ RLS<br/>DB-enforced scoping"]:::p
    A9["9️⃣ Mutation<br/>+ audit in ONE txn"]:::p
    A10["✅ Allow + obligation"]:::ok
    DENY["🔴 Deny 403<br/>+ access.denied audit"]:::no
    R --> A1 --> A2 --> A3 --> A4 --> A5 --> A6 --> A7 --> A8 --> A9 --> A10
    A1 -.->|fail| DENY
    A3 -.->|fail| DENY
    A5 -.->|fail| DENY
    A5 -.->|"PDP unreachable"| DENY
    A6 -.->|absent| DENY
    A7 -.->|self-approve| DENY
    classDef in fill:#141A2E,stroke:#8B95B8,color:#E8ECF8
    classDef p fill:#241A4D,stroke:#6C5CE7,color:#E8ECF8
    classDef ok fill:#06251D,stroke:#06D6A0,color:#E8ECF8
    classDef no fill:#2A1220,stroke:#EF476F,color:#E8ECF8
```

> ⚠️ **Order is normative.** Authorisation is evaluated **after** validation (so policy never evaluates attacker-controlled shapes) and **before** the data access layer (so RLS sees a scoped identity). Every `deny` path emits `access.denied` with the correlation ID, the PDP decision, and the policy version — a silent deny is an A09 monitoring failure.

### 7.2 Control Catalogue

| ID | Control Statement | Sev | Implementation | Verified by |
|:--|:--|:-:|:--|:--|
| **SEC-AUTH-01** | Authorisation **MUST** be deny-by-default; the absence of an explicit allow is a deny | 🔴 | `policies/sc3d/authz.rego` — `default decision := {"allow": false}` | `T-AUTH-01` 🔴 |
| **SEC-AUTH-02** | Every protected route **MUST** be covered by the automated authz matrix test (routes × roles × resources) with **no** untested combination | 🔴 | `tests/security/authz-matrix.spec.ts`; 100 % coverage gate | `T-AUTH-02` 🔴 |
| **SEC-AUTH-03** | `SU` permissions (`audit:read`, `audit:export`, `score:adjust`, `policy:deploy`, `secret:read`, `user:manage`) **MUST** require re-authentication within 5 minutes | 🔴 | Step-up matrix; `stepUpSatisfied` in the audit record | `T-AUTH-03` 🔴 |
| **SEC-AUTH-04** | Object-level authorisation **MUST** be enforced on every resource access; a client-supplied identifier **MUST NOT** be trusted without a resource-scoped check | 🔴 | Repository layer requires an `actor` parameter (SC-11); BOLA fuzz suite | `T-AUTH-04` 🔴 |
| **SEC-AUTH-05** | Row-Level Security **MUST** be forced for every application role; `row_security = on` with the app role non-owner | 🟠 | `ALTER TABLE … FORCE ROW LEVEL SECURITY`; policies per role | `T-AUTH-05` 🟠 |
| **SEC-AUTH-06** | Database roles **MUST** be least-privilege and separated: `app_rw`, `app_ro`, `ingest_ro`, `audit_ro`, `report_ro`, `seal_wo`, `migrator` | 🟠 | Role grants in `db/roles.sql`; no shared superuser; Vault dynamic creds TTL 1 h | `T-AUTH-06` 🟠 |
| **SEC-AUTH-07** | Score mutation and freeze **MUST** require two distinct people; self-approval **MUST** be impossible | 🔴 | `pending_approval` state; second approver ≠ requester; AL-05 on bypass attempt | `T-AUTH-07` 🔴 |
| **SEC-AUTH-08** | No identity **MUST** hold both score-mutation authority and audit-deletion authority | 🔴 | Database grants: no non-owner role has `DELETE` on `audit_log`; asserted continuously | `T-AUTH-08` 🔴 |
| **SEC-AUTH-09** | No identity **MUST** hold both `role:manage` and `policy:deploy`; policy deploys **MUST** require a signed bundle and a 24 h change window | 🟠 | Continuous compliance test; `separation_of_duties` policy | `T-AUTH-09` 🟠 |

### 7.3 Separation of Duties — Binding Matrix

| Action | Requester | Approver | Mechanism | Control |
|:--|:--|:--|:--|:--|
| Manual score adjustment | `referee_lead` | `referee_lead` (different person) | `pending_approval` + second approver | `SEC-AUTH-07` |
| Freeze / unfreeze top 3 | `referee_lead` | `referee_lead` (different person) | Same two-person flow | `SEC-AUTH-07` |
| Revert a solve | `referee` | — (single actor, fully audited) | Reversal event + `before`/`after` diff | `SEC-AUD-02` |
| User role grant | `security_admin` | `security_admin` (different person) | 2-of-2 approval + SoD policy | `SEC-AUTH-09` |
| Policy bundle deploy | `security_admin` | `security_admin` (different person) | Signed bundle, dual approval, 24 h window | `SEC-AUTH-09` |
| Report template registration | `ops_admin` | `security_admin` | Sandbox required + signature | `SEC-SC-06` |
| Audit log export | `auditor` | — (read-only, itself audited) | Cannot delete; export logged | `SEC-AUD-05` |
| Backup restore | `security_admin` | `security_admin` (different person) | Change window + `critical_system_operation` | SEC-IR-04 |
| Break-glass activation | `oncall` | Post-hoc CISO review ≤ 24 h | 60-min auto-expiry + P1 | `SEC-IAM-08` |

### 7.4 ABAC Obligations

Every allow decision may carry obligations. An obligation that cannot be satisfied converts the decision to a **deny**, never to a warning.

| Obligation | Trigger | Effect if unsatisfiable |
|:--|:--|:--|
| `audit:log_decision` | Every privileged decision | 🔴 Deny — SP-03 |
| `mfa:webauthn` | `security_admin`, `auditor` with export | 🔴 Deny |
| `step_up:5min` | SU permissions | 🔴 Deny |
| `two_person` | `score.adjust`, `event:freeze` | 🔴 Deny |
| `window:maintenance` | High-risk action outside a change window | 🔴 Deny |
| `device:managed` | `security_admin` | 🔴 Deny |
| `watermark:confidential` | Report download at classification ≥ confidential | 🔴 Deny download |
| `ip:allowlist` | Admin console from a managed range | 🟠 Step-up challenge |

```yaml
# Obligation semantics — a partially satisfiable obligation set is a denial
decision := {
  "allow": true,
  "obligations": ["audit:log_decision", "mfa:webauthn", "step_up:5min"],
  "policyId": "pol-2026-09-14.3",
  "expiresAt": "2026-09-26T19:09:11.482Z"   # step-up validity window
}
# PDP returns allow=false if any obligation has no satisfied evaluator.
```

### 7.5 Banned Permission Combinations (Continuous Assertions)

| Assertion | Query | Fail Action |
|:--|:--|:--|
| No role with `score:adjust` also has any `audit:*write` or delete capability | Entitlement reconciliation query | 🔴 P1 + auto-revoke |
| No identity with `role:manage` also has `policy:deploy` | Entitlement reconciliation query | 🔴 P1 + auto-revoke |
| No identity with `secret:read` also has `policy:deploy` | Entitlement reconciliation query | 🟠 P2 + review task |
| No dormant privileged account > 60 days | AL-22 query | 🟡 P3 + review task |
| No service identity outside its declared scope | Scope-diff check | 🟠 P2 |

> 🧪 These are not quarterly reports. They are **CI assertions on every deploy** and **hourly reconciliation jobs**, because an entitlement that drifts silently for 89 days is the actual threat, not the grant itself.

---

## 8. 🟢 Application Hardening Controls

**Family objective:** the application fails safely, validates everything, leaks nothing, and treats every byte from outside the trust boundary as hostile.

### 8.1 Request Handling Controls

| ID | Control Statement | Sev | Implementation | Verified by |
|:--|:--|:-:|:--|:--|
| **SEC-APP-01** | Every request body, query, header, and path parameter **MUST** be validated with a Zod `.strict()` schema at the boundary; unknown keys **MUST** be rejected | 🔴 | `packages/validation/`; `.strict()` on all 40+ endpoint schemas | `T-APP-01` 🔴 |
| **SEC-APP-02** | Database access **MUST** use parameterised queries exclusively; string-concatenated SQL is prohibited | 🔴 | Repository layer; ESLint `no-unsafe-*`; Semgrep rule `sql-injection` | `T-APP-02` 🔴 |
| **SEC-APP-03** | Client-supplied `rank`, `score`, `points`, or identity **MUST** be ignored or rejected; the server recomputes all of them | 🔴 | DTO whitelist; `sc-03` custom lint rule; rank never accepted from the client | `T-APP-03` 🔴 |
| **SEC-APP-04** | Dynamic HTML **MUST** be contextually encoded; `innerHTML`, `dangerouslySetInnerHTML`, and `eval` are prohibited | 🔴 | ESLint bans; DOMPurify for the rare sanitised case; Trusted Types enforced | `T-APP-04` 🔴 |
| **SEC-APP-05** | Content-Security-Policy **MUST** be enforced with `default-src 'none'`, nonce-based `script-src`, and `require-trusted-types-for 'script'` | 🔴 | [`architecture.md` §10.6](./architecture.md#106-content-security-policy) | `T-APP-05` 🔴 |
| **SEC-APP-06** | Sub-resources **MUST** carry integrity attributes, and the bundle digest **MUST** be pinned in `index.html` | 🟠 | SRI for fonts/wasm; CSP `require-corp` + COEP | `T-APP-06` 🟠 |
| **SEC-APP-07** | Deserialisation **MUST** be schema-validated; blind `JSON.parse` into typed objects is prohibited | 🔴 | Zod at every parse boundary (`sc-14`) | `T-APP-07` 🔴 |
| **SEC-APP-08** | All mutating endpoints **MUST** require an `Idempotency-Key` and honour a 24-hour replay window | 🟠 | `Idempotency-Key` on POST/PATCH; unique index; duplicate ⇒ `200 {"status":"duplicate"}` | `T-APP-08` 🟠 |
| **SEC-APP-09** | Cache entries **MUST** be purged event-driven on mutation; a stale leaderboard read **MUST** never exceed its documented TTL | 🟠 | `stale-while-revalidate=30s`; purge published on the Redis bus | `T-APP-09` 🟠 |
| **SEC-APP-10** | Rate limits **MUST** be enforced per identity and per source: public 60/min, admin 300/hr, auth 5/15 min, reports 20/hr | 🟠 | Sliding-window limiter in Redis; AL-09 on deny-rate spikes | `T-APP-10` 🟠 |
| **SEC-APP-11** | Request bodies **MUST** be capped at 256 KB (1 MB admin), headers at 8 KB, and JSON depth at 12 | 🟡 | `bodyLimit` in Fastify; depth validator | `T-APP-11` 🟡 |
| **SEC-APP-12** | Errors returned to clients **MUST** come from the safe-message catalogue (RFC 9457); stack traces, SQL, file paths, and library versions **MUST NOT** reach the client | 🟡 | `errors/catalogue.ts`; SC-07; internal detail to correlated log only | `T-APP-12` 🟡 |
| **SEC-APP-13** | Every outbound call **MUST** have a timeout, bounded retry with jitter, and a circuit breaker | 🟠 | `resilience/` wrapper; lint-enforced (`sc-08`) | `T-APP-13` 🟠 |
| **SEC-APP-14** | Regexes **MUST** be anchored and ReDoS-checked; catastrophic backtracking patterns are prohibited | 🟡 | `safe-regex` CI gate | `T-APP-14` 🟡 |

### 8.2 Error Handling — Safe Message Catalogue

| Code | HTTP | Client-safe `title` | Operator detail (log only) |
|:--|--:|:--|:--|
| `E-AUTH-401` | 401 | Authentication required | Session missing/expired/revoked + reason enum |
| `E-AUTH-403` | 403 | Insufficient permission | PDP decision, policy version, obligation list |
| `E-AUTH-428` | 428 | Step-up authentication required | `stepUpSatisfied=false`, required re-auth age |
| `E-VAL-422` | 422 | Request failed validation | Zod issue paths + received shape (redacted) |
| `E-IDEM-409` | 409 | Idempotency key conflict | Key hash, original seq, request hash comparison |
| `E-RATE-429` | 429 | Rate limit exceeded | Limit name, window, current count, identity |
| **E-SYS-500** | 500 | Internal error | `traceId`, full exception, stack, SQL — **never** returned |
| **E-SYS-503** | 503 | Service temporarily unavailable | Failing dependency, circuit state, degradation mode |

```json
{
  "type": "https://errors.example.com/insufficient-permission",
  "title": "Insufficient permission",
  "status": 403,
  "detail": "Role 'observer' may not perform 'score.adjust' on resource 'team'.",
  "instance": "/api/v1/admin/scores/adjust",
  "traceId": "4bf92f3577b34da6a3ce929d0e0e4736",
  "timestamp": "2026-09-26T19:04:11.482Z",
  "policyVersion": "pol-2026-09-14.3"
}
```

> 🔒 `detail` is **generated from a catalogue**, never interpolated from a caught exception. A `catch` block that reaches the client layer with a raw message is a review-blocking defect, and `T-APP-15` greps the codebase for that pattern.

### 8.3 Cross-Site Controls

| Control | Requirement | Reference |
|:--|:--|:--|
| 🛡️ CSRF | Double-submit token **and** `SameSite=Strict` **and** Origin allow-list; any mismatch ⇒ 403 + audit | A01 |
| 🌐 CORS | Explicit origin allow-list; `Access-Control-Allow-Origin: *` **MUST NOT** appear with credentials; `Vary: Origin` always set | A02 |
| 🖼️ Clickjacking | `frame-ancestors 'none'` + `X-Frame-Options: DENY` | A02 |
| 📜 MIME sniffing | `X-Content-Type-Options: nosniff`; explicit `Content-Type` on every response | A02 |
| 🔗 Referrer | `strict-origin-when-cross-origin`; no query-string secrets | A04 |
| 🎥 Feature policy | `camera=(), microphone=(), geolocation=(), payment=(), usb=()` | A02 |
| 🧮 Rate/abuse | Sliding window per identity; bot scoring at the edge | A04 |
| 🔗 CSRF token scope | Token bound to session **and** path prefix; not reusable across privilege boundaries | A01 |

### 8.4 Injection Prevention Matrix

| Injection class | Vector in this system | Defence | Test |
|:--|:--|:--|:--|
| SQL | Search filters, report queries, leaderboard sort | Parameterised queries; `report_ro` role has no DML; RLS | `T-APP-02` |
| NoSQL | Redis key construction from user input | Key builder with allow-listed prefixes; no string interpolation | `T-APP-16` |
| Command | Report renderer, PDF converter, ffmpeg | Binary allow-list; no `child_process` with user input (`sc-18`) | `T-APP-17` |
| Template | Report templates (Handlebars-like) | Logic-less templates; no helper injection; sandboxed renderer | `T-APP-18` |
| XSS | Team names, challenge titles, report labels | Contextual encoding + DOMPurify + CSP + Trusted Types | `T-APP-04` |
| SSRF | Webhook URL validation, evidence-pack fetch | Egress allow-list; no user-supplied URL fetch; DNS pinning | `T-EXT-06` |
| Log | User-controlled strings in audit fields | Structured JSON logger with typed fields; control chars stripped | `T-APP-19` |
| Prototype pollution | JSON body merge | `Object.create(null)` schemas; `__proto__` key rejection in Zod | `T-APP-20` |

## 9. 🟣 Cryptography, Keys & Secrets

**Family objective:** every cryptographic decision is a standard-library decision with named parameters, every key has an owner and an expiry, and no secret is ever written to disk, a log, or a browser.

### 9.1 Algorithm Policy (Normative)

| Use case | Algorithm | Parameters | Key length | Control |
|:--|:--|:--|:--:|:--|
| HTTPS / mTLS | TLS 1.3 (1.2 fallback) | AEAD AES-256-GCM or ChaCha20-Poly1305; X25519; SHA-256 HRR | 256-bit | `SEC-CRY-01` |
| Database at rest | AES-256-GCM | Volume encryption + CMEK, FIPS 140-3 L2 | 256-bit | `SEC-CRY-02` |
| PII column | AES-256-GCM | Per-record random IV + auth tag | 256-bit | `SEC-CRY-03` |
| Blind index (PII lookup) | HMAC-SHA-256 | Key separate from the encryption key | 256-bit | `SEC-CRY-03` |
| Password hashing | Argon2id | m=64 MiB, t=3, p=4 | — | `SEC-IAM-05` |
| TOTP | HMAC-SHA-1 (RFC 6238) | 6 digits, 30 s, ±1 step | 160-bit | `SEC-IAM-02` |
| WebAuthn | ES256 (P-256) or Ed25519 | Attestation: none / indirect | 256-bit | `SEC-IAM-02` |
| JWT signing | RS-256 or ES-256 | `kid` header, JWKS dual-active rotation | 2048/256-bit | `SEC-CRY-04` |
| Webhook signing | HMAC-SHA-256 | Per-partner key, constant-time compare | 256-bit | `SEC-EXT-02` |
| Audit chain hash | SHA-256 | `SHA256(prev_hash ‖ canonical_event)` | 256-bit | `SEC-AUD-03` |
| Merkle root | SHA-256 | Batched every 1,000 events or 5 min | 256-bit | `SEC-AUD-05` |
| Object storage | SSE-KMS | CMEK per class, annual rotation | 256-bit | `SEC-CRY-02` |
| Report signing | RSA-PSS-4096 or Ed25519 | Detached signature; public key embedded | 4096/256-bit | `SEC-CRY-06` |
| Artefact signing | Sigstore / cosign | Keyless (OIDC) or KMS; ECDSA P-256 | 256-bit | `SEC-SC-04` |
| Randomness | `crypto.randomBytes` / `os.urandom` | CSPRNG only | 256-bit | `SEC-CRY-07` |

```mermaid
%%{init: {"theme":"base","themeVariables":{"primaryColor":"#6C5CE7","primaryTextColor":"#E8ECF8","primaryBorderColor":"#6C5CE7","lineColor":"#8B95B8","fontFamily":"Inter, sans-serif"}}}%%
flowchart TB
    subgraph F["🚫 FORBIDDEN — blocked by crypto-lint, 🔴 gating"]
        F1["❌ MD5"]:::bad
        F2["❌ SHA-1 (except TOTP per RFC 6238)"]:::bad
        F3["❌ DES / 3DES / RC4"]:::bad
        F4["❌ ECB mode"]:::bad
        F5["❌ Static IVs"]:::bad
        F6["❌ Math.random() for tokens, nonces, IDs"]:::bad
        F7["❌ Bespoke / home-made ciphers"]:::bad
        F8["❌ 'Encrypted' fields without an AEAD"]:::bad
    end
    subgraph A["✅ ALLOWED — the entire approved surface"]
        A1["✅ TLS 1.3 · AES-256-GCM · ChaCha20-Poly1305"]:::ok
        A2["✅ Argon2id · bcrypt (legacy read only)"]:::ok
        A3["✅ Ed25519 · ES256 · RS-PSS · RS256"]:::ok
        A4["✅ HMAC-SHA-256 · SHA-256 · SHA-512"]:::ok
        A5["✅ HKDF · X25519 · ECDH"]:::ok
    end
    F ==>|"crypto-lint CI gate"| STOP(["🚫 BUILD BLOCKED"]):::stop
    A ==> GO(["✅ PERMITTED"]):::go
    classDef bad fill:#2A1220,stroke:#EF476F,color:#E8ECF8
    classDef ok fill:#06251D,stroke:#06D6A0,color:#E8ECF8
    classDef stop fill:#EF476F,stroke:#E8ECF8,stroke-width:3px,color:#0B0E1A
    classDef go fill:#06251D,stroke:#06D6A0,stroke-width:3px,color:#E8ECF8
```

> ⚠️ **Bespoke cryptography is a finding, not a contribution.** The only acceptable way to add an algorithm is to add it to the approved list, update the key inventory, and add a rotation plan. RFC 9106 / NIST SP 800-131A Rev. 2 alignment is asserted by `T-CRY-01`.

### 9.2 Control Catalogue

| ID | Control Statement | Sev | Implementation | Verified by |
|:--|:--|:-:|:--|:--|
| **SEC-CRY-01** | Transport **MUST** be TLS 1.3 with TLS 1.2 fallback; HSTS **MUST** be `max-age=63072000; includeSubDomains; preload` | 🔴 | `nginx/tls.conf`; `ssl_protocols TLSv1.3 TLSv1.2`; cipher allow-list only | `T-CRY-02` 🔴 |
| **SEC-CRY-02** | Data at rest **MUST** use AES-256-GCM with a customer-managed key (CMEK) per data class; disk-only encryption is insufficient | 🔴 | KMS CMK per class; `pgBackRest` encrypted; S3 SSE-KMS | `T-CRY-03` 🔴 |
| **SEC-CRY-03** | PII columns **MUST** use per-record random IV AES-256-GCM, with a **separate** HMAC key for the blind index (key separation) | 🟠 | `crypto/pii.ts`; `blind_index = HMAC(k_idx, lower(email))` | `T-CRY-04` 🟠 |
| **SEC-CRY-04** | Signing keys **MUST** be KMS/HSM-resident, rotated per the key matrix, and support dual-active overlap for zero-downtime rotation | 🟠 | [`architecture.md` §12.2](./architecture.md#122-key-hierarchy--lifecycle); rotation is an audited event | `T-CRY-05` 🟠 |
| **SEC-CRY-05** | Key material **MUST NOT** be generated in application code, committed, logged, or written to disk outside Vault | 🔴 | KMS/HSM generation only; `noexec,nosuid,nodev` tmpfs for secrets | `T-CRY-06` 🔴 |
| **SEC-CRY-06** | Reports and evidence artefacts **MUST** carry a detached signature, and the verifying public key **MUST** be distributed with the artefact | 🟠 | RSA-PSS-4096 / Ed25519 detached signature + embedded public key + verification instructions | `T-CRY-07` 🟠 |
| **SEC-CRY-07** | All security-relevant randomness **MUST** come from a CSPRNG; `Math.random()` **MUST NOT** produce tokens, nonces, IVs, or IDs | 🟠 | Entropy lint rule; `crypto.randomBytes` / `os.urandom` only | `T-CRY-08` 🟠 |
| **SEC-CRY-08** | No credential or key **MUST** ever reach the browser: no API keys, no signing keys, no bearer tokens in JS storage | 🔴 | Structural; bundle analyser fails on high-entropy strings; SP-09 | `T-CRY-09` 🔴 |
| **SEC-CRY-09** | Compromise **MUST** trigger revocation of the affected key within 1 hour, with dependent key re-issue planned and recorded | 🟠 | IR-4 playbook; key inventory owner notified; `secret.rotated` audit | `T-CRY-10` 🟠 |
| **SEC-CRY-10** | The system **MUST** be crypto-agile: algorithm identifiers live in a versioned configuration, never hard-coded, so a PQC migration is a config change | 🟡 | `crypto/algorithms.yaml`; NIST PQC migration readiness | `T-CRY-11` 🟡 |

### 9.3 Key Inventory (Authoritative Extract)

| Key | Algorithm | Location | Rotation | Owner | Backup |
|:--|:--|:--|:--|:--|:--|
| 🔑 Root CA | RSA-4096 | HSM, offline, air-gapped | 10 years | Platform Lead | HSM-wrapped, annual restore test |
| 🔑 TLS Issuing CA | RS-256 | KMS HSM | 2 years | Platform Lead | HSM-wrapped |
| 🔑 JWT signing | ES-256 | KMS HSM | 90 days, dual active | Security Eng | HSM-wrapped |
| 🔑 Code signing | Ed25519 | KMS HSM | 1 year | Platform Lead | HSM-wrapped |
| 🔑 DB CMEK | AES-256 | Cloud KMS | 1 year, automatic | Data Lead | HSM-wrapped |
| 🔑 S3 SSE-KMS CMEK | AES-256 | Cloud KMS | 1 year | Data Lead | HSM-wrapped |
| 🔑 PII data key | AES-256-GCM | Vault transit | 90 days | DPO | Raft snapshot, sealed |
| 🔑 Blind index key | HMAC-SHA-256 | Vault transit | 90 days | DPO | Raft snapshot, sealed |
| 🔑 Webhook HMAC | HMAC-SHA-256 | Vault | 1 year, dual-key overlap | Platform Lead | Raft snapshot, sealed |
| 🔑 Dynamic DB credentials | — | Vault | TTL 1 hour, single use | Platform Lead | Not backed up (by design) |
| 🔑 Report signing | RSA-PSS-4096 | KMS | 1 year | GRC | HSM-wrapped |
| 🔑 Break-glass set | — | Sealed envelope + Vault | On use | Security Eng | Two offline copies |

### 9.4 Secret-Handling Prohibitions

| Prohibition | Enforcement | Gate |
|:--|:--|:--|
| ❌ Secrets in git, ever | `gitleaks` + `trufflehog`, full history | 🔴 Block |
| ❌ Secrets in container images / layers | Trivy secret scanner | 🔴 Block |
| ❌ Secrets in client bundles | Bundle analyser, high-entropy scan | 🔴 Block |
| ❌ Secrets in logs | Log scrubber + entropy detector on **all** output streams | 🔴 Block |
| ❌ Secrets in error messages | Safe catalogue only (`SEC-APP-12`) | 🔴 Block |
| ❌ Secrets in URLs or query strings | POST/PUT only; URL redaction middleware | 🟠 Fail |
| ❌ Long-lived cloud keys | OIDC federation everywhere; 15-minute CI credentials | 🔴 Block |
| ❌ Shared credentials | Per-identity, per-role; no `admin:admin` | 🔴 Block |
| ❌ `.env` committed | `.env.example` committed, `.env` gitignored and verified absent | 🔴 Block |
| ❌ Secrets as environment variables in images | Vault Agent sidecar → tmpfs | 🟠 Review |

```bash
# The only permitted way to obtain a database credential at runtime
vault read -format=json database/creds/sc3d_app_rw \
  | jq -r '.data | "postgres://\(.username):\(.password)@postgres:5432/sc3d?sslmode=verify-full"'
# TTL 3600 s, single use, every read audited, connection closed on release.
```

---

## 10. 🟠 Software Supply Chain Controls

**Family objective:** every artefact that runs is traceable to a reviewed source commit, built by a known pipeline, described by an SBOM, and cryptographically signed — and anything unsigned never starts.

```mermaid
%%{init: {"theme":"base","themeVariables":{"primaryColor":"#FF9F1C","primaryTextColor":"#E8ECF8","primaryBorderColor":"#FF9F1C","lineColor":"#8B95B8","fontFamily":"Inter, sans-serif"}}}%%
flowchart LR
    S["🌱 Source<br/>reviewed commit"]:::s
    W["🔨 Build<br/>hermetic, pinned"]:::b
    P["📦 SBOM<br/>SPDX + CycloneDX"]:::p
    V["🔍 Verify<br/>SCA · secret · IaC"]:::v
    G["✍️ Sign<br/>cosign keyless"]:::g
    PR["🏷️ Provenance<br/>SLSA L3"]:::pr
    R[("🗄️ Registry<br/>by digest only")]:::r
    D["🚀 Deploy<br/>2-person prod"]:::d
    A["🔍 Admission<br/>verify sig + policy"]:::a
    X["🚫 Unsigned /<br/>unsigned-push ⇒ halt"]:::x
    S --> W --> P --> V --> G --> PR --> R --> D --> A
    G -.->|cosign verify fails| X
    R -.->|mutable tag used| X
    S --> W
    W --> X
    classDef s fill:#06251D,stroke:#06D6A0,color:#E8ECF8
    classDef b fill:#241A4D,stroke:#6C5CE7,color:#E8ECF8
    classDef p fill:#062B3A,stroke:#00D2FF,color:#E8ECF8
    classDef v fill:#2E2205,stroke:#FFD166,color:#0B0E1A
    classDef g fill:#3A2A05,stroke:#FF9F1C,color:#E8ECF8
    classDef pr fill:#2A1220,stroke:#EF476F,color:#E8ECF8
    classDef r fill:#141A2E,stroke:#8B95B8,color:#E8ECF8
    classDef d fill:#241A4D,stroke:#6C5CE7,color:#E8ECF8
    classDef a fill:#062B3A,stroke:#00D2FF,color:#E8ECF8
    classDef x fill:#EF476F,stroke:#E8ECF8,stroke-width:3px,color:#0B0E1A
```

### 10.1 Control Catalogue

| ID | Control Statement | Sev | Implementation | Verified by |
|:--|:--|:-:|:--|:--|
| **SEC-SC-01** | Every build **MUST** emit an SBOM in SPDX **and** CycloneDX, stored with the artefact and diffed on each release | 🟠 | `syft` in CI; artefact retained 7 years alongside provenance | `T-SC-01` 🟠 |
| **SEC-SC-02** | Dependencies **MUST** be installed from a lockfile with integrity hashes; a lockfile change is a security-relevant change requiring review | 🟠 | `npm ci` only; `CODEOWNERS` on lockfiles; CI diff check | `T-SC-02` 🟠 |
| **SEC-SC-03** | `postinstall` scripts **MUST** be disabled in CI; packages needing build steps are built and signed explicitly | 🔴 | `--ignore-scripts`; explicit build stage with its own scan | `T-SC-03` 🔴 |
| **SEC-SC-04** | Images **MUST** be signed with cosign, and deployment **MUST** verify the signature; verification failure **MUST** halt the deploy | 🔴 | Keyless OIDC signing; `cosign verify` in the deploy job; AL-13 | `T-SC-04` 🔴 |
| **SEC-SC-05** | Images **MUST** be referenced by digest (`image@sha256:…`); mutable tags **MUST NOT** be used in any deployment manifest | 🟠 | Kubernetes manifests + Compose files pinned by digest | `T-SC-05` 🟠 |
| **SEC-SC-06** | A dependency allow-list **MUST** block any package not explicitly approved by the security team; new dependencies sit a **7-day quarantine** | 🟠 | Allow-list in `policy/deps.yaml`; OPA gatekeeper; quarantine workflow | `T-SC-06` 🟠 |
| **SEC-SC-07** | CI/CD workflows **MUST** pin third-party actions to a full commit SHA and run with `permissions: read-all` plus an explicit allow-list | 🟠 | `.github/workflows/*`; `zizmor` / `actionlint` in CI | `T-SC-07` 🟠 |
| **SEC-SC-08** | Build provenance **MUST** meet SLSA Build L3 expectations: hermetic build, isolated runner, two-party review for source changes | 🟠 | `slsa-verifier`; isolated ephemeral runners; branch protection | `T-SC-08` 🟠 |

### 10.2 Vulnerability Gates

| Gate | Tool | Threshold | Behaviour |
|:--|:--|:--|:--|
| 🔴 SAST | Semgrep + CodeQL | 0 Critical / 0 High | Block |
| 🔴 SCA | `osv-scanner` + license check | 0 Critical; High ≤ 7 days | Block |
| 🔴 IaC + image | Checkov + Trivy | 0 Critical / 0 High | Block |
| 🔴 Secrets | `gitleaks` full history | 0 findings | Block |
| 🟡 Tests | Vitest + Testcontainers | Coverage ≥ 80 %; 100 % authz paths | Block |
| 🟠 DAST / fuzz | ZAP + Jazzer | 0 High; 0 unhandled crashes | Advisory → block on High |
| 🔴 Policy | OPA gatekeeper / Conftest | 0 violations | Block |
| 🟠 Crypto policy | `crypto-lint` | No weak primitive | Block |

### 10.3 Dependency Change Protocol

| Step | Actor | Artefact | Gate |
|:--|:--|:--|:--|
| 1. Request | Engineer | Dependency request with justification, licence, maintainer count | — |
| 2. Quarantine | Security Eng | 7-day observation, no production reachability | 🟡 Automated |
| 3. Review | Security Eng + code owner | Licence, provenance, CVE history, install scripts, maintainer bus factor | Human |
| 4. Allow-list | Security Eng | `policy/deps.yaml` entry with rationale | PR review |
| 5. Integrate | Engineer | Lockfile PR + SBOM diff | 🔴 CI |
| 6. Monitor | Security Eng | `renovate.json`; weekly re-scan; yank notice path | Continuous |

> 🧾 **A dependency is a supplier with an API surface.** The allow-list review asks the same questions a procurement review asks: who maintains it, how are they paid, how fast are they patched, what do they phone home to, and what happens if they are acquired. A transitive package that appears in a lockfile diff without a corresponding allow-list entry is a 🔴 build failure, not a warning.

## 11. 🔵 Data Protection & Privacy

**Family objective:** collect the minimum, protect it in transit and at rest, keep it only as long as a stated purpose requires, and honour every data-subject right without exception.

### 11.1 Data Classification

| Class | Examples | Encryption | Masking in UI | Retention | Export |
|:--|:--|:--|:--|:--|:--|
| ⚫ **Public** | Team handle, score, rank, challenge title, freeze state | Not required (public by design) | None | Indefinite (event record) | Open |
| 🔵 **Internal** | Event config, scoring model, template catalogue, non-sensitive telemetry | At rest (disk) | None | 24 months | `analyst` |
| 🟡 **Confidential** | Team member email, IP address, user agent, report contents, webhook payloads | AES-256-GCM + CMEK, PII columns | Email `j***@e***`, IP /24 | ~5 months (PII) | `analyst` + step-up + watermark |
| 🔴 **Restricted** | Audit log, evidence packs, Merkle seals, key inventory, break-glass material | AES-256-GCM + CMEK, WORM for immutable classes | Never masked for authorised readers; export watermarked | 7 years (audit) | `auditor` + 2-person |
| ⬛ **Prohibited** | Raw client secrets, plaintext passwords, full PAN-equivalent identifiers, third-party API keys | Never stored | — | Never | Never |

```mermaid
%%{init: {"theme":"base","themeVariables":{"primaryColor":"#00D2FF","primaryTextColor":"#E8ECF8","primaryBorderColor":"#00D2FF","lineColor":"#8B95B8","fontFamily":"Inter, sans-serif"}}}%%
flowchart TB
    subgraph SRC["📥 COLLECTION — minimisation gate"]
        S1["🌐 Public board<br/>no PII at all"]:::pub
        S2["📨 CTF webhook<br/>pseudonymous team id"]:::int
        S3["🧑‍💻 Staff session<br/>identity + device"]:::conf
        S4["🔍 Client RUM<br/>pseudonymous, 14 d"]:::int
    end
    subgraph PROC["⚙️ PROCESSING"]
        P1["🧬 PII column AES-GCM<br/>+ HMAC blind index"]:::proc
        P2["🔎 Redact at source<br/>before any log call"]:::proc
        P3["🗄️ RLS scoping"]:::proc
    end
    subgraph STORE["🗄️ STORAGE"]
        D1["🗄️ PostgreSQL<br/>CMEK, retention worker"]:::store
        D2["🧾 Audit store<br/>WORM 7 years"]:::store
        D3["🗄️ Redis<br/>TTL ≤ 24 h, no PII"]:::store
    end
    subgraph OUT["📤 EXPORT — controlled egress"]
        O1["📋 Report<br/>watermark + signed"]:::out
        O2["🧬 Evidence pack<br/>manifest + hashes"]:::out
        O3["🗑️ Erasure<br/>except legal hold"]:::out
    end
    S1 --> D1
    S2 --> P1 --> D1
    S3 --> P2 --> D1
    S4 --> P2 --> D3
    D1 --> D2
    D1 --> O1
    D2 --> O2
    D1 --> O3
    classDef pub fill:#06251D,stroke:#06D6A0,color:#E8ECF8
    classDef int fill:#062B3A,stroke:#00D2FF,color:#E8ECF8
    classDef conf fill:#2E2205,stroke:#FFD166,color:#0B0E1A
    classDef proc fill:#241A4D,stroke:#6C5CE7,color:#E8ECF8
    classDef store fill:#3A2A05,stroke:#FF9F1C,color:#E8ECF8
    classDef out fill:#2A1220,stroke:#EF476F,color:#E8ECF8
```

### 11.2 Control Catalogue

| ID | Control Statement | Sev | Implementation | Verified by |
|:--|:--|:-:|:--|:--|
| **SEC-DATA-01** | Collection **MUST** be minimised: no field is stored unless a documented purpose, lawful basis, and retention period exist | 🟠 | Data inventory register; DPIA before Phase 2; new-field PR checklist | `T-DATA-01` 🟠 |
| **SEC-DATA-02** | PII **MUST** be redacted at source, before any logging call, and **MUST** never appear in a log line or error payload | 🟠 | Logger middleware with typed fields; `sc-10`; unit tests on every log call site | `T-DATA-02` 🟠 |
| **SEC-DATA-03** | Team member PII **MUST** be deleted ~5 months after event end, unless a legal hold applies; the deletion **MUST** itself be audited | 🟠 | Retention worker; `info.deletion` audit event; GDPR Art. 5(1)(e) | `T-DATA-03` 🟠 |
| **SEC-DATA-04** | Pseudonymisation **MUST** be used wherever the full value is not required (IP truncated to /24, UA hashed, device id opaque) | 🟡 | Audit schema design; explorer displays prefixes only | `T-DATA-04` 🟡 |
| **SEC-DATA-05** | Personal data in backups **MUST** inherit the retention schedule, and backups **MUST NOT** be a loophole that keeps deleted data alive indefinitely | 🔴 | Backup lifecycle policy; 12-month archive with deletion tombstones; restore-time re-applied expiry | `T-DATA-06` 🔴 |
| **SEC-DATA-06** | A data breach **MUST** be assessed for GDPR Art. 33 notification within 24 h of detection, with a 72 h regulatory deadline tracked explicitly | 🟠 | IR-4 + DPO runbook; Art. 33/34 assessment artefact | `T-DATA-07` 🟠 |
| **SEC-DATA-07** | Data-subject requests (access, erasure, portability) **MUST** be fulfilled within 30 days by an automated, logged workflow | 🟡 | `dsr` service; RB-13 runbook; identity verification step | `T-DATA-08` 🟡 |
| **SEC-DATA-08** | Report and evidence downloads **MUST** be watermarked, classified, rate-limited, and logged with the requester identity | 🟠 | Watermark service; AL-08 mass-download detection; `report.downloaded` audit | `T-DATA-09` 🟠 |
| **SEC-DATA-09** | Every data class **MUST** have a documented retention schedule, a legal-hold override, and a tested deletion path | 🟠 | Retention matrix (below); quarterly deletion-job assertion | `T-DATA-10` 🟠 |

### 11.3 Retention Matrix (Security View)

| Data | Hot | Warm | Archive (WORM) | Total | Legal hold | Deletion proof |
|:--|:--|:--|:--|:--|:--:|:--|
| 🧾 Audit log | 90 d (PG) | 13 mo (search) | **7 years** | 7 yr | ✅ Overridable | Tombstone + hash manifest |
| 🏆 Score events | 90 d | 24 mo | 7 years | 7 yr | ✅ | Tombstone + hash manifest |
| 📨 Raw webhook events | 30 d | 12 mo | 24 mo | 2 yr | ✅ | Tombstone + hash manifest |
| 📋 Generated reports | 90 d (S3) | — | — | 90 d | ✅ On request | Object delete receipt |
| 🧬 Evidence artefacts | 30 d | 12 mo | **7 years** | 7 yr | ✅ | Receipt + WORM expiry record |
| 🔑 Merkle seals | 7 d | 90 d | 7 years | 7 yr | ✅ | Receipt + WORM expiry record |
| 👤 User accounts & sessions | 13 mo | — | 24 mo | 2 yr | ✅ | Tombstone |
| 👥 Team member PII | Event end + 30 d | 90 d | — | **~5 mo** | ✅ | Cryptographic erasure + audit |
| 📈 Telemetry (no PII) | 30 d | 12 mo | 24 mo | 2 yr | ❌ | Tombstone |
| 📈 Client RUM (pseudonymous) | 14 d | 90 d | — | 3 mo | ❌ | Tombstone |
| 🗄️ Backups | 35 d | — | 12 mo | 1 yr | ✅ Propagated | Restore-time re-expiry |

```mermaid
%%{init: {"theme":"base","themeVariables":{"primaryColor":"#EF476F","primaryTextColor":"#E8ECF8","primaryBorderColor":"#EF476F","lineColor":"#8B95B8","fontFamily":"Inter, sans-serif"}}}%%
flowchart LR
    subgraph NORMAL["🟢 NORMAL — no hold"]
        N1["🗄️ Write"]:::n --> N2["⏳ TTL / partition drop"]:::n --> N3["🗑️ Deleted + tombstone"]:::n
    end
    subgraph HOLD["🔴 LEGAL HOLD — hold applied"]
        H1["⚖️ Hold registered<br/>case ref + scope"]:::h --> H2["🔒 Retention worker<br/>SKIPS scope"]:::h --> H3["🧾 Hold logged<br/>who/why/until"]:::h
    end
    subgraph RELEASE["🟡 RELEASE — hold lifted"]
        R1["📋 Hold release<br/>authorised"]:::r --> R2["⏳ Backlog drains<br/>within 30 d"]:::r --> R3["🗑️ Deleted + tombstone"]:::r
    end
    N1 -.->|"hold"| H1
    H3 -.->|"release"| R1
    classDef n fill:#06251D,stroke:#06D6A0,color:#E8ECF8
    classDef h fill:#2A1220,stroke:#EF476F,color:#E8ECF8
    classDef r fill:#2E2205,stroke:#FFD166,color:#0B0E1A
```

> 🔒 **Deletion is a first-class, evidenced operation.** Every delete emits a tombstone containing the record identifier, classification, schedule applied, legal-hold status, actor (`system:retention-worker` or a human), and the resulting row/object count. "We ran the job" is not evidence; a tombstone is.

### 11.4 Privacy Engineering Rules

| Rule | Requirement |
|:--|:--|
| 🧾 Purpose binding | Every stored field links to a purpose ID in the data inventory; a field without a purpose ID is rejected at PR |
| 🕵️ Pseudonymisation first | Store the minimum identifying attribute; keep the re-identification key separate and access-logged |
| 🧬 No PII in keys | Redis keys, log fields, and metric labels never contain personal data (metric-label cardinality is also a DoS risk) |
| 🔒 Encryption is not anonymisation | Encrypted PII is still PII for GDPR purposes; retention and rights obligations are unchanged |
| 🧾 Consent & notice | The public board shows a minimal cookie notice; spectators are never tracked across sites |
| 🌍 Transfer control | No personal data leaves the configured region; sub-processor list maintained and reviewed annually |
| 🧑‍💻 Automated decisions | No solely automated decision with legal effect; score disputes are always human-reviewed (`solve.disputed`) |

---

## 12. 🔴 Audit, Detection & Alerting

**Family objective:** every security-relevant action is recorded immutably, correlated, monitored, and provable to a third party without trusting the platform.

### 12.1 Audit Architecture Principles

| # | Principle | Statement |
|:-:|:--|:--|
| 1 | 🔒 **Same transaction** | The audit insert commits with the mutation or neither commits. There is no window in which a change exists without a record. |
| 2 | 🧬 **Append-only** | `UPDATE` and `DELETE` on `audit_log` are structurally impossible for any non-owner role. |
| 3 | 🔗 **Chained** | Each record hashes its predecessor, so any modification, deletion, or insertion is detectable. |
| 4 | ✍️ **Externally sealed** | Merkle roots are signed and written to Object Lock COMPLIANCE mode, then externally timestamped. |
| 5 | 🔍 **Observable** | Every record carries a correlation ID, policy version, and outcome. |
| 6 | 🚫 **Closed vocabulary** | `action` comes from a fixed list; free-text actions are impossible. |
| 7 | 🗣️ **Explained** | Every mutation carries a mandatory `reason` of at least 10 characters. |

```sql
-- SEC-AUD-03: immutability enforced by the database, not by convention
CREATE RULE audit_log_no_update AS ON UPDATE TO audit_log DO INSTEAD NOTHING;
CREATE RULE audit_log_no_delete AS ON DELETE TO audit_log DO INSTEAD NOTHING;
GRANT INSERT, SELECT ON audit_log TO app_rw;
-- No UPDATE/DELETE grant exists for ANY non-owner role, including the on-call DBA.
-- A restore that would violate this is refused by the same rule.
```

### 12.2 Control Catalogue

| ID | Control Statement | Sev | Implementation | Verified by |
|:--|:--|:-:|:--|:--|
| **SEC-AUD-01** | Every security-relevant action **MUST** produce an audit record, including **denials** | 🔴 | Central audit service; `access.denied` for every 403; sampled for public reads | `T-AUD-05` 🔴 |
| **SEC-AUD-02** | The audit insert **MUST** commit in the same transaction as the mutation it describes | 🔴 | Shared transaction boundary in the repository layer; unit test asserts rollback coupling | `T-AUD-02` 🔴 |
| **SEC-AUD-03** | `audit_log` **MUST** be append-only at the database level; no non-owner role may `UPDATE` or `DELETE` | 🔴 | `CREATE RULE` immutability; grants; RLS | `T-AUD-01` 🔴 |
| **SEC-AUD-04** | Audit records **MUST** be hash-chained (`SHA256(prev_hash ‖ canonical_event)`) and verified hourly, alerting on any break | 🔴 | Chain verifier job; AL-01 P1 on break | `T-AUD-03` 🔴 |
| **SEC-AUD-05** | Merkle roots **MUST** be batched (1,000 events or 5 min), signed, and sealed to Object Lock COMPLIANCE mode | 🟠 | Seal worker; `seals[]` in the audit schema | `T-AUD-04` 🟠 |
| **SEC-AUD-06** | Sealed roots **MUST** be externally anchored (RFC 3161 TSA and/or a public transparency log) to defend against wholesale history forgery | 🔴 | Anchor job publishes a signed timestamp; verification instructions in the evidence pack | `T-AUD-06` 🔴 |
| **SEC-AUD-07** | Log records **MUST NOT** contain secrets or full PII; sensitive attributes **MUST** be hashed or truncated | 🟠 | Log schema allow-list; scrubber; entropy detector | `T-AUD-07` 🟠 |
| **SEC-AUD-08** | Audit data **MUST** be retained 7 years in WORM storage, replicated to a second region, with legal-hold override | 🟠 | Object Lock; cross-region replication; retention matrix | `T-AUD-08` 🟠 |
| **SEC-AUD-09** | Audit queries and exports **MUST** be authorised with `audit:read` / `audit:export` (step-up) and themselves audited | 🟠 | `SU` permission; `audit.exported` record; OpenSearch query authz | `T-AUD-09` 🟠 |

### 12.3 Audit Event Schema (Security-Relevant Fields)

```jsonc
{
  "schemaVersion": 3,
  "auditId": 918273,                     // monotonic, gap-detectable
  "eventId": "evt_2026_ctf_final",
  "occurredAt": "2026-09-26T19:04:11.482Z",  // UTC, NTP-synchronised
  "recordedAt": "2026-09-26T19:04:11.501Z",  // latency signal
  "actor": {
    "type": "user",                       // user | system | service
    "id": "usr_9f2a41",
    "roles": ["referee_lead"],
    "authMethod": "oidc+mfa_webauthn",
    "sessionId": "sha256:a1b2…",          // hashed reference only
    "mfaSatisfied": true,
    "stepUpSatisfied": true
  },
  "origin": {
    "ipPrefix": "203.0.113.0/24",         // truncated for GDPR
    "asn": "AS64496",
    "userAgentHash": "sha256:9a2f…",
    "deviceId": "dev_kiosk_04",
    "networkZone": "net_app"
  },
  "action": "score.adjust",               // closed vocabulary
  "resource": { "type": "team_score", "id": "t_041", "eventId": "evt_2026_ctf_final" },
  "outcome": "success",                   // success | denied | failed | partial
  "reason": "Referee overturned challenge #42 due to infrastructure fault",
  "before": { "totalPoints": 4300, "rank": 5 },
  "after":  { "totalPoints": 3850, "rank": 9 },
  "policy": { "decision": "allow", "policyId": "pol-2026-09-14.3",
              "obligations": ["audit:log_decision"] },
  "request": { "correlationId": "4bf92f3577b34da6a3ce929d0e0e4736",
               "method": "POST", "path": "/api/v1/admin/scores/adjust" },
  "integrity": { "prevHash": "3f2a…", "thisHash": "b91c4e7d8a…" },
  "seals": [ { "merkleRoot": "9de1…", "sealedAt": "2026-09-26T19:05:00Z",
               "signature": "MEUCIQ…" } ]
}
```

**Closed vocabulary for `action`** — unbounded action strings are unauditable:

```
event.phase.changed      event.started        event.ended
team.created             team.updated         team.deleted
team.eligibility.changed team.merged
challenge.created        challenge.updated    challenge.released
challenge.retired        challenge.points.changed
solve.recorded           solve.verified       solve.disputed
solve.reverted           penalty.applied      score.adjusted
freeze.window.opened     freeze.window.closed
report.requested         report.generated     report.downloaded
report.revoked           report.template.registered
user.login               user.logout          user.mfa.enrolled
user.mfa.challenge       user.created         user.updated
user.disabled            user.role.changed    session.revoked
access.denied            auth.failed          auth.locked
audit.exported           audit.verified       audit.chain.broken
policy.deployed          config.updated       secret.read     secret.rotated
breakglass.activated     breakglass.expired
webhook.received         webhook.rejected     webhook.replay.detected
```

### 12.4 Detection Rules (Security Subset)

| ID | Rule | Sev | Signal | Response |
|:--|:--|:-:|:--|:--|
| AL-01 | Audit chain break detected | 🔴 P1 | `audit_chain_break_total > 0` | Page; freeze admin writes; preserve evidence; start IR |
| AL-02 | Webhook replay detected | 🟠 P2 | `webhook_replay_detected_total` | Validate platform; rotate HMAC key if unexplained |
| AL-03 | Reconciliation mismatch | 🔴 P1 | `reconciliation_mismatch_total > 0` | Halt scoring; replay from source; page on-call |
| AL-04 | Score adjusted outside a live event | 🟠 P2 | `score.adjust` when phase ≠ `scoring_open` | Notify CISO; verify referee authorisation |
| AL-05 | Two-person control bypass attempt | 🔴 P1 | `score.adjust` with self-approval | Page security; preserve session evidence |
| AL-06 | Break-glass activated | 🔴 P1 | `breakglass.activated` | Page CISO; 60-min timer; PIR mandatory |
| AL-07 | Secret / encryption key read | 🟠 P2 | `secret:read` | Verify authorisation; escalate if unexpected |
| AL-08 | Mass report download | 🟠 P2 | > 10 reports/hr or > 100 MB/hr per user | Review; revoke if unjustified |
| AL-09 | AuthZ deny-rate spike | 🟠 P2 | > 20× 7-day baseline | Possible privilege-escalation campaign |
| AL-11 | MFA failure burst | 🟠 P2 | > 10 failures / 5 min / account | Lock + notify user + security |
| AL-13 | Image signature verification failure | 🔴 P1 | `cosign verify` non-zero | Halt deploy; investigate supply chain |
| AL-16 | Egress denial spike | 🟡 P3 | `net_app` egress denies | Possible C2 or misconfiguration |
| AL-17 | Clock drift > 1 s | 🟠 P2 | NTP offset | Fix chrony; ordering integrity at risk |
| AL-18 | Projection lag > 30 s | 🟠 P2 | `projection_lag_seconds` | Scale projectors; check DB contention |
| AL-19 | Report job failure rate > 5 % | 🟡 P3 | `report_jobs_total{status=failed}` | Inspect template; notify requester |
| AL-20 | Backup not verified in 24 h | 🟠 P2 | Missing restore-check heartbeat | Investigate; protect RPO |
| AL-21 | Client FPS p5 < 30 | 🟡 P3 | RUM | Review default quality tier; GPU driver matrix |
| AL-22 | Dormant privileged account (60 d) | 🟡 P3 | Entitlement reconciliation | Review and revoke if unjustified |
| **AL-S01** | 🆕 Deny-by-default bypass attempt (policy bundle rollback) | 🔴 P1 | `policy.deployed` without matching approval | Freeze deploys; page security |
| **AL-S02** | 🆕 Audit insert failure while mutation proceeds | 🔴 P1 | Transaction-coupling assertion fails | 🔴 Fail closed; page |
| **AL-S03** | 🆕 Retention worker silent > 26 h | 🟠 P2 | Missing tombstone heartbeat | Investigate; GDPR obligation at risk |
| **AL-S04** | 🆕 Legal hold scope accessed by non-DPO role | 🟠 P2 | Hold-scoped read by other role | Review; possible privilege misuse |
| **AL-S05** | 🆕 Step-up assertion reused (same assertion, two actions) | 🔴 P1 | `jti` reuse in step-up cache | Revoke session; investigate |

> 🧪 **Every rule is a tested rule.** Each `AL-*` entry has a corresponding synthetic-event test in the detection harness ([§17](#17--security-testing--verification-catalogue)) proving the rule fires and routes to the correct severity. An alert that has never been observed firing is indistinguishable from an alert that does not work.

### 12.5 What the Audit Log Cannot Prove

| It **cannot** prove | Why | Compensating control |
|:--|:--|:--|
| That a human physically performed an action | Credentials can be shared or stolen | MFA, attestation, session recording for `secret:read`, SoD |
| That no event was ever fabricated before anchoring | A consistent chain can be forged from scratch | `SEC-AUD-06` external anchoring raises the bar materially |
| That a spectator did not refresh a page | Reads are not individually meaningful | Rate limits, bot scoring, aggregate access telemetry |
| Complete deletion of PII from every backup replica | Backups are immutable within their window | `SEC-DATA-05` re-applied expiry at restore + documented 12-month archive ceiling |
| Intent | Systems record actions, not motives | Post-incident review, `reason` fields, human attestation |

## 13. 🟡 Infrastructure, Network & Container Controls

**Family objective:** the blast radius of any single compromised component is one component. Segmentation, immutability, and least privilege are enforced by the platform, not by discipline.

### 13.1 Network Zoning

```mermaid
%%{init: {"theme":"base","themeVariables":{"primaryColor":"#FFD166","primaryTextColor":"#0B0E1A","primaryBorderColor":"#FFD166","lineColor":"#8B95B8","fontFamily":"Inter, sans-serif"}}}%%
flowchart TB
    subgraph Z0["🌍 net_edge — public ingress only"]
        E0["🌐 CDN + DDoS"]:::z0
        E1["🕷️ WAF (OWASP CRS v4)"]:::z0
        E2["🔒 Nginx TLS 1.3 + rate limit"]:::z0
    end
    subgraph Z1["⚙️ net_app — application services"]
        A1["🖥️ API gateway"]:::z1
        A2["⚙️ Scoring + ingest"]:::z1
        A3["📊 Report workers"]:::z1
        A4["🖥️ Admin SPA (static)"]:::z1
        A5["🧠 PDP (Cerbos/OPA)"]:::z1
    end
    subgraph Z2["🗄️ net_data — stateful services only"]
        D1["🗄️ PostgreSQL + TimescaleDB"]:::z2
        D2["⚡ Redis cluster"]:::z2
        D3["🔐 Vault"]:::z2
    end
    subgraph Z3["🧾 net_audit — write-mostly, no egress"]
        U1["🧾 Audit service"]:::z3
        U2["🔍 OpenSearch"]:::z3
        U3["🧬 WORM object store"]:::z3
    end
    subgraph Z4["🏛️ net_mgmt — break-glass only"]
        M1["🔑 KMS / HSM"]:::z4
        M2["📊 SIEM"]:::z4
    end
    E0 --> E1 --> E2 --> A1
    A1 --> A5
    A1 --> A2 & A3 & A4
    A2 --> D1 & D2 & D3
    A3 --> D1 & U3
    A2 --> U1
    U1 --> U2
    U1 --> U3
    D3 --> M1
    U2 --> M2
    A1 -.->|"deny by default"| D1
    Z3 -.->|"no egress to internet"| OUT(["🌍 Internet"]):::no
    Z4 -.->|"no ingress from app"| A1
    classDef z0 fill:#062B3A,stroke:#00D2FF,color:#E8ECF8
    classDef z1 fill:#241A4D,stroke:#6C5CE7,color:#E8ECF8
    classDef z2 fill:#2E2205,stroke:#FFD166,color:#0B0E1A
    classDef z3 fill:#2A1220,stroke:#EF476F,color:#E8ECF8
    classDef z4 fill:#3A2A05,stroke:#FF9F1C,color:#E8ECF8
    classDef no fill:#EF476F,stroke:#E8ECF8,stroke-width:3px,color:#0B0E1A
```

**Zone policy**

| Zone | Ingress from | Egress to | Rationale |
|:--|:--|:--|:--|
| `net_edge` | Internet | `net_app` only | Public surface isolated from data |
| `net_app` | `net_edge` | `net_data`, `net_audit`, DNS, NTP, IdP, CTF platform | Application cannot reach `net_mgmt` |
| `net_data` | `net_app` | Replicas within zone only | State stores never initiate internet calls |
| `net_audit` | `net_app` (write), `auditor` (read via gateway) | **None** | Evidence must not be exfiltrated from its own zone |
| `net_mgmt` | Break-glass path only | — | Highest-value assets, minimal reachability |

### 13.2 Control Catalogue

| ID | Control Statement | Sev | Implementation | Verified by |
|:--|:--|:-:|:--|:--|
| **SEC-INFRA-01** | All inter-zone traffic **MUST** be default-deny; every allowed flow **MUST** be an explicit, reviewed rule | 🔴 | Docker networks + `DOCKER-USER` iptables chain; network policies in K8s | `T-INFRA-01` 🔴 |
| **SEC-INFRA-02** | Containers **MUST** run as non-root, with a read-only root filesystem, all capabilities dropped, and a seccomp profile | 🟠 | `USER 10001`; `read_only: true`; `cap_drop: [ALL]`; `seccomp: runtime/default` | `T-INFRA-02` 🟠 |
| **SEC-INFRA-03** | Container images **MUST** come from the hardened internal base, with no shell tools, no package manager, and no curl/wget in runtime layers | 🟠 | Distroless / `scratch` runtime stage; multi-stage builds; CIS Docker Benchmark ≥ 95 % | `T-INFRA-03` 🟠 |
| **SEC-INFRA-04** | The host **MUST** enforce a restrictive `umask`, encrypted swap, locked-down `sysctl`, and no local user accounts beyond the two break-glass operators | 🟡 | Host bootstrap script; CIS host benchmark; PAM lockout | `T-INFRA-04` 🟡 |
| **SEC-INFRA-05** | All infrastructure **MUST** be defined as code, linted, and applied only through the pipeline; console changes are drift (AL-14) | 🟠 | Terraform + Compose; Checkov + TFLint; remote state, versioned | `T-INFRA-05` 🟠 |
| **SEC-INFRA-06** | Edge protections **MUST** include DDoS scrubbing, WAF with OWASP CRS, and bot scoring; volumetric defence is a platform dependency | 🟠 | CDN + WAF + limiter; AL-15 WAF severity-1 triage ≤ 1 h | `T-INFRA-06` 🟠 |
| **SEC-INFRA-07** | Resource limits **MUST** be set on every container and node (CPU, memory, PIDs), with quotas preventing one service starving another | 🟡 | Compose limits; cgroups; load-shedding order documented | `T-INFRA-07` 🟡 |
| **SEC-INFRA-08** | Time **MUST** be NTP-synchronised across all components; drift > 1 s **MUST** alert and **MUST** halt manual audit appends | 🟠 | chrony everywhere; AL-17; ordering integrity for the chain | `T-INFRA-08` 🟠 |

### 13.3 Container Baseline

```yaml
# Minimum viable hardened service definition — every container inherits this
services:
  api:
    image: registry.internal/sc3d-api@sha256:9f2a…   # digest, never tag
    read_only: true
    user: "10001:10001"
    cap_drop: [ALL]
    security_opt:
      - no-new-privileges:true
      - seccomp:runtime/default
    tmpfs:
      - /tmp:size=64m,mode=1777,noexec,nosuid,nodev
    networks: [net_app]          # no net_data membership
    cap_egress:                   # explicit allow-list, deny by default
      - "postgres:5432"
      - "redis:6379"
      - "vault:8200"
      - "*.ctf-platform:443"
    deploy:
      resources:
        limits: { cpus: "2.0", memory: 2G, pids: 512 }
    read_only_root: true
    healthcheck:
      test: ["CMD", "/app/healthz"]
      interval: 10s
      timeout: 2s
      retries: 3
```

| Setting | Value | Control |
|:--|:--|:--|
| `read_only` | `true` | `SEC-INFRA-02` |
| `user` | non-root UID ≥ 10000 | `SEC-INFRA-02` |
| `cap_drop` | `ALL` | `SEC-INFRA-02` |
| `no-new-privileges` | `true` | `SEC-INFRA-02` |
| `seccomp` | `runtime/default` | `SEC-INFRA-02` |
| tmpfs mounts | `noexec,nosuid,nodev` | `SEC-CRY-05` |
| Egress | explicit allow-list, default deny | `SEC-INFRA-01` |
| Resource limits | CPU, memory, PIDs | `SEC-INFRA-07` |
| Image | digest-pinned, signed | `SEC-SC-04`, `SEC-SC-05` |

### 13.4 Host & Cloud Posture

| Area | Requirement | Reference |
|:--|:--|:--|
| 🖥️ Host hardening | CIS Level 1 baseline; unattended-upgrades; auditd; no inbound SSH except via bastion | `SEC-INFRA-04` |
| 🔐 SSH | Key-only, `PermitRootLogin no`, bastion + session recording, 4-week key expiry | `SEC-IAM-07` |
| ☁️ IAM | No standing `*:*`; permissions scoped per role; unused credentials flagged daily | `SEC-AUTH-06` |
| 🪪 SCPs | Org guardrails deny public buckets, unencrypted volumes, and un-tagged resources | `SEC-CRY-02` |
| 🗄️ Backups | Delete-protection on; cross-region copy; separate credentials from the workload | `SEC-IR-04` |
| 📜 Logging | Cloud control-plane logs shipped to the SIEM with a 400-day searchable window | `SEC-AUD-08` |
| 🧾 Secrets in cloud | No secret manager values in IaC state; state backend encrypted and access-logged | `SEC-CRY-05` |
| 🔍 Vulnerability scanning | Continuous host + image scanning; findings route to the same SLA table as code | `SEC-SDLC-05` |

---

## 14. 🔵 Third-Party & Webhook Trust

**Family objective:** every external system is untrusted until proven, per request. Trust is derived from cryptography, not from network position or vendor reputation.

```mermaid
%%{init: {"theme":"base","themeVariables":{"primaryColor":"#00D2FF","primaryTextColor":"#E8ECF8","primaryBorderColor":"#00D2FF","lineColor":"#8B95B8","fontFamily":"Inter, sans-serif"}}}%%
sequenceDiagram
    autonumber
    participant CTF as 🏆 CTF platform
    participant EDGE as 🕷️ WAF
    participant API as ⚙️ Ingest service
    participant VAULT as 🔐 Vault
    participant DB as 🗄️ raw_event
    participant AUD as 🧾 Audit

    CTF->>EDGE: POST /webhooks/ctf (mTLS client cert)
    EDGE->>EDGE: TLS 1.3, cert CN in allow-list
    EDGE->>API: Forward raw body bytes + headers
    API->>API: 1. Read body as Buffer — never re-serialise
    API->>VAULT: Fetch HMAC key for CN
    VAULT-->>API: key material (TTL 1 h, audited)
    API->>API: 2. HMAC-SHA256 over raw bytes
    API->>API: 3. crypto.timingSafeEqual vs header
    API->>API: 4. |now - ts| <= 300 s ?
    API->>API: 5. Zod .strict() schema validation
    API->>API: 6. Idempotency key = SHA256(slug ‖ source ‖ id)
    alt valid and fresh
        API->>DB: INSERT … ON CONFLICT DO NOTHING
        DB-->>API: rows = 1
        API->>AUD: webhook.received (inside same txn)
        API-->>CTF: 202 Accepted
    else duplicate
        DB-->>API: rows = 0
        API->>AUD: webhook.received (outcome=duplicate)
        API-->>CTF: 200 {"status":"duplicate","original_seq":n}
    else bad signature, skew, or schema
        API->>AUD: webhook.rejected / webhook.replay.detected
        API-->>CTF: 401 / 400 (safe catalogue)
    end
```

### 14.1 Control Catalogue

| ID | Control Statement | Sev | Implementation | Verified by |
|:--|:--|:-:|:--|:--|
| **SEC-EXT-01** | Inbound webhooks **MUST** use mutual TLS 1.3 with the partner CA pinned; the client certificate CN **MUST** be in an allow-list | 🔴 | Nginx `ssl_client_certificate`; CN → partner mapping in Vault metadata | `T-EXT-04` 🔴 |
| **SEC-EXT-02** | Webhook signatures **MUST** be HMAC-SHA-256 over the **raw** request body and compared with `crypto.timingSafeEqual` — never `===`, never `localeCompare` | 🔴 | `webhook/verify.ts`; body captured as `Buffer` before any parsing | `T-EXT-01` 🔴 |
| **SEC-EXT-03** | A replay window of ±300 s **MUST** be enforced; outside the window the request is rejected and `webhook.replay.detected` is raised | 🟠 | Timestamp skew check; AL-02; nightly re-validation of the previous 24 h | `T-EXT-02` 🟠 |
| **SEC-EXT-04** | Webhook payloads **MUST** be validated with a Zod **strict** schema; unknown properties are rejected | 🟠 | `/schemas/v1/ctf-webhook.json`; contract tests against the live platform | `T-EXT-05` 🟠 |
| **SEC-EXT-05** | Webhook processing **MUST** be idempotent via a unique `idempotency_key`; duplicates return `200` with the original sequence and never a `5xx` or `409` | 🔴 | `UNIQUE(idempotency_key)`; `ON CONFLICT DO NOTHING` | `T-EXT-03` 🔴 |
| **SEC-EXT-06** | The webhook principal **MUST** hold only `ingest:solve`, `ingest:team`, `ingest:challenge`; it **MUST NOT** be able to read or administer anything | 🟠 | Dedicated DB role `ingest_ro` + PDP policy for the service identity | `T-EXT-07` 🟠 |
| **SEC-EXT-07** | Outbound calls to third parties **MUST** resolve against an egress allow-list with DNS pinning; user-supplied URLs **MUST NOT** be fetched | 🟠 | Egress proxy; no URL parameter in any report/export path | `T-EXT-08` 🟠 |

### 14.2 Idempotency Key Construction

```
key = SHA-256( event_slug ‖ source_system ‖ source_event_id )
```

| Condition | Response | Rationale |
|:--|:--|:--|
| Fresh event | `202 Accepted` + enqueue | Accepted for processing; scoring is asynchronous |
| Duplicate (same key) | `200 {"status":"duplicate","original_seq":n}` | A retry storm must not become an outage, and `409` would trigger infinite client retries |
| Signature invalid | `401` + `webhook.rejected` | No detail about *which* check failed |
| Skew outside window | `401` + `webhook.replay.detected` + AL-02 | Replay is a security event, not a validation error |
| Schema invalid | `400` + field-level safe errors | Actionable for the platform, non-informative about internals |
| Rate limit exceeded | `429` + `Retry-After` | Per certificate CN, 1,000 req/min |

### 14.3 Federation & Vendor Controls

| Relationship | Control | Cadence |
|:--|:--|:--|
| 🆔 OIDC IdP | SP-initiated only; no IdP-initiated POST to the app; JWKS pinned with dual-active rotation; SCIM for lifecycle | Continuous |
| 🏆 CTF platform | Contracted webhook spec; mTLS + HMAC; monthly reconciliation report; incident notification clause | Monthly |
| 📦 OCI registry | Private, replicated, pull-by-digest, short-lived federation credentials | Per build |
| ✍️ Sigstore / Fulcio | Keyless OIDC identity; signature verification at admission | Per deploy |
| 🕒 RFC 3161 TSA | Root anchoring; verification instructions published in evidence packs | Per seal |
| 🔍 Pen-test firm | Annual + post-major-change; findings tracked to closure; safe-harbour for the bounty programme | Annual |

## 15. 🟣 Secure SDLC & Release Gates

**Family objective:** no change reaches production without passing an automated, evidence-producing gate chain; and no engineer can bypass a gate alone.

```mermaid
%%{init: {"theme":"base","themeVariables":{"primaryColor":"#6C5CE7","primaryTextColor":"#E8ECF8","primaryBorderColor":"#6C5CE7","lineColor":"#8B95B8","fontFamily":"Inter, sans-serif"}}}%%
flowchart TB
    DEV(["🧑‍💻 Developer pushes"]):::in
    subgraph LOCAL["🔍 PRE-COMMIT — under 3 seconds"]
        P1["gitleaks"]:::p
        P2["eslint-plugin-security"]:::p
        P3["type-check + prettier"]:::p
    end
    subgraph CI["🤖 CI GATE CHAIN — every push"]
        G1["1️⃣ SAST<br/>Semgrep + CodeQL<br/>0 Critical/High"]:::g
        G2["2️⃣ SCA<br/>osv-scanner + licence<br/>0 Critical"]:::g
        G3["3️⃣ IaC + image<br/>Checkov + Trivy<br/>0 Critical/High"]:::g
        G4["4️⃣ Secrets + history<br/>gitleaks full history"]:::g
        G5["5️⃣ Tests<br/>unit + integration + authz matrix<br/>coverage ≥ 80%"]:::g
        G6["6️⃣ DAST + fuzz<br/>ZAP + Jazzer<br/>0 High"]:::g
        G7["7️⃣ Policy<br/>OPA gatekeeper<br/>0 violations"]:::g
        G8["8️⃣ SBOM + provenance<br/>syft + slsa"]:::g
    end
    BLOCK(["🚫 BLOCKED — no override by a single engineer"]):::block
    OK(["✅ BUILD APPROVED"]):::ok
    SIGN["✍️ cosign sign (keyless)"]:::s
    PROD["🚀 Deploy — 2-person production approval"]:::prod
    POST["🔍 Post-deploy: verify sig · policy gate · smoke · audit event"]:::post

    DEV --> P1 --> P2 --> P3 --> G1
    G1 --> G2 --> G3 --> G4 --> G5 --> G6 --> G7 --> G8
    G1 -.->|fail| BLOCK
    G3 -.->|fail| BLOCK
    G5 -.->|fail| BLOCK
    G7 -.->|fail| BLOCK
    G8 --> SIGN --> PROD --> POST
    classDef in fill:#241A4D,stroke:#6C5CE7,color:#E8ECF8
    classDef p fill:#062B3A,stroke:#00D2FF,color:#E8ECF8
    classDef g fill:#2E2205,stroke:#FFD166,color:#0B0E1A
    classDef block fill:#EF476F,stroke:#E8ECF8,stroke-width:3px,color:#0B0E1A
    classDef ok fill:#06251D,stroke:#06D6A0,color:#E8ECF8
    classDef s fill:#2A1220,stroke:#EF476F,color:#E8ECF8
    classDef prod fill:#3A2A05,stroke:#FF9F1C,color:#E8ECF8
    classDef post fill:#062B3A,stroke:#00D2FF,color:#E8ECF8
```

### 15.1 Control Catalogue

| ID | Control Statement | Sev | Implementation | Verified by |
|:--|:--|:-:|:--|:--|
| **SEC-SDLC-01** | Branch protection **MUST** require 1 review + 1 CODEOWNER approval, linear history, and **MUST** forbid force-push to `main` | 🟠 | Repository settings; CODEOWNERS on `policies/`, `db/`, `.github/` | `T-SDLC-01` 🟠 |
| **SEC-SDLC-02** | Production deploys **MUST** require two-person approval; a single engineer **MUST NOT** be able to ship to production | 🟠 | Environment protection rules; deploy job gated on 2 approvals | `T-SDLC-02` 🟠 |
| **SEC-SDLC-03** | The OpenAPI spec **MUST** be generated from the validation schemas, so the contract cannot drift from enforcement | 🟡 | `@asteasolutions/zod-to-openapi`; CI diff check | `T-SDLC-03` 🟡 |
| **SEC-SDLC-04** | Policy bundles **MUST** be signed, versioned, deployed only in a change window, and rollback-capable | 🔴 | `policy.deployed` audit; dual approval; 24 h window; rollback tested | `T-SDLC-04` 🔴 |
| **SEC-SDLC-05** | Critical CVEs **MUST** be patched within 24 h, High within 7 days, and exposed-component SLAs **MUST** be halved | 🟠 | OSV feed × SBOM match; AL-12; emergency change path with retrospective gate | `T-SDLC-05` 🟠 |
| **SEC-SDLC-06** | Every engineer with production or policy access **MUST** complete secure-coding training annually, with phishing simulation quarterly | 🟡 | LMS records; simulation results; AL-10 informed by outcomes | `T-SDLC-06` 🟡 |
| **SEC-SDLC-07** | An independent penetration test **MUST** be performed annually and after any major architectural change, with findings tracked to closure | 🟠 | External firm; 0 High/Critical open > 30 days | `T-SDLC-07` 🟠 |
| **SEC-SDLC-08** | The threat model **MUST** be reviewed on every architectural change and after every P1, with abuse-case tests updated in the same PR | 🟡 | Review checklist gate; `AB-01`…`AB-18` suite | `T-SDLC-08` 🟡 |

### 15.2 Gate Bypass Policy

| Situation | Permitted? | Compensating control |
|:--|:--:|:--|
| 🔴 Critical CVE, no fix available | ✅ Emergency change | Retrospective full gate run; documented exception with expiry ≤ 14 days; exec approval |
| 🟠 WAF rule blocking legitimate traffic | ✅ Emergency WAF tune | Change reviewed by security; rule change audited; no permanent allow-all |
| 🔴 Incident containment (kill switch) | ✅ Emergency | Runbook pre-authorisation; every action audited as `critical_system_operation`; PIR mandatory |
| 🟡 Failing flaky test | ⛔ **No** | Fix the flake; a red gate normalised is a gate that no longer exists |
| 🔴 Any gate disabled to ship a feature | ⛔ **No** | Feature velocity never outranks a security gate; escalate instead |

> 🧾 **A gate that is routinely bypassed is worse than no gate**, because it creates documented evidence of a control that does not operate. Emergency paths exist for genuine emergencies, and every one of them is audited, time-boxed, and reviewed.

---

## 16. 🟠 Vulnerability & Patch Management

### 16.1 SLA Matrix

| Finding class | Patch SLA | Escalation | Gate effect |
|:--|:--|:--|:--|
| 🔴 Critical | ≤ 24 hours | Page on-call; exec notification; PIR if exploited | 🔴 Blocks release |
| 🟠 High | ≤ 7 days | Team lead; documented risk acceptance if blocked | 🔴 Blocks release unless accepted |
| 🟡 Medium | ≤ 30 days | Tracked in backlog with owner | 🟡 Advisory |
| 🟢 Low | ≤ 90 days | Tracked | 🟢 Informational |
| 🌐 Internet-exposed component | SLA halved | 🔴 Always paged | 🔴 Blocks release |
| 🔑 Auth / crypto library | Zero-day response ≤ 48 h | 🔴 Vendor escalation | 🔴 Blocks release |
| 🧱 Base image | Weekly automated rebase + rebuild + sign | 🟢 Automatic | 🔴 Must be signed to deploy |
| ⏳ Dependency quarantine | 7 days minimum | 🟢 Security Eng | ⛔ No production reach |

### 16.2 Detection Sources

| Source | Cadence | Integration |
|:--|:--|:--|
| 🧬 OSV / GitHub Advisory | Continuous | Matched against the SBOM on every build (AL-12) |
| 🖼️ Trivy image + host scan | CI + nightly | Findings open tickets automatically with the SLA clock |
| 🧱 `docker-bench-security` | Weekly | CIS Docker Benchmark ≥ 95 %, 0 critical |
| 🏛️ OPA / Checkov IaC scan | Every build | Blocks on Critical/High |
| 🕵️ External pen test | Annual + on change | Findings tracked in the risk register |
| 🌐 Bug bounty | Continuous | Safe-harbour policy published; triage ≤ 3 days |
| 🧑‍💻 Dependency update bot | Weekly | `renovate.json` groups by patch/minor/major with different review depth |

### 16.3 Vulnerability Disclosure

| Stage | Commitment | Channel |
|:--|:--|:--|
| 🕒 Response | Acknowledge ≤ 24 h; triage ≤ 3 days | `security@` alias, published PGP key |
| 🔬 Assessment | Severity per [§5.4](#54-severity-model), scored by outcome | Private issue tracker |
| 🛠️ Fix | Critical ≤ 24 h; High ≤ 7 days | Private branch + signed release |
| 📣 Disclosure | Coordinated 90 days after fix, or immediately if actively exploited | Public advisory + changelog |
| ⚖️ Safe harbour | Good-faith research is authorised; no legal action for non-harmful probing | Published policy |

## 17. 🟢 Security Testing & Verification Catalogue

**Family objective:** every `SEC-*` control has at least one executable test. A control without a test is an assertion; a test that has never failed is an unverified assumption.

```mermaid
%%{init: {"theme":"base","themeVariables":{"primaryColor":"#06D6A0","primaryTextColor":"#E8ECF8","primaryBorderColor":"#06D6A0","lineColor":"#8B95B8","fontFamily":"Inter, sans-serif"}}}%%
flowchart LR
    SEC["🛡️ 97 SEC-* controls"]:::a
    T["🧪 120 T-* tests"]:::b
    AL["🔍 27 detection rules"]:::c
    E["📦 Evidence artefacts"]:::d
    AU["👤 Auditor<br/>independent"]:::e
    SEC -->|"every control ≥ 1 test"| T
    T -->|"CI evidence bundle"| E
    SEC -->|"violation signal"| AL
    AL --> E
    E --> AU
    AU -->|"finding"| SEC
    classDef a fill:#241A4D,stroke:#6C5CE7,color:#E8ECF8
    classDef b fill:#06251D,stroke:#06D6A0,color:#E8ECF8
    classDef c fill:#2E2205,stroke:#FFD166,color:#0B0E1A
    classDef d fill:#2A1220,stroke:#EF476F,color:#E8ECF8
    classDef e fill:#062B3A,stroke:#00D2FF,color:#E8ECF8
```

### 17.1 Test Matrix by Family

| Family | Tests | Cadence | Coverage rule |
|:--|--:|:--|:--|
| 🔵 `T-IAM` | 10 | Every commit + E2E nightly | 100 % of auth flows and session lifecycle transitions |
| 🔴 `T-AUTH` | 9 | Every commit | 100 % of routes × roles × resources |
| 🟢 `T-APP` | 20 | Every commit + nightly DAST | Every coding standard and injection class |
| 🟣 `T-CRY` | 11 | Every build | Every algorithm and forbidden primitive |
| 🟠 `T-SC` | 8 | Every build | Every supply-chain gate |
| 🔵 `T-DATA` | 10 | Every commit + quarterly | Every data class and retention path |
| 🔴 `T-AUD` | 9 | Hourly chain verify | Every audit guarantee, including tamper cases |
| 🟡 `T-INFRA` | 8 | Every deploy + weekly | Every hardening baseline assertion |
| 🔵 `T-EXT` | 8 | Every commit + nightly | Every trust check, including negative cases |
| 🟣 `T-SDLC` | 8 | Every pipeline | Every gate, including bypass attempts |
| 🟠 `T-IR` | 6 | Quarterly drill | Every P1 runbook, timed |
| ⚛️ `T-DER` | 13 | Every commit + nightly rebuild | Every determinism, replay, and state-derivation invariant |
| **Total** | **120** | — | **No control without a passing test** |

### 17.2 🔵 Identity & Session Tests

| ID | Test | Assertion | Gate |
|:--|:--|:--|:--|
| `T-IAM-01` | OIDC flow enforcement | Implicit / password flows rejected; `code_challenge_method=S256` required; `state`+`nonce` present | 🔴 |
| `T-IAM-02` | MFA enforcement | Every staff role challenged; WebAuthn preferred; TOTP fallback accepted; recovery codes single-use | 🔴 |
| `T-IAM-03` | Cookie hardening | `__Host-` prefix, `Secure`, `HttpOnly`, `Path=/`, no `Domain`, `SameSite=Strict` | 🟠 |
| `T-IAM-04` | Session expiry | Idle 15 min and absolute 8 h enforced; 4 h/5 min for privileged roles; server-side, not cookie-only | 🟠 |
| `T-IAM-05` | Password storage | No local password hash uses a non-Argon2id algorithm; break-glass set sealed in Vault | 🟠 |
| `T-IAM-06` | Brute-force defence | 5 attempts/15 min triggers backoff; lockout is risk-based, not blind; AL-11 fires | 🟠 |
| `T-IAM-07` | Revocation propagation | Role change, disablement, and break-glass close SSE streams and invalidate cached authz within 60 s | 🔴 |
| `T-IAM-08` | Break-glass discipline | Two-person authorisation enforced; auto-expiry at 60 min; P1 raised; post-hoc review task created | 🔴 |
| `T-IAM-09` | Device posture | `security_admin` refused without managed-device attestation; kiosk token cannot reach admin routes | 🟡 |
| `T-IAM-10` | Enumeration resistance | Login, recovery, and MFA responses indistinguishable for unknown and known principals (timing + body) | 🔴 |

### 17.3 🔴 Authorisation Tests

| ID | Test | Assertion | Gate |
|:--|:--|:--|:--|
| `T-AUTH-01` | Default deny | An action with no matching policy is denied; removing a policy never grants | 🔴 |
| `T-AUTH-02` | Authz matrix | Every route × role combination has an explicit expected outcome; no gaps permitted | 🔴 |
| `T-AUTH-03` | Step-up enforcement | Each `SU` permission refuses without a ≤ 5-minute re-auth; `428` returned with a safe message | 🔴 |
| `T-AUTH-04` | BOLA / IDOR | Fuzzed object identifiers cannot read or mutate another team's, event's, or user's resource | 🔴 |
| `T-AUTH-05` | RLS enforcement | Direct SQL as each role returns only permitted rows; `row_security` forced | 🟠 |
| `T-AUTH-06` | DB least privilege | Each role's grants match the documented set; no role holds `superuser`; dynamic creds TTL ≤ 1 h | 🟠 |
| `T-AUTH-07` | Two-person integrity | Self-approval of `score.adjust` / `event:freeze` is impossible; AL-05 fires on an attempt | 🔴 |
| `T-AUTH-08` | Evidence separation | No principal can both mutate a score and delete audit evidence; grants are structurally incapable | 🔴 |
| `T-AUTH-09` | Banned combinations | `role:manage`+`policy:deploy` and `secret:read`+`policy:deploy` are continuously absent | 🟠 |

### 17.4 🟢 Application Hardening Tests

| ID | Test | Assertion | Gate |
|:--|:--|:--|:--|
| `T-APP-01` | Strict validation | Unknown keys rejected at every boundary; mass assignment impossible; depth > 12 rejected | 🔴 |
| `T-APP-02` | SQL injection | Semgrep rule plus DAST: no injectable parameter in any of the 40+ endpoints | 🔴 |
| `T-APP-03` | Client-trust | Submitting `rank`, `score`, or identity in a payload has no effect on stored state | 🔴 |
| `T-APP-04` | XSS sinks | No `innerHTML` / `dangerouslySetInnerHTML` / `eval`; team names rendered as text; CSP blocks execution | 🔴 |
| `T-APP-05` | CSP enforcement | A nonce-less inline script is blocked; `require-trusted-types-for 'script'` active; violations reported | 🔴 |
| `T-APP-06` | Subresource integrity | Missing/incorrect SRI blocks load; bundle digest pinned in `index.html` | 🟠 |
| `T-APP-07` | Deserialisation | Every parse boundary validated; malformed payload rejected without a crash or a partial write | 🔴 |
| `T-APP-08` | Idempotency | Replaying a mutation with the same key changes nothing and returns the original result | 🟠 |
| `T-APP-09` | Cache invalidation | A mutation purges the leaderboard cache within 1 s; no stale read beyond TTL | 🟠 |
| `T-APP-10` | Rate limiting | Public 60/min, admin 300/hr, auth 5/15 min, reports 20/hr enforced per identity and per IP | 🟠 |
| `T-APP-11` | Payload limits | 256 KB body (1 MB admin), 8 KB header, depth 12; oversize rejected with `413` | 🟡 |
| `T-APP-12` | Error safety | No response body contains a stack trace, SQL fragment, path, or library version; `traceId` correlates to a log | 🟡 |
| `T-APP-13` | Resilience wrapper | Every outbound call has timeout + bounded retry + breaker; breaker opens and half-opens as specified | 🟠 |
| `T-APP-14` | Regex safety | `safe-regex` clean; catastrophic patterns rejected at PR | 🟡 |
| `T-APP-15` | Catch-block hygiene | Grep/CI assertion: no `catch` interpolates a raw message into a client response | 🟠 |
| `T-APP-16` | NoSQL / key injection | User input cannot alter a Redis key namespace or key structure | 🟠 |
| `T-APP-17` | Command injection | No `child_process` invocation with user input; binary allow-list enforced | 🔴 |
| `T-APP-18` | Template injection | Report template cannot reach code execution, prototype pollution, or file read outside the sandbox | 🔴 |
| `T-APP-19` | Log injection | Control characters and forged newlines stripped from user-controlled log fields | 🟡 |
| `T-APP-20` | Prototype pollution | `__proto__`, `constructor`, and `prototype` keys rejected; objects built with `Object.create(null)` | 🟠 |

### 17.5 🟣 Cryptography Tests

| ID | Test | Assertion | Gate |
|:--|:--|:--|:--|
| `T-CRY-01` | Forbidden primitives | `crypto-lint` finds no MD5, SHA-1 (outside TOTP), DES/3DES/RC4, ECB, static IV, or bespoke cipher | 🔴 |
| `T-CRY-02` | Transport | TLS 1.3 negotiated; 1.2 only where required; cipher allow-list honoured; SSL Labs grade A+ | 🔴 |
| `T-CRY-03` | At-rest encryption | CMEK present per class; rotation works without data loss; plaintext never written to disk | 🔴 |
| `T-CRY-04` | PII columns | Per-record IV uniqueness across 10⁶ records; blind index key ≠ encryption key; tamper detected | 🟠 |
| `T-CRY-05` | Key rotation | JWT dual-active rotation with no validation outage; rotation emits `secret.rotated` | 🟠 |
| `T-CRY-06` | Key hygiene | No key material in source, images, logs, or crash dumps; generation only via KMS/HSM | 🔴 |
| `T-CRY-07` | Report signature | Detached signature verifies with the distributed public key; a modified PDF fails verification | 🟠 |
| `T-CRY-08` | Entropy | `Math.random()` absent from security-relevant paths; 10⁶ tokens unique | 🟠 |
| `T-CRY-09` | No client secrets | Bundle scan finds no high-entropy key-like strings; no token in web storage | 🔴 |
| `T-CRY-10` | Compromise response | Simulated key leak triggers revocation ≤ 1 h with dependent re-issue recorded | 🟠 |
| `T-CRY-11` | Crypto agility | Algorithm identifiers resolve from versioned config; a test algorithm swap succeeds without a code change | 🟡 |

### 17.6 🟠 Supply Chain Tests

| ID | Test | Assertion | Gate |
|:--|:--|:--|:--|
| `T-SC-01` | SBOM presence and diff | SPDX + CycloneDX emitted per build; unexpected new packages fail the diff review | 🟠 |
| `T-SC-02` | Lockfile integrity | `npm ci` only; integrity hashes verified; lockfile change triggers CODEOWNER review | 🟠 |
| `T-SC-03` | Install scripts disabled | `--ignore-scripts`; a package requiring a build step fails closed rather than executing | 🔴 |
| `T-SC-04` | Signature verification | `cosign verify` succeeds for our image and **fails** for a tampered one; deploy halts; AL-13 fires | 🔴 |
| `T-SC-05` | Digest pinning | No mutable tag in any manifest; a tag-only reference is rejected by policy | 🟠 |
| `T-SC-06` | Allow-list | An unapproved package cannot be installed; new dependency blocked until quarantined 7 days | 🟠 |
| `T-SC-07` | Workflow hardening | Actions pinned to full SHA; `permissions` minimal; no `pull_request_target` with checkout of untrusted code | 🟠 |
| `T-SC-08` | Provenance level | `slsa-verifier` confirms L3 predicate; a hand-built image fails admission | 🟠 |

### 17.7 🔵 Data Protection Tests

| ID | Test | Assertion | Gate |
|:--|:--|:--|:--|
| `T-DATA-01` | Minimisation | Every stored field maps to a purpose ID; an unmapped field fails the schema check | 🟠 |
| `T-DATA-02` | Redaction at source | No log line, metric label, or trace attribute contains an email or a full IP | 🟠 |
| `T-DATA-03` | PII deletion | Retention worker removes team member PII ~5 months after event end and emits a tombstone | 🟠 |
| `T-DATA-04` | Pseudonymisation | Audit store holds `/24` prefixes and hashed UAs only; explorer cannot reveal a full IP | 🟡 |
| `T-DATA-05` | Derived-state rebuild | Leaderboard projections rebuilt from the event store match the live projection byte-for-byte | 🟠 |
| `T-DATA-06` | Backup retention | A restored backup re-applies expiry; deleted PII does not reappear in a restored dataset | 🔴 |
| `T-DATA-07` | Breach assessment | A simulated personal-data breach produces an Art. 33 assessment within 24 h with the 72 h clock tracked | 🟠 |
| `T-DATA-08` | DSAR fulfilment | Access, erasure, and portability requests complete within 30 days with identity verification | 🟡 |
| `T-DATA-09` | Download control | Reports are watermarked, classified, rate-limited, and logged with requester identity; AL-08 fires | 🟠 |
| `T-DATA-10` | Deletion path | Every retention class has a tested deletion job; a silent retention worker raises AL-S03 | 🟠 |

### 17.8 🔴 Audit & Evidence Tests

| ID | Test | Assertion | Gate |
|:--|:--|:--|:--|
| `T-AUD-01` | Immutability | `UPDATE` and `DELETE` on `audit_log` fail for every non-owner role, including the on-call role | 🔴 |
| `T-AUD-02` | Transaction coupling | Forcing the audit insert to fail also rolls back the mutation (and vice versa) | 🔴 |
| `T-AUD-03` | Chain verification | Tampering, deleting, or inserting a historical event is detected by the hourly verifier; AL-01 fires | 🔴 |
| `T-AUD-04` | Sealing | A Merkle root is produced at the specified cadence, signed, and written to Object Lock COMPLIANCE mode | 🟠 |
| `T-AUD-05` | Denial coverage | Every 403 produces an `access.denied` record with correlation ID and policy version | 🔴 |
| `T-AUD-06` | External anchoring | A published root verifies against the RFC 3161 timestamp and the transparency log | 🔴 |
| `T-AUD-07` | Log hygiene | No secret or full PII in any audit field; entropy detector clean over a full event | 🟠 |
| `T-AUD-08` | Retention | Audit data present and WORM-protected at 7 years; cross-region replica verified | 🟠 |
| `T-AUD-09` | Query authorisation | `audit:read` and `audit:export` enforced with step-up; every export emits `audit.exported` | 🟠 |

### 17.9 🟡 Infrastructure Tests

| ID | Test | Assertion | Gate |
|:--|:--|:--|:--|
| `T-INFRA-01` | Segmentation | Every unlisted inter-zone flow is refused; `net_app` cannot reach `net_mgmt`; `net_audit` has no egress | 🔴 |
| `T-INFRA-02` | Container baseline | No container runs as root, with a writable root fs, or with any capability | 🟠 |
| `T-INFRA-03` | Image hygiene | Runtime image contains no shell, package manager, or network client; CIS ≥ 95 %, 0 critical | 🟠 |
| `T-INFRA-04` | Host baseline | CIS host benchmark pass; no local accounts; SSH key-only; encrypted swap | 🟡 |
| `T-INFRA-05` | IaC-only change | A console modification is detected as drift (AL-14) and reverted by re-apply | 🟠 |
| `T-INFRA-06` | Edge protection | WAF blocks a CRS severity-1 payload; bot scoring challenges a scraper; rate limit engages | 🟠 |
| `T-INFRA-07` | Resource isolation | A CPU/memory/PID exhaustion attempt in one service does not degrade another | 🟡 |
| `T-INFRA-08` | Time integrity | Clock drift > 1 s raises AL-17 and halts manual audit appends until NTP is healthy | 🟠 |

### 17.10 🔵 Third-Party Trust Tests

| ID | Test | Assertion | Gate |
|:--|:--|:--|:--|
| `T-EXT-01` | Signature forgery | A body modified after signing is rejected; a truncated body is rejected; a wrong-key signature is rejected | 🔴 |
| `T-EXT-02` | Replay | A capture replayed inside and outside the 300 s window behaves correctly; outside ⇒ reject + AL-02 | 🟠 |
| `T-EXT-03` | Duplicate delivery | The same event delivered 3× produces exactly one `raw_event` and one score effect | 🔴 |
| `T-EXT-04` | mTLS enforcement | A request without a client certificate, or with an untrusted CA, is refused at the edge | 🔴 |
| `T-EXT-05` | Schema strictness | An unknown property, a wrong type, and an oversized field are each rejected with a safe error | 🟠 |
| `T-EXT-06` | SSRF | A user-supplied URL in any export/report path is never fetched; egress allow-list blocks it | 🟠 |
| `T-EXT-07` | Principal scope | The webhook identity cannot read teams, users, audit, or reports; only ingest permissions resolve | 🟠 |
| `T-EXT-08` | Outbound allow-list | Only the contracted partner hosts are reachable; a DNS-rebinding attempt fails | 🟠 |

### 17.11 🟣 Process Tests

| ID | Test | Assertion | Gate |
|:--|:--|:--|:--|
| `T-SDLC-01` | Branch protection | Direct push to `main` refused; 1 CODEOWNER approval enforced; force-push refused | 🟠 |
| `T-SDLC-02` | Deploy approval | A single approver cannot deploy to production; the gate is enforced by the platform, not by convention | 🟠 |
| `T-SDLC-03` | Contract drift | A schema change without a regenerated OpenAPI spec fails CI | 🟡 |
| `T-SDLC-04` | Policy deployment | Unsigned, out-of-window, or single-approval policy deploys are refused; rollback succeeds | 🔴 |
| `T-SDLC-05` | Patch SLA | A seeded Critical CVE opens a P1 with a 24-hour clock and blocks the next release | 🟠 |
| `T-SDLC-06` | Training currency | An engineer with prod access and lapsed training blocks the deploy approval | 🟡 |
| `T-SDLC-07` | Pen-test closure | No High/Critical finding open beyond 30 days; ageing findings escalate automatically | 🟠 |
| `T-SDLC-08` | Threat-model currency | A significant architecture change without an updated threat model fails the review gate | 🟡 |

### 17.12 🧪 Abuse-Case Coverage

| Abuse case | Description | Controls | Tests |
|:--|:--|:--|:--|
| `AB-01` | Spectator enumerates other teams' private detail | `SEC-AUTH-04`, `SEC-DATA-01` | `T-AUTH-04`, `T-DATA-01` |
| `AB-02` | Botted scraping of the full leaderboard | `SEC-APP-10`, `SEC-INFRA-06` | `T-APP-10`, `T-INFRA-06` |
| `AB-03` | Credential stuffing against admin endpoints | `SEC-IAM-06`, `SEC-APP-10` | `T-IAM-06`, `T-APP-10` |
| `AB-04` | Forged webhook to award points | `SEC-EXT-01`, `SEC-EXT-02` | `T-EXT-01`, `T-EXT-04` |
| `AB-05` | Replayed legitimate webhook | `SEC-EXT-03`, `SEC-EXT-05` | `T-EXT-02`, `T-EXT-03` |
| `AB-06` | Malicious team name carrying a script payload | `SEC-APP-04`, `SEC-APP-05` | `T-APP-04`, `T-APP-05` |
| `AB-07` | Client-side rank manipulation | `SEC-APP-03` | `T-APP-03` |
| `AB-08` | Referee session theft via XSS | `SEC-APP-04`, `SEC-APP-05`, `SEC-IAM-07` | `T-APP-04`, `T-IAM-07` |
| `AB-09` | Step-up bypass by replaying an old assertion | `SEC-IAM-07`, `SEC-AUTH-03` | `T-AUTH-03`, AL-S05 |
| `AB-10` | Self-approval of a score adjustment | `SEC-AUTH-07` | `T-AUTH-07` |
| `AB-11` | Insider edits the audit log directly | `SEC-AUD-03` | `T-AUD-01` |
| `AB-12` | Insider suppresses logging during a change | `SEC-AUD-02` | `T-AUD-02`, AL-S02 |
| `AB-13` | Insider deletes WORM evidence | `SEC-AUD-05`, `SEC-DATA-09` | `T-AUD-04`, `T-AUD-08` |
| `AB-14` | Dependency confusion via a typosquatted package | `SEC-SC-02`, `SEC-SC-06` | `T-SC-02`, `T-SC-06` |
| `AB-15` | Compromised CI runner signing a malicious image | `SEC-SC-04`, `SEC-SC-08` | `T-SC-04`, `T-SC-08` |
| `AB-16` | Secret leaked in a log or an image layer | `SEC-CRY-05`, `SEC-SC-01` | `T-CRY-06`, `T-SC-01` |
| `AB-17` | Break-glass used to cover an error | `SEC-IAM-08`, `SEC-AUD-01` | `T-IAM-08`, `T-AUD-05` |
| `AB-18` | Report artefact exfiltrated in bulk | `SEC-DATA-08`, `SEC-AUD-09` | `T-DATA-09`, `T-AUD-09` |

> 📖 The abuse-case suite runs on **every commit** (`🧪 Success criteria: all AB-01…AB-18 pass`) and is extended whenever the threat model changes. An abuse case with no automated test is a story, not a control.

### 17.13 ⚛️ Determinism, Replay & Derivation Tests

> These tests defend the claim that a score is *explainable*. If a replay of the same event log can produce a different leaderboard, then no dispute can be settled with evidence and the audit trail is decorative. They enforce the invariants defined in [`state.md` §7](./state.md#7--invariants--the-non-negotiable-rules).

| ID | Test | Assertion | Gate |
|:--|:--|:--|:-:|
| `T-DER-01` | Score recomputation from the log | Recomputing every team score from `score_event` + `scoring_model` reproduces the stored `team_score` exactly; zero tolerance, no rounding band | 🔴 |
| `T-DER-02` | Projection purity | The scorer opens no socket, reads no clock, consumes no RNG, and writes nothing outside its return value; enforced by a static import allow-list and a read-only database role | 🔴 |
| `T-DER-03` | Rebuild-and-diff | Rebuilding every projection from the event log into a shadow schema yields zero divergent rows across all teams, events, and ranks | 🔴 |
| `T-DER-04` | Replay determinism | Replaying the same sealed event log twice, and once under a 90-day clock skew, produces identical projection output; the purifier window is asserted explicitly | 🔴 |
| `T-DER-05` | Derivation completeness | A `score_event` cannot be inserted without `derivation`, `scoring_model_version`, and `occurred_at`; `NOT NULL` plus a check constraint rejects a partial write | 🟠 |
| `T-DER-06` | Monotonic application | An out-of-order or stale frame never overwrites a newer aggregate version; the projector asserts `incoming > stored` before applying | 🔴 |
| `T-DER-07` | Gap detection | A deliberately removed `seq` raises a resync and an alert within one projector cycle; the pipeline never silently skips a gap | 🔴 |
| `T-DER-08` | Score property test | Across generated event sequences: score is never negative, decay never increases a score, rank is a total order, and tie-breaks yield exactly one first place | 🟠 |
| `T-DER-09` | State machine guards | Every illegal transition in the event, team, solve, adjustment, and report-job machines is rejected by the transition function itself, not by a UI check | 🟠 |
| `T-DER-10` | Projection write isolation | The projector role holds `INSERT` on projection tables only; it cannot write `audit_log`, `raw_event`, or `score_event`, and an attempted write is denied and audited | 🔴 |
| `T-DER-11` | Frame ordering contract | Every SSE frame carries `seq` and `aggregateVersion`; the client reducer rejects a frame whose `seq ≤ lastSeq` and never mutates render state | 🟠 |
| `T-DER-12` | Poison-event containment | A schema-invalid event lands in the DLQ with a named owner and raises an alert; ingestion stays available and `lastApplied` does not advance | 🟠 |
| `T-DER-13` | Referential completeness | Every `score_event` resolves to a live team, a real event, and a registered `scoring_model` version; orphans are impossible by foreign key and are swept nightly | 🟠 |

> 🧾 **The tests that matter most are the boring ones.** `T-DER-03` and `T-DER-04` run nightly against production-shaped data. They are the reason a score dispute can be settled by replay instead of by argument.

## 18. 🔴 Incident Response & Runbooks

**Family objective:** during an incident, the system behaves predictably — evidence is preserved automatically, blast radius is contained, and every action is attributable. Response capability is rehearsed, not documented and hoped for.

### 18.1 Severity & Response Targets

| Severity | Definition | Response | Notify | Target |
|:--|:--|:--|:--|:--|
| 🔴 **P1 Critical** | Active compromise, score tampering, audit chain break, personal-data breach | Page immediately; incident commander; bridge ≤ 15 min | CISO, DPO, executives, affected users (Art. 33 within 72 h) | Contain ≤ 1 h |
| 🟠 **P2 High** | Confirmed vulnerability without exploitation; partial outage; key exposure | Page in hours; fix ≤ 24 h | Team lead, CISO | Fix ≤ 24 h |
| 🟡 **P3 Medium** | Suspicious activity; minor defect; control deviation | Ticket; investigate ≤ 3 d | Team | Fix ≤ 7 d |
| 🟢 **P4 Low** | Informational; hardening improvement | Backlog | — | Next sprint |

```mermaid
%%{init: {"theme":"base","themeVariables":{"primaryColor":"#EF476F","primaryTextColor":"#E8ECF8","primaryBorderColor":"#EF476F","lineColor":"#8B95B8","fontFamily":"Inter, sans-serif"}}}%%
flowchart TB
    P1["1️⃣ Preparation<br/>playbooks · on-call rota<br/>tabletops · tooling"]:::a
    P2["2️⃣ Identification<br/>SIEM · reports · monitoring"]:::b
    P3["3️⃣ Containment<br/>isolate · block · revoke<br/>preserve evidence"]:::c
    P4["4️⃣ Eradication<br/>root cause · rotate<br/>all exposed credentials"]:::d
    P5["5️⃣ Recovery<br/>restore · replay · verify<br/>re-enable carefully"]:::e
    P6["6️⃣ Lessons learned<br/>PIR ≤ 14 days<br/>actions to closure"]:::f
    P7["7️⃣ Improvement<br/>playbooks · controls<br/>training · threat model"]:::g
    P1 --> P2 --> P3 --> P4 --> P5 --> P6 --> P7
    P3 -.->|"every action audited<br/>as critical_system_operation"| EV["🧾 Evidence preserved<br/>WORM snapshot · hashes<br/>chain of custody"]:::ev
    classDef a fill:#241A4D,stroke:#6C5CE7,color:#E8ECF8
    classDef b fill:#062B3A,stroke:#00D2FF,color:#E8ECF8
    classDef c fill:#2A1220,stroke:#EF476F,color:#E8ECF8
    classDef d fill:#3A2A05,stroke:#FF9F1C,color:#E8ECF8
    classDef e fill:#2E2205,stroke:#FFD166,color:#0B0E1A
    classDef f fill:#141A2E,stroke:#8B95B8,color:#E8ECF8
    classDef g fill:#06251D,stroke:#06D6A0,color:#E8ECF8
    classDef ev fill:#2A1220,stroke:#EF476F,color:#E8ECF8
```

### 18.2 Control Catalogue

| ID | Control Statement | Sev | Implementation | Verified by |
|:--|:--|:-:|:--|:--|
| **SEC-IR-01** | Every P1 alert **MUST** page a named on-call responder with a runbook link, and **MUST** open an incident record automatically | 🔴 | Alertmanager routing; `runbook_url` annotation; incident auto-creation | `T-IR-01` 🔴 |
| **SEC-IR-02** | Incident evidence **MUST** be preserved automatically (audit chain snapshot, DB and access-log export, artefact register) before any remediation touches the system | 🔴 | Evidence collector runs first in the containment playbook; WORM + signed | `T-IR-02` 🔴 |
| **SEC-IR-03** | A security incident **MUST NOT** be closed until a post-incident review is completed within 14 days, with every action tracked to closure | 🟠 | PIR template; action tracker; recurrence check | `T-IR-03` 🟠 |
| **SEC-IR-04** | Restores and other `critical_system_operation` actions **MUST** require `security_admin` + two-person approval + a change window, and **MUST** be audited | 🔴 | Change management; audit action `critical_system_operation` | `T-IR-04` 🔴 |
| **SEC-IR-05** | Game-day exercises (tabletop and live) **MUST** be run semi-annually, covering every P1 runbook | 🟠 | Exercise calendar; after-action report | `T-IR-05` 🟠 |
| **SEC-IR-06** | A breach assessment for GDPR Art. 33/34 **MUST** be produced within 24 h of detection of a personal-data breach, with the 72 h regulatory deadline tracked | 🔴 | DPO runbook; assessment artefact template | `T-IR-06` 🔴 |

### 18.3 Runbook Index

| ID | Runbook | Sev | Owner | Key first actions |
|:--|:--|:-:|:--|:--|
| `RB-01` | Audit chain break — triage & containment | 🔴 P1 | Security | Freeze admin writes → snapshot chain → identify divergence window → preserve evidence |
| `RB-02` | Suspected score tampering | 🔴 P1 | Backend + Security | Halt scoring → reconcile against platform → freeze top 3 → preserve session evidence |
| `RB-03` | Webhook compromise / key rotation | 🟠 P2 | Platform | Revoke partner key → issue dual-key overlap → replay last 24 h → notify platform |
| `RB-04` | Admin account compromise | 🔴 P1 | Security | Revoke sessions → force re-auth with WebAuthn → audit the account's actions → reset role grants |
| `RB-05` | L7 DDoS during a live event | 🔴 P1 | Platform | Engage scrubbing → enable challenge page → pre-warm CDN → shift to polling fallback |
| `RB-06` | Database restore from PITR | 🔴 P1 | Data | Two-person approval → restore to isolated host → verify chain + reconcile → re-point traffic |
| `RB-07` | Region loss failover | 🔴 P1 | Platform | Promote standby → re-point object store → verify audit chain continuity → reconcile |
| `RB-08` | Break-glass activation & closure | 🔴 P1 | Security | Two-person activation → 60-min timer → record purpose → CISO review ≤ 24 h → seal |
| `RB-09` | Report artefact suspected leaked | 🟠 P2 | GRC | Revoke artefact → invalidate links → identify recipients → Art. 33 assessment → notify |
| `RB-10` | Supply-chain compromise | 🔴 P1 | Security | Halt deploys → identify affected digests → verify signatures of running images → rebuild from known-good source |
| `RB-11` | Key/secret exposure in the repository | 🟠 P2 | Security | Revoke key ≤ 1 h → rotate dependents → purge history → scan for usage → assess disclosure |
| `RB-12` | Public display compromise / defacement | 🟠 P2 | Platform | Redeploy digest-pinned image → verify signature → rotate CDN cache → review `config.updated` |
| `RB-13` | GDPR data-subject request | 🟡 P3 | DPO + GRC | Verify identity → locate data across all tiers → execute erasure except holds → respond ≤ 30 days |
| `RB-14` | Ingest backlog replay | 🟠 P2 | Backend | Drain the Redis buffer in order → verify no duplicate application → reconcile totals → unseal |

### 18.4 Mandatory Evidence Preservation

```
✅ Snapshot the audit chain up to the incident moment (WORM, signed)
✅ Full database and access-log export (hashed, sealed, chain-of-custody record)
✅ Preserve the report artefact register and download history
✅ Preserve the policy bundle version in force and the entitlement snapshot
✅ No deletion of any potentially relevant log during the investigation
✅ GDPR Art. 33/34 notification assessment within 24 h
✅ Every responder action recorded as critical_system_operation
```

### 18.5 Degradation Security Rules

| Condition | Security rule | Rationale |
|:--|:--|:--|
| PDP unreachable | 🔴 Fail closed — deny | An authorisation outage must not become an authorisation bypass |
| Audit store unavailable | 🔴 Refuse the mutation | A change without an audit record is an unauditable change |
| IdP unreachable | 🔴 Fail closed for admin; public board continues | Availability of governance > availability of admin |
| Database unavailable | 🟠 Read-only; board shows the last sealed state | Never fabricate data |
| CDN unavailable | 🟡 Serve from origin; edge assets cached | Availability fallback |
| Report workers exhausted | 🟡 Queue with visible ETA; never fail the request | Asynchronous by design |
| Clock drift > 1 s | 🟠 Alert; halt manual audit appends | Chain ordering integrity |

## 19. 🟡 Exceptions & Risk Acceptance

**Family objective:** a deviation is a *decision with an owner, an expiry date, and evidence* — never a silent gap. This section is what makes an honest control environment possible: without it, teams either lie about coverage or stop trying.

### 19.1 Exception Principles

| # | Principle |
|:-:|:--|
| 1 | 🟢 **No exception for a 🔴 Critical control.** If a critical control cannot be implemented, the feature or deployment that depends on it does not ship. |
| 2 | 🟡 **An exception has an expiry date.** A permanent exception is a design decision, and must be argued as one in the architecture record, not granted as a waiver. |
| 3 | 🟡 **An exception has a compensating control.** "We will fix it later" is not a compensating control. |
| 4 | 🔵 **Acceptance is a business decision.** The engineer who wants the exception does not accept the risk; the accountable owner does. |
| 5 | 🟢 **Acceptance is auditable.** Every exception appears in the Statement of Applicability, in the risk register, and in the evidence pack. |
| 6 | 🟡 **Expiry is enforced.** An expired exception auto-escalates to a 🔴 finding and blocks the next release. |

### 19.2 Exception Request Record

| Field | Required | Example |
|:--|:--:|:--|
| Exception ID | ✅ | `EXC-2026-004` |
| Control(s) | ✅ | `SEC-INFRA-03` |
| Justification | ✅ | *"Distroless base image unavailable for the ARM report-renderer; hardened Debian is the interim base."* |
| Risk description | ✅ | *"Larger image, more packages, higher CVE surface on a worker that parses untrusted data."* |
| Inherent risk | ✅ | 🟠 High |
| Compensating control | ✅ | Trivy scan + read-only rootfs + no egress + 24 h patch SLA + renderer sandbox |
| Residual risk | ✅ | 🟡 Medium |
| Owner accepting risk | ✅ | `role:manage` holder, named |
| Expiry | ✅ | 2026-12-31 (hard maximum 180 days) |
| Review trigger | ✅ | On any Critical CVE in the affected image |
| Linked risk register entry | ✅ | `R-14` |

### 19.3 Exception Register (Current)

| ID | Control | Deviation | Compensating control | Residual | Owner | Expiry | Status |
|:--|:--|:--|:--|:-:|:--|:--|:--|
| `EXC-2026-001` | `SEC-AUD-06` | External transparency log not yet contracted; RFC 3161 TSA used instead | Signed TSA timestamps per seal; procedure to add a transparency log within 30 days of contract | 🟡 | Security Eng | 2026-12-31 | 🟠 Active |
| `EXC-2026-002` | `SEC-EXT-01` | CTF platform cannot present a client certificate for its staging environment | Staging webhooks accepted only from an isolated network with a shared secret and no production data | 🟡 | Platform Lead | 2026-11-30 | 🟠 Active |
| `EXC-2026-003` | `SEC-INFRA-03` | Report renderer requires a glibc base for a native PDF library | Read-only rootfs, non-root, no network client, no egress allow-list, sandboxed renderer, Trivy gate, 24 h CVE SLA | 🟡 | Platform Lead | 2026-12-31 | 🟠 Active |

> 🔍 **Reviewer question:** *"Why is the compensating control actually equivalent?"* For `EXC-2026-003`, the compensating control set removes the network capability that a compromised package would abuse, and confines the blast radius to a worker with no credentials beyond a scoped report-writing role. That is a defensible argument. A compensating control of "we monitor it" is not.

---

## 20. 🟣 Compliance Traceability

> This section is what an auditor reads first. **Requirement → control → implementation → evidence → verification.** All evidence is produced automatically by the collectors in [`architecture.md` §15.5](./architecture.md#155-evidence-automation).

### 20.1 OWASP Top 10:2025 Coverage

| # | Category | Key Controls | Verification | Residual |
|:--|:--|:--|:--|:-:|
| **A01** | Broken Access Control | `SEC-AUTH-01`…`09`, `SEC-APP-03`, `SEC-APP-08` | `T-AUTH-01`…`09`, `T-APP-03` | 🟡 |
| **A02** | Security Misconfiguration | `SEC-APP-05`, `SEC-INFRA-02`…`05`, `SEC-INFRA-08` | `T-APP-05`, `T-INFRA-02`…`05` | 🟡 |
| **A03** | Software Supply Chain Failures | `SEC-SC-01`…`08` | `T-SC-01`…`08` | 🟡 |
| **A04** | Cryptographic Failures | `SEC-CRY-01`…`10`, `SEC-APP-13` | `T-CRY-01`…`11` | 🟡 |
| **A05** | Injection | `SEC-APP-01`, `SEC-APP-02`, `SEC-APP-04`, `SEC-APP-07` | `T-APP-01`, `T-APP-02`, `T-APP-04`, `T-APP-07` | 🟡 |
| **A06** | Insecure Design | `SEC-AUTH-07`, `SEC-APP-10`, `SEC-AUD-01`, abuse-case suite | `T-AUTH-07`, `AB-01`…`AB-18` | 🟡 |
| **A07** | Authentication Failures | `SEC-IAM-01`…`10` | `T-IAM-01`…`10` | 🟡 |
| **A08** | Software/Data Integrity Failures | `SEC-EXT-02`…`05`, `SEC-SC-04`, `SEC-AUD-04` | `T-EXT-01`…`03`, `T-SC-04`, `T-AUD-04` | 🟡 |
| **A09** | Security Logging & Alerting Failures | `SEC-AUD-01`, `SEC-AUD-04`, `SEC-AUD-07`, AL-01…AL-S05 | `T-AUD-03`, `T-AUD-05`, `T-AUD-07` | 🟡 |
| **A10** | Mishandling of Exceptional Conditions | `SEC-APP-12`, `SEC-APP-13`, degradation rules | `T-APP-12`, `T-APP-13`, `T-IR-02` | 🟡 |

### 20.2 ISO/IEC 27001:2022 — Annex A Mapping

| Annex A | Control intent | Implementation | `SEC-*` | `T-*` |
|:--|:--|:--|:--|:--|
| A.5.1 | Policies for information security | Document set with owners and review cycle | all | quarterly review |
| A.5.3 | Segregation of duties | Two-person integrity; no score+evidence authority | `SEC-AUTH-07`, `SEC-AUTH-08` | `T-AUTH-07`, `T-AUTH-08` |
| A.5.7 | Threat intelligence | STRIDE model, detection rules, threat feeds | `SEC-AUD-04` | `T-AUD-03` |
| A.5.9 | Inventory of assets | CMDB + SBOM + key inventory | `SEC-CRY-03` | `T-SC-01`, `T-CRY-05` |
| A.5.12 | Classification of information | Five-class data model | `SEC-DATA-01` | `T-DATA-01` |
| A.5.14 | Information transfer | TLS 1.3, signed webhooks, mTLS | `SEC-CRY-01`, `SEC-EXT-01` | `T-CRY-02`, `T-EXT-04` |
| A.5.15 | Access control | RBAC × resource + ABAC | `SEC-AUTH-01`, `SEC-AUTH-04` | `T-AUTH-01`, `T-AUTH-04` |
| A.5.16 | Identity management | OIDC federation, SCIM lifecycle | `SEC-IAM-01` | `T-IAM-01` |
| A.5.17 | Authentication information | Argon2id, sealed break-glass, no shared creds | `SEC-IAM-05`, `SEC-CRY-05` | `T-IAM-05`, `T-CRY-06` |
| A.5.18 | Access rights | Quarterly access review, recertification | `SEC-SDLC-01` | `T-SDLC-01` |
| A.5.23 | Cloud services security | Least-privilege IAM, SCPs, Object Lock | `SEC-AUTH-06`, `SEC-AUD-08` | `T-AUTH-06`, `T-AUD-08` |
| A.5.24–A.5.28 | Incident management | IR lifecycle, P1–P4, evidence preservation | `SEC-IR-01`…`03` | `T-IR-01`…`03` |
| A.5.29 | Business continuity | Recovery priority order, warm standby | `SEC-IR-04` | `T-IR-04` |
| A.5.30 | ICT readiness | Game-day exercises, RTO/RPO drills | `SEC-IR-05` | `T-IR-05` |
| A.5.31 | Legal requirements | Contractual notification, licensing | `SEC-SDLC-07` | `T-SDLC-07` |
| A.5.33 | Protection of records | 7-year WORM retention, legal hold | `SEC-AUD-08`, `SEC-DATA-09` | `T-AUD-08`, `T-DATA-10` |
| A.5.34 | Privacy and PII protection | Minimisation, encryption, DSAR, DPIA | `SEC-DATA-01`…`09` | `T-DATA-01`…`10` |
| A.5.35 | Independent review | Annual pen test, internal audit | `SEC-SDLC-07` | `T-SDLC-07` |
| A.5.37 | Documented operating procedures | Runbooks RB-01…RB-14 | `SEC-IR-01` | `T-IR-01` |
| A.8.1–A.8.2 | Privileged access / accounts | `security_admin` 2-of-2, no standing privilege | `SEC-AUTH-09`, `SEC-IAM-08` | `T-AUTH-09`, `T-IAM-08` |
| A.8.4 | Source code access | Branch protection, CODEOWNERS | `SEC-SDLC-01` | `T-SDLC-01` |
| A.8.5 | Secure authentication | MFA, PKCE, short sessions | `SEC-IAM-02`, `SEC-IAM-04` | `T-IAM-02`, `T-IAM-04` |
| A.8.7 | Malware protection | Signed images, admission verification | `SEC-SC-04` | `T-SC-04` |
| A.8.8–A.8.9 | Vulnerabilities / configuration | SCA, IaC scan, patch SLA | `SEC-SDLC-05`, `SEC-INFRA-05` | `T-SDLC-05`, `T-INFRA-05` |
| A.8.10 | Deletion of information | Retention worker + tombstones | `SEC-DATA-03`, `SEC-DATA-09` | `T-DATA-03`, `T-DATA-10` |
| A.8.11 | Data masking | Blind index, UI masking, IP truncation | `SEC-CRY-03`, `SEC-DATA-04` | `T-CRY-04`, `T-DATA-04` |
| A.8.12 | Data leakage prevention | Watermarking, egress allow-list, AL-08 | `SEC-DATA-08`, `SEC-EXT-07` | `T-DATA-09`, `T-EXT-07` |
| A.8.13 | Information backup | pgBackRest, cross-region, verified restores | `SEC-IR-04` | `T-IR-04` |
| A.8.15–A.8.17 | Logging / monitoring / clock sync | Hash chain, SIEM, NTP | `SEC-AUD-01`…`08`, `SEC-INFRA-08` | `T-AUD-03`, `T-AUD-05`, `T-INFRA-08` |
| A.8.20–A.8.22 | Network security / segregation | 5 zones, default deny, egress allow-list | `SEC-INFRA-01` | `T-INFRA-01` |
| A.8.24 | Use of cryptography | Algorithm policy, key hierarchy, crypto-agility | `SEC-CRY-01`…`10` | `T-CRY-01`…`11` |
| A.8.25–A.8.26 | Secure development lifecycle | Gates, threat model, abuse cases | `SEC-SDLC-01`…`04`, `SEC-SDLC-08` | `T-SDLC-01`…`04`, `T-SDLC-08` |
| A.8.27–A.8.28 | Secure architecture / coding | Defence in depth, 18 coding standards | all `SEC-APP-*` | `T-APP-01`…`20` |
| A.8.29 | Security testing in development | 120-test catalogue, DAST, fuzzing | `SEC-SDLC-05` | all `T-*` |
| A.8.31–A.8.34 | Test/ prod separation, change mgmt, audit testing | Isolated staging, change windows, two-person deploys | `SEC-SDLC-02`, `SEC-SDLC-04` | `T-SDLC-02`, `T-SDLC-04` |

### 20.3 Abuse-Case Coverage

Abuse-case coverage is maintained in [§17.12](#1712--abuse-case-coverage): all 18 cases map to at least one control and one automated test, and the mapping is reviewed whenever the threat model changes.

### 20.4 NIST SP 800-53 Rev. 5 — Moderate Baseline (Selected)

| Control | Intent | `SEC-*` | `T-*` |
|:--|:--|:--|:--|
| AC-2 | Account management | `SEC-IAM-01`, `SEC-SDLC-01` | `T-IAM-01` |
| AC-3 | Access enforcement | `SEC-AUTH-01`, `SEC-AUTH-04` | `T-AUTH-01`, `T-AUTH-04` |
| AC-6 | Least privilege | `SEC-AUTH-05`, `SEC-AUTH-06` | `T-AUTH-05`, `T-AUTH-06` |
| AC-7 | Unsuccessful logon attempts | `SEC-IAM-06` | `T-IAM-06` |
| AC-12 | Session termination | `SEC-IAM-04`, `SEC-IAM-07` | `T-IAM-04`, `T-IAM-07` |
| AU-2 | Event logging | `SEC-AUD-01` | `T-AUD-05` |
| AU-3 | Content of records | `SEC-AUD-07` | `T-AUD-07` |
| AU-6 | Audit review | `SEC-AUD-04`, `SEC-AUD-09` | `T-AUD-03`, `T-AUD-09` |
| AU-9 | Protection of audit information | `SEC-AUD-03`, `SEC-AUD-08` | `T-AUD-01`, `T-AUD-08` |
| AU-11 | Audit record retention | `SEC-AUD-08`, `SEC-DATA-09` | `T-AUD-08`, `T-DATA-10` |
| CA-7 | Continuous monitoring | AL-01…AL-S05 | detection harness |
| CM-3 | Configuration change control | `SEC-INFRA-05`, `SEC-SDLC-04` | `T-INFRA-05`, `T-SDLC-04` |
| CM-6 | Configuration settings | `SEC-INFRA-02`, `SEC-INFRA-07` | `T-INFRA-02`, `T-INFRA-07` |
| CP-9 | System backup | `SEC-IR-04` | `T-IR-04` |
| CP-10 | System recovery | `SEC-IR-04`, `SEC-IR-05` | `T-IR-04`, `T-IR-05` |
| IA-2 | Identification and authentication | `SEC-IAM-01`, `SEC-IAM-02` | `T-IAM-01`, `T-IAM-02` |
| IA-5 | Authenticator management | `SEC-IAM-05`, `SEC-CRY-09` | `T-IAM-05`, `T-CRY-09` |
| IR-4 | Incident handling | `SEC-IR-01`…`03` | `T-IR-01`…`03` |
| RA-5 | Vulnerability monitoring | `SEC-SDLC-05` | `T-SDLC-05` |
| SA-10 | Developer configuration management | `SEC-SC-07` | `T-SC-07` |
| SA-11 | Developer testing | all `T-*` | 120 tests |
| SC-7 | Boundary protection | `SEC-INFRA-01`, `SEC-INFRA-06` | `T-INFRA-01`, `T-INFRA-06` |
| SC-12 | Cryptographic key establishment | `SEC-CRY-04`, `SEC-CRY-05` | `T-CRY-05`, `T-CRY-06` |
| SC-13 | Cryptographic protection | `SEC-CRY-01`, `SEC-CRY-02` | `T-CRY-02`, `T-CRY-03` |
| SC-28 | Protection of information at rest | `SEC-CRY-02`, `SEC-CRY-03` | `T-CRY-03`, `T-CRY-04` |
| SI-4 | System monitoring | `SEC-AUD-01`, `SEC-AUD-04` | `T-AUD-03`, `T-AUD-05` |
| SI-7 | Software, firmware, information integrity | `SEC-SC-04`, `SEC-SC-08` | `T-SC-04`, `T-SC-08` |

### 20.5 GDPR Mapping

| Article | Obligation | Control | Evidence |
|:--|:--|:--|:--|
| Art. 5(1)(a) | Lawfulness, fairness, transparency | `SEC-DATA-01`, `SEC-DATA-04` | Data inventory; notice text |
| Art. 5(1)(c) | Data minimisation | `SEC-DATA-01`, `SEC-DATA-04` | `T-DATA-01`, `T-DATA-04` |
| Art. 5(1)(e) | Storage limitation | `SEC-DATA-03`, `SEC-DATA-09` | `T-DATA-03`, `T-DATA-10` |
| Art. 5(1)(f) | Integrity & confidentiality | `SEC-CRY-02`, `SEC-CRY-03` | `T-CRY-03`, `T-CRY-04` |
| Art. 6 | Lawful basis | `SEC-DATA-01` | Purpose register with basis |
| Art. 15–17 | Access, erasure, restriction | `SEC-DATA-07` | `T-DATA-08` |
| Art. 20 | Data portability | `SEC-DATA-07` | `T-DATA-08` |
| Art. 25 | Data protection by design | `SEC-DATA-01`, `SEC-DATA-08` | DPIA; `T-DATA-09` |
| Art. 30 | Records of processing | Data inventory register | Exportable register |
| Art. 32 | Security of processing | `SEC-CRY-*`, `SEC-INFRA-*` | `T-CRY-*`, `T-INFRA-*` |
| Art. 33 | Breach notification (72 h) | `SEC-IR-06`, `SEC-DATA-06` | `T-IR-06`, `T-DATA-07` |
| Art. 35 | DPIA | Required before Phase 2 | Signed DPIA artefact |
| Art. 44–49 | Transfers | `SEC-DATA-01` (region pinning) | Sub-processor register |

## 21. 🔵 Security Metrics & KPIs

> Metrics exist to change behaviour. A metric nobody looks at is decoration, and a metric that is gamed is worse than no metric. Each metric below names the decision it informs.

### 21.1 Control Health

| Metric | Target | Decision it informs |
|:--|:--|:--|
| Controls 🟢 Enforced / total | ≥ 95 % by end of Phase 2 | Roadmap prioritisation |
| Controls with a passing test | **100 % (hard floor)** | Release readiness |
| Controls with a live detection signal | 100 % of 🔴 Critical | Detection engineering backlog |
| Open exceptions past expiry | **0** | Escalation; release block |
| SoD violations found by continuous assertion | **0** | Identity governance |
| Orphaned entitlements | **0** | Quarterly access review focus |
| Policies deployed outside a change window | **0** | Change-management discipline |

### 21.2 Operational Security

| Metric | Target | Notes |
|:--|:--|:--|
| MTTD (detection) | ≤ 5 min for P1 | Alert quality tuning |
| MTTR (containment) | ≤ 60 min for P1 | Runbook maturity |
| Alerts with no documented triage | 0 after 30 days | Alert fatigue reduction |
| False-positive rate on security alerts | ≤ 20 % | Detection tuning |
| Time to revoke a session after disablement | ≤ 60 s | `SEC-IAM-07` |
| Time to revoke a compromised key | ≤ 60 min | `SEC-CRY-09` |
| Critical CVE patch latency | ≤ 24 h | `SEC-SDLC-05` |
| High CVE patch latency | ≤ 7 d | `SEC-SDLC-05` |
| Mean time to close a pen-test finding | ≤ 30 d | `SEC-SDLC-07` |

### 21.3 Assurance & Evidence

| Metric | Target |
|:--|:--|
| Audit chain verification success rate | 100 % (0 breaks) |
| Audit records failing schema validation | 0 |
| Evidence collectors passing | 100 % of 14 collectors |
| Reports generated without a signature | 0 |
| Restores verified against RTO/RPO | 4 per year (quarterly) |
| Game-day exercises completed | 2 per year |
| Post-incident reviews within 14 days | 100 % |

### 21.4 Privacy

| Metric | Target |
|:--|:--|
| PII fields without a purpose ID | **0** |
| Retention jobs silent > 26 h | 0 (AL-S03) |
| DSARs completed within 30 days | 100 % |
| Deletions with a tombstone record | 100 % |
| Art. 33 assessments within 24 h of detection | 100 % |

```mermaid
%%{init: {"theme":"base","themeVariables":{"primaryColor":"#00D2FF","primaryTextColor":"#E8ECF8","primaryBorderColor":"#00D2FF","lineColor":"#8B95B8","fontFamily":"Inter, sans-serif"}}}%%
flowchart LR
    subgraph INPUT["📥 SIGNAL SOURCES"]
        I1["🧪 CI gate results"]:::i
        I2["🔍 SIEM alerts"]:::i
        I3["🧾 Audit chain verifier"]:::i
        I4["🌱 Retention worker"]:::i
        I5["🖼️ Scanner findings"]:::i
    end
    subgraph AGG["📊 AGGREGATION"]
        A1["SLO-style burn<br/>rate windows"]:::a
        A2["Control coverage<br/>dashboard"]:::a
    end
    subgraph OUT["📤 OUTPUT"]
        O1["🟢 Weekly security review"]:::o
        O2["🔴 Page on threshold breach"]:::o
        O3["📦 Monthly evidence pack"]:::o
        O4["🗓️ Quarterly attestation"]:::o
    end
    I1 --> A1 & A2
    I2 --> A1
    I3 --> A1
    I4 --> A1
    I5 --> A1
    A1 --> O1 & O2
    A2 --> O1 & O3 & O4
    classDef i fill:#062B3A,stroke:#00D2FF,color:#E8ECF8
    classDef a fill:#241A4D,stroke:#6C5CE7,color:#E8ECF8
    classDef o fill:#06251D,stroke:#06D6A0,color:#E8ECF8
```

---

## 22. ⬜ Appendices

### 22.1 Complete Control Index

**🔵 `SEC-IAM` — Identity & Session (9)**

| ID | Title | Sev | Test |
|:--|:--|:-:|:--|
| `SEC-IAM-01` | OIDC Authorization Code + PKCE only | 🔴 | `T-IAM-01` |
| `SEC-IAM-02` | MFA mandatory for all staff | 🔴 | `T-IAM-02` |
| `SEC-IAM-03` | `__Host-` session cookie hardening | 🟠 | `T-IAM-03` |
| `SEC-IAM-04` | Idle and absolute session expiry | 🟠 | `T-IAM-04` |
| `SEC-IAM-05` | Argon2id password storage; break-glass only | 🟠 | `T-IAM-05` |
| `SEC-IAM-06` | Brute-force defence and backoff | 🟠 | `T-IAM-06` |
| `SEC-IAM-07` | Session revocation propagation ≤ 60 s | 🟠 | `T-IAM-07` |
| `SEC-IAM-08` | Break-glass two-person, 60-min, P1 | 🔴 | `T-IAM-08` |
| `SEC-IAM-09` | Device posture and scoped kiosk tokens | 🟡 | `T-IAM-09` |

**🔴 `SEC-AUTH` — Authorisation & Separation of Duties (9)**

| ID | Title | Sev | Test |
|:--|:--|:-:|:--|
| `SEC-AUTH-01` | Deny-by-default authorisation | 🔴 | `T-AUTH-01` |
| `SEC-AUTH-02` | 100 % route × role authz matrix | 🔴 | `T-AUTH-02` |
| `SEC-AUTH-03` | Step-up re-authentication ≤ 5 min | 🔴 | `T-AUTH-03` |
| `SEC-AUTH-04` | Object-level authorisation (no BOLA) | 🔴 | `T-AUTH-04` |
| `SEC-AUTH-05` | Row-Level Security forced | 🟠 | `T-AUTH-05` |
| `SEC-AUTH-06` | Least-privilege, separated DB roles | 🟠 | `T-AUTH-06` |
| `SEC-AUTH-07` | Two-person integrity on score & freeze | 🔴 | `T-AUTH-07` |
| `SEC-AUTH-08` | Score authority ⇏ evidence-deletion authority | 🔴 | `T-AUTH-08` |
| `SEC-AUTH-09` | Banned permission combinations | 🟠 | `T-AUTH-09` |

**🟢 `SEC-APP` — Application Hardening (14)**

| ID | Title | Sev | Test |
|:--|:--|:-:|:--|
| `SEC-APP-01` | Strict schema validation at every boundary | 🔴 | `T-APP-01` |
| `SEC-APP-02` | Parameterised queries only | 🔴 | `T-APP-02` |
| `SEC-APP-03` | Client-supplied rank/score/identity ignored | 🔴 | `T-APP-03` |
| `SEC-APP-04` | Contextual output encoding; no HTML sinks | 🔴 | `T-APP-04` |
| `SEC-APP-05` | Enforced CSP with nonce and Trusted Types | 🔴 | `T-APP-05` |
| `SEC-APP-06` | Subresource integrity and pinned bundle digest | 🟠 | `T-APP-06` |
| `SEC-APP-07` | Schema-validated deserialisation | 🔴 | `T-APP-07` |
| `SEC-APP-08` | Mandatory idempotency keys on mutations | 🟠 | `T-APP-08` |
| `SEC-APP-09` | Event-driven cache invalidation | 🟠 | `T-APP-09` |
| `SEC-APP-10` | Rate limiting by identity and source | 🟠 | `T-APP-10` |
| `SEC-APP-11` | Body, header, and depth payload limits | 🟡 | `T-APP-11` |
| `SEC-APP-12` | Safe error catalogue; no internals leaked | 🟡 | `T-APP-12` |
| `SEC-APP-13` | Timeout + bounded retry + circuit breaker | 🟠 | `T-APP-13` |
| `SEC-APP-14` | Anchored, ReDoS-checked regexes | 🟡 | `T-APP-14` |

**🟣 `SEC-CRY` — Cryptography, Keys & Secrets (10)**

| ID | Title | Sev | Test |
|:--|:--|:-:|:--|
| `SEC-CRY-01` | TLS 1.3 with 1.2 fallback; HSTS preload | 🔴 | `T-CRY-02` |
| `SEC-CRY-02` | AES-256-GCM with CMEK at rest | 🔴 | `T-CRY-03` |
| `SEC-CRY-03` | PII column encryption + separate blind-index key | 🟠 | `T-CRY-04` |
| `SEC-CRY-04` | KMS/HSM keys with dual-active rotation | 🟠 | `T-CRY-05` |
| `SEC-CRY-05` | No key material outside Vault; no generation in app code | 🔴 | `T-CRY-06` |
| `SEC-CRY-06` | Signed reports and evidence artefacts | 🟠 | `T-CRY-07` |
| `SEC-CRY-07` | CSPRNG for all security randomness | 🟠 | `T-CRY-08` |
| `SEC-CRY-08` | No secrets in the browser, ever | 🔴 | `T-CRY-09` |
| `SEC-CRY-09` | 1-hour key revocation on compromise | 🟠 | `T-CRY-10` |
| `SEC-CRY-10` | Crypto-agility via versioned algorithm config | 🟡 | `T-CRY-11` |

**🟠 `SEC-SC` — Software Supply Chain (8)**

| ID | Title | Sev | Test |
|:--|:--|:-:|:--|
| `SEC-SC-01` | SBOM per build (SPDX + CycloneDX) with diff | 🟠 | `T-SC-01` |
| `SEC-SC-02` | Lockfile-only installs with integrity hashes | 🟠 | `T-SC-02` |
| `SEC-SC-03` | Install scripts disabled in CI | 🔴 | `T-SC-03` |
| `SEC-SC-04` | cosign signing with fail-closed verification | 🔴 | `T-SC-04` |
| `SEC-SC-05` | Digest-pinned image references | 🟠 | `T-SC-05` |
| `SEC-SC-06` | Dependency allow-list and 7-day quarantine | 🟠 | `T-SC-06` |
| `SEC-SC-07` | Pinned third-party actions; minimal workflow permissions | 🟠 | `T-SC-07` |
| `SEC-SC-08` | SLSA Build L3 provenance | 🟠 | `T-SC-08` |

**🔵 `SEC-DATA` — Data Protection & Privacy (9)**

| ID | Title | Sev | Test |
|:--|:--|:-:|:--|
| `SEC-DATA-01` | Data minimisation and purpose binding | 🟠 | `T-DATA-01` |
| `SEC-DATA-02` | PII redacted at source before logging | 🟠 | `T-DATA-02` |
| `SEC-DATA-03` | Timed PII deletion with tombstone evidence | 🟠 | `T-DATA-03` |
| `SEC-DATA-04` | Pseudonymisation where full value is unnecessary | 🟡 | `T-DATA-04` |
| `SEC-DATA-05` | Backup retention inheritance; no resurrection | 🔴 | `T-DATA-06` |
| `SEC-DATA-06` | Art. 33 breach assessment within 24 h | 🟠 | `T-DATA-07` |
| `SEC-DATA-07` | DSAR fulfilment within 30 days | 🟡 | `T-DATA-08` |
| `SEC-DATA-08` | Watermarked, logged, rate-limited downloads | 🟠 | `T-DATA-09` |
| `SEC-DATA-09` | Retention schedule, hold override, tested deletion | 🟠 | `T-DATA-10` |

**🔴 `SEC-AUD` — Audit, Detection & Alerting (9)**

| ID | Title | Sev | Test |
|:--|:--|:-:|:--|
| `SEC-AUD-01` | Every security-relevant action audited, denials included | 🔴 | `T-AUD-05` |
| `SEC-AUD-02` | Audit insert in the same transaction as the mutation | 🔴 | `T-AUD-02` |
| `SEC-AUD-03` | Append-only audit at the database level | 🔴 | `T-AUD-01` |
| `SEC-AUD-04` | Hash-chained records verified hourly | 🔴 | `T-AUD-03` |
| `SEC-AUD-05` | Signed Merkle roots sealed to Object Lock | 🟠 | `T-AUD-04` |
| `SEC-AUD-06` | External anchoring (RFC 3161 / transparency log) | 🔴 | `T-AUD-06` |
| `SEC-AUD-07` | No secrets or full PII in logs | 🟠 | `T-AUD-07` |
| `SEC-AUD-08` | 7-year WORM retention with legal hold | 🟠 | `T-AUD-08` |
| `SEC-AUD-09` | Authorised, audited audit queries and exports | 🟠 | `T-AUD-09` |

**🟡 `SEC-INFRA` — Infrastructure, Network & Containers (8)**

| ID | Title | Sev | Test |
|:--|:--|:-:|:--|
| `SEC-INFRA-01` | Default-deny inter-zone traffic | 🔴 | `T-INFRA-01` |
| `SEC-INFRA-02` | Non-root, read-only fs, no capabilities, seccomp | 🟠 | `T-INFRA-02` |
| `SEC-INFRA-03` | Hardened minimal base images; no tooling in runtime | 🟠 | `T-INFRA-03` |
| `SEC-INFRA-04` | Host baseline and key-only SSH | 🟡 | `T-INFRA-04` |
| `SEC-INFRA-05` | Infrastructure as code only; console = drift | 🟠 | `T-INFRA-05` |
| `SEC-INFRA-06` | DDoS, WAF, and bot scoring at the edge | 🟠 | `T-INFRA-06` |
| `SEC-INFRA-07` | Resource limits and isolation per service | 🟡 | `T-INFRA-07` |
| `SEC-INFRA-08` | NTP synchronisation; drift > 1 s halts manual appends | 🟠 | `T-INFRA-08` |

**🔵 `SEC-EXT` — Third-Party & Webhook Trust (7)**

| ID | Title | Sev | Test |
|:--|:--|:-:|:--|
| `SEC-EXT-01` | mTLS 1.3 with pinned partner CA and CN allow-list | 🔴 | `T-EXT-04` |
| `SEC-EXT-02` | HMAC-SHA-256 over raw bytes, constant-time compare | 🔴 | `T-EXT-01` |
| `SEC-EXT-03` | ±300 s replay window with alerting | 🟠 | `T-EXT-02` |
| `SEC-EXT-04` | Strict schema validation of webhook payloads | 🟠 | `T-EXT-05` |
| `SEC-EXT-05` | Idempotent ingest; duplicates never error | 🔴 | `T-EXT-03` |
| `SEC-EXT-06` | Webhook principal limited to ingest permissions | 🟠 | `T-EXT-07` |
| `SEC-EXT-07` | Egress allow-list; no user-supplied URL fetches | 🟠 | `T-EXT-08` |

**🟣 `SEC-SDLC` — Process & Governance (8)**

| ID | Title | Sev | Test |
|:--|:--|:-:|:--|
| `SEC-SDLC-01` | Branch protection and CODEOWNERS | 🟠 | `T-SDLC-01` |
| `SEC-SDLC-02` | Two-person production deploy approval | 🟠 | `T-SDLC-02` |
| `SEC-SDLC-03` | OpenAPI generated from validation schemas | 🟡 | `T-SDLC-03` |
| `SEC-SDLC-04` | Signed, windowed, rollback-capable policy deploys | 🔴 | `T-SDLC-04` |
| `SEC-SDLC-05` | Patch SLAs with halved SLA for exposed components | 🟠 | `T-SDLC-05` |
| `SEC-SDLC-06` | Annual secure-coding training; quarterly phish sim | 🟡 | `T-SDLC-06` |
| `SEC-SDLC-07` | Annual independent penetration test | 🟠 | `T-SDLC-07` |
| `SEC-SDLC-08` | Threat model reviewed on change and after every P1 | 🟡 | `T-SDLC-08` |

**🟠 `SEC-IR` — Incident Response & Continuity (6)**

| ID | Title | Sev | Test |
|:--|:--|:-:|:--|
| `SEC-IR-01` | P1 alerts page on-call with a runbook link | 🔴 | `T-IR-01` |
| `SEC-IR-02` | Evidence preserved before remediation | 🔴 | `T-IR-02` |
| `SEC-IR-03` | PIR within 14 days; actions tracked to closure | 🟠 | `T-IR-03` |
| `SEC-IR-04` | Two-person, windowed, audited critical operations | 🔴 | `T-IR-04` |
| `SEC-IR-05` | Semi-annual game-day exercises | 🟠 | `T-IR-05` |
| `SEC-IR-06` | Art. 33/34 assessment within 24 h | 🔴 | `T-IR-06` |

### 22.2 Glossary

| Term | Definition |
|:--|:--|
| 🛡️ **PDP** | Policy Decision Point — the service that answers "allow or deny" for a request |
| 📜 **PIP** | Policy Information Point — supplies attributes to the PDP |
| 🔁 **PE** | Policy Enforcement Point — the middleware that calls the PDP and enforces the result |
| 🧱 **SoD** | Separation of duties — no identity can both act and conceal |
| 🔐 **2P** | Two-person integrity — a second, different human must approve |
| 🆙 **SU** | Step-up — re-authentication required within a short window before an action |
| 🧬 **WORM** | Write Once, Read Many — storage that cannot be modified or deleted before its expiry |
| ✍️ **Seal** | A signed Merkle root anchored to WORM storage, bounding the audit chain |
| 🕒 **TSA** | Time Stamp Authority — an external service that proves a document existed at a time |
| 🧾 **Derivation** | The stored JSON describing exactly how a score was computed |
| 🔗 **Idempotency key** | A hash-derived unique value that makes a repeated mutation a no-op |
| 📉 **Cold / warm / hot** | Retention tiers balancing query cost against restore latency |
| 🗣️ **RPO / RTO** | Maximum tolerable data loss / maximum tolerable time to restore |
| 🎭 **SDL** | A synthetic event used to prove a detection rule actually fires |
| 🚫 **Fail closed** | When a security decision cannot be made, deny — never allow |
| 🕶️ **Blind index** | A keyed hash enabling equality search on encrypted data |
| 🧑‍💻 **Abuse case** | A test derived from a threat, expressed as an executable assertion |
| ⏱️ **Burn rate** | How fast an error budget is being consumed, used for alert thresholds |

### 22.3 Companion Documents

| Document | Purpose | Read it when |
|:--|:--|:--|
| [`architecture.md`](./architecture.md) | System design, components, data flows, decisions | You need to know *what* the system is |
| [`state.md`](./state.md) | State taxonomy, lifecycles, invariants, synchronisation | You are implementing or debugging state |
| [`memory.md`](./memory.md) | Memory tiers, durability, retention, backup and recovery | You are designing storage or operating restores |
| **This document** | Security controls, tests, detection, response | You are changing or auditing security posture |

---

<div align="center">

### 🛡️ Security Baseline Complete

| | |
|:--|:--|
| 🛡️ **97** | Security controls across **11** families |
| 🧪 **120** | Executable verification tests |
| 🔍 **27** | Detection and alerting rules |
| 📖 **14** | Incident runbooks |
| ⚖️ **3** | Active, time-boxed risk acceptances |
| ⬛ **0** | Accepted gaps in 🔴 Critical controls |

**`Fail closed · Audited or not done · No client-side secrets · Evidence over assertion`**

</div>

