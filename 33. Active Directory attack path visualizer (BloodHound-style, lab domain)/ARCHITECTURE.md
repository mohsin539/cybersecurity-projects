# SentinelGraph — Active Directory Attack Path Visualizer

**BloodHound-style AD attack-path analysis for banking environments, with continuous compliance posture across OWASP Top 10 2021, ISO/IEC 27001:2022, NIST CSF 2.0, NIST SP 800-53 r5, PCI DSS 4.0, and CIS Controls v8.**

> Lab / training scope: run against lab domains or imported SharpHound collections. Never point collection tooling at a production forest without written authorization.

---

## 1. Purpose & Banking Context

Banks fail audits not because they lack tools, but because identity attack paths — helpdesk resets reaching Tier-0, kerberoastable service accounts, legacy DCSync grants — live in undocumented ACL sprawl. This platform:

1. **Visualizes** the AD privilege graph (users, groups, computers, GPOs, ACL edges) in an interactive, risk-colored map.
2. **Computes** attack paths, blast radius, choke points, and Tier-0 exposure per Microsoft's Enterprise Access Model.
3. **Detects** misconfigurations (10 rule families mapped to MITRE ATT&CK).
4. **Continuously maps** runtime evidence to six control frameworks with per-control status, giving CISO office / GRC a live posture instead of a point-in-time spreadsheet.
5. **Audits** every security-relevant action in an append-only trail (regulator-ready).

---

## 2. High-Level Architecture

```
┌───────────────────────────────────────────────────────────────────────────┐
│                             PRESENTATION TIER                             │
│  React 18 + TypeScript + Tailwind (dark SOC UI) · Cytoscape.js graph       │
│  Tabs: Dashboard · Graph Explorer · Compliance · Audit Trail (RBAC-scoped) │
│  Token in memory only · strict CSP · no inline handlers                    │
└──────────────────────────────┬────────────────────────────────────────────┘
                               │ HTTPS (HSTS) · JWT bearer (15 min TTL)
┌──────────────────────────────▼────────────────────────────────────────────┐
│                          APPLICATION TIER (FastAPI)                       │
│  ┌─────────────┐ ┌──────────────┐ ┌───────────────────┐                   │
│  │ Middleware   │ │ API routers  │ │ Engines           │                  │
│  │ · Security   │ │ · /auth      │ │ · analysis/       │                  │
│  │   headers    │ │ · /graph     │ │   engine.py       │                  │
│  │ · CORS lab   │ │ · /analysis  │ │ · findings/rules  │                  │
│  │ · Rate limit │ │ · /findings  │ │ · compliance/     │                  │
│  │              │ │ · /compliance│ │   mapper.py       │                  │
│  │ Error shield │ │ · /audit     │ │ · tiers.py        │                  │
│  └─────────────┘ └──────┬───────┘ └─────────┬─────────┘                   │
│                         │                   │                             │
│  ┌──────────────────────▼───────────────────▼──────────────────────────┐ │
│  │                    GRAPH CORE (storage-agnostic)                    │ │
│  │  model.py (Node/Edge schema) · store.py (GraphStore interface)      │ │
│  │  InMemoryStore (lab default) · Neo4jStore (large domains)           │ │
│  │  lab_seed.py (CORP.LAB) · importer.py (SharpHound ZIP/JSON ETL)     │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │  Cross-cutting: audit.py (append-only) · security.py (JWT/RBAC)     │ │
│  │  rate_limit.py · errors.py (no info leakage) · config.py (env)      │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
└──────────────────────────────┬────────────────────────────────────────────┘
                               │ bolt:// (optional)
┌──────────────────────────────▼────────────────────────────────────────────┐
│  DATA TIER — In-memory graph (lab) | Neo4j (prod-scale labs) | SIEM sink  │
└───────────────────────────────────────────────────────────────────────────┘
```

### Component responsibilities

| Component | File | Responsibility |
|---|---|---|
| Graph schema | `backend/app/graph/model.py` | Node kinds (user/group/computer/domain/gpo/ou/container), 15 edge kinds with BloodHound equivalents, privilege weights |
| Graph store | `backend/app/graph/store.py` | `GraphStore` interface; thread-safe in-memory store; dangling-edge pruning |
| Neo4j store | `backend/app/graph/neo4j_store.py` | Same interface over bolt; enable with `SG_NEO4J_ENABLED=true` |
| Lab domain | `backend/app/graph/lab_seed.py` | CORP.LAB synthetic domain with 9 planted bank-realistic weaknesses |
| Collection ETL | `backend/app/graph/importer.py` | SharpHound ZIP / bloodhound-python JSON → normalized graph; size/entry caps |
| Tiering | `backend/app/analysis/tiers.py` | Tier-0 propagation (group patterns, DCs, membership) |
| Path engine | `backend/app/analysis/engine.py` | BFS paths, hop-discounted risk scoring, blast radius, choke points, Tier-0 exposure |
| Findings | `backend/app/findings/rules.py` | 10 detection rules → MITRE ATT&CK, severity, remediation |
| Compliance | `backend/app/compliance/catalogs.py` + `mapper.py` | 6 frameworks, ~90 controls, evidence-based live status |
| API | `backend/app/api/` | 15+ endpoints, JWT + RBAC + rate limits |
| UI | `frontend/src/` | Dashboard / Explorer / Compliance / Audit tabs |

---

## 3. Graph Data Model

### 3.1 Node kinds & tiers

| Kind | Example | Tiering source |
|---|---|---|
| `user` | `user:da_admin` | Member of Tier-0 group ⇒ Tier-0 |
| `group` | `group:domain_admins` | Name pattern match (Domain Admins, Schema Admins, …) |
| `computer` | `computer:dc01` | `role=DC` ⇒ Tier-0 |
| `domain` | `domain:CORP.LAB` | Always Tier-0 |
| `gpo` | `gpo:gpo_legacy` | — |
| `ou` / `container` | `ou:tier0` | — |

### 3.2 Edge kinds (BloodHound-equivalent semantics)

| Edge | BloodHound edge | Weight | Abuse primitive |
|---|---|---|ACE |
| `dcsync` | DCSync (GetChanges+GetChangesAll) | 1.00 | Replicate all directory data incl. krbtgt |
| `generic_all` | GenericAll | 0.95 | Full control of target object |
| `owns` | Owns | 0.90 | Rewrite target DACL |
| `write_owner` / `write_dacl` | WriteOwner / WriteDacl | 0.85 / 0.80 | Ownership/DACL takeover |
| `all_extended_rights` | AllExtendedRights | 0.75 | Reset pwd, add SPN, etc. |
| `generic_write` | GenericWrite | 0.70 | Write props (SPN set → targeted kerberoast) |
| `admin_on` | AdminTo | 0.80 | Local admin, credential theft |
| `force_change_pw` | ForceChangePassword | 0.60 | Reset then logon |
| `add_member` | AddMember | 0.60 | Self-add to privileged group |
| `allowed_to_delegate` | AllowedToDelegate | 0.55 | S4U2self protocol transition |
| `rdp_on` | CanRDP | 0.30 | Lateral movement |
| `has_session` | HasSession | 0.40 | Credential theft staging |
| `member_of` | MemberOf | tier-resolved | Privilege inheritance |
| `gplink` | GpLink | 0.20 | GPO abuse chains |

### 3.3 CORP.LAB planted weaknesses (bank-flavored)

| # | Weakness | ATT&CK | Path to crown jewels |
|---|---|---| compromised via |
| 1 | `svc_sql` SPN + SQL-admin membership | T1558.003 | kerberoast → local admin on core-banking DB |
| 2 | Helpdesk `bob` resets CISO (Tier-0) password | T1098 | reset → logon → Tier-0 |
| 3 | `svc_backup`/`svc_legacy` AS-REP roastable | T1558.004 | offline crack → ACL writes to Tier-1 groups |
| 4 | Domain Users RDP on jump host | T1021.001 | any phished user → jump host → DA session theft |
| 5 | `banking_app` DCSync without Tier-0 | T1003.006 | immediate domain domination |
| 6 | `file01` unconstrained delegation | T1558.004 | coerce auth → TGT capture → DA |
| 7 | GPP cpassword in SYSVOL GPO | T1552.006 | plaintext-equivalent credential |
| 8 | CISO session on workstation | T1003 | credential theft → DA |
| 9 | Stale 240–900-day service passwords | T1078.002 | rotation policy violation |

---

## 4. Analysis Engine

### 4.1 Risk scoring
`score = 40·avg(edge weights) + 30/(1+0.35·(hops−1)) + 25·[target is Tier-0] + 10·[source is user]`, capped at 100. Rationale: **attack value decays with hops, principal privilege edges dominate, and Tier-0 objectives weigh most** — mirroring how a bank's red team prioritizes and how FFEICO-style examiners expect risk to be quantified.

### 4.2 Key queries
- **Attack paths** (`POST /analysis/paths`): bounded BFS from any principal; paths terminate at Tier-0 objectives; top-N by risk.
- **Blast radius** (`blast_radius()`): all reachable nodes + Tier-0 hit count; risk = `45·[T0>0] + 8·min(T0,5) + 2·√reachable`.
- **Choke points** (champion/upstream analog): principals unlocking the most Tier-0 reach — the remediation priority list for the CISO office.
- **Tier-0 exposure**: per crown-jewel asset, attacker count and best paths.
- **Domain summary**: tier distribution + riskiest principals for board reporting.

### 4.3 Complexity & limits
BFS is O(V+E) per source; choke-point and exposure computations are O(V·(V+E)) bounded to lab-scale graphs (<50k nodes). In production, precompute offline and serve cached results (BloodHound's approach); the API contract does not change.

---

## 5. Findings Engine (MITRE ATT&CK mapped)

| Rule | Detection | Severity | ATT&CK |
|---|---|---|---|
| F-DCSYNC-001 | DCSync held by non-Tier-0 principal | critical | T1003.006 |
| F-DELEG-001 | Unconstrained delegation | critical | T1558.004 |
| F-GPP-001 | GPP cpassword (MS14-025) | critical | T1552.006 |
| F-KRB-001 | Kerberoastable accounts | high | T1558.003 |
| F-ASREP-001 | AS-REP roastable (no pre-auth) | high | T1558.004 |
| F-TIER-001 | Helpdesk reset on Tier-0 | high | T1098 |
| F-SESS-001 | Tier-0 credentials on lower-tier hosts | high | T1003 |
| F-RDP-001 | Domain Users RDP on servers | medium | T1021.001 |
| F-NEST-001 | Nested privileged group membership | medium | T1078 |
| F-PWD-001 | Stale service-account passwords | medium | T1078.002 |

Each finding carries: affected principals with *why*, remediation runbook, and ATT&CK technique — directly consumable by SOC triage and GRC reporting.

---

## 6. Compliance Mapping Engine

Evidence types computed at runtime: `tiering` (tier coverage), `graph` (inventory completeness), `rbac` (API role enforcement), `crypto` (secret strength, TLS), `audit` (append-only events), `validation` (strict parsing, size caps). Each control declares the evidence it needs; the mapper derives **pass / partial / fail** and a weighted score.

| Framework | Coverage focus | Example controls |
|---|---|---|
| **OWASP Top 10 2021** | A01–A10 | A01 access control ↔ tiering+RBAC evidence; A07 authN ↔ JWT+rate-limit+audit |
| **ISO/IEC 27001:2022** | Annex A Technological + Organizational | A.8.2 privileged access ↔ tiering; A.8.15/16 logging & monitoring ↔ audit trail |
| **NIST CSF 2.0** | All six functions | GV.PO policy; PR.AA-05 least privilege ↔ tiering; DE.CM detection ↔ audit |
| **NIST SP 800-53 r5** | AC/AU/IA/CM/SI families | AC-6(1) privileged inventory; AU-9 audit protection |
| **PCI DSS 4.0** | 7/8/10 requirements | 7.2.4 least-privilege review; 8.2.2 generic accounts; 10.2/10.3 logs |
| **CIS Controls v8** | IG1–IG2 safeguards | 5.4 restrict admin; 6.8 limit privileges; 8 audit log management |

Scoring: `pass=1, partial=0.5, fail=0` averaged per framework. In production, partial statuses are closed by wiring the platform to the real IdP (MFA evidence) and SIEM (log retention evidence).

---

## 7. Security Architecture (OWASP / NIST-aligned)

| Threat | Control | Framework refs |
|---|---|---|
| Credential theft / brute force | bcrypt (600k-iter PBKDF2 fallback), 15-min JWT, login rate limit 5/min + lockout telemetry | OWASP A07, PCI 8.3, NIST 800-63B AAL2 |
| Privilege escalation in-app | Three roles (admin/analyst/auditor) enforced server-side on every route; auditors read-only | OWASP A01, ISO A.8.2, PCI 7.2 |
| XSS / UI redress | Strict CSP (no external origins, `object-src none`, `frame-ancestors none`), React escaping, token in memory only | OWASP A03/A05, ISO A.8.28 |
| Injection | Pydantic validation on every body/query; parameterized Cypher; no string-built queries from user input | OWASP A03, PCI 6.2.4 |
| Info leakage | Uniform error envelope, stack traces suppressed, /api/docs only in lab | OWASP A05, ISO A.8.9 |
| DoS / resource abuse | Import caps (512 MB archive, 2M entries), rate limits, bounded BFS depth/limit | OWASP A05, NIST CA-2 |
| Log tampering | Append-only audit with monotonic timestamps, severity escalation, SIEM-ready JSON lines | ISO A.8.15, PCI 10.3, NIST AU-9 |
| Transport | HSTS, TLS terminated at gateway in staging/prod; lab binds loopback | PCI 4.2.1, NIST SC-8 |
| Supply chain | Pinned requirements, SBOM via `pip freeze`/npm lock, integrity-verified builds | OWASP A08, CIS 16 |

### 7.1 Deployment postures

| Mode | Use case | Notes |
|---|---|---|
| **Portable .exe** | Auditor laptop, air-gapped labs | PyInstaller one-file; binds 127.0.0.1; UI served same-origin; no external DB required |
| **Docker Compose** | Team lab servers | app + optional Neo4j; internal network; volumes for collections |
| **K8s (prod-style)** | Bank innovation labs | TLS at ingress, secrets from vault, SIEM shipper sidecar, HSM-backed JWT signing in production |

### 7.2 Data protection
- Collections may contain sensitive AD data → treat as **confidential**: encrypted at rest (BitLocker/vault), TLS in transit, role-scoped API access, audit on every read/write.
- Production hardening path: real IdP SSO + MFA (PCI 8.2.4), SIEM streaming (Splunk/Sentinel), immutable audit sink (WORM), per-tenant graph isolation, mTLS between app and Neo4j.

---

## 8. Data Flow (collection → insight → action)

```
SharpHound / bloodhound-python          (run in authorized lab)
        │ ZIP/JSON
        ▼
importer.py  ── schema normalization ──►  GraphStore (in-memory | Neo4j)
        │                                        │
        │                          ┌─────────────┴──────────────┐
        ▼                          ▼                            ▼
 lab_seed (demo domain)     analysis/engine.py          findings/rules.py
        │                          │                            │
        └────────────┬─────────────┴────────────┬───────────────┘
                     ▼                          ▼
             /api/v1/analysis/*          /api/v1/findings
                     │                          │
                     ├──────────┬───────────────┘
                     ▼          ▼
              compliance/mapper.py (evidence → control status)
                     │
                     ▼
        React UI: Explorer · Dashboard · Compliance · Audit
                     │
                     ▼
        Append-only audit trail → (prod) SIEM → regulator reporting
```

---

## 9. Scalability Path

| Stage | Store | Notes |
|---|---|---|
| Lab (<50k nodes) | InMemoryStore | Zero-dependency, single process, sub-ms queries |
| Team lab | Neo4jStore | Same interface; Cypher shortestPath for heavy queries |
| Enterprise | Neo4j cluster + read replicas | Precomputed attack-path materialized views; CDC-driven refresh |

The engine consumes the `GraphStore` interface only — swapping stores requires **zero** engine changes.

---

## 10. Verification & Quality Gates

- **12/12 backend tests pass** (auth, RBAC, graph, paths, findings, compliance, audit).
- Frontend: strict TypeScript (`tsc --noEmit`), production build green.
- E2E smoke: login → graph (32 nodes) → paths (risk 89 to Tier-0 from helpdesk) → 9 findings → all 6 framework scores → SPA served at `/`.
- OWASP ASVS L1/L2 checklist mapped in SECURITY.md; ISO SoA mapping in the compliance engine.

## 11. Roadmap (post-lab)
1. SharpHound v2 edge translation (cert abuser edges, DPAPI, CA store).
2. Sidebar JIT/PIM simulation ("what-if" remediation deltas).
3. gMSA password rotation evidence ingestion for PCI 8.6.x attestations.
4. Neo4j Cypher shortestPath backend for 100k+ node forests.
5. SOC integrations: Sentinel/Splunk alerting on new Tier-0 paths.
