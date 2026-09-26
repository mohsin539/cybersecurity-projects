# SOC Alert Triage Dashboard — Architecture & Compliance Package

Production-grade architecture for a SOC **Alert Triage Dashboard** whose core functions are:

1. **Severity Scoring** — deterministic, explainable, tunable risk scoring of normalized alerts.
2. **Alert Deduplication** — high-precision suppression of duplicate/near-duplicate alerts with full auditability (no alert is ever destroyed).

The design is **secure-by-design** and explicitly mapped to:

| Framework | Scope in this package |
|---|---|
| **OWASP Top 10 (2021)** | Control-by-control mapping incl. ASVS 4.0 verification anchors → `04-security-architecture.md` |
| **NIST CSF 2.0** | Full GOVERN–IDENTIFY–PROTECT–DETECT–RESPOND–RECOVER mapping → `05-compliance-nist.md` |
| **NIST SP 800-53 Rev. 5** | Control families (AC, AT, AU, CA, CM, IA, IR, MA, MP, PS, PE, SA, SC, SI, SR) → `05-compliance-nist.md` |
| **NIST SP 800-61 Rev. 2/3** | Incident handling lifecycle (Preparation → D&I → Containment/Eradication/Recovery → Post-Incident) → `05-compliance-nist.md` |
| **ISO/IEC 27001:2022 Annex A** | All 93 controls across the four themes → `06-compliance-iso27001.md` |

---

## Document map

| Doc | Contents |
|---|---|
| [`01-architecture-overview.md`](01-architecture-overview.md) | Business/context view, C4 views, tech stack, data flows, deployment, SLOs, DR |
| [`02-triage-engine.md`](02-triage-engine.md) | Normalization pipeline, severity scoring model (deep dive), dedup engine (deep dive), API/data contracts, ML lifecycle |
| [`03-data-and-rbac.md`](03-data-and-rbac.md) | Logical data model, RBAC/ABAC model, multi-tenancy, retention & privacy |
| [`04-security-architecture.md`](04-security-architecture.md) | Secure-by-design principles, trust boundaries, STRIDE threat model, OWASP Top 10 2021 mapping (with ASVS anchors), secure SDLC |
| [`05-compliance-nist.md`](05-compliance-nist.md) | NIST CSF 2.0 mapping, SP 800-53 Rev. 5 control matrix, SP 800-61 incident-response integration |
| [`06-compliance-iso27001.md`](06-compliance-iso27001.md) | ISO/IEC 27001:2022 Annex A mapping (all 93 controls), SoA guidance, audit evidence plan |
| [`07-ops-runbook.md`](07-ops-runbook.md) | Operational runbook: SLOs & alerts, tuning/safety procedures, kill switches, DR drills |
| [`adr/`](adr/) | Architecture Decision Records (ADRs) |
| [`state.md`](state.md) | **Reservation doc**: authoritative application state model (ownership, lifecycle, invariants) |
| [`memory.md`](memory.md) | **Reservation doc**: cross-session project memory (decisions, facts, session log) |

## Running implementation (GUI/web based)

A working, zero-dependency reference implementation of this architecture ships in-repo:

| File | Role |
|---|---|
| `server.js` | Node.js (≥18, stdlib only — no npm install) API + static host: scoring engine, exact-key dedup, RBAC/ABAC, hash-chained audit log, kill switches, fail-closed boot integrity check |
| `public/index.html`, `public/app.js`, `public/styles.css` | Dashboard SPA (queue, alert detail with factor breakdown + dedup tree, audit view, config view); strict CSP, text-only rendering |
| [`security.md`](security.md) | Implementation-level security reference: OWASP Top 10 (2021) / SP 800-53 / CSF 2.0 / Annex A mapping with ✅/🟡/🔲 status per control |
| `test_e2e.sh` | 24-check end-to-end verification suite (auth, golden vector, dedup, tenant isolation, CSRF, ABAC, audit chain, headers) |

Run:

```bash
node server.js          # → http://localhost:8080
bash test_e2e.sh        # while server is running (server restarts seed fresh data)
```

Demo identities (no password, localhost demo scope — production auth path documented in `security.md` §1 A07): `analyst@t1` (tier1), `lead@t1` (soc.lead), `auditor@t1` (read-only cross-tenant counts), `analyst@t2` (tenant isolation demo).

## At-a-glance architecture

```
 SIEM / EDR / NDR / IAM / Cloud / Email ──► Collectors ──► Ingest (Kafka) ──► Normalizers
                                                                        │
                                                        ┌───────────────┴───────────────┐
                                                        ▼                               ▼
                                                Dedup Engine  ◄──────────────►  Scoring Engine
                                                        │                               │
                                                        └───────────────┬───────────────┘
                                                                        ▼
                                                          Alert Store (Postgres) + Cache
                                                                        │
                                          ┌─────────────────────────────┼──────────────────────┐
                                          ▼                             ▼                      ▼
                                     Triage API  ◄──────────  Triage Dashboard (SPA)   SOAR / Webhooks
```

Key properties: **immutable event log** (append-only), **no destructive suppression** (dedup links duplicates to a canonical alert), **explainable scores** (every score carries a factor breakdown), **fail-open vs fail-closed decided per component** (documented in ADR-001), **full audit trail** of every human and machine decision.

## Non-negotiable design invariants

1. **Auditability** — every triage action, score change, and suppression decision is append-only logged (who/what/when/why).
2. **No silent alert loss** — dedup suppresses display, never storage; un-suppression is always possible.
3. **Explainability** — every severity score is reproducible from its inputs + rule version (deterministic core).
4. **Least privilege** — service and human access is RBAC+ABAC scoped per tenant and per action.
5. **Tenant isolation** — every read/write is tenant-scoped at the data layer (RLS), not only at the API layer.
6. **Versioned everything** — scoring rules, dedup keys, and normalization mappings are versioned; historical scores remain reproducible.

## Intended audience

Security architects, platform engineers building the system, SOC leads (tuning and workflow), compliance/audit leads (GRC evidence).
