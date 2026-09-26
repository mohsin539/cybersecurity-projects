# 01 — Architecture Overview

Status: Approved v1.0 · Owner: Security Architecture · Review cadence: quarterly

---

## 1. Purpose & scope

### 1.1 Problem statement

A mid-to-large SOC receives 10k–2M raw events/sec upstream and produces 5k–200k alerts/day. Analyst burnout and missed incidents are driven by:

- **Volume**: >70% of alerts are duplicates or low-value noise.
- **Flat severity**: static rule severities ignore asset criticality, identity risk, and attack-chain position.
- **Context fragmentation**: analysts pivot across 5–10 consoles per alert.
- **Inconsistent dispositions**: tribal knowledge, no feedback loop into detection engineering.

### 1.2 In scope

1. Alert ingestion, normalization, enrichment.
2. **Severity scoring** (deterministic core + ML-assisted calibration).
3. **Alert deduplication** (exact + near-duplicate, tenant-scoped, non-destructive).
4. Triage dashboard: queue, alert detail, disposition workflow, collaboration.
5. Feedback loop into detection engineering and scoring model.

### 1.3 Out of scope (consumed, not built)

- Raw telemetry collection agents (EDR/NDR/CDM agents), SIEM storage engine, SOAR playbook execution engine (we *emit* to SOAR), case management (we integrate via webhook/API).

### 1.4 Key assumptions

| # | Assumption | Consequence if wrong |
|---|---|---|
| A1 | Upstream sources can emit to Kafka or webhook | Collector shim layer required (provided) |
| A2 | CMDB/asset inventory with criticality is available via API | Asset-context factors degrade to "unknown" defaults; scoring falls back (documented behavior) |
| A3 | Tenant count ≤ 500, alerts ≤ 200k/day/tenant at peak | Partitioning strategy re-evaluated (§9) |
| A4 | Analysts work in shifts; P95 concurrent dashboard users ≤ 2k | Read-path caching re-sized |

---

## 2. Quality attributes (architecture drivers)

| Attribute | Target | Primary mechanism |
|---|---|---|
| Ingest latency (event → queryable) | P99 ≤ 10 s | Kafka, streaming normalizers, no batch on hot path |
| Scoring latency (per alert) | P99 ≤ 250 ms | Pre-computed enrichment features, local feature cache |
| Dedup decision latency | P99 ≤ 500 ms | Two-stage: exact-key O(1) + bounded ANN search |
| Dashboard queue load | P95 ≤ 1.5 s first paint | Server-side pagination, materialized queue views, CDN |
| Availability (triage API + dashboard) | 99.9% monthly | Multi-AZ, stateless services, graceful degradation (§8.3) |
| Duplication suppression precision | ≥ 95% (target 99%) | Two-stage dedup, conservative fuzzy thresholds, feedback loop |
| Score reproducibility | 100% | Deterministic core + versioned rules + immutable score records |
| Audit completeness | 100% of state-changing actions | Append-only audit log, hash-chained (§ security doc) |

---

## 3. C4 Level 1 — System context

```
                    ┌──────────────────────────┐
  SOC Analysts ────►│                          │────► SOAR platform (containment actions)
  SOC Leads    ────►│   SOC Alert Triage       │────► Case management (ticket sync)
  Detection Eng ───►│   Dashboard System       │────► Notification (Slack/Teams/PagerDuty)
                    │                          │◄──── Feedback (dispositions from case mgmt)
                    └────────────┬─────────────┘
                                 │ ingests
     ┌───────────┬───────────┬────┴──────┬─────────────┬──────────────┐
     ▼           ▼           ▼           ▼             ▼              ▼
   SIEM        EDR         NDR         IAM/IdP      Cloud posture   Email gw
 (Splunk/EQ) (CrowdStrike)(Corelight) (Entra/Okta) (CSPM alerts)   (Abnormal)
```

Trust: the triage system is **read-mostly** w.r.t. telemetry, and **write-only** to downstream action systems via scoped, short-lived, audience-bound service tokens (never stored credentials in playbooks).

## 4. C4 Level 2 — Container view

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│  Edge: WAF + mTLS gateway (API GW) · OIDC SSO (identity proxy to corp IdP)      │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  [Collectors]──►[ Kafka: raw.<source> ]──►[ Normalizer svc ]──►[ Kafka: alerts.normalized.v1 ]
│                                                    │                                    │
│                                                    ▼ (bulkhead topic)                  │
│                                       [ Enrichment svc ] ◄──(cache)── Feature Store │
│                                                    │                                    │
│                     ┌──────────────────────────────┴──────────────┐                     │
│                     ▼                                             ▼                     │
│             [ Dedup Engine ]  ◄── Redis (exact keys) ──►  [ Scoring Engine ]            │
│                     │  + pgvector (near-dup ANN)             │  + Rules engine (OPA)  │
│                     ▼                                        ▼                         │
│             [ Kafka: alerts.triaged.v1 ] ──► [ Alert Store: PostgreSQL (+RLS) ]         │
│                                                  │            │                        │
│                                                  │            └──► [ Audit Log (WORM) ] │
│                                                  ▼                                     │
│  [ Triage API (REST+WS) ] ──► [ Dashboard SPA (React, CSP strict) ]                    │
│  [ Webhook/SOAR emitter ]   [ Notification svc ]  [ Feedback ingest svc ]              │
│                                                                                        │
│  [ ML platform (offline): training, drift, calibration ]  [ Admin/Config svc ]         │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

Containers and responsibilities:

| Container | Runtime | State | Scaling | Fail mode (see ADR-001) |
|---|---|---|---|---|
| Collector(s) | JVM/Go per source type | none (offsets) | per-source | fail-closed: buffer, backpressure |
| Normalizer svc | Go/Kafka Streams | schema reg cache | partition-aligned | poison → DLQ, never drop |
| Enrichment svc | Go | Redis feature cache | horizontal | degrade to "unknown context" defaults |
| Dedup Engine | Go | Redis + pgvector | tenant-sharded | fail-open (show alert unsuppressed) |
| Scoring Engine | Go + embedded OPA | rules from config svc | horizontal | fail-closed to static base severity + flag |
| Alert Store | PostgreSQL 16, RLS on | system of record | primary + replicas | fail-closed |
| Triage API | Node/Go, REST + WebSocket | none | horizontal | fail-closed |
| Dashboard SPA | React + TS, static CDN | browser only | n/a | strict CSP, no inline JS |
| Audit Log | WORM store (S3 Object Lock) / qlog | append-only | n/a | fail-closed (block action if audit write fails) |
| Config/Rules svc | Git-backed, signed bundles | Git + signing | n/a | fail-closed (keep last-good rules) |

## 5. C4 Level 3 — Core components

### 5.1 Normalizer
- Consumes `raw.<source>`; maps vendor payloads → **OCSF v1.1** `Detection Finding` profile; attaches `schema_version`, `source_fingerprint`, `event_uid` (UUIDv7, time-ordered).
- Idempotency: `event_uid = sha256(tenant_id | source | vendor_event_id)`; duplicates at this layer are dropped **with counter metrics** (never silently).
- Contract tests per source adapter; adapters versioned; unknown fields preserved in `raw_original` (90-day TTL) for replay.

### 5.2 Enrichment service
- Pulls, per alert: asset criticality (CMDB), identity risk (IdP risk events), TI matches (TIP, cached, hash-based lookups only — full IOCs never sent externally), vulnerability context (KEV/EPSS), historical entity behavior (last 30d aggregates from feature store).
- All enrichment calls have hard timeouts (50–200 ms) + circuit breakers; missing enrichment yields explicit `unknown` values, never fabricated data.

### 5.3 Dedup engine (deep dive in `02-triage-engine.md` §5)
- Stage 1: exact key `dedup_key_v1 = sha256(tenant | rule_id | sorted(entity_ids) | activity_window_bucket)` in Redis SETNX with TTL = window.
- Stage 2 (only for low-confidence exact groups): near-duplicate via MinHash/SimHash signature + pgvector ANN search restricted to `tenant_id` + time window; cosine threshold 0.92 default (per-tenant tunable 0.85–0.98).
- Emits `duplicate_of` link; canonical alert accumulates `occurrence_count`, `first_seen`, `last_seen`, `variant_entities`.

### 5.4 Scoring engine (deep dive in `02-triage-engine.md` §4)
- Deterministic factor model: `score = clamp(Σ weighted_factors × context_multipliers, 0, 100)`; factors versioned; every score persisted with full `factor_breakdown`.
- Rules evaluated via OPA (Rego) bundles signed and pinned by hash; shadow-mode evaluation for canary rules.
- ML calibration layer (XGBoost monotonic-constrained) re-ranks queue order only — **cannot suppress or promote above a governance floor** without rule change.

### 5.5 Triage API
- REST for CRUD-ish operations, WebSocket (or SSE fallback) for queue streaming; all responses tenant-scoped via server-side session claims (never client-supplied `tenant_id`).
- Idempotent mutation endpoints via `Idempotency-Key` header + stored response replay (24 h).

## 6. Key end-to-end data flows

**F1 — Alert lifecycle (happy path)**
1. EDR detection → collector → `raw.edr` → normalizer → `alerts.normalized.v1`.
2. Enrichment adds asset/identity/TI context → triage bus.
3. Dedup decides: canonical (new) or duplicate (link). Both paths persist.
4. Scoring computes severity + explanation → persists → queue view materialized.
5. Dashboard streams alert to entitled analysts; dispositions recorded; audit chained.
6. Critical+ queue overflow → SOAR emitter → playbook; notification service pages.

**F2 — Feedback loop**: case-management disposition (e.g., "benign — duplicate of CAM-1") → feedback ingest → dedup tuning dataset + scoring label store → weekly calibration job → shadow deployment → governed promotion.

**F3 — Config change (rules/thresholds)**: PR in Git → CI (unit tests, differential replay on 7-day sample, score-distribution diff) → approval (2-person) → signed bundle → config svc → engines hot-reload; automatic rollback on SLO breach (score-shift alarm).

## 7. Technology stack (with rationale)

| Layer | Choice | Rationale |
|---|---|---|
| Streaming | Kafka (3 AZ, RF=3) | replay, DLQ, ordered per tenant partition; mature ecosystem |
| Schema | OCSF v1.1 + JSON Schema + schema registry | industry-normal schema enables source portability and dedup keys |
| Services | Go (hot path), Node (API/BFF) | predictable p99 under GC; rich web ecosystem |
| Rules | OPA/Rego bundles | declarative, testable, signed bundles, sandboxed eval |
| Store | PostgreSQL 16 + RLS + pgvector | system of record + ANN in one consistent store; row-level security is the tenant boundary |
| Cache | Redis Cluster | exact-key dedup, feature cache, WS presence |
| Object/WORM | S3 + Object Lock (compliance mode) | immutable audit + evidence export |
| Frontend | React + TS + strict CSP + no third-party JS (self-hosted assets, SRI) | supply-chain hardening (OWASP A06/A08) |
| IdP | Existing corp IdP via OIDC; SCIM for lifecycle | phishing-resistant auth (WebAuthn/FIDO2 required for privileged roles) |
| Observability | OTel → Prometheus/Mimir, Loki, Tempo; separate security analytics pipeline | SLOs + security monitoring of the security tool itself |

## 8. Deployment & environments

- **Environments**: `dev` (synthetic data only), `staging` (masked replays of prod), `prod`. No real customer data outside prod (data passport documented in `03`).
- **Topology**: Multi-AZ within primary region; Kubernetes with namespace-per-trust-tier, Pod Security Standards `restricted`, network policies default-deny, service mesh mTLS (SPIFFE identities).
- **Secrets**: external secrets operator → cloud KMS; no secrets in env at rest in Git; rotation ≤ 90 days (automated, evidence logged).
- **Region strategy**: active/active read, single writer per tenant shard; RPO ≤ 5 min, RTO ≤ 60 min (see §10).

## 9. Capacity model (initial)

| Metric | Assumption | Headroom |
|---|---|---|
| Peak ingest | 50k alerts/day/tenant × 100 tenants ≈ 60/sec avg, 10× diurnal peak = 600/sec | 3× provisioned |
| Dedup Redis ops | ~4 ops/alert → 2.4k ops/sec | cluster of 3 primaries |
| Near-dup ANN | 10% of alerts → 60 qps at 95 pct ≤ 50 ms | HNSW index, 1 shard/50 tenants |
| Postgres write | ~700 rows/sec avg (alerts + scores + audit) | 2× IOPS headroom; monthly partitioning |

## 10. Availability, failure modes, DR

### 10.1 Fail-open vs fail-closed matrix

| Component | Failure | Mode | Rationale |
|---|---|---|---|
| Dedup Redis down | dedup unavailable | **fail-open** — alerts shown unsuppressed | alert loss is worse than noise (SP 800-61 detection principle) |
| Enrichment down | context missing | degrade to unknown factors + flag | scoring stays deterministic |
| Scoring rules unavailable | bundle fetch fail | **fail-closed** to last-good signed bundle; if none, static base severity + `unscored` flag | never invent scores |
| Audit write failure | WORM unavailable | **fail-closed**: block the mutating action | auditability invariant |
| Dashboard/API down | queue unreadable | status page + fallback: export critical queue via notifier | SOC keeps working |

### 10.2 DR

- PostgreSQL: streaming replica cross-AZ + PITR (WAL to object storage, 35-day retention); quarterly restore drill (evidence recorded).
- Kafka: 7-day retention; reprocess from `raw` topics for full rebuild of derived state (dedup Redis and queue views are rebuildable).
- Runbooks + game days: quarterly, including "dedup engine poisoned key" and "scoring rules rollback" scenarios (see `07-ops-runbook.md`).

## 11. SLOs & error budget

| SLO | Target | Measurement |
|---|---|---|
| Ingest-to-queryable P99 | ≤ 10 s | OTel span: collector ack → store commit |
| Queue read P95 | ≤ 1.5 s | API server timing |
| Dedup precision (sampled audit) | ≥ 95% | weekly analyst-sampled audit (n=400) |
| Scoring reproducibility | = 100% | nightly recompute of 1% sample, diff vs stored |
| Dashboard availability | 99.9% | synthetics + real user monitoring |

Error-budget policy: budget burn > 25%/week freezes non-safety releases; > 50% triggers review with SOC leads (documented in runbook).
