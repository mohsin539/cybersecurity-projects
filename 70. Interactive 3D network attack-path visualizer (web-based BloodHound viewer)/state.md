# state.md — Application, Graph & Persistence State Model (PathSphere 3D)

**Version:** 1.0  
**Classification:** Internal Design Reference  
**Related:** ARCHITECTURE.md, security.md, memory.md

---

## 1. Purpose & Scope

This document describes **all state** in PathSphere 3D: client-side application state, server-side service state, graph state (Neo4j), relational state (PostgreSQL), cache/queue state (Redis), object storage state (S3/WORM), and how state transitions are audited. It defines canonical shapes, ownership, TTLs, backup/recovery, and reservation semantics (idempotency, locks, leases).

**Key FS (feature set) touchpoints:** 3D viewer state, persisted GraphQL query registry, path-analysis job state, audit ledger, report record lifecycle, OPA access scope.

---

## 2. State Ownership Map

| State Domain | Owner | Persistent Store | Volatile/Cache | Lifecycle |
|---|---|---|---|---|
| Graph topology | Ingestion + Neo4j | Neo4j (graph of record) | Redis hot subgraphs | Immutable per collection version; snapshot-versioned |
| Identities (principals) | Auth + Identity + Postgres | PostgreSQL | Redis sessions | Mutable (SCIM/JML) |
| Session/tokens | Auth + Identity | Vault (optional) + Redis | Redis | Short-lived (15-min JWT, refresh rotation) |
| Path compute results | Path Analysis | Postgres (findings) + Redis | Redis (hot) | Refresh on graph version change |
| Audit events | Audit Ledger | PostgreSQL append-only + S3 WORM | Redis stream (transient) | Immutable; retention 7y |
| Reports | Report Engine | Postgres (record) + S3 | Redis (cache, optional) | Versioned; retention per schedule |
| OPA policies | Policy team (Git) | GitOps + OPA bundle store | OPA in-memory bundle | Versioned; 4-eyes change control |
| Quotas/rate limits | API Gateway | Redis | Redis | Windowed (sliding token bucket) |
| Job/Task state | Services via Redis | Redis Streams + Postgres (final) | Redis | Until terminal; then durable provenance |
| Feature flags/Config | Platform | Postgres + GitOps | Redis | Versioned, audited |

---

## 3. Client-Side Application State (SPA)

### 3.1 Client Stores
- **UI/View state (zustand):** selected node, camera position/bookmarks, active filters (tactics, edge types, tiers), hover/selection, path-replay slider index, snapshot capture mode.
- **Server cache (Apollo):** normalized client cache of nodes/edges/subgraphs fetched via persisted queries; cache-only reads when stale-while-revalidate.
- **Offline snapshot (IndexedDB):** materialized view of the last-open subgraph (sanitized to ABAC scope), used when connectivity drops; TTL 24h, overwritten on reauth.
- **Delta subscriptions (WebSocket):** in-memory event queue applying micro-mutations (node added, edge added) without full refetch.

### 3.2 Client State Rules
- **AuthZ is never client-side:** filtering for display only; server re-authors every query (ABAC).
- **No secrets in client state:** tokens stored in memory + secure cookie; never in localStorage.
- **Session lifecycle:** token refresh with rotation; on reuse detection, force re-auth.
- **Deep-link safety:** URL-anchored filters validated against persisted-query allow-list and ABAC scope before render.

---

## 4. Server-Side State

### 4.1 Per-Request Context (propagated via trace/context)
Standardize a context object: `{ schema, role, tenant, ous[], sensitivity, feature_flags, request_id }`. Every downstream call (GraphQL → path → OpenSearch/log) carries it. Used by OPA for authorization decisions.

### 4.2 Graph Query Service State
- **Persisted Query Registry:** allow-list mapping `operation_name → hashed_query → parameters_schema`. Stored in Postgres; loaded into Redis on startup.
- **Query Budget State:** per-tenant counters (depth, rows, cost, time) in Redis; sliding-window.

### 4.3 Path Analysis Engine State
- **Job State Machine:** `queued → running → complete | failed | cancelled`.
- **Job Record (Postgres):** `job_id, source_graph_version, dst/source set, k, filters (hash), status, timestamps, execution_ms, result_reference, audit_ref`.
- **Cache Key:** `hash(tenant, graph_version, path_request_digest)` in Redis TTL aligned to graph freshness.

### 4.4 Auth/Identity State
- **Session record (Redis):** `session_id, user, refresh_hash, device_fingerprint, expires, rotation_count`.
- **Token claims:** `{ sub, role, tenant, scope_hashes, jti, iss, aud, exp, nbf, iat }`.
- **Secrets (Vault):** app secrets, keys (report-signing, integration), throttled with lease TTLs.

### 4.5 Audit Ledger State
- Append-only events as defined in `security.md` §2.5; stored atomically with `prev_hash` chain construction; streamed to SIEM (best-effort, not authoritative).
- **Chain cursor:** latest event hash + last verified Merkle root (persisted to both Postgres and S3 WORM).

### 4.6 Policy Engine (OPA) State
- Bundle from GitOps (`.rego`), loaded into OPA sidecars; decision caching bounded by bundle version + inputs; decision log emitted per request (asynchronously appended to audit).

---

## 5. Graph State (Neo4j)

### 5.1 Node Labels
`User`, `Group`, `Computer`, `Domain`, `OU`, `Container`, `GPO`, `AzureUser`, `AzureGroup`, `AzureDevice`, `ServicePrincipal`, `ForeignPrincipal`, `ApplyingTo`-style edges, plus `Host`/`Service`. Additional flags: `os`, `enabled`, `sessions`.

### 5.2 Edge Types (attack surface — core to visualization)
| Edge | Meaning | Risk Weight (design) |
|---|---|---|
| `MemberOf` | User/group membership escalation | Medium |
| `HasSession` | Credential access / lateral movement | High |
| `AdminTo` | Local admin to computer | High |
| `GenericAll` / `GenericWrite` | Full/write ACL control | Critical |
| `WriteDacl` / `WriteOwner` | DACL/owner manipulation | Critical |
| `ForceChangePassword` | Password reset control | Critical |
| `AddMember` / `AddSelf` | Group membership control | High |
| `CanRDP` / `CanPSRemote` / `AllowedToDelegate` | Remote access / delegation abuse | High |
| `Owns` | Object owner ACL | Critical |
| `GPLink` / `AddKeyCredentialLink` | GPO link / shadow credential | Medium/Critical |
| `Contains` | OU/container containment | Info (visual layout) |

### 5.3 Graph Versioning & Reservations
- **Collection snapshot version:** monotonically increasing `graph_version` (e.g., `v-<sha256-of-canonical-snapshot>`).
- **Upsert semantics:** ingestion merges on identity key; edge changes detected as delta; never in-place update of immutable user data without version bump.
- **Reservation/Idempotency:** ingestion keys on `(collector_id, collection_timestamp, content_hash)`; duplicate uploads skipped (idempotent).
- **Tier-0 marker:** nodes tagged `crown_jewel:true` or label `Domain` used for Tier-0 reachability computation.

---

## 6. Relational State (PostgreSQL)

### 6.1 Primary Tables
- `users`, `roles`, `user_roles`, `tenant`, `tenant_user`
- `persisted_queries` (operation_name, hash, schema, version, enabled)
- `path_jobs` (job state machine)
- `findings`, `finding_edges` (result of path analysis; explicit, bounded, deduped)
- `reports`, `report_versions`, `report_recipients`
- `audit_events` (append-only; triggers block UPDATE/DELETE)
- `opa_decisions` (ledger-referenced)
- `feature_flags`, `config` (versioned)
- `approvals` (4-eyes workflow)
- `remediation_tasks` (linked to SoTs/tickets)
- `retention_policy` (schedule registry)

### 6.2 Row-Level Security (RLS)
- Tenant column enforced via `SET app.tenant = ...` + RLS policies on all tenant-scoped tables.
- Reports/audit evidence accessible only by scoped role + tenant.

---

## 7. Cache & Queue State (Redis)

| Key Prefix | Purpose | TTL | Notes |
|---|---|---|---|
| `sess:` | Session vault | 15m–24h | Broken during rotation/reuse detection |
| `pq:` | Persisted queries (hot) | indefinite | Refreshed on registry change |
| `budget:` | Query budget counters | 60s sliding | Per-tenant + per-user |
| `graph:v:<ver>:` | Hot subgraph cache | to graph_version | Invalidated on version bump |
| `path:` | Path result cache | to graph_version | Deterministic digest key |
| `streams:jobs:*` | Job work queues | until ack | Ack + at-least-once |
| `lock:*` | Distributed lock/lease | 30–60s | For path analysis concurrency |
| `rl:` | Rate-limit counters | 1m/1h | Token bucket / sliding window |

---

## 8. Object Storage State (S3/WORM)

- **Report artifacts:** `reports/<tenant>/<report_id>/v<n>/<artifact>.pdf|.csv|.json|.html` — SSE-KMS, versioned, Object Lock (Compliance), retention `retention_until`.
- **Audit archives:** `audit/<year>/<month>/<ledger_file>.json.gz` — append-only bucket, Object Lock Compliance, 7y retention.
- **Ingest quarantine:** `ingest/quarantine/<hash>/...` — malformed/suspicious uploads with AV flags.
- **Offline packs:** `bundles/<compliance_pack>/...` for air-gapped mode.

---

## 9. Reservation Semantics (Concurrency & Idempotency)

| Operation | Reservation Approach | Failure Handling |
|---|---|---|
| Ingest upsert | Idempotency key `(collector_id, ts, content_hash)` | Skip duplicate; quarantine on anomaly; heal via re-ingest of same snapshot |
| Path compute | Distributed lease per `(graph_version, digest)` | On crash: lease expiry → retry; result cached before lease release |
| Report regeneration | Versioned; single-flight via Redis lock `lock:report:<id>` | Collision: latest wins; old version retained for audit |
| Token refresh | Rotation registry (Redis `sess:` reuse flag) | Reuse → revoke all + force re-auth (P1 SIEM alert) |
| Delta apply | Sequence-numbered delta queue per graph_version | Stale delta (older version) dropped; full refetch fallback |
| Quota/rate limit | Redis counters (atomic) | Throttle/429 with retry-After; over-limit logged |
| Approval/4-eyes | Single-row claim lock + state (pending/approved/denied) | Timeout returns to pending; audit of override |

---

## 10. Backup, Recovery & DR

### 10.1 Backup Matrix
| Datastore | Method | RPO | RTO | Encryption | Restore check |
|---|---|---|---|---|---|
| Neo4j | Causal cluster + nightly full + PITR log | ≤ 15 min | ≤ 1 h | AES-256 / KMS | Nightly automated restore drill + integrity hash |
| PostgreSQL | Base backup + WAL archive (PITR) | ≤ 15 min | ≤ 1 h | AES-256 / KMS | Quarterly restore test |
| Redis | Snapshot (RDB) + AOF | ≤ 5 min (rebuild) | 15 min | AES-256 / KMS | Load test on staging |
| S3/WORM | Versioning + cross-region replication | ~minutes | immediate | SSE-KMS | Object-lock + integrity verify |

### 10.2 DR Scenarios
- **Zone failure:** Multi-AZ auto-failover for Neo4j/Postgres; Redis Sentinel.
- **Region failure:** Passive standby region; promote per runbook; RPO ≤ 15 min / RTO ≤ 1 h.
- **Data corruption/tamper:** Restore nearest PITR; run report/audit verify (Ed25519 + chain) to isolate corruption window; CAPA.

---

## 11. State Change → Audit Correlation

| State Transition | Emitted Audit Event | Ledger Relevance |
|---|---|---|
| Login / MFA / lockout / logout | `auth.login`, `auth.mfa`, `auth.lockout`, `auth.logout` | Chain-anchored |
| Graph query executed | `graph.query` (object IDs + scope digest) | Chain-anchored |
| Sensitive node reveal | `graph.reveal` (justification) | Chain-anchored |
| Path export / report download | `report.export` | Chain-anchored |
| Report created/approved | `report.create`, `report.approve` | Dual-actors separation |
| Policy (Rego) change | `policy.change` (git commit + bundle version) | Chain-anchored |
| Role grant/revoke | `rbac.grant`, `rbac.revoke` | Chain-anchored |
| Break-glass usage | `pam.breakglass` | Mandatory justification |
| Ingest upload | `ingest.upload` (content hash) | Chain-anchored |
| Key rotation | `crypto.keyrotation` | Chain-anchored |
| Retention purge | `data.purge` (object IDs + reason) | Chain-anchored |

---

## 12. State Consistency Rules

1. **Single writer per aggregate:** Ingestion owns graph writes; Report engine owns report artifacts; Auth owns sessions/tokens.
2. **Eventual consistency tolerated** for: SIEM stream, notifications, delta subscriptions (designated non-authoritative).
3. **Strong consistency required** for: audit ledger append, approval transitions, token rotation (single-source of truth).
4. **Idempotency enforced** for ingestion, path compute (cache), report regeneration, webhook deliveries (idempotency key).
5. **Versioning mandatory** for: persisted queries, policies (bundles), graph snapshots, reports, feature flags/config.
6. **Redaction protective layer:** queries return ABAC-scoped/pseudonymized payloads; reveal paths require explicit audited action.

---

## 13. Reference Configuration Snapshot (Design Values)

- JWT TTL: 15 min; refresh window 24h; rotation max 10 per session.
- Query budget: max depth 12, max rows 50k, max cost units 1000 per tenant per 60s.
- Path compute ceiling: 2 s; k-shortest k ≤ 20; max hops 30.
- Cache TTL (subgraphs): aligned to graph_version freshness (default 15 min refresh).
- Report retention: legal 7y, audit pack 3y, draft 30d (configurable).
- Audit retention: online 12m, archive 24m, security events 7y (immutable).

**Document End**