# memory.md — Memory, Caching & Reservation Architecture (PathSphere 3D)

**Version:** 1.0  
**Classification:** Internal Design Reference  
**Related:** ARCHITECTURE.md, security.md, state.md

---

## 1. Purpose & Scope

This document defines the **knowledge/memory model** of PathSphere 3D: what the platform remembers (cacheable graph knowledge, learned risk context, session/state memory), how knowledge is stored and retrieved (Redis/Postgres/S3/OPA bundles), embedding/indexing strategy for semantic search, cache tiers and TTLs, retention, and the **reservation** semantics that make distributed operations idempotent and concurrently safe.

"Reservation" is used here in the operational sense: locks, leases, idempotency keys, single-flight, and exactly-once delivery — the mechanisms that reserve capacity/ownership before work happens and prevent duplicate or lost side effects.

---

## 2. Memory Model Overview

PathSphere has four memory layers:

| Layer | What it stores | Where | Latency | Freshness |
|---|---|---|---|---|
| L0 · Working memory | Request context, mocks, ephemeral buffers | Process (per-node) | ns | request lifecycle |
| L1 · Hot cache | AuthZ decisions, subgraph hot paths, path results, reports | Redis | < 1 ms | aligned to graph_version |
| L2 · Semantic knowledge | Embeddings of paths/findings/techniques, similarity index | Redis + Postgres (pgvector) | ms | incremental emit |
| L3 · Durable memory | Versioned graph, audit chain, report artifacts, policies | Neo4j · Postgres · S3/WORM · Git | — | authoritative |

**Memory is governed by:** authorization scope (never cache beyond the user's ABAC scope), expiry (TTL per class), eviction (LRU + invalidations on graph_version/role change), and auditability (access to high-sensitivity cached artifacts is logged).

---

## 3. Working Memory (Runtime)

### 3.1 Request Context
Every request carries a canonical context object (see `state.md` §4.4) propagated via tracing:
```
{ request_id, schema, role, tenant, ous[], sensitivity, feature_flags, abac_scope_hash, session_id, ts }
```
Used by middleware (OPA), logging, and quota checks. Released at request end.

### 3.2 Process-Local State
- gRPC/HTTP connection pools (Neo4j driver, Postgres, Redis) — bounded.
- Per-request memoization for path fragments and ATT&CK lookups (bounded LRU).

---

## 4. Hot Memory (Redis)

### 4.1 Cache Classes
| Class | Key | Example Value | TTL | Invalidation |
|---|---|---|---|---|
| AuthZ decision | `az:<scope_hash>:<resource>` | allow/deny + reason | 60s (negative 5s) | policy bundle version bump |
| Persisted queries | `pq:<operation_name>` | operation schema hash | long | registry change |
| Hot subgraph | `graph:v:<v>:sub:<digest>` | sanitized node/edge batch | to graph_version | version bump / role change |
| Path cache | `path:<tenant>:<digest>` | computed paths (serialized) | to graph_version | version bump |
| Findings hot | `find:<tenant>:<digest>` | top findings preview | to graph_version | version bump |
| Report preview | `rp:<report_id>:preview` | first page/layout | 5 min | report version bump |
| Browse/serp | `serp:<query_hash>` | search results (titles) | 15 min | role/tenant change |
| Quota counters | `uq:<tenant>`, `rq:<user>` | token buckets | 60s/1h sliding | per window |

### 4.2 Cache Isolation & Security
- Keys namespaced by `tenant`.
- Cached payloads already passed ABAC server-side; payloads honor field-level redaction.
- No PII/external secrets cached without explicit redaction, and never in clear.
- Memory usage budget per tenant enforced via eviction policy (maxmemory-policy `allkeys-lru` + reserve for hot paths).

---

## 5. Semantic Memory (Embeddings & Knowledge)

### 5.1 Motivation
Enable analyst questions like: "find paths similar to this one", "what commonly precedes AdminTo retention events", "cluster of risky principals". Not a replacement for graph query — a complementary retrieval layer.

### 5.2 Advisor/Vector Store Design
- **Engine:** PostgreSQL `pgvector` (pairs with existing Postgres; avoids new state store) or Redis vSSIM until pgvector matures — **decision: pgvector primary**, Redis for hot cosine results.
- **Embeddings produced for:**
  - Path objects (serialized: ordered edge-type sequence + risk weights + node labels + ATT&CK tags) → `embedding(768d)`.
  - Findings (title + description + remediation) → semantic title.
  - Techniques (MITRE ATT&CK technique descriptions) → lookup vectors.
  - Threat intel bulletins (NVD/CVE) → for matching to platform CVEs.

### 5.3 Embedding Pipeline (state transition)
1. **Emit** on `finding` / `path` finalization (async, dedup by `(graph_version, object_id)`).
2. **Index** into pgvector table `knowledge.embeddings` with columns: `embedding_id, object_type, object_id, scope, language, model_version, vector, created_at, updated_at`.
3. **Model version** pinned; reindex on model upgrade (versioned like OPA bundles).
4. **Search:** k-NN (cosine) with ABAC filter (`scope` matches caller's scope + RLS on tenant).
5. **Feedback loop:** analyst "relevant/not relevant" reactions feed a lightweight collaborative filter scoring (kept in Redis, TTL 30d), improving future recall ordering.

### 5.4 Retrieval API (design)
```
POST /v1/knowledge/search
  body: { query, object_types[], top_k, filters{} }
  → candidates ranked by score + context
  Guardrails: ABAC pre-filter (no cross-tenant leakage), result paylod redaction, query rate limits, audit "search" event when depth/class ≥ confidential.
```

### 5.5 Retention & Privacy
- Embeddings associated with researcher's scope only; source objects honor retention (delete object → delete embeddings).
- Embedding of PII-bearing text avoided; principal IDs embedded as salted hashes (transient), not raw identities.

---

## 6. Reservation Layer (Operational Memory)

Reservation = ownership+guardrails for distributed operations. Prevents duplicate ingestion, thundering herd on path compute, broken 4-eyes, and lost webhooks.

### 6.1 Idempotency & Lock Registry (Redis)
| Mechanism | Implementation | Use |
|---|---|---|
| Idempotency key | `ie:<service>:<hash>` (SET NX + TTL) | Ingest upsert, report regen, webhook delivery (exactly-once) |
| Distributed lock | `lock:<job>:<digest>` (SET NX EX 30–60s) | Path compute single-flight |
| Semaphore | `sem:<pool>` (INCR/DECR + TTL) | Controller farm for headless Chrome worker pool |
| Lease | `lease:<reporter>` (renew ≤ 30s) | Background queue workers lease before processing |
| 4-eyes claim | `claim:<approval>:<id>` (single-writer) | One approver claims an approval ticket |
| Quota reserve | `reserve:<tenant>:` token bucket | Pre-reserve budget per request before execution |

### 6.2 Reservation Safety Rules
1. **Owner explicit:** each reservation carries owner id/request_id for debugging/tracing lineage.
2. **Bounded TTL:** never infinite; lease renewal is a heartbeat with expiry → retry.
3. **Idempotent release:** releases are GETDEL/compare-and-delete, safe to repeat.
4. **Overlap guard:** path compute on same `(graph_version, digest)` blocks concurrent duplicates queue.
5. **Dead-letter:** failed reserved jobs move to `dlq:` stream with original payload + reason; alert on depth.
6. **Recovery:** crash of a lessee → TTL expires → new reservation; at-least-once + idempotent consumer semantics preserve correctness.

### 6.3 Reservation Registry (Postgres)
For long-lived reservations (reports, ingest batches, certification campaigns), persist a durable `reservations` table:
```
{ reservation_id, owner, kind, resource_digest, status, acquired_at, expires_at, released_at, attempts, meta }
```
Redis reservation is the fast path; Postgres is the durable state for audit/governance (tied to audit_events).

---

## 7. Durable Memory (Authoritative)

| Dataset | Store | Lifecycle |
|---|---|---|
| Graph snapshot versioning | Neo4j (+ versioned labels/props) | Immutable version per collection; PITR |
| Findings & path results | Postgres | Explicit bounded; retention per finding SLA |
| Audit chain | Postgres append-only + S3 WORM | Immutable; 12m/24m/7y |
| Report artifacts | S3/WORM + Postgres record | Re-tention schedule (7y/3y/30d) |
| Policies (Rego) | GitOps + OPA bundles | Versioned, 4-eyes |
| Embeddings | pgvector (Postgres) | Retention tied to source object |
| SBOM / signatures | Artifact registry + Sigstore | Per release, cosign-verifiable |

---

## 8. TTL & Invalidation Matrix

| Memory Class | TTL (default) | Invalidation Event | Notes |
|---|---|---|---|
| AuthZ decision | 60s | policy bundle bump | negative cache 5s |
| Hot subgraph | to graph_version | `graph.v` bump | also role change → scope re-eval |
| Path cache | to graph_version | new finding/edge | digest-based |
| Findings hot | 15 min | ingestion | high-churn guarded |
| Report preview | 5 min | report version | expensive asset only |
| Search results | 15 min | role/tenant change | redaction enforced |
| Sessions | 15m + refresh | rotation/reuse | see state.md §7 |
| Quota counters | 60s/1h | — | windowed |

**Global rule:** Any cached object whose source was authored under a *narrower* ABAC scope must be invalidated on scope change; revalidation is always server-side (never trust cache for authZ).

---

## 9. Memory & Compliance (Security Intersection)

- **Everything is Evidence (P-05):** cache-access logs for sensitive classes (confidential+), reveal actions, export of cached path sets → audit events.
- **Retention vs. Memory:** long-lived caches (subgraphs) expire with graph_version; no indefinite PII caches.
- **Encryption:** Redis at rest SSE (managed) or sidecar AES-GCM; TLS in transit; KMS-managed keys.
- **Deny-by-default:** semantic search pre-filters by scope; embeddings never leak across tenants (column `scope` + RLS).
- **Tamper:** report/signing integrity (Ed25519) + audit-chain verify cover the "memory of record".

---

## 10. Reference Configuration (Design Values)

| Parameter | Default |
|---|---|
| Redis memory budget | 60% node for app cache; 40% reserve |
| Path compute concurrency | 1 job per `(graph_version, digest)` |
| Report regen single-flight | yes |
| Embedding dimension | 768 (bge-base) / model versioned |
| k-NN top_k | ≤ 50 (default 20) |
| Idempotency TTL | 24h (replay window) |
| Lease TTL / renew | 30s / 25s |
| Dead-letter alert threshold | ≥ 5 messages or age > 15 min |
| Search audit threshold | all confidential+ queries logged |

---

## 11. Operational Considerations

- **Memory eviction testing:** chaos tests for Redis eviction under max load; ensure hot subgraph & session classes prioritized (allkeys-lru with reservation).
- **Backpressure:** semantic embed pipeline paced by source stream lag; DLQ monitor.
- **Predictability:** tenant budget guarantees prevent noisy-neighbor memory exhaustion.
- **Observability:** per-class hit-rate, eviction rate, embed backlog, lock contention dashboards.

---

## 12. Roadmap (Memory Enhancements)

| Phase | Item |
|---|---|
| Q1 | pgvector semantic search for paths/findings; persisted query registry; hot-subgraph cache v1 |
| Q2 | Embedding model upgrade cadence + reindex pipeline; collaborative "relevant" ranking |
| Q3 | Cross-version delta memory (what changed since last snapshot) surfaced in search |
| Q4 | Autonomous "suggested next target" retrieval (WIP) with strict scope guards |

---

## 13. Conclusion

The memory model separates **hot caches** (Redis, ABAC-scoped, versioned), **semantic knowledge** (pgvector embeddings), and **durable memory** (Neo4j/Postgres/S3/Git). Reservation semantics — idempotency, leases, single-flight, bounded TTL — make distributed operations safe and exactly-once. Security rides on top of every memory surface: scope-checked retrieval, redaction, retention, audit events, and immutability of the audit chain.

This layer is designed to be **left-down, upward scalable**: hot memory grows with Redis clusters, semantic knowledge with pgvector partitions, durable memory with graph/relational HA — while reservations guarantee correctness under scale.

**Document End**