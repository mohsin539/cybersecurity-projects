# state.md — Application State Model (Reservation Document)

Status: Active · Owner: Platform · Companion to `01-architecture-overview.md` and `02-triage-engine.md`

> **Reservation rule**: `state.md` is the single authoritative record of every piece of state the application owns or touches. Any change to state shape, ownership, lifecycle, or persistence must update this document in the same change set. Nothing else in the repo may redefine state semantics.

---

## 1. State taxonomy

| Class | Examples | Lifetime | Owner | Persistence | Notes |
|---|---|---|---|---|---|
| **Identity** | sessions, CSRF tokens, nonces | ≤ 12 h | server (memory) | none (volatile by design) | see §3.1 |
| **Domain (system of record)** | alerts, scores, dedup links, dispositions, audit | permanent (demo: process life) | server store | JSON file `data/store.json` (design target: PostgreSQL per 03) | append-only records |
| **Derived state** | queue views, occurrence counts, canonical aggregates | = domain | server store | same file, recomputed from events | never authoritative |
| **Configuration** | weights, thresholds, kill switches, tenants/users/roles | until changed | server store | same file | versioned via audit chain |
| **Client state** | selected alert, filters, cursor, websocket connection | page session | browser SPA | none (server holds truth) | no client-owned truth |
| **Operational state** | switch positions, degraded flags | until changed | server store | same file | surfaced in UI banner |

**No client-owned truth.** The browser holds only view state; every domain fact is server-side.

## 2. Domain state definitions

### 2.1 Alert (canonical + duplicate forms)

| Field | Type | Mutability | Semantics |
|---|---|---|---|
| `id` | opaque UUID | immutable | opaque, never sequential |
| `tenantId` | string | immutable | derived from authenticated session, never from request body |
| `isCanonical` | bool | immutable after link | dedup discriminator |
| `canonicalId` | UUID \| null | link-only (split clears via new canonical) | dedup tree membership |
| `source`, `ruleId`, `ruleFamily`, `tactic` | string | immutable | provenance |
| `title`, `summary`, `entities[]` | string/list | immutable | dedup key inputs |
| `occurredAt`, `observedAt` | RFC3339 | immutable | time normalization (02 §2) |
| `occurrenceCount` | int | append-only increments | canonical aggregate |
| `firstSeen`, `lastSeen` | RFC3339 | monotonic | canonical aggregate |
| `status` | enum | append-only via dispositions | `open/assigned/investigating/false_positive/benign/contained/resolved` |
| `assignedTo` | string \| null | append-only via assignments | role-scoped |
| `degradedContext` | bool | server-set | honesty flag (enrichment missing) |
| `rawOriginal` | object | immutable | 90-day TTL in design; minimized fields only |

### 2.2 Score record (immutable, versioned)
`(alertId, scoreVersion, inputsHash, score, band, factorBreakdown, computedAt)` — insert-only; recomputation uses stored inputs + stored version (02 §4.3). `factorBreakdown` always includes `mlAdjustment` (fixed 0 in this implementation, reserved field).

### 2.3 Dedup link (edge)
`(canonicalId, duplicateId, method: exact\|fuzzy, similarity, thresholdUsed, createdAt, unlinkedAt?, unlinkedBy?)` — un-link (split) **sets `unlinkedAt`**; rows are never deleted.

### 2.4 Disposition / assignment (append-only ledger)
Every status/assignment change appends a record; current status is derived from the latest entry — **history is never overwritten**.

### 2.5 Audit event (hash-chained, append-only)
`(seq, ts, tenantId, actorId, action, objectType, objectId, before, after, reason, prevHash, entryHash)`.
- `entryHash = sha256(canonicalJson({seq,ts,tenantId,actorId,action,objectType,objectId,before,after,reason,prevHash}))`.
- `prevHash` of first entry per tenant = `sha256("genesis:<tenantId>")`.
- **Fail-closed**: mutations are rejected if the audit write fails.
- Export: `GET /api/audit/export` streams JSONL with `Content-Disposition: attachment`.

### 2.6 Configuration state (kill switches, weights, thresholds)
All config is server-held, mutated only through the `/api/config` endpoints, every change audited with before/after. Weight changes bump `scoreVersion`.

## 3. State lifecycle rules

### 3.1 Sessions (volatile by design)
- Server-side session store: `Map<sessionId, {user, expiresAt, csrf}>`.
- **12 h absolute expiry, 30 min idle timeout**, sliding on activity, purge interval 10 min.
- Logout and session purge erase immediately (memory-only ⇒ instant revocation; ADR note: prod target uses server-side revocation list per 04 §4 A07).
- Cookie: `HttpOnly; SameSite=Strict; Path=/; Secure` (Secure enforced when TLS-terminated).

### 3.2 Domain events → state transitions
| Event | State effect |
|---|---|
| ingest | dedup decision → canonical (score computed) or duplicate (link; canonical re-scored with updated aggregates) |
| disposition | append disposition record → status derived |
| assign | append assignment → `assignedTo` derived |
| split (un-dedup) | set `unlinkedAt` on link row; duplicate becomes canonical with own score |
| config change | config version bump; audited; weights change ⇒ `scoreVersion` bump |

### 3.3 Invariants (checked in code and testable)
1. Every alert row has `tenantId` and every read/write is tenant-scoped.
2. Score records are never updated after write.
3. Dedup links are never deleted, only `unlinkedAt`-marked.
4. Dispositions/assignments are never overwritten.
5. Audit chain verifies per tenant (daily in prod; on demand via API).
- Test hook: `GET /api/meta/invariants` runs all five assertions live.

## 4. Multi-tenant scoping

- Every store structure is `Map<tenantId, …>`; every query filter includes `tenantId` derived **only** from the session claim.
- The `X-Tenant` header is accepted **only** for the `auditor` role (read-only, cross-tenant oversight); rejected for all other roles (prevents header-based tenant spoofing — A01 mitigation).
- Auditor with `X-Tenant: *` gets read-only cross-tenant statistics (counts only, no payload data).

## 5. Reserved extension points

| Extension | Reserved in state | Trigger |
|---|---|(GUI hook)
| ML overlay adjustment | `factorBreakdown.mlAdjustment` (currently 0) | enable `scoring.ml_overlay` switch |
| Fuzzy dedup | `dedup_method=fuzzy` enum value | pluggable similarity module |
| Backfill re-scoring | new score record (same alert, new version) | explicit audited operation |
| Case/SOAR escalation | `status=contained` + `escalatedTo` ledger entry | webhook emitter (reserved) |
| Case-mgmt feedback | `feedback_records` table (reserved, not instantiated) | HMAC-verified webhook |

## 6. State export/import (portability + backup)

- `GET /api/audit/export` — full audit JSONL (WORM-compatible format).
- `GET /api/meta/export` — full store snapshot (JSON) for backup/restore; requires `platform.admin`.
- Restore = start with `--import <file>`; restore validates the audit chain before accepting (chain must verify, else refuse to start).

Restore integrity rule: **a store whose audit chain does not verify is refused at startup** (fail-closed for integrity, consistent with 01 §10.1).
