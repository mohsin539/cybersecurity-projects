# 02 — Triage Engine: Severity Scoring & Deduplication (Deep Dive)

Status: Approved v1.0 · Owner: Detection Engineering + Platform · Review cadence: quarterly

---

## 1. Pipeline position

```
raw.<source> ──► Normalizer ──► Enricher ──► ┌ Dedup ┐ ──► Scoring ──► Alert Store ──► Queue views
                                             └───────┘
                       (both engines consume the same normalized+enriched alert; dedup runs
                        first so the scoring is computed for the canonical alert and inherited
                        by duplicates with a `dup_penalty` factor)
```

Ordering rationale: dedup before scoring avoids scoring work on duplicates and guarantees the canonical alert's score reflects aggregate occurrence context (e.g., `occurrence_count` velocity).

## 2. Normalization contract

- Target schema: **OCSF v1.1 `Detection Finding`**, profile additions: `triage` (our extension block: `dedup`, `score`, `provenance`).
- Every alert carries: `tenant_id`, `source`, `rule_id` (vendor rule or detection id), `event_uid` (UUIDv7), `occurred_at` (event time), `observed_at` (ingest time), `entities[]` (normalized: `user`, `host`, `ip`, `file_hash`, `process`, `container`, `resource`), `raw_original` (90-day TTL).
- Time normalization: all timestamps → UTC RFC3339; clock-skew guard: `observed_at - occurred_at > 15 min` ⇒ flag `skewed=true`, bucketing uses `occurred_at` clamped to observed window.
- Entity canonicalization rules (deterministic, versioned `mapping_pack_version`):
  - hostnames: lowercase, strip domain suffix per tenant mapping table
  - users: `user@domain` normalized to tenant directory id when resolvable, else literal
  - IPs: preserve; private ranges mapped to `host:` entity when CMDB match exists
  - file hashes: prefer SHA-256, fall back MD5/SHA-1 with `hash_algo` tag

## 3. Enrichment feature contract

| Feature | Source | Missing-value policy |
|---|---|---|
| `asset_criticality` | CMDB (tier 0–4) | `tier_unknown` → neutral 0.5 tier |
| `identity_risk_level` | IdP risk events (30d) | `unknown` → 0 |
| `ti_match` (hash/ip/domain) | TIP (cached 15 min, hash-keyed) | none → 0 |
| `kev_listed`, `epss` | CISA KEV / FIRST EPSS (daily refresh) | n/a |
| `entity_history_30d` (agg) | Feature store (batch+stream) | cold-start → population priors |
| `queue_context` | triage system | n/a |

Rules: enrichment never *changes* the alert semantics, only adds `enrichments{}`; enrichment failures produce explicit `unknown` markers and a `degraded_context=true` flag surfaced in the UI (analysts must see why a score may be understated).

## 4. Severity scoring engine (deep dive)

### 4.1 Design principles

1. **Deterministic and explainable** — same inputs + rule version ⇒ same score; every score persisted with a factor breakdown that the UI renders as "why this score".
2. **Two-layer**: deterministic base (auditable, governed) + ML calibration (monotonic, bounded influence, re-ranks within bands).
3. **Governed tunability** — SOC leads tune weights within min/max bands; changes go through PR + differential replay; per-tenant overrides are allowed but every override is versioned and expiring.
4. **No black-box decisions** — ML cannot suppress alerts or move an alert across governance bands (e.g., cannot demote a `critical` asset alert below `high`).

### 4.2 Factor model (v1)

```
score_raw = Σ (w_i × f_i)                    (each f_i ∈ [0,1], Σ w_i = 100)
score     = clamp(round(score_raw × M_ctx), 0, 100)
```

| Factor f_i | Inputs | Default w_i | Bounds (governance band) |
|---|---|---|---|
| f1 detection_confidence | source rule confidence (vendor) × source reliability | 20 | 10–25 |
| f2 asset_criticality | CMDB tier (0=most critical) | 20 | 15–30 |
| f3 attack_tactic_severity | MITRE ATT&CK tactic mapped to chain position (Initial Access=0.3 … Impact=1.0) | 15 | 10–20 |
| f4 ti_match_strength | no match=0, witnessed- community=0.4, confirmed-malicious=1.0 | 15 | 8–20 |
| f5 identity_risk | IdP risk (impossible travel, MFA fatigue, dormant account use) | 10 | 5–15 |
| f6 exploitability | KEV listed ×0.6 + EPSS ×0.4 | 8 | 4–12 |
| f7 behavioral_anomaly | entity-history z-score of similar events | 7 | 3–12 |
| f8 occurrence_velocity | log-scaled dedup aggregate rate (see §5.7) | 5 | 2–8 |

Context multipliers M_ctx (multiplicative, capped at 1.5 total):
- ×1.25 alert on tier-0 asset **and** tactic ∈ {Credential Access, Privilege Escalation, Impact}
- ×1.15 active incident (linked case open) for the entity
- ×0.85 change-window match with approved change record
- ×0.75 tenant-specific tuning (governed, expiring)

Bands: `critical ≥ 85`, `high 65–84`, `medium 40–64`, `low 15–39`, `informational < 15` (thresholds themselves versioned config).

**Worked example** (rendered as explanation in UI):
```
f1 0.75×20=15.0  EDR rule confidence 75%, source reliability 1.0
f2 1.00×20=20.0  asset FIN-DB-001 (tier 0)
f3 0.80×15=12.0  tactic: Credential Access
f4 1.00×15=15.0  TI: hash confirmed malicious (3 sources)
f5 0.60×10= 6.0  identity risk: impossible travel 12h ago
f6 0.84× 8= 6.8  KEV listed (0.6) + EPSS 0.61 × 0.4 → 0.844
f7 0.20× 7= 1.4  z=1.3 on host process-launch volume
f8 0.30× 5= 1.5  4 occurrences/10min → log scale
M_ctx ×1.25      tier-0 + Credential Access
score = clamp(round((15+20+12+15+6+6.8+1.4+1.5) × 1.25), 0, 100)
      = clamp(round(77.7 × 1.25), 0, 100) = clamp(round(97.1), 0, 100) = 97  → band: critical
```
*Note: the shipped calculator is unit-tested against 500+ golden vectors (02 §8); this example is one of them.*

### 4.3 Versioning & reproducibility

- `score_version = (ruleset_semver, mapping_pack_version, factor_weights_hash)`.
- Alert store keeps immutable `(alert_id, score_version, inputs_hash, score, factor_breakdown, computed_at)`; recomputation for audit uses stored inputs + same version (no live config).
- Nightly job recomputes a 1% sample with the stored version and asserts bit-equality; any drift pages detection engineering (this is also an anti-tamper control — silent weight edits in prod are detectable).

### 4.4 ML calibration layer (bounded)

- Model: gradient-boosted trees with **monotonic constraints** (score can only increase with f2, f4, f6…), trained on 180-day disposition history, per tenant-cohort (privacy: features are tenant-pseudonymized; no raw payload text in features).
- Output: bounded re-rank within band + optional sub-band ordering; influence capped at ±10 points; model cannot cross band boundaries; `ml_adjustment` recorded separately in factor breakdown.
- Lifecycle: quarterly retrain, weekly drift check (PSI on features, calibration curve Brier score), champion/challenger shadow mode for 2 weeks before governed promotion; rollback = config change, not code deploy.
- Fairness/abuse guard: model features exclude user identity attributes beyond pseudonymous ids (no protected-class features); anti-gaming: dedup aggregates and occurrence velocity features are computed server-side only.

### 4.5 Governance of scoring changes

- Weights/thresholds live in Git (`triage-rules` repo) as signed Rego + YAML weights; CI runs: unit golden vectors, differential replay on 7-day production sample (score distribution diff, band-migration report), performance budget.
- Approval: 2-person rule (detection eng + SOC lead); emergency hotfix path with 24 h retro-approval and audit record.
- Every change yields a new `score_version`; in-flight alerts keep their original scores (no retro-rescoring except explicit, audited backfill operation with approval).

## 5. Deduplication engine (deep dive)

### 5.1 Goals and non-goals

- Goal: collapse repeated/near-identical detections into one canonical alert with full occurrence history, to cut queue volume without information loss.
- Non-goals: cross-tenant dedup (never), correlation into incidents (case/SIEM link only), suppression by allowlist (that's detection engineering's job via feedback loop).

### 5.2 Two-stage architecture

**Stage 1 — exact key (fast path, ≥80% of duplicates)**
```
dedup_key_v1 = sha256( tenant_id
                     | rule_id
                     | canonical_sorted(entity_ids)
                     | activity_window_bucket(occurred_at, window=rule.window or 15m) )
```
- Redis `SET key canonical_alert_id NX TTL <window>` → winner becomes canonical; losers get `duplicate_of` link.
- Window bucketing prevents boundary straddling: bucket = floor(occurred_at / window); sliding semantics achieved by checking previous bucket too (SETNX on both bucket t and t-1 → link to the newer canonical if hit).

**Stage 2 — near-duplicate (semantic/variant detection)**
- Triggered only for alerts that *missed* exact key but share `rule_id` family or entity overlap ≥ 2.
- Signature: MinHash (k=128, shingles over sorted normalized entity pairs + tactic + rule_family) and/or SimHash over tokenized `summary` fields (tenant language-agnostic config).
- ANN search: pgvector HNSW index, filtered by `tenant_id` + `occurred_at ≥ now - max_window` (index-level tenant filter — no cross-tenant leakage by construction).
- Decision: cosine ≥ θ (default 0.92, tenant-tunable 0.85–0.98) **and** rule_family match ⇒ link as duplicate; θ ∈ [0.85, 0.92) requires secondary signal (same entity OR same file_hash) to link.
- All near-dup links are stamped `dedup_method=fuzzy, similarity=x, threshold=θ` and are **first-class citizens in the audit trail** and in the weekly precision audit sample (oversampled on purpose).

### 5.3 Canonical alert lifecycle

```
             ┌──────────────┐   new exact/fuzzy link    ┌──────────────────┐
 new alert ─►│ is canonical?├──────────────────────────►│ canonical alert  │
             │      yes     │                           │ occurrence_count++│
             └──────┬───────┘                           │ last_seen=t      │
                    │ no                                │ variant_entities │
                    ▼                                   └────────┬─────────┘
             duplicate record                                    │
             (linked, hidden by default)                         ▼
                                                    re-score ONLY canonical
                                                    (dup_penalty factor guards
                                                     analyst-perceived inflation)
```

- Suppression is **display-level only**: duplicates are stored, queryable, and one click from "promote to canonical" (split) when an analyst disagrees.
- Split operation: analyst promotes duplicate → new canonical id minted, both alerts audited with linkage preserved; ML never performs splits.

### 5.4 Safety controls (prevent over-suppression)

1. **Precision-first thresholds**: fuzzy default 0.92 with secondary-signal requirement below that.
2. **Governed kill switch** (per tenant, per rule family, global): `dedup_mode = off | exact_only | full` — flip is a config change with audit + automatic 30-minute re-evaluation alarm.
3. **Bounded aggregation**: canonical alert caps `occurrence_count` influence in scoring (f8) so a flood cannot self-amplify severity unboundedly; velocity is log-scaled.
4. **Shadow mode for new keys/signatures**: 2-week parallel run measuring would-be suppression against analyst dispositions before enablement.
5. **Canary tenants** for threshold changes; automatic rollback if sampled precision < 95%.
6. **DLQ replay** for dedup failures (fail-open: alert is surfaced unsuppressed rather than lost).

### 5.5 Performance design

- Exact stage: O(1) Redis ops; p99 ≤ 5 ms.
- Fuzzy stage: MinHash LSH prefilter → pgvector ANN over candidate set (≤ 5k per tenant-window), p99 ≤ 500 ms; overflow (topic lag > 30 s) degrades to exact-only mode with a UI banner (documented degraded state).
- Backpressure: Kafka consumer pause; raw topics retain 7 days so nothing is lost.

### 5.6 Multi-tenancy guarantees

- All keys/indexes prefix `tenant_id`; RLS policies on `alerts`, `alert_links`, `dedup_signatures`; ANN search executes with `SET LOCAL app.tenant_id` and index filter pushdown; cross-tenant tests in CI (they must fail to find each other's alerts).

### 5.7 Interaction with scoring (f8 occurrence_velocity)

```
f8 = min(1, log10(1 + occurrences_per_window) / log10(1 + 50))
```
- Computed **per canonical alert** from dedup aggregates, so repeated alerts raise urgency *without* each duplicate inflating the queue; capped so floods cannot manufacture criticals.

## 6. API contracts (v1, OpenAPI source of truth)

```
POST   /v1/alerts                      (internal, collector/normalizer only, mTLS)
GET    /v1/queue?band=&assigned=&cursor= (tenant-scoped, server-side pagination)
GET    /v1/alerts/{id}                 (includes factor_breakdown, dedup tree)
GET    /v1/alerts/{id}/duplicates
POST   /v1/alerts/{id}/disposition     {status, reason_code, note?}
POST   /v1/alerts/{id}/assign          {assignee}
POST   /v1/alerts/{id}/split-duplicate {duplicate_id}
POST   /v1/alerts/{id}/escalate        {case_id | soar_playbook}
POST   /v1/feedback                    (case-mgmt webhook, HMAC-signed)
GET    /v1/meta/explain/{alert_id}     (score explanation, dedup explanation)
```

- All mutations: `Idempotency-Key` required; audit event emitted synchronously before response (fail-closed rule).
- Queue reads support `If-None-Match`/ETag; WebSocket stream `wss://…/v1/stream` sends delta frames with server-side cursor, resumable via `Last-Event-ID`.

## 7. Data retention within the triage plane

| Data | Hot store | Cold/export |
|---|---|---|
| Canonical + duplicate alerts | 180 days Postgres (partitioned) | parquet to object storage, 2 years |
| Score records (immutable) | same as alert | 2 years (audit) |
| Dedup links + signatures | 180 days | 2 years |
| Raw original payload | 90 days | none (minimization) |
| Audit events | 400 days WORM | export to SIEM (real-time) |

## 8. Testing strategy (engine-specific)

- **Golden-vector tests** for scoring: 500+ versioned vectors; CI asserts exact match.
- **Property tests**: score invariance to entity order; monotonicity in f2/f4; clamp correctness; band-boundary tests.
- **Dedup precision harness**: replay labeled 7-day samples; report precision/recall per rule family; regression gate ≥ 95% precision.
- **Cross-tenant isolation tests**: synthetic cross-tenant duplicates must NOT link (CI-enforced).
- **Determinism test**: same input replayed twice ⇒ identical score record hash.
- **Chaos drills**: Redis partition (fail-open verified), OPA bundle timeout (fail-closed to last-good), audit-write outage (mutations blocked — correctness of fail-closed).
