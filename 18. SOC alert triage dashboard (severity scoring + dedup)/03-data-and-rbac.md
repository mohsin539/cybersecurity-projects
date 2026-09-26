# 03 — Data Model, RBAC/ABAC, Multi-Tenancy & Privacy

Status: Approved v1.0 · Owner: Platform + Security Architecture · Review cadence: semi-annual

---

## 1. Logical data model (PostgreSQL, RLS-protected)

```
tenants ──┬─< users ──< role_assignments >── roles ──< role_permissions >── permissions
          │
          ├─< alerts (canonical + duplicates, discriminator: is_canonical)
          │      │
          │      ├─< alert_scores (immutable, versioned)     ← score reproducibility
          │      ├─< alert_links (dedup edges)               ← dedup tree
          │      ├─< alert_dispositions (append-only)        ← analyst decisions
          │      └─< alert_assignments (append-only history)
          │
          ├─< audit_events (hash-chained, exported to WORM)
          ├─< feedback_records (case-mgmt outcomes → tuning labels)
          └─< config_overrides (per-tenant weights/thresholds, versioned, expiring)
```

Key tables (abridged):

```sql
alerts (
  id uuid pk, tenant_id uuid not null, is_canonical bool not null default true,
  canonical_id uuid null references alerts(id),
  source text, rule_id text, rule_family text, tactic text,
  event_uid uuid, occurred_at timestamptz, observed_at timestamptz,
  entities jsonb not null,          -- normalized entity set
  dedup_key_v1 text null,           -- exact key (stage 1)
  occurrence_count int default 1, first_seen timestamptz, last_seen timestamptz,
  raw_original jsonb null,          -- 90-day TTL, minimized
  degraded_context bool default false
)
alert_scores (
  alert_id uuid, score_version text, inputs_hash text,
  score int check (score between 0 and 100), band text,
  factor_breakdown jsonb not null,  -- includes ml_adjustment separately
  computed_at timestamptz, primary key (alert_id, score_version, computed_at)
)
alert_links (
  id uuid pk, tenant_id uuid, canonical_id uuid, duplicate_id uuid,
  dedup_method text check (dedup_method in ('exact','fuzzy')),
  similarity real null, threshold_used real null, rule_family text,
  created_at timestamptz, unlinked_at timestamptz null, unlinked_by uuid null
)
audit_events (
  seq bigserial, tenant_id uuid, actor_type text, actor_id text,
  action text, object_type text, object_id text, before jsonb, after jsonb,
  reason text, prev_hash bytea, entry_hash bytea, created_at timestamptz
)
```

- All tenant-owned tables carry `tenant_id` with **RLS policies** (`app.tenant_id` GUC, set per transaction; no superuser bypass in app role; migrations run under a separate controlled role).
- Immutability: `alert_scores`, `audit_events`, `alert_dispositions` are insert-only; `REVOKE UPDATE/DELETE` from app roles; enforced additionally by triggers.
- JSONB indexes: GIN on `entities`, HNSW on `dedup_signatures.embedding vector(256)` with tenant filter column included.

## 2. Identity & access model

### 2.1 Roles (RBAC)

| Role | Queue | Alert detail | Disposition | Assign | Split-duplicate | Escalate/SOAR | Tune rules | Admin |
|---|---|---|---|---|---|---|---|---|
| analyst.tier1 | read | read | ✓ (low/med) | ✓ | – | – | – | – |
| analyst.tier2 | read | read | ✓ (all bands) | ✓ | ✓ | ✓ | – | – |
| soc.lead | read | read | ✓ | ✓ | ✓ | ✓ | ✓ (bands) | – |
| detection.eng | read | read | – | – | – | – | ✓ (full) | – |
| auditor | read (read-only, all-queue visibility) | read | – | – | – | – | – | – |
| platform.admin | – | – | – | – | – | – | – | ✓ |
| svc.soar | – | read (scoped) | ✓ (machine-attributed) | – | – | ✓ | – | – |

### 2.2 Attributes (ABAC overlay)

- `tenant_id` (mandatory, from token — never from request), `band` (tier1 cannot close `critical`), `incident_linked` (escalation-only until case attached), `data_sensitivity` (PII-flagged alerts need `pii_reader` claim), `region` (data-residency routing).
- Pseudonymous analyst mode: a "break-glass" `de-anonymize` action exists for HR/legal cases, dual-authorized, time-boxed (15 min), fully audited.

### 2.3 Enforcement points (defense in depth)

1. **Gateway**: OIDC token validation, audience, scopes; mTLS for service callers.
2. **API/BFF**: coarse RBAC; tenant from token claims; ABAC predicates for band/PII; Idempotency-Key handling.
3. **Data layer**: RLS as the final boundary — even a bug in API code cannot cross tenants (tested in CI with a dedicated "isolation" suite).
4. **Frontend**: UI hides actions, but is never the enforcement point.

### 2.4 Machine identities

- Every service has a SPIFFE identity; short-lived (≤ 1 h) audience-bound tokens; no shared service accounts; SOAR caller uses a dedicated `svc.soar` identity with per-action scopes and HMAC-signed webhooks for inbound feedback (timestamp + nonce replay protection).

## 3. Multi-tenancy model

- **Pool model** with hard RLS boundary (chosen over silo for cost; see ADR-003): shared compute, isolated data rows, tenant-sharded Kafka partitions, tenant-prefixed Redis keys, per-tenant ANN filter columns.
- Noisy-neighbor controls: per-tenant token-bucket rate limits on ingest and API; per-tenant ANN candidate caps; queue views materialized per tenant.
- Cross-tenant analytics (product improvement) uses only k-anonymized aggregates (k ≥ 25) or synthetic data; contractually disclosed.
- Data residency: tenant attribute `region` pins storage + processing to allowed regions; scheduler and storage routes respect it (documented per-tenant in DPA).

## 4. Privacy engineering

| Aspect | Control |
|---|---|
| Minimization | `raw_original` 90-day TTL; payload fields not needed for triage are dropped at normalizer (schema allowlist, not denylist) |
| PII handling | `data_sensitivity=pii` alerts visible only with `pii_reader`; hash-based TI lookups (no raw IOC export); pseudonymous analyst view by default |
| Purpose limitation | Feedback data used for model tuning only with tenant opt-in (contractual); opt-out tenants excluded from training sets |
| Subject rights | Tenant-admin self-service export & deletion API (deletion = crypto-shredding via per-tenant DEK destruction, 30-day SLA) |
| Cross-border | Region pinning (§3); TI lookups via regional caches |
| DPA/records | ROPA maintained; DPIA for scoring/dedup (automated decision-making documentation) |

## 5. Retention & disposition summary

| Data | Retention | Basis |
|---|---|---|
| Alerts (canonical+dups) | 180 d hot / 2 y cold | investigation needs |
| Score records | = alert lifetime (immutable) | auditability invariant |
| Audit events | 400 d WORM + export | compliance (SP 800-53 AU-11, ISO 93xxx logging controls) |
| Feedback/labels | 2 y | model governance |
| Config override history | 2 y | change governance |

## 6. Change management for schema

- Migrations: expand → migrate → contract pattern; RLS policies versioned in migrations; every migration reviewed for tenant-scoping (checklist item in PR template).
- Backfills are explicit, rate-limited, audited operations with approval — never side effects of deploys.
