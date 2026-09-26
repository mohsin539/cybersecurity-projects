# SEAS — State Management Design (state.md)

> **Reservation → Implemented.** This is the authoritative state design for the
> Social Engineering Awareness Simulator (SEAS), an internal phishing/social-engineering
> test platform for Bangladeshi banks. It documents every stateful concern, how each is
> represented, how each transitions, and how each is persisted in the shipped build.
> Every reference below points at the exact module/line that implements the rule.

## 1. State Layers

| Layer                    | Technology                                             | Where                                             |
| ------------------------ | ------------------------------------------------------ | ------------------------------------------------- |
| Persistent state         | SQLAlchemy 2.0 ORM; SQLite default → Postgres via `DATABASE_URL` | `backend/app/db.py`, `backend/app/models.py` |
| Session / auth state     | Stateless signed JWT (HS256)                           | `backend/app/security.py`, `backend/app/deps.py`  |
| Login rate-limit state   | In-memory sliding window (per IP)                      | `backend/app/routers/auth.py`                     |
| Transient simulation     | Detached background thread + DB-backed `Delivery` rows | `backend/app/services/delivery.py`                |
| Client UI state          | React local state + `localStorage` (`seas_token`, `seas_user`) | `frontend/src/App.tsx`, `frontend/src/api.ts` |
| Evidence state           | Append-only SHA-256 hash chain                         | `backend/app/services/audit.py`                   |
| Export/delivery capability tokens | Unforgeable random `secrets.token_urlsafe(32)`   | `backend/app/security.py:new_token`               |

## 2. Persistent Entities (`backend/app/models.py`)

| Table                | Entity               | Purpose                                              |
| -------------------- | -------------------- | ---------------------------------------------------- |
| `users`              | `User`               | Console operators; role in `{admin, security, hr, analyst, auditor}` |
| `employees`          | `Employee`           | Target directory; `opt_out` = Do-Not-Phish registry  |
| `email_templates`    | `EmailTemplate`      | Lure e-mail clones (EN/BN)                           |
| `landing_pages`      | `LandingPage`        | Simulated secure-login / lure pages                  |
| `campaigns`          | `Campaign`           | Multi-vector campaign + lifecycle status             |
| `campaign_variants`  | `CampaignVariant`    | A/B variants bound to template + landing page + weight |
| `deliveries`         | `Delivery`           | Per-employee lure; status + per-stage timestamps + capability token |
| `events`             | `Event`              | Open/click/submit/report facts (ISO timestamps)      |
| `submissions`        | `Submission`         | Masked username + salted credential **hash only**    |
| `risk_scores`        | `RiskScore`          | Rolling SE-Index snapshots per employee              |
| `trainings`          | `Training`           | Awareness modules, completion + score                |
| `consent_records`    | `ConsentRecord`      | Consent ledger (one per employee on creation)        |
| `audit_logs`         | `AuditLog`           | Immutable hash-chained evidence                       |
| `report_bundles`     | `ReportBundle`       | Generated XLSX/CSV/HTML exports + download token      |

Schema is created by `Base.metadata.create_all(engine)` in the FastAPI lifespan
(`backend/app/seed.py:init_db`), then `seed(db)` populates demo data exactly once and
repair-fixes seeded `Event.delivery_id` references. The DB file (`backend/seas.db`) is
single-file and safe to snapshot with standard backup agents; Postgres deployments use
WAL archival and the same ORM models.

## 3. Campaign Lifecycle State Machine

```
 draft ──► review ──► approved ──► scheduled ──► running ──► completed
   │          │           │                          ▲
   │          │           └──── (reject) ────────────┘ reserved
   └──────────┴── (approve again → re-entered review/approved) 
```

Implemented transitions and their enforcing code:

| Transition       | Action                                                          | Enforced by                                                  |
| ---------------- | --------------------------------------------------------------- | ------------------------------------------------------------ |
| create → draft   | `POST /api/v1/campaigns`                                         | `backend/app/routers/campaigns.py:create_campaign` (status forced `"draft"`) |
| draft → review   | `POST /{id}/approve` (first approver)                            | `approve_campaign` — first signature                          |
| review → approved| `POST /{id}/approve` (second, distinct approver)                | `approve_campaign` — dual sign-off (admin + security)         |
| approved → scheduled/running | `POST /{id}/launch`                              | `launch_campaign` — accepts only `approved\|scheduled\|running`; idempotent |
| running → …      | Delivery ramp drains to `completed` (reserved; `cancel` transition reserved for UI v2) | `backend/app/services/delivery.py` |

Every transition writes an `AuditLog` row: `campaign.created`, `campaign.approved`,
`campaign.dual-approved`, `campaign.launched`. Approve is idempotence-guarded — a user who
already signed cannot sign again, and a `campaign` that is already `approved` is rejected
(`HTTP 400`). Launching from `draft`/`review` is rejected (`HTTP 400`).

## 4. Delivery Lifecycle (per-employee lure)

| Status (column) | Meaning                                  | Set by                                          |
| --------------- | ---------------------------------------- | ----------------------------------------------- |
| `pending`       | queued in the launch ramp                | `build_deliveries`                              |
| `sent`          | lure dispatched (simulated)              | `delivery._mark_sent` (background thread)       |
| `opened`        | open-pixel `/t/o/{token}.png` fired      | `backend/app/routers/tracking.py:track_open`    |
| `clicked`       | click URL `/t/c/{token}` 302-redirected  | `track_click`                                   |
| `submitted`     | credentials submitted on `/t/s/{token}`  | `track_submit` (303 → `/t/r/{token}`)           |
| `reported`      | employee alerted `/t/r/{token}`          | `track_report` (302 → `/t/e/{token}` training)  |

Each stage records the corresponding timestamp column (`sent_at`, `opened_at`,
`clicked_at`, `submitted_at`, `reported_at`) and appends an `Event` row. Stage
transitions are guarded so the first occurrence wins (later hits re-serve the same
response without re-mutating state) — e.g. a repeated pixel request does not double-log.

`ConsentRecord` + `opt_out` are evaluated when deliveries are built:
`build_deliveries` filters `Employee.opt_out == False` and optional branch/division
filters, so Do-Not-Phish staff never receive lures.

## 5. Auth & Operator Session State

- **Login rate limiter** (`backend/app/routers/auth.py`): in-memory sliding window, max
  8 failed attempts per IP in a rolling 60s window → `HTTP 429`. Evicted when the window
  lapses. Validation failures call `AuditService.log("login.failed", "user")`.
- **JWT session** (`backend/app/security.py`): stateless HS256 token, `sub` = user id,
  `role`, `username`, `exp` = now + `access_token_expire_minutes` (env, default 180).
  `backend/app/deps.py:get_current_user` decodes + re-hydrates; 401 on missing/invalid/
  expired/inactive. `backend/app/deps.py:require_roles` gates routes by role.
- No server-side session map; scaling out keeps JWT stateless (only rate-limiter and
  delivery ramp need a shared store → see `docs/memory.md` §4 Redis swap).

## 6. Frontend Client State

- Auth persistence: `seas_token` + `seas_user` in `localStorage` (`frontend/src/api.ts`);
  injected as `Authorization: Bearer` on every request; **401 clears the session and
  reloads** to the login screen.
- View routing: single `View` enum in `frontend/src/App.tsx`
  (`dashboard / campaigns / templates / targets / training / reports / audit`). Each view
  owns a local `useEffect` fetch cycle and renders fresh server data.
- No global store is used; state is deliberately fetch-on-view so every screen is
  consistent with the server (fresh SE-Index after each drill).

## 7. Report / Export State

- `ReportBundle` rows track `name`, `fmt`, `size`, `status`, `url_token`, `created_by`,
  `created_at`.
- Export pipeline: authorised request → live SQL rollups (`reports._collect_report_data`)
  → sync render via `services/exporters.build_export` (XLSX-charts / CSV-UTF-8-BOM / HTML)
  → `ReportBundle` row with `url_token = new_token()` (32-byte capability token) → download
  validated by DB token lookup on `GET /api/v1/reports/{url_token}/download`; a missing
  file or unknown token is `HTTP 404`. Tokens are unguessable capability values — clients
  cannot forge or enumerate downloads.

## 8. Concurrency & Transaction Rules

- One DB session per request via `get_db` dependency; mutations commit explicitly.
- Dashboard/stat reads compute `sent/opened/clicked/submitted/reported` via
  `services/scoring.campaign_stats` on snapshot selects — live screens never block the
  simulator thread.
- The delivery ramp is a detached daemon thread (`delivery_launch_campaign`) that writes
  through its own short-lived `SessionLocal`, decoupled from request lifecycle.
- Idempotent approvals: status guard + per-approver de-dup prevents double-signing or
  relaunching (`campaigns.approve_campaign`, `launch_campaign`).
- `AuditService` uses its DB session transaction; callers commit after logging — the chain
  hash is computed at insert time from the latest row (`services/audit._last_hash`).

## 9. Backup / DR / Retention

- SQLite single-file DB (`backend/seas.db`): snapshot-safe with bank backup agents.
  Postgres deployments use continuous WAL archival; engines are swappable via
  `DATABASE_URL` (`backend/app/db.py`).
- Reports include a captured `generated_at` and derive from `Event`/`Delivery` rows; the
  audit chain (non-deletable by design) lets exports be re-verified against evidence
  after restoration (regulatory retention window, ISO 27001 evidence).
- Retention policy: lure artifacts/templates archived post-campaign; audit chain retained
  for the full regulatory window.

## 10. End-to-End State Walkthrough (what the smoke test proves)

1. `login.success` → JWT issued; operator session starts (stateless).
2. `campaign.created` → draft row in `campaigns`; audit entry chained.
3. `campaign.dual-approved` → campaign `approved`; launch gate opens.
4. `campaign.launched` → `build_deliveries` creates `Delivery(pending)` rows for eligible
   staff; thread sets `sent`.
5. Pixel/click/submit/report mutate the single `Delivery` row + timestamp columns and
   append `Event` rows; submit persists *only* masked username + credential hash.
6. `record_risk_snapshot` computes SE-Index (`RiskScore`) after a submit.
7. `report.generated` → `ReportBundle` + file on disk; `report.downloaded` on download.
8. Every mutating action above is chained into `audit_logs` for tamper-evident recovery.