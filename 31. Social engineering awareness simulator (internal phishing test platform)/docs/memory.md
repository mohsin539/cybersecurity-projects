# SEAS — Memory & Evidence Design (memory.md)

> **Reservation → Implemented.** This is the authoritative memory design for the
> Social Engineering Awareness Simulator (SEAS). It answers two questions that make
> phishing platforms dangerous or safe:
> 1. **What stays in runtime memory?** — must be transient, discarded, never written.  
> 2. **What becomes evidence?** — must survive, immutable, hash-chained.
>
> The hard rule of this build: *data that must be transient is never persisted, and
> everything that must survive is hash-chained.* Raw phished credentials are the
> canonical example — parsed, hashed, discarded in a single request, never stored.

## 1. Runtime / In-Memory Store

| Item                        | Lifetime        | Implementation                                                         |
| --------------------------- | --------------- | --------------------------------------------------------------------- |
| Login rate-limit windows    | Rolling 60 s    | In-memory sliding window keyed by IP in `backend/app/routers/auth.py` (8 fails → HTTP 429); evicted when the window lapses |
| Submitter credential shadows| Single request  | Parsed in `track_submit`, `hash_value()` (SHA-256) or `"hashed-empty"`, then the raw value is dropped before `db.commit()` — never written, never exported |
| Delivery ramp state         | Duration of launch | `threading.Thread` (daemon) in `backend/app/services/delivery.py`; per-`Delivery` rows are also persisted (`sent`) as the durable proof — thread is only a dispatcher |
| JWT verification state      | Stateless       | No server-side session map; signature + `exp` checked per request via `deps.get_current_user` |
| Lure / export URL tokens    | Lifetime of row | Random 32-byte capability tokens (`secrets.token_urlsafe`) — no plaintext/PII index lookups on the public path |
| HTTPX/TestClient lifespan   | Process         | Started via context manager in `backend/tests/smoke.py` only |

Nothing security-critical lives in process-global memory beyond the rate limiter and the
delivery dispatcher — both replaced by Redis in the scaled topology (§4). The rate-limiter
is intentionally kept per-worker; it rejects *before* the expensive PBKDF2 check runs.

## 2. Evidence / Persistent Memory

### 2.1 Tamper-Evident Audit Chain (`AuditLog`)

Every mutation calls `AuditService.log(...)` which computes:

```
payload = json(actor, action, target_type, target_id, detail, ip)   # sort_keys
hash    = SHA256(prev_hash | payload)
```

(`backend/app/services/audit.py`, `backend/app/security.py:audit_hash`.) Rows are never
updated or deleted; verification walks the chain backwards and recomputes each entry — a
single tampered row breaks consecutive hashes. This is the *write-once memory* that
satisfies ISO 27001 Annex A evidence and bank-examiner traceability. The chain is
relational (SQLite/Postgres both support the hash-walk) and survives DB snapshot
restores.

### 2.2 Event Trace (`Event`)

Open / click / submit / report facts with ISO timestamps and their `Delivery`, plus a
`payload` of context (user-agent, IP, internal-network flag, masked username). This is the
source of truth for SE-Index, exports and remediation — not the submissions table.

### 2.3 Submission & Risk Memory (`Submission`, `RiskScore`)

- `Submission` stores **only** `masked_username` (first/last char + `*` fill) and
  `password_hash` = salted-SHA-256 of whatever the subject typed.
- Per-employee `RiskScore` keeps the rolling SE-Index (0–100) updated by
  `backend/app/services/scoring.py` after each submit snapshot.
- Credential content therefore exists only as a hash *in memory of the request that
  produced it* — and is gone by the next line.

## 3. Memory Policy Summary

| Question                          | Answer                                                           |
| --------------------------------- | --------------------------------------------------------------- |
| What is transient?                | Raw phished credentials, rate-limit windows, delivery ramp queues |
| What is immutable?                | Audit chain, event traces, consent records                       |
| What is derived?                  | SE-Index, campaign stats, report bundles                         |
| What is public?                   | Lure URLs (token-gated), open pixel, redirect                    |
| What is never stored even in memory? | Plaintext passwords staff submit to any fake page            |

## 4. Scaling to Redis / Postgres

| Current (single node)            | Scaled (bank production)                          |
| -------------------------------- | ------------------------------------------------- |
| In-memory IP rate limiter        | Redis `INCR + EXPIRE` sliding window (shared across replicas) |
| `threading.Thread` delivery ramp | Redis Streams queue + worker process reading `Delivery` rows by state |
| SQLite `seas.db`                 | PostgreSQL 16 (via `DATABASE_URL`), RLS, WAL replication |
| JWT / capability tokens          | Stay stateless in app memory (unchanged)           |
| Audit chain                      | Append-only table (unchanged) — hash-walk verification is scale-independent |

Exports move to async `Celery + Redis` + MinIO/S3 in the production topology
(`docs/architecture.md`); report bundles get signed short-lived URLs instead of a DB-token
lookup.

## 5. Verification Contract

`backend/tests/smoke.py` must terminate with **`SMOKE TEST PASSED`** and asserts:

1. **Health + seeded access** — `/health` 200; `admin` login returns a Bearer JWT and 3
   bad passwords are rejected (rate-limit path).
2. **Dashboard** — ≥ 12 seeded employees and ≥ 1 campaign with live `sent/clicked/avg_SE`.
3. **Dual approval** — admin sets `review`, security sets `approved` (idempotence guard).
4. **Launch + tracking walkthrough** — deliveries move `pending → sent`; `/t/o/{token}.png`
   returns `image/png`; `/t/c/{token}` redirects to the sandboxed landing page.
5. **Credential drop** — POST `/t/s/{token}` returns `303 → /t/r/{token}`; the produced
   `Submission` contains **no stored password**; the drop recalculates risk.
6. **Exports** — `.xlsx`, `.csv`, `.html` all generate and download with non-empty bodies.
7. **Audit chain** — every `audit_logs` row has a non-empty chained hash; the latest row
   reflects the most recent action.
8. **Training loop** — enroll + `auto-assign` respond 201/200 and produce records.

> Independent verification of step 5, item 6 and the hash walk is on-disk evidence:
> `backend/services/reports/*.xlsx|*.csv|*.html` artifacts must parse, and every
> `AuditLog.hash` must recompute from `prev_hash | payload`. See `docs/state.md` §10 for
> the end-to-end walkthrough the modern build documents.