# 3D CTF Scoreboard

An offline-capable, event-sourced CTF scoreboard: a FastAPI service that recomputes every
score from an append-only event log, and a dependency-free WebGL2 front end that renders it
as a 3D bar race with a fully accessible table fallback.

No CDN, no npm, no build step. `python run.py` and open the page.

---

## Why it is built this way

The board is never trusted as state. It is a **pure function** of the event log:

```
state = f(event log, scoring model, as_of)
```

Consequences that the rest of the design follows from:

- Every mutation appends to `event_log`, which is hash-chained. A row cannot be updated or
  deleted; the database enforces this with triggers, not with convention.
- Every write also lands in `audit_log`, a second hash chain, in the same transaction as the
  event and the idempotency record.
- Scores are recomputed, never incremented. "Why is this team on 400?" is answerable from
  the derivation stored with each solve (`T-DER-05`).
- A projection is compared against a fresh recomputation. If they disagree, the board
  refuses to serve it (`INV-17`).

The production target in [`architecture.md`](architecture.md) is PostgreSQL/TimescaleDB,
Redis and S3 Object Lock with multi-region operation. This repository implements the same
contract on SQLite so it runs on one machine with no services to install.

---

## Running it

```bash
cd ctf-scoreboard
python -m venv .venv
.venv\Scripts\activate          # Windows
pip install -r requirements.txt
python run.py
```

Then open <http://127.0.0.1:8000>. On first start the database is created, seeded with 24
teams, 12 challenges, six hours of plausible solve history, and a live simulator that keeps
the board moving. Delete `data/scoreboard.db*` to start over.

Run the tests and the end-to-end smoke test:

```bash
python -m pytest -q            # 101 unit/integration tests
python tools/smoke_test.py     # boots uvicorn and exercises the real HTTP surface
```

### Configuration

All settings are environment variables prefixed `SCOREBOARD_`:

| Variable | Default | Meaning |
| --- | --- | --- |
| `SCOREBOARD_DB` | `data/scoreboard.db` | SQLite file path |
| `SCOREBOARD_SECRET` | random per process | Signs sessions and seals. **Required in production** — the service refuses to start without it (SEC-IAM-01) |
| `SCOREBOARD_WEBHOOK_SECRET` | dev fallback | Default HMAC secret for ingest. **Required in production** (SEC-EXT-01) |
| `SCOREBOARD_ENV` | `development` | `production` enforces secure cookies and refuses dev secrets |
| `SCOREBOARD_HOST` / `SCOREBOARD_PORT` | `127.0.0.1` / `8000` | Bind address |
| `SCOREBOARD_SESSION_TTL` | `28800` | Session lifetime in seconds |
| `SCOREBOARD_COOKIE_SECURE` | `false` | Force the `Secure` cookie flag outside production |
| `SCOREBOARD_WEBHOOK_WINDOW` | `300` | Replay window in seconds for `x-timestamp` |
| `SCOREBOARD_SCORING_MODEL` | `scoring-v1.2.0` | Model version recorded with every solve |
| `SCOREBOARD_DECAY_PER_HOUR` | `0.02` | Score decay rate |
| `SCOREBOARD_DECAY_FLOOR` | `0.4` | Lower bound on the decay factor |
| `SCOREBOARD_FIRST_BLOOD` | `50` | Awarded to the first solver of a challenge |
| `SCOREBOARD_TOP10_BONUS` | `25` | Flat bonus for the top ten |
| `SCOREBOARD_PURIFIER_WINDOW` | `1800` | Seconds after a solve during which decay is frozen |
| `SCOREBOARD_SEAL_BATCH` / `SCOREBOARD_SEAL_INTERVAL` | `250` / `300` | Merkle sealing by batch size or age |
| `SCOREBOARD_SSE_HEARTBEAT` / `SCOREBOARD_SSE_REPLAY` | `15` / `500` | SSE keepalive interval and replay buffer size |
| `SCOREBOARD_RWW_TOLERANCE` | `3` | Read-your-writes budget for the acting admin |
| `SCOREBOARD_SEED` | `true` | Seed the demo board when the database is empty |
| `SCOREBOARD_SEED_TEAMS` / `SCOREBOARD_SEED_CHALLENGES` | `24` / `12` | Demo board size |
| `SCOREBOARD_SIMULATE` | `true` | Enable the live solve simulator |
| `SCOREBOARD_SEED_RATE` | `0.9` | Simulated solves per second |

### Demo accounts

Password for all four: `scoreboard-demo`.

| Handle | Role | Can |
| --- | --- | --- |
| `spectator` | spectator | View the board only |
| `referee-1`, `referee-2` | referee | Record solves, propose adjustments, seal the log |
| `admin` | admin | Everything, including the event phase |

---

## Scoring

```
award    = base_points + (50 if first blood)
score    = Σ award × decay(solved_at) + Σ applied_adjustments + (25 if in the top ten)
decay    = max(0.40, exp(-0.02 × hours_since_solve))
```

Decay is measured from the team's own most recent solve, so an active team is not penalised
for old solves. Ranks break ties by decayed score, then raw score, then the **earlier** last
solve, then team name — a stable, total order, so two clients always agree.

The top-ten bonus is applied *after* ordering, so it cannot change who is in the top ten.
Each solve stores the base points it was scored against, so re-pricing a challenge later
cannot rewrite history.

`?as_of=<ISO timestamp>` replays the board at any past instant. Because the live board
decays continuously, two reads seconds apart legitimately differ; pin `as_of` when you need
to compare two snapshots.

---

## HTTP surface

**Public**

| Route | Purpose |
| --- | --- |
| `GET /api/leaderboard` | Board snapshot, `?as_of=` for a historical replay |
| `GET /api/leaderboard.csv` | CSV export |
| `GET /api/report.json` | Snapshot plus manifest with chain state |
| `GET /api/teams/{slug}` | Team detail with every solve and derivation |
| `GET /api/invariants` | Every invariant as a pass/warn/fail verdict |
| `GET /api/integrity` | Hash chain and seal verification |
| `GET /api/audit` | Security audit trail (filtered) |
| `GET /api/stream` | SSE: `snapshot`, `board`, `solve`, `notice`, `resync` |
| `GET /api/config` | Frontend configuration |
| `GET /api/health` | Liveness, chain status, stream status |

**Staff** — session cookie required; `POST /api/auth/login`, `/api/auth/logout`,
`/api/auth/step-up`, `GET /api/auth/me`.

`POST /api/admin/solves`, `POST /api/admin/adjustments`,
`POST /api/admin/adjustments/{id}/decision`, `POST /api/admin/phase`,
`POST /api/admin/challenges/{slug}/active`, `POST /api/admin/seal`,
`GET /api/admin/audit/export.csv` (requires step-up).

**Webhook** — `POST /api/webhooks/ctf`, signed ingest. See below.

Errors share one shape: `{"error": "<code>", "detail": "<human sentence>", ...}`. Validation
errors from pydantic use FastAPI's `{"detail": [...]}`.

---

## Signed ingest

```python
body = json.dumps({"type": "solve.recorded", "id": "evt-1",
                   "team": "null-pointer", "challenge": "baby-rsa"}).encode()

signature = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
POST /api/webhooks/ctf
  x-client-id: platform-demo
  x-timestamp: 1780000000
  x-signature: <signature>
```

- The signature covers the **raw bytes**, verified before the body is parsed.
- `x-timestamp` outside the replay window is rejected and audited as
  `webhook.replay.detected`.
- `id` is an idempotency key: redelivering it returns the original response with
  `"idempotent_replay": true` and changes nothing.
- A payload that is malformed, unknown, or unprocessable is **quarantined** into
  `dead_letters` with an owner rather than retried forever.
- The webhook can never set a score. Points are always recomputed server-side.

---

## Security controls

- **Passwords**: PBKDF2-HMAC-SHA256, 240,000 rounds, per-user salt, constant-time compare.
- **Sessions**: random token in an `HttpOnly`, `SameSite=Strict` cookie. `__Host-` prefixed
  and `Secure` in production. Only the token hash is stored, and a new login replaces the
  old session.
- **Step-up**: destructive and export operations re-verify the password within 10 minutes.
- **Two-person rule**: a score adjustment is proposed by one staff member and applied only
  when a *different* one approves. The database refuses to close an adjustment without an
  approver, and a proposer may not decide their own proposal in either direction.
- **RBAC**: spectator → participant → referee → admin, checked server-side on every route.
- **Audit**: every transition, denial included, in a separate hash chain. A denial is
  committed in its own transaction — rolling it back with the failed request would leave
  brute-force attempts invisible.
- **Invariants**: `GET /api/invariants` returns a verdict per check, including deliberate
  `"delegated"` entries for controls that live in the client.

---

## Front end

- `web/js/gl.js` — mat4 math, shader helpers, instanced cube geometry, fullscreen triangle.
- `web/js/scene.js` — instanced bars, procedural floor, particles, pulse rings, orbit
  camera, canvas labels.
- `web/js/app.js` — API loading, SSE reconciliation, stale/resync handling, the referee
  console, integrity view, view switching.

The server is authoritative: the client never computes a score or a rank. It renders what it
is given, discards any frame whose `seq` it has already seen, and marks the board **stale**
rather than current if the stream drops. If WebGL2 is unavailable, the page falls back to
the semantic `<table>`, which is always present and always correct.

---

## Layout

```
ctf-scoreboard/
  app/
    config.py       settings from the environment
    database.py     schema, transactions, append-only triggers
    eventlog.py     event + audit hash chains, Merkle sealing
    scoring.py      pure projection and rank order
    invariants.py   INV-01..INV-18 as executable assertions
    service.py      mutation orchestration
    security.py     passwords, sessions, RBAC, step-up, HMAC
    realtime.py     SSE hub with replay buffer
    seed.py         deterministic demo data
    simulator.py    live solve generator
    main.py         app factory and lifespan
    api/            public, admin and ingest routers
  web/              index.html, css, js (no build step)
  tests/            pytest suite
  tools/smoke_test.py
```

`INV-12`, `INV-13`, `INV-05` and `INV-16` are reported as `delegated`: they are properties of
the client, and `GET /api/invariants` says so explicitly instead of claiming a pass it
cannot verify.
