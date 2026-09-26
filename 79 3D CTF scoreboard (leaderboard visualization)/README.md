# 🏆 3D CTF Scoreboard (leaderboard visualization)

Event-sourced **CTF scoreboard**: a FastAPI service that recomputes every score from an
append-only, hash-chained event log, rendered as a **3D bar race** with a dependency-free
WebGL2 front end and a fully accessible table fallback.

> Part of the [AI Masterclass cybersecurity portfolio](../../#readme) — project 79 of 72.
> Scoring is fully deterministic and auditable — designed for fair play.

**📖 Full documentation lives in [`ctf-scoreboard/README.md`](ctf-scoreboard/README.md).**

## 🚀 Quickstart

```bash
cd ctf-scoreboard
pip install -r requirements.txt
python run.py            # → http://127.0.0.1:8000
```

First start creates and seeds the database (24 teams, 12 challenges, simulated solve
history and a live simulator). Tests: `pytest -q`.

## ✨ Highlights

- **`state = f(event log)`** — the board is never trusted as state; scores are recomputed,
  never incremented (`T-DER-05` derivation stored with every solve)
- **Hash-chained, append-only** event + audit logs enforced by SQLite triggers
- **Self-verifying** — a projection is compared against a fresh recomputation; on mismatch
  the board refuses to serve it (`INV-17`)
- **No CDN, no npm, no build step** — FastAPI + stdlib backend, vanilla WebGL2 front end
- The production deployment path (PostgreSQL/TimescaleDB, Redis, S3 Object Lock with
  multi-region operation) is described in the nested README's design notes

## 🗂️ Project Layout

| Path | What it is |
|---|---|
| `ctf-scoreboard/app/` | FastAPI service: API, scoring, event log, invariants, realtime |
| `ctf-scoreboard/web/` | WebGL2 3D bar-race UI + accessible table fallback |
| `ctf-scoreboard/tests/` | pytest suites: API, determinism, event log, realtime, service |
| `ctf-scoreboard/tools/` | End-to-end smoke test |

## 🧪 CI

A GitHub Actions job installs `requirements.txt` and runs `pytest -q` on every push — see
[`.github/workflows/ci.yml`](../../blob/master/.github/workflows/ci.yml).
