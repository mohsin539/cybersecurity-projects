# Bandwidth Monitor & Traffic Visualizer Dashboard

A production-oriented, cross-platform (Windows / Linux / macOS) dashboard for
real-time network traffic monitoring and rich visualization. It samples network
interface counters every second, derives live upload/download throughput, keeps
a rolling history, enriches the view with per-process connection data and
streams everything to a browser dashboard over WebSockets.

Built with **Clean Architecture**: the domain core has zero framework
dependencies; adapters (psutil capture, in-memory store, FastAPI delivery) plug
in behind stable ports.

---

## Quick start

Requires **Python 3.10+**.

### Windows (easiest)

```
run.bat
```

`run.bat` picks a usable interpreter automatically (`.venv` → `py -3` →
`python`), so it works even when the Microsoft Store `python.exe` stub is
first on PATH (the usual cause of *“Python was not found”* when running
`python main.py`).

### Manual (any OS)

```bash
# 1. create a virtual environment
python -m venv .venv          # or: py -3 -m venv .venv  (Windows)

# Windows
.venv\Scripts\activate
# Linux / macOS
source .venv/bin/activate

# 2. install
pip install -r requirements.txt

# 3. run
python main.py

# 4. open the dashboard
#    http://127.0.0.1:8000
```

Interactive API docs at `http://127.0.0.1:8000/docs` (OpenAPI).

> **“Python was not found” on Windows?** Your `python` is the Microsoft
> Store alias stub. Use `run.bat`, or call `py -3 main.py` (the official
> launcher is installed with python.org builds), or disable the stub under
> *Settings → Apps → Advanced app settings → App execution aliases*.

### Command line

```
run.bat --host 0.0.0.0 --port 9000 --interval 0.5 --no-connections
# or, with an activated venv:
python main.py --host 0.0.0.0 --port 9000 --interval 0.5 --no-connections
```

Add `--open-browser` (or set `BWMON_OPEN_BROWSER=true`) to have the effective
URL opened in your default browser automatically — handy when `BWMON_PORT`
points somewhere other than 8000 or the port falls back because it was busy.

All options are optional; every value can also be supplied through `BWMON_*`
environment variables (see [Configuration](#configuration)).

### Docker

```bash
docker compose up --build
```

`network_mode: host` is used deliberately so psutil observes the real host
network interfaces rather than the container bridge.

### Dev / tests

```bash
pip install -r requirements-dev.txt
pytest -q                    # unit + API tests (e2e deselected by default)

# End-to-end browser tests (real Chromium against the real server):
playwright install chromium  # one-time browser download
pytest -m e2e
```

---

## Feature highlights

- Live KPI cards via WebSocket push – current download/upload rates and
  cumulative totals (with mini sparklines).
- **Live throughput gauges** – semi-circular dials for download/upload with
  automatic scaling, session-peak readout and a **red alert zone + threshold
  tick** at the configured `BWMON_ALERT_*_BPS` limits; the value segment turns
  red when traffic crosses the threshold.
- Main traffic time-series chart with selectable **interface** and **time
  window** (1 min / 5 min / 15 min / 1 hour), seeded from a real history query.
- **Bandwidth by process** – per-process traffic attribution (top talkers)
  derived from psutil I/O counters with smoothed rates (approximate: the OS
  mixes disk + network I/O; disable with `--no-processes`).
- Per-interface throughput breakdown (stacked horizontal bar).
- Protocol mix doughnut (TCP / UDP) and top-processes by connection count.
- Live connections table (process, protocol, state, local/remote endpoint).
- Threshold alerting with cooldown (log + real-time dashboard feed).
- **Durable history** – SQLite-backed snapshot store so charts survive
  restarts (switch back to in-memory with `BWMON_STORE_BACKEND=memory`).
- Dark, responsive UI that degrades gracefully without WebSockets (falls back
  to polling) and works fully offline (Chart.js is vendored locally).

## Architecture

```
┌────────────────────────  PRESENTATION  ────────────────────────┐
│  browser dashboard           presentation/static/              │
│  (HTML + CSS + Chart.js + plain JS)                            │
└──────────────▲──────────────────────▲──────────────────────────┘
        WebSocket /ws           REST /api/*
┌──────────────┴──────────────────────┴──────────────────────────┐
│                    INFRASTRUCTURE   infrastructure/             │
│   FastAPI app factory (web/server.py)                          │
│   REST controllers (web/controllers.py)                        │
│   WebSocket registry (web/manager.py)                          │
│              ▲                              ▶ storage/          │
│   ports: SystemNetworkSource, SnapshotStore  (ring buffer)     │
│              ▲                                                │
│   capture/psutil_source.py — OS telemetry                     │
└──────────────┼─────────────────────────────────────────────────┘
┌──────────────┴─────────────────────────────────────────────────┐
│                    APPLICATION   application/                  │
│   TelemetryService — sampling loop, rate derivation            │
│   AlertService     — threshold rules + cooldown                │
│   dto.py           — JSON-safe serializers                     │
└──────────────┼─────────────────────────────────────────────────┘
┌──────────────┴─────────────────────────────────────────────────┐
│                      DOMAIN   domain/                          │
│   entities.py   — Snapshot, RateSample, Alert, ... (dataclasses)│
│   interfaces.py — ports consumed by the outer layers           │
└────────────────────────────────────────────────────────────────┘
```

### Dependency rule

- `domain` has no imports from `application`, `infrastructure` or frameworks.
- `application` depends only on `domain` abstractions.
- `infrastructure` implements `domain` ports; composition happens in
  `main.py` (the composition root).
- `presentation` is pure static assets served by `infrastructure`.

---

## Data flow (real time)

1. `TelemetryService` (background thread) reads cumulative counters from
   psutil every `refresh_interval` seconds.
2. Consecutive reads produce per-interface and aggregate byte/second rates
   (counter resets/sleeps are guarded).
3. Each `Snapshot` is stored in a bounded ring buffer
   (`SnapshotsStore.push`) and broadcast via
   `ConnectionManager.publish` → WebSocket clients.
4. Alert rules are evaluated on the same tick; newly fired alerts ride along
   the next WebSocket payload and appear instantly in the feed.
5. The browser keeps a client ring of the live stream and can seed a chart
   from `GET /api/history` when the interface or window changes.

## REST API

| Method | Path                | Description                                        |
| ------ | ------------------- | -------------------------------------------------- |
| GET    | `/`                 | Dashboard page                                     |
| GET    | `/api/health`       | Service health, uptime, sample count               |
| GET    | `/api/interfaces`   | Detected interfaces and metadata                   |
| GET    | `/api/current`      | Latest snapshot + recent alerts                    |
| GET    | `/api/history`      | `?interface=total&range_seconds=300` history series|
| GET    | `/api/connections`  | Connection summary, protocol/proc aggregation      |
| GET    | `/api/processes`    | Top talkers by bandwidth (`?limit=10`)             |
| GET    | `/api/alerts`       | Recent alerts                                      |
| GET    | `/api/config`       | Effective runtime configuration                    |
| WS     | `/ws`               | Live telemetry push (`{"type":"telemetry",…}`)     |

All numeric rates are expressed in **bytes/second** in the API; the frontend
renders them as bits/second.

## Configuration

| Env var                       | Default           | Meaning                                   |
| ----------------------------- | ----------------- | ----------------------------------------- |
| `BWMON_HOST`                  | `127.0.0.1`       | Bind address                              |
| `BWMON_PORT`                  | `8000`            | Bind port                                 |
| `BWMON_REFRESH_INTERVAL`      | `1`               | Sampling cadence (seconds, min 0.1s)      |
| `BWMON_HISTORY_CAPACITY`      | `3600`            | Retained snapshots (ring buffer)          |
| `BWMON_STORE_BACKEND`         | `sqlite`          | `sqlite` or `memory` history backend      |
| `BWMON_STORE_PATH`            | `bwmon_history.db`| SQLite database file location             |
| `BWMON_PROCESSES_ENABLED`     | `true`            | Per-process bandwidth attribution         |
| `BWMON_PROCESS_SCAN_SPACING`  | `3`               | Seconds between process scans (CPU bound) |
| `BWMON_CONNECTIONS_ENABLED`   | `true`            | Enrich dashboard with connection data     |
| `BWMON_CONNECTIONS_LIMIT`     | `200`             | Max top-processes returned                |
| `BWMON_INCLUDE`               | *(empty)*         | Comma-separated interface allowlist       |
| `BWMON_EXCLUDE`               | `lo`              | Comma-separated interface denylist        |
| `BWMON_ALERT_DOWNLOAD_BPS`    | `104857600`       | Download alert threshold (bit/s)          |
| `BWMON_ALERT_UPLOAD_BPS`      | `104857600`       | Upload alert threshold (bit/s)            |
| `BWMON_ALERT_COOLDOWN_SECONDS`| `60`              | Seconds between re-alerts for same event  |
| `BWMON_LOG_LEVEL`             | `INFO`            | Logging verbosity                         |
| `BWMON_STRICT_PORT`           | `false`           | `true`: fail on busy port instead of fallback |
| `BWMON_OPEN_BROWSER`          | `false`           | `true`: open the dashboard URL in your browser at startup |

### Port behavior & .env

At startup the effective dashboard URL is printed (and `API docs: …/docs`
alongside it). When the port is anything other than the default 8000 — via
`BWMON_PORT`, `--port`, or the automatic busy-port fallback — a yellow note
reminds you of the actual URL so the dashboard is never hunted for at the
wrong address. With `--host 0.0.0.0` / `::` the printed URL shows the local
loopback equivalent, since wildcard bind addresses are not browsable.

By default a busy port is **not fatal**: the server logs a warning (with the
PID of the process holding the port) and starts on the next free port. Set
`BWMON_STRICT_PORT=true` or pass `--strict-port` to make a busy port an
error (exit code 1).

Local overrides can live in a **`.env`** file at the project root (git-ignored,
excluded from Docker builds). The file is validated at startup: malformed
values (e.g. `BWMON_PORT=8o01`), typo'd `BWMON_*` keys, and structurally
broken lines are logged as warnings — they would otherwise be silently
skipped or fall back to defaults. Precedence is always:

```
real environment variables  >  .env file  >  built-in defaults
```

Example `.env`:

```ini
BWMON_PORT=8001
#BWMON_STORE_BACKEND=memory
#BWMON_PROCESSES_ENABLED=false
```

## Project layout

```
.
├── main.py                     # composition root + CLI entry point
├── config/                     # env-driven Settings
├── domain/                     # entities + ports (frameworks-free)
│   ├── entities.py
│   ├── process_traffic.py      # per-process attribution port
│   └── interfaces.py
├── application/                # use cases: telemetry, alerts, DTOs
│   ├── monitoring.py
│   ├── alerts.py
│   ├── process_stats.py        # attribution smoothing + ranking
│   └── dto.py
├── infrastructure/             # adapters
│   ├── capture/psutil_source.py
│   ├── capture/psutil_process_traffic.py
│   ├── storage/ring_buffer.py
│   ├── storage/sqlite_store.py # durable history (survives restarts)
│   └── web/  (server.py, controllers.py, manager.py)
├── presentation/static/        # dashboard (html/css/js, Chart.js vendored)
├── tests/                      # pytest suite + Playwright e2e
├── requirements.txt            # runtime deps
├── requirements-dev.txt        # dev deps (pytest, httpx, playwright)
├── Dockerfile
└── docker-compose.yml
```

## Notes & limitations

- Connection enumeration may require elevated privileges on some systems; the
  capturer degrades gracefully (feature disabled, warning logged).
- **Per-process bandwidth is approximate**: operating systems do not expose
  network-only counters per process, so psutil's mixed disk+network I/O
  counters are used and scans are throttled (`BWMON_PROCESS_SCAN_SPACING`) to
  bound CPU cost. Disable with `BWMON_PROCESSES_ENABLED=false` or
  `--no-processes`.
- The dashboard only monitors the machine it runs on; use host networking in
  containers so host interfaces stay visible.
- History defaults to SQLite (`bwmon_history.db`); the in-memory ring buffer is
  still available via `BWMON_STORE_BACKEND=memory`, and any other backend can
  be added by implementing the `SnapshotStore` port in `domain.interfaces`.
  If the database cannot be opened the store degrades to memory automatically.