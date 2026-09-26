# C2 Study Lab — Minimal C2 beacon + listener over HTTP (educational skeleton)

A **color-coded**, GUI-driven, **portable .exe** lab that demonstrates a minimal
command-&amp;-control (C2) architecture for *security education, red-team training
and detection testing*. The listener, beacon, encryption, audit trail and
reporting are deliberately small so every moving part is easy to read.

> **Authorized use only.** Run this inside your own lab against systems you own
> or have explicit written permission to test. It is a *skeleton*: pure-Python
> whitelisted tasks, no shell, no persistence, no propagation.

---

## Features

| Area | What you get |
|---|---|
| **Listener** | HTTP `ThreadingHTTPServer` (stdlib) — visible request/response mechanics |
| **Beacon** | Polling agent; Fernet-encrypted check-ins/results; allowlisted tasks only |
| **GUI** | Colorful Tkinter console: KPIs, beacon/task/audit tables, live logs, exporters |
| **Security** | Bearer-token auth (2 principals), rate limiting, input caps, AEAD crypto |
| **Audit** | Append-only JSONL audit trail + rotating session logs |
| **Reporting** | `.xlsx` / `.csv` / `.html` evidence reports |
| **Portable** | PyInstaller builds one-file windowed `.exe` |
| **Compliance** | Mapped to ISO 27001 / NIST CSF / OWASP Top 10 (see `COMPLIANCE.md`) |

## Architecture

![architecture](architecture.html)
Open `architecture.html` in a browser for the interactive colored diagram.

```
 +----------------+      HTTPS/TLS + Fernet      +---------------------+
 |  Beacon        | ---------------------------> |  HTTP Listener       |
 |  (agent)       |  POST /api/v1/checkin <----  |  (ThreadingHTTPServer)|
 |  poll loop     |  GET pending tasks           |  token auth          |
 |  task allowlist|  POST /api/v1/result  -----> |  rate limit          |
 +----------------+                              |  input validation    |
                                                +----------+----------+
                                                           |
                                                 +---------v---------+
                                                 |  Service Core      |
                                                 | registry + tasking |
                                                 | crypto (Fernet)    |
                                                 | audit (JSONL)      |
                                                 +---------+----------+
                                                           |
                                          +-----------------v------------------+
                                          | GUI Console   + Reporting Engine    |
                                          | colorful dash | .xlsx .csv .html    |
                                          +-------------------------------------+
```

**Layers (see `architecture.html`):**
- **L5 Presentation** — Tkinter GUI console
- **L4 Communication Hub** — `listener.py` HTTP server + endpoint routing
- **L3 Service Core** — `registry.py`, tasking, `crypto.py`, `authn.py`
- **L2 Agent** — `beacon.py` poll loop + allowlisted executors
- **L1 Evidence** — rotating logs, JSONL audit trail, report exports

**API Surface**

| Method | Endpoint | Principal | Purpose |
|---|---|---|---|
| GET | `/api/v1/health` | public | liveness + counters |
| POST | `/api/v1/checkin` | beacon | heartbeat + fetch tasks |
| POST | `/api/v1/result` | beacon | submit task result |
| POST | `/api/v1/task` | console | dispatch whitelisted task |
| GET | `/api/v1/beacons` | console | beacon inventory |
| GET | `/api/v1/events` | console | audit events |

All protected bodies are **Fernet-encrypted** (`{"payload": "<ciphertext>"}`).

## Quick start (source)

```bash
pip install -r requirements.txt
python src/main.py --demo        # headless self-test + sample reports in ./reports
python src/main.py               # colorful GUI console
python src/main.py --beacon      # standalone beacon client
```

From the GUI: press **START** (the lab auto-spawns a demo beacon), watch it
register, dispatch a task from the **Tasking** tab, then export a report from
the **EXPORT REPORT** bar.

## Build portable .exe

```bat
build.bat
```

Output in `dist/`:

| Artifact | Purpose |
|---|---|
| `C2StudyLab.exe` | GUI console (operator) — windowed, one-file |
| `C2StudyLab_Beacon.exe` | Beacon agent — run `C2StudyLab_Beacon.exe --server http://HOST:PORT --id lab-1` |

Customize lab identity via environment variables: `C2_BEACON_TOKEN`,
`C2_CONSOLE_TOKEN`, `C2_FERNET_KEY`, `C2_INTERVAL`.

## Reporting

| Format | File(s) | Contents |
|---|---|---|
| `.xlsx` | `C2StudyLab_report.xlsx` | Summary + Beacons + Tasks + Audit sheets, styled/auto-filtered |
| `.csv` | `beacons.csv`, `tasks.csv`, `events.csv` | plain delimited evidence rows |
| `.html` | `C2StudyLab_report.html` | self-contained colorful dashboard with badges |

Reports support audit &amp; evidence review — ISO 27001 A.12.7 / A.18,
NIST AU-6.

## Security &amp; compliance posture

- **OWASP A01** broken access control → every protected route token-gated, failures audited.
- **OWASP A02 / ISO A.10** cryptographic failures → Fernet AEAD on all payloads, no plaintext task/result transport, transport should additionally be TLS/HTTPS in deployment.
- **OWASP A05 / A07** misconfiguration &amp; auth failures → secure defaults, constant-time compare, per-IP rate limiting, distinct beacon vs console principals.
- **OWASP A09 / ISO A.12.4** logging &amp; monitoring → append-only JSONL audit trail, rotating logs.
- **NIST** AU / AC / SC control families exercised by the same mechanisms.

Full control-by-control mapping: [`COMPLIANCE.md`](COMPLIANCE.md).

## Repository layout

```
architecture.html   colorful interactive architecture diagram
COMPLIANCE.md       ISO 27001 / NIST / OWASP mapping
build.bat           PyInstaller portable-exe builder
requirements.txt
reports/            generated .xlsx/.csv/.html evidence
src/
  authn.py          token auth + rate limiting
  beacon.py         agent (poll loop, allowlist executors)
  beacon_entry.py   standalone beacon entry (portable exe)
  c2logging.py      rotating logs + append-only audit + GUI queue
  config.py         settings & env-based secrets
  crypto.py         Fernet payload encryption
  gui.py            colorful Tkinter console
  listener.py       HTTP listener (ThreadingHTTPServer)
  main.py           entry points (gui / demo / beacon)
  registry.py       beacon & task registry (thread-safe)
  reporting.py      .xlsx/.csv/.html exporters
  util.py           shared helpers
logs/               session.log + audit.jsonl
```

## License / ethics

Educational material only. The beacon executes a **whitelist of pure-Python
functions** — it cannot run arbitrary shell commands, cannot persist, and
cannot self-propagate. Use it to study C2 *architecture*, train defenders and
test detection rules in your own lab. Never point telemetry at systems you do
not own or lack written authorization to assess.