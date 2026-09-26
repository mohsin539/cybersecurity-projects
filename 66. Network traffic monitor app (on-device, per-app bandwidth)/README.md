# 📡 Network Traffic Monitor

On-device, **per-app bandwidth monitoring for Windows** with a real-time web dashboard. The
agent samples live network activity on the host, attributes throughput to individual
applications (by PID), and renders animated, color-coded visualizations in the browser.

> Part of the [AI Masterclass cybersecurity portfolio](../../#readme) — project 66 of 72.
> Educational/lab use; all collection is strictly local to your own machine.

## ✨ Features

- **Per-process attribution** — real-time (≈2 s) sampling via `Get-NetTCPConnection`,
  `Get-NetUDPEndpoint`, `Get-NetAdapterStatistics`, `Get-Process`
- **Connection-weighted model** — measured adapter throughput is distributed across active
  connections per PID (estimated, not per-flow metering)
- **Live dashboard** — animated charts: per-app breakdown, history sparklines, ranking bars
- **Zero-install** — no npm dependencies; pure Node.js `http` + static assets

## 🚀 Quickstart

```bat
run.bat
```

Then open **http://127.0.0.1:8070**.

Requirements: Windows 10/11, PowerShell 5.1+, Node.js ≥ 18. To start without opening a
browser: `run.bat --no-browser`.

Manual start: `node server/server.js` (binds to `127.0.0.1` only).

## 🗂️ Project Layout

| Path | What it is |
|---|---|
| `server/server.js` | HTTP + WebSocket server, aggregation engine, ring-buffer history |
| `server/collector.ps1` | PowerShell sampling worker (OS data source) |
| `public/` | Dashboard UI — HTML/CSS/JS, charts |
| `android/` | Companion Android app (Kotlin, debug APK available locally) |
| `ARCHITECTURE.md` | Full C4 architecture blueprint with diagrams |
| `architecture.html` | Standalone rendered version of the blueprint |

## 🔒 Security Notes

- Server binds to **loopback (127.0.0.1) only** — the dashboard is not exposed to the network
- **No telemetry** — nothing leaves the machine; data lives in an in-memory ring buffer
- See [`security.md`](security.md) for the threat model and hardening notes

## 🧪 CI

A GitHub Actions job syntax-checks all JavaScript and builds the Android debug APK — see
[`.github/workflows/ci.yml`](../../blob/master/.github/workflows/ci.yml).
