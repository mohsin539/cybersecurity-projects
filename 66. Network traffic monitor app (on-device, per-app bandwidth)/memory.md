# 🧠 Project Memory — Network Traffic Monitor

> **Purpose:** durable context for future coding sessions on this project.
> Update after any meaningful change (new feature, refactor, decision).

**Last updated:** 2026-09-23 · **Project version:** v2.0 (Windows web v1.0 + Android APK)

---

## 1. One-Paragraph Snapshot

A **zero-dependency** Windows web app that monitors **per-app network
bandwidth** on the device it runs on. A Node scheduler spawns a PowerShell
worker every ~2 s; the worker samples TCP/UDP endpoint tables + adapter byte
counters, attributes throughput to processes by connection weight, and pushes
JSON snapshots into a ring buffer. A dark, glassmorphic dashboard polls the
REST API and renders animated canvas charts, per-app tables, and a detail
drawer. Everything stays on `127.0.0.1`.

---

## 2. Decisions Log (current + superseded)

| # | Decision | Why | Status |
|---|----------|-----|--------|
| D1 | Zero npm deps (pure `http` + canvas) | App must run anywhere Node ≥ 18 exists, offline, no install window | **Active** |
| D2 | PowerShell worker spawned per tick (no long-running daemon) | Worker exits → frees handles, isolates failures, easy kill | **Active** |
| D3 | Throughput attribution: `bps × (weight_pid / Σweight)`, TCP=1.0, UDP=0.35 | No public per-process byte counters on Windows; cheap & stable | **Active** |
| D4 | In-memory ring buffer (300 samples ≈ 10 min), no DB | Fast, bounded memory, plenty for a v1 dashboard | **Active** |
| D5 | Simulation-mode fallback after 2 failed live ticks | Keeps demo/UI meaningful when host is idle or cmdlets fail | **Active** |
| D6 | Bind to `127.0.0.1:8070` only | Privacy + zero LAN attack surface | **Active** |
| D7 | Polling (2 s) instead of WebSockets | Zero deps, simpler; revisit at "Roadmap 1" | **Superseded-by** |
| D8 | Android port: zero runtime deps (no AndroidX/Compose), framework Canvas views | Mirrors D1; builds fast + tiny APK (0.8 MB) | **Active** |
| D9 | Android collector: `NetworkStatsManager.queryDetailsForUid` (per-UID) — real per-app counters, no heuristic | Android exposes per-UID byte totals publicly; usage-access gate only | **Active** |
| D10 | Android permissions: `PACKAGE_USAGE_STATS` (usage access) + `QUERY_ALL_PACKAGES`, **no** `INTERNET` | Stats read is on-device; zero egress (Android equivalent of D6) | **Active** |

---

## 3. Architecture Cheat-Sheet (fast recap)

```
public/index.html ──▶ app.js ──▶ fetch('/api/stats') ──▶ server.js ──▶ spawn ──▶ collector.ps1
        │                │                                                                 │
        └── charts ──────┘        ◀── JSON snapshots ◀────────────────────────────────────
```

| File | Responsibility | Key symbols |
|------|----------------|-------------|
| `server/server.js` | HTTP + scheduler + validation + ring buffer | `tick()`, `ingest()`, `validate()`, `simSample()`, `/api/{stats,history,apps,health}` |
| `server/collector.ps1` | Windows sampling → JSON to stdout | `Get-AdapterThroughput`, `Get-ConnectionMap`, `Get-Category` |
| `public/app.js` | poll + render + canvas | `drawArea()`, `renderTable()`, `renderDrawer()`, `trackApp()` |
| `public/style.css` | dark glass theme, CSP-friendly | CSS vars `--rx`, `--tx`, `--grad` |
| `public/index.html` | shell + drawer | KPI cards, chart canvas, app table |

---

## 4. Reference Facts (verified during build)

- Node available: **v24.20.0**; PowerShell **5.1** (build 26100).
- `Get-NetAdapterStatistics` needs no admin; byte counters reset on adapter restart → Δ guarded with `if (Δ < 0) Δ = 0`.
- `Get-NetUDPEndpoint` has no remote port — UDP weight is lower than TCP to avoid skew.
- History is keyed by wall-clock `HH:MM:SS`; ring slices both `labels`, `rx`, `tx`.
- PID → name map from `Get-Process`; unknown PIDs fall back to the connection owner (often empty).
- Category → color constants live in BOTH `collector.ps1` (`Get-Color`) and the UI palette; keep in sync.
- Max rows enforced: apps `25`, adapters `6`, drawer history `80`.

---

## 5. Conventions & Style

- **No comments** unless required by the code owner's instruction; filenames kebab-case.
- Server logs use emoji prefixes (`📡`, `[sim]`).
- Numbers are `Math.round()` in snapshot; UI formats via `fmtBps()`.
- Async is promise-based (`fetchJSON`), UI never throws unhandled (loop catches).
- Charts: dark grid `rgba(255,255,255,.06)`, RX=`#22d3ee`, TX=`#a78bfa`.

---

## 6. Known Limitations (be honest)

1. Attribution is an **estimate** — per-process numbers are proportional, not packet-accurate.
2. Older Windows (pre-10/Server 2016) may lack some `Net*` cmdlets → sim fallback.
3. History is lost on restart (no persistence).
4. `chrome.exe`/`msedge.exe` child processes aren't merged into the parent profile.
5. Adapter byte counters include non-TCP traffic (ICMP, etc.) — total may exceed the sum of TCP/UDP app shares.

---

## 7. Open Questions / Future Direction

- [ ] WebSocket push to kill 2 s polling (see "Roadmap 1" in ARCHITECTURE.md)?
- [ ] Merge browser helper processes (renderer/gpu/network) into the browser profile?
- [ ] SQLite roll-up for daily/weekly per-app totals?
- [ ] Per-app data caps / quiet-mode thresholds + optional notifications?

---

## 8. Session Reunion Checklist (run at the start of the next session)

1. Read this file + `state.md` + `ARCHITECTURE.md`.
2. `node server/server.js` → visit `http://127.0.0.1:8070`.
3. Check `/api/health` → confirm `mode` + `lastError`.
4. If collector fails on this machine, don't delete code — remember D5 (sim).
5. Sweep `security.md` §6 checklist after any change affecting I/O.