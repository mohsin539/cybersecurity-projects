# 📊 Project State — Network Traffic Monitor

> **Purpose:** live status tracker. Mirrors the satellite of truth for this
> project (workspace + `memory.md`). Update whenever work starts or finishes.
> Tracks: status · features · files · latest run · errors · next actions.

**Last updated:** 2026-09-23 · **Canonical plan:** ARCHITECTURE.md §9 Roadmap

---

## 1. Current Status Board

| Area | State |
|------|-------|
| **Overall project** | ✅ **v2.0 — Windows v1.0 + Android APK built** |
| Server (engine + API + scheduler) | ✅ done |
| Raw collector (Windows per-app sampler) | ✅ done |
| Web dashboard (charts, table, drawer) | ✅ done |
| Architecture docs (`ARCHITECTURE.md`, `architecture.html`) | ✅ done |
| Memory stack (`security.md`, `memory.md`, `state.md`) | ✅ done |
| End-to-end runtime verification | ⏳ pending (this session) |
| **Android APK (`TrafficMonitor-debug.apk`)** | ✅ **built** (com.trafficmonitor v1.0, minSdk 26 / targetSdk 35) |
| Android on-device test on a real device | 🔜 pending |

---

## 2. Feature Matrix

| Feature | v1.0? | Notes |
|---------|:-----:|-------|
| Live per-app RX/TX (bytes/sec) | ✅ | TCP/UDP connection weighting |
| Total link throughput (download/upload) | ✅ | Δ adapter counters |
| Per-adapter breakdown | ✅ | top 6 interfaces |
| 10-min time-series chart | ✅ | ring buffer 300 |
| Top-apps horizontal ranking | ✅ | animated bars |
| App detail drawer + sparkline | ✅ | 80-sample window |
| Simulation-mode fallback | ✅ | after 2 failed ticks |
| `/api/health` observability | ✅ | mode, uptime, samples, lastError |

---

## 3. File Inventory & Status

```
├── ARCHITECTURE.md        ✅ delivered              ← blueprint w/ mermaid
├── architecture.html      ✅ delivered              ← colorful interactive visual
├── security.md            ✅ delivered              ← threat model + controls
├── memory.md              ✅ delivered              ← durable project memory
├── state.md               ✅ delivered              ← this file
├── server/
│   ├── server.js          ✅ implemented            ← zero-dep HTTP + engine
│   └── collector.ps1      ✅ implemented            ← Windows sampler
├── public/
│   ├── index.html         ✅ implemented            ← dashboard shell
│   ├── style.css          ✅ implemented            ← dark glass theme
│   └── app.js             ✅ implemented            ← poll + canvas render
├── TrafficMonitor-debug.apk  ✅ built 2026-09-23    ← Android port (0.83 MB)
└── android/               ✅ implemented
    ├── settings.gradle.kts / build.gradle.kts       ← AGP 8.9.2 + Kotlin 2.1.20
    ├── gradle/wrapper/*                             ← reproducible builds (8.11.1)
    └── app/src/main/java/com/trafficmonitor/
        ├── MainActivity.kt      ← dash shell: KPI, chart, ranking, table, dialog
        ├── MonitorEngine.kt     ← engine: aggregation + 300-sample ring buffer
        ├── StatsCollector.kt    ← LiveCollector (NetworkStatsManager) + SimCollector
        ├── Category.kt          ← palette + category classify (kept in sync w/ UI)
        └── ui/                  ← AreaChartView, SparklineView, AppRowView, RankBarView
└── data/                      (runtime optional)    ← future persistence
```

---

## 4. Runbook

| Command | Purpose |
|---------|---------|
| `node server/server.js` | start the monitor (server) |
| `node server/collector.ps1 …` (via server only) | never run manually — it expects server context |
| `http://127.0.0.1:8070` | dashboard |
| `http://127.0.0.1:8070/architecture.html` | interactive architecture |
| `http://127.0.0.1:8070/api/health` | health snapshot |

---

## 5. Latest Runtime Observations

> To be filled on the first verified run. Expected values below:

| Check | Expected | Observed |
|-------|----------|----------|
| Server binds | `127.0.0.1:8070` | — |
| `/api/health` returns | `{ok:true, mode:'live'\|'sim', …}` | — |
| Collector exit code | `0` | — |
| First sample latency | < 3 s | — |
| `/api/stats` apps length | 0–25 | — |
| Dashboard charts animate | RX cyan / TX violet | — |

**Last error seen:** —

---

## 6. Risks & Blockers

| Risk | Impact | Mitigation |
|------|--------|-----------|
| Cmdlets unavailable on older Windows | sim-mode only | D5 auto-fallback |
| Attribution is heuristic, not packet-accurate | numbers "soft" | documented in Limitations |
| History volatile (no persistence) | restart wipes charts | SQLite on roadmap |
| `arch`-specific emoji in console on some terminals | cosmetic | ignore |

---

## 7. Next Actions (ordered)

1. [ ] **Verify** end-to-end: run server, curl `/api/health`, open dashboard, confirm live+sim modes behave.
2. [ ] Screenshot dashboard for the project gallery (color approval).
3. [ ] Optional: merge browser helper processes into parent profile (Q in memory.md §7).
4. [ ] Optional: WebSocket push + SQLite daily roll-up (ARCHITECTURE.md §9).
5. [ ] Confirm `security.md` §6 checklist prior to any sharing of the codebase.

---

## 8. Change Log

| Date | Change | By |
|------|--------|----|
| 2026-09-23 | v1.0 scaffold: architecture, collector, server, dashboard, memory stack | — |
| 2026-09-23 | v2.0 Android port: Gradle project, NetworkStatsManager collector, Compose-free canvas dashboard → `TrafficMonitor-debug.apk` built | — |