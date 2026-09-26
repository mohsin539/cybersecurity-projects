# 🧠 AEGIS-SENTINEL — State Architecture

> Companion to [`architecture.md`](./architecture.md) (§2 presentation layer, §8 data models)
> and the reserved [`memory.md`](./memory.md) (persistence & lifecycle).
> This document covers **client state**: what lives where, who owns it, and how it flows.

---

## 1. State Topology

```
┌──────────────────────────────────────────────────────────────┐
│                        React UI layer                        │
│   Hud · FilterRail · Legend · Ticker · Drawer · Modals       │
└──────────────┬───────────────────────────┬───────────────────┘
               │ hooks (subscriptions)     │ actions
┌──────────────▼───────────┐   ┌───────────▼───────────────────┐
│  threatStore (zustand)   │   │  uiStore (zustand)            │
│  events · filter ·       │   │  modal · toasts · role ·      │
│  visible · selected      │   │  booted · perf/cinematic flags│
└──────────────┬───────────┘   └───────────────────────────────┘
               │ ingest() / setFilter()
┌──────────────▼───────────┐   ┌───────────────────────────────┐
│  ThreatStream (data)     │   │  auditLedger (security)       │
│  mock generator → batches│   │  hash chain → useSyncExternal │
└──────────────────────────┘   │  Store via auditStore          │
                               └───────────────────────────────┘
               ▲
┌──────────────┴───────────┐
│  GlobeEngine (WebGL)     │  ← imperative, NOT a store:
│  arcs · markers · waves  │    fed via setEvents() effect diffing
└──────────────────────────┘
```

**Design rule:** *one directional flow* — stream → store → (React | engine). The WebGL engine is
deliberately **outside** React state: per-frame GPU objects would thrash reconciliation, so the
engine receives plain snapshots through `setEvents(events, selectedId)` and diffs internally.

---

## 2. Store Contracts

### 2.1 `threatStore` — single source of truth for threat data

| Slice | Type | Owner | Notes |
|---|---|---|---|
| `events` | `ThreatEvent[]` | store | Ring-capped at 3000 (FIFO). Newest first. |
| `filter` | `ThreatFilter` | store | Severities, categories, minRisk, sources, windowMinutes |
| `visible` | `ThreatEvent[]` | derived | `applyFilter(events, filter)` recomputed on every ingest/filter change |
| `selected` | `ThreatEvent \| null` | store | Set by globe pick or ticker click |
| `lastUpdate` | `number` | store | Epoch ms of last ingest — drives the HUD clock |

**Actions:** `ingest(batch)`, `setFilter(patch)`, `resetFilter()`, `select(id)`.

**Invariant:** `visible ⊆ events`, and every filter change re-derives `visible` synchronously —
no stale-render windows. `DEFAULT_FILTER` ships all severities on, window = 60 min.

### 2.2 `uiStore` — ephemeral UI concern

Modal kind (`reports | audit | verify | about | null`), toast stack (max 4, auto-dismiss 4.2 s),
session role, boot flag, and display toggles (perf HUD, cinematic orbit, director mode).
Nothing here is persisted — refresh resets to defaults (see memory.md §4 for the persistence tier).

### 2.3 `auditStore` — React bridge over the ledger

The ledger is a plain class (framework-agnostic, unit-testable). `auditStore` exposes it via
`useSyncExternalStore` with a stable snapshot: the array identity only changes on append, so
`verify()`-style expensive consumers can trust reference equality.

---

## 3. Data Flow Walkthroughs

### 3.1 Live ingest → pixels

```
ThreatStream.tick()                     every 0.9–2.2 s, 1–3 events
  → threatStore.ingest(batch)           cap 3000, re-derive visible
    → App effect [visible, selectedId]  fires on change
      → GlobeEngine.setEvents()         diff by event_id
        ├─ new      → createArc + markers (+ shockwave if critical)
        ├─ stale    → dispose geometry/material (no leaks)
        └─ selected → uBoost uniform 1.8 (highlight)
```

Latency contributors are all O(diff): no full teardown between frames; the GPU buffer set is
touch-only. This is the client-side mirror of architecture.md §2.2's 250 ms budget.

### 3.2 Filter → audit → visible

```
FilterRail.toggle*()
  → setFilter(patch)                    re-derive visible synchronously
  → auditLedger.append('filter.apply')  what was changed, by whom, when
```

Filter changes are security-relevant (a narrowed window can hide incidents), hence they are
audited like data reads.

### 3.3 Report generation (read path with authorization + integrity)

```
ReportModal.generate(format)
  → allow(role,'report.download')?      deny → toast + stop (no audit spam; denial logged in prod OPA)
  → audit: report.request
  → generateReport(opts)                snapshot = current visible[] (point-in-time)
      digest = SHA-256(canonical(provenance)|body)
      sig    = Ed25519({digest, provenance})
  → downloadBlob()                      browser download
  → audit: report.generate  →  report.download   (digest recorded in both)
```

### 3.4 Selection → drill-down

```
canvas click → engine.pick(x,y) → event_id | null
  → threatStore.select(id)
  → audit: globe.event_select           resource = event:<id>
  → EventDrawer renders from `selected`
```

---

## 4. Derived Data & Selectors

`computeStats(events)` (in `threatStore.ts`) produces HUD aggregates — totals, per-severity
counts, records impacted, average risk, top-5 source countries. It is O(n) over ≤ 3000 rows and
runs only when `visible` changes; no memoization library needed at this scale (≤ 0.1 ms measured
class of workload).

Severity legend counts derive from the same object — single computation, two consumers.

---

## 5. State ↔ Engine Boundary

| Concern | Decision | Rationale |
|---|---|---|
| Render loop | `requestAnimationFrame` inside engine | React re-renders must never drive frames |
| Event diffing | `Map<event_id, ArcHandle>` inside engine | Stable GPU handles; dispose-on-evict |
| Selection highlight | Uniform boost on arc material | No scene rebuild on selection change |
| UI flags (cinematic/director) | Copied to engine fields via effect | One-way push, no engine → React writes |
| Picking | `engine.pick()` returns plain id | Engine never imports stores (keeps it portable/testable) |

This boundary is what makes the engine unit-testable without React and the stores testable
without WebGL.

---

## 6. Concurrency & Timing

- **Stream timing** — randomized 0.9–2.2 s ticks simulate bursty feeds; backfill of 400 events
  gives an instantly meaningful globe (first-paint UX, architecture.md §5.3).
- **StrictMode double-mount** — the engine/stream effects clean up fully (`destroy()`,
  `handle.close()`), so dev-mode double invocation leaves no orphan rAF loops or timers.
- **Toast auto-dismiss** — `window.setTimeout` captured per toast id; dismiss is idempotent.

---

## 7. Error & Edge Handling

| Case | Behavior |
|---|---|
| Malformed event geometry | `try/catch` around arc creation — event skipped, loop lives |
| Stream subscriber throws | Isolated per-listener try/catch in `notify()` |
| Ledger listener throws | Never breaks `append()` — chain integrity first |
| WebGL context loss | Renderer disposed on unmount; production adds `webglcontextlost` handler (see architecture.md §5.4 fallback ladder) |
| Empty `visible` | Ticker/legend render zero-state; globe simply still |

---

## 8. Testing Strategy for State

- **Ledger chain tests** (`tests/auditLedger.test.ts`) — the security-critical core.
- Stores are plain zustand creators — directly instantiable in vitest (no renderer needed).
- Engine smoke paths are exercised in Playwright probes on the production roadmap
  (architecture.md §13.1 synthetic checks).
