# 🧠 memory.md — Working Memory & Caching Layer

> Companion to `architecture.md` §4 (processing/service tier). Documents the
> *short-lived, process-scoped* memory that sits ahead of the durable state layer
> (`state.md`): an LRU cache for hot objects and a bounded event ring for the
> audit/telemetry dashboard.

---

## 1. Why a working-memory layer?

The durable store (`pcapless.db`) is the system of record. But two hot paths
benefit from near-zero-cost reads:

| Path | Cost if DB-bound | Working-memory answer |
|---|---|---|
| Opening a story repeatedly within one session | Repeated JSON parse of `story_json`/`events_json` | `LRUCache.recall()` returns the decoded dict |
| Audit/telemetry dashboard | Full-table scans each poll | Bounded in-RAM ring of recent events |
| Ingest worker ↔ GUI progress | Cross-thread marshalling | A dedicated job `queue.Queue` (not in `memory.py` but part of the same design) |

Memory is **strictly a cache**: it holds no extra truth, is safe to wipe, and is
never the source for reports or audit verification.

---

## 2. Components (`app/core/memory.py`)

### 2.1 `LRUCache`
- Thread-safe (`RLock`), capacity-bounded `OrderedDict`.
- `get(key)` promotes entry to the tail (recently-used); evicts least-recently-used
  beyond capacity.
- Used via `WorkingMemory.store(key, value)` / `recall(key)`.

### 2.2 `WorkingMemory`
Process-level singleton `WORKING_MEMORY`:

| Role | Key space |
|---|---|
| Story cache | `story:<session_id>` → decoded story dict |
| Session cache | `session:<session_id>` → reconstructed rec |
| Event ring | `recent_events(limit)` → last N `{kind, detail, ts}` notes |

`WorkingMemory.note(kind, detail, ts)` appends lightweight telemetry (e.g.
"story_loaded", "report_pdf_exported") for the dashboard; bounded to
`event_ring` (default 500) so memory stays constant.

### 2.3 `snapshot()`
Returns `{lru: {size, capacity}, events_buffered}` — surfaced in the About tab so
operators can observe memory hygiene without a profiler.

---

## 3. Lifecycle

```text
Story tab opens session s
   └─ recall("session:s") ── hit? ──────────────────► render immediately
        │
        miss ─► StateDB.session_rec(s)
                  └─ store("session:s", rec)   (LRU capacity 1024)
```

Because SQLite already caches pages and rows are small, cache hit-rate is the
dominant variable — the LRU absorbs it deterministically.

---

## 4. Cross-process vs in-process

- **In-process only.** The `.exe` is single-process; no shared-memory protocol is
  required, so the LRU never has invalidation races between processes.
- The ingest worker → GUI transfer uses a thread-safe `queue.Queue` polled on the
  UI event loop (`after`); results land in the durable DB **and** the LRU.

---

## 5. Sizing guidance

| Knob | Default | When to raise |
|---|---|---|
| `capacitLRU=capacity` | 1024 entries | Hundreds of sessions with fat stories in one analysis |
| `event_ring` | 500 events | Busy multi-hour sessions with constant audit telemetry |
| UI poll interval | 120 ms | Large captures (raise to ~250 ms to reduce redraw churn) |

---

## 6. Guarantees & honesty

- **No false persistence:** a crash loses only cache + ring events; re-derivable
  from `pcapless.db` and the original capture.
- **No cache-mediated integrity decisions:** audit verification and report
  rendering always read the authoritative DB row, not the LRU.
- **Bounded memory:** worst case LRU ≈ `cap × avg_rec_size`; the ring is fixed-size.