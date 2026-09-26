# 🗄️ state.md — State Management & Persistence

> Companion to `architecture.md` §4.5/§10. Documents the durable state layer of the
> portable suite: what is stored, where, when it is written, and how it preserves
> cases across restarts ("reservation" of cases, sessions, reports, audit).

---

## 1. Overview

The portable build persists all durable state in a **single local SQLite database**
(`WAL` journal mode) so the whole tool remains self-contained and movable.

```text
PCAFLESS_DATA_DIR   (env override)
   │  default:  C:\Users\<user>\.pcapless\
   │
   ├── pcapless.db            ← all state (SQLite, WAL)
   ├── .pcapless_master.key   ← sealed 32-byte integrity key (security.md)
   └── reports\               ← exported reports (default output dir)
```

Setting `PCAFLESS_DATA_DIR` moves the *entire* state bundle (→ air-gap, shared
drives, USB case carry-over).

---

## 2. Schema & ownership (`app/core/state.py` → `StateDB`)

| Table | Records | Written by | Read by |
|---|---|---|---|
| `cases` | Case ID, name, clearance, created | First-run bootstrap; future case mgmt | All tabs (case-scoped views) |
| `captures` | File name, SHA-256, size, frame count, import time | Ingest worker | Sessions list, integrity display |
| `sessions` | Flow key, proto, L7, endpoints, byte/frame stats, story, events | Ingest worker (after story build) | Sessions tab, Story tab, Reports |
| `reports` | Format, file, sha256, size, report_version, timestamp | Report export | Reports tab history |
| `audit` | Chained, signed audit events (security.md §5) | AuditBus on every operation | Audit tab |
| `config` | Key/value app settings | Outdir overrides etc. | App bootstrap |

### Sessions row ↔ session record mapping

```json
sessions {
  session_id, flow_key, proto, l7, src, sport, dst, dport,
  start_ts, end_ts, bytes_c2s, bytes_s2c, frames,
  stats_json {c2s_packets, s2c_packets, retransmits, out_of_order, gaps,
              l7_confidence, beacon_score, detected_os},
  story_json  {nodes[], edges[], narrative[], findings[], risk_score, severity, ttp},
  events_json [{seq, dir, type, details, frame_id, payload_offset, ts, ...}],
  beacon
}
```

---

## 3. Write-path guarantees

- **Single-writer discipline:** all DB writes happen either in the ingest worker
  thread (capture/session bulk insert) or the main GUI thread (reports, audit).
  SQLite handles locking; the app performs no concurrent writes to the same tables.
- **Atomicity:** every `add_*` helper uses a single `INSERT` + `commit()`.
- **Idempotent ingest:** `INSERT OR REPLACE` keyed on `session_id` means re-runs of
  the same capture cannot duplicate sessions.
- **Report versioning:** `report_version` auto-increments per target session so a
  later export never silently overwrites an earlier one's history row.

---

## 4. Lifecycle of a captured case ("reservation")

1. **Bootstrap** — `StateDB()` creates schema + `DEFAULT` case (clearance 2).
2. **Ingest** — `captures` row (pre-processing SHA-256) → `sessions` rows (each with
   story + events) → `audit` row `INGEST`.
3. **Analysis** — Story tab reads `story_json`/`events_json`; viewing logs `STORY_VIEW`.
4. **Export** — `reports` row + `audit` row + file on disk (Reports tab).
5. **Persistence** — everything survives restart; nothing is cached-only.
6. **Audit** — `Verify hash-chain` re-walks the audit table end-to-end.

---

## 5. Data hygiene

| Concern | Policy |
|---|---|
| DB location | `%USERPROFILE%\.pcapless\pcapless.db` (or `PCAFLESS_DATA_DIR`) |
| Journal mode | `WAL` (crash-safe, better read concurrency) |
| Foreign keys | `PRAGMA foreign_keys=ON` |
| Migration path | Fresh schema on missing tables; columns added forward-compatibly |
| Size guardrails | Audit viewer limited to 300 rows (10 000 in export); session event lists capped per flow |
| Backup | Copy the folder while the app is closed (WAL file flush) |

---

## 6. Failure & recovery matrix

| Scenario | Behaviour |
|---|---|
| Corrupt/absent key file | New key generated on next start (evidence tagged by new key — see security.md limits) |
| DB file deleted | Schema + DEFAULT case re-created automatically |
| Ingest interrupted | Partial `sessions` rows persist; re-import of same file is idempotent |
| Disk full during export | Error surfaced in GUI; `reports` history row only written after successful render |

---

## 7. Env surface

| Variable | Effect |
|---|---|
| `PCAFLESS_DATA_DIR` | Moves DB + key + default report dir as one unit |
| `PYTHONHOME`/`PYTHONPATH` | Only relevant when running from source; immutable inside the `.exe` |