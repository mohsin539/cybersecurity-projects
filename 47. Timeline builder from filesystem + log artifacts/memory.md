# MEMORY - TimelineBuilder (project knowledge & handover)

Durable "how and why" notes so the project can be picked up cold. Pair with
`state.md` (current status) and `SECURITY.md` (control evidence).

- **Product:** TimelineBuilder - portable DFIR timeline builder (filesystem + logs)
- **Version:** 1.0.0
- **Entry points:** `python -m timeline_builder` (GUI) - `python -m timeline_builder cli ...` (CLI)

---

## 1. One-Paragraph Mental Model

Evidence (files + logs) -> **collectors** emit `TimelineEvent`s -> **normalizer**
forces UTC / dedupes / sorts -> **correlator** finds bursts -> **CaseStore**
(SQLite) holds them -> GUI/CLI query, filter and **export** (CSV/JSON/HTML). A
cross-cutting **security spine** hashes artifacts, validates paths and appends
every action to a tamper-evident audit chain.

---

## 2. Key Decisions & Rationale

| Decision | Why |
|---|---|
| Pure-stdlib core; GUI optional | Core (collect/analyze/store/export) and all tests run without PySide6; keeps CLI headless and the frozen exe resilient. |
| Single `TimelineEvent` schema | One normalized row absorbs filesystem + every log format; enables one table, one query path, one exporter. |
| MACB as `TimeKind` (B/A/C/M/E) | Preserves forensic time semantics instead of flattening to one timestamp. |
| Platform-aware birth/change time | Windows `st_ctime` = **creation** (changed time unavailable); POSIX `st_ctime` = **change**, birth only if `st_birthtime`. |
| SQLite (WAL) case store | Zero-install, portable, transactional, indexed; thread-safe via `check_same_thread=False` + `RLock`. |
| QThread + `ScanWorker` object | Keeps the UI responsive; progress/cancel via signals and a `threading.Event`. |
| SHA-256 hash-chained audit log | Repudiation resistance / tamper evidence without external infrastructure. |
| Optional Fernet (AES-CBC+HMAC) + PBKDF2 | Strong, well-reviewed primitives; avoids home-grown crypto; 600k iterations. |
| No network code anywhere | Removes exfiltration/SSRF surface by construction (offline tool). |
| HTML-escape at output boundary | Log content is untrusted; neutralize stored XSS in the HTML report. |
| PyInstaller onefile/windowed | Single portable `.exe`, no installer/elevation. |

---

## 3. Critical Implementation Details (do not break)

### 3.1 Audit hash chain (`security/audit.py`)
- `canonical(payload)` = `json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)`.
- `digest = SHA256(prev_hash + "|" + canonical(payload))`.
- `payload` contains: `seq, ts, actor, case_id, action, target, outcome, detail`
  and **excludes** `prev_hash` and `hash`.
- On append, `full = payload + {prev_hash, hash}`; `prev_hash` starts at `"0"*64`.
- **GOTCHA:** `verify_audit_chain()` must `pop("prev_hash")` **and** `pop("hash")`
  before recomputing the digest. If `prev_hash` stays in the dict, every record
  fails verification (this exact bug was hit and fixed).
- Records are appended + `fsync`-ed; never rewrite the log in place.

### 3.2 Filesystem MACB (`collectors/filesystem.py`)
- `st_birthtime` if present, else Windows `st_ctime`, is used for **Birth**.
- Changed time = POSIX `st_ctime` only; `None` on Windows.
- Symlinks not followed unless `follow_symlinks=True`.
- Optional hashing bounded by `hash_max_bytes`.
- `_walk()` is a **generator**; `collect()` wraps it in `list(...)` because it
  needs `len(targets)` for progress (a generator caused a `TypeError` once).

### 3.3 Log parsing (`collectors/logs.py`)
- `detect_format()` sniffs extension then content (JSON array vs JSONL vs delimited vs text).
- Flexible field mapping via key tuples: `TS_KEYS`, `LEVEL_KEYS`, `MSG_KEYS`, `USER_KEYS`, `HOST_KEYS`.
- `_flatten()` lower-cases and flattens nested objects so EVTX/JSON nests resolve.
- `parse_timestamp()` handles ISO-8601 (incl. `Z` and `+HHMM`), a strptime table, epoch seconds/ms, and syslog `Mon DD HH:MM:SS`.
- Invalid records are skipped, never fatal; per-file errors are collected.

### 3.4 Store (`storage/case_store.py`)
- Tables: `meta`, `sources`, `events`; indexes on ts/severity/source_type/path/host/user.
- `INSERT OR IGNORE` on `event_id` -> idempotent re-scans.
- `query()/count()` share `_build_filters()` (text + facets + time window).
- `_row_to_event()` reconstructs `TimelineEvent` incl. `tags` and parsed `raw` JSON.

### 3.5 GUI (`ui/`)
- `MainWindow` owns `CaseStore` and `AuditLogger`; attaches audit via `store.audit`.
- Scan: `QThread` + `ScanWorker` moved to it; wired `started->run`, `finished/failed->quit`, `thread.finished->cleanup`.
- `TimelineTableModel` supports sorting and exposes the `TimelineEvent` at a row via `event_at()`.
- Facets (`host`) repopulated from `store.distinct("host")` after each scan.

### 3.6 Frozen exe (`run_app.py`)
- **GOTCHA:** the exe entry `run_app.py` must call `timeline_builder.__main__.main`,
  **not** `app.main`. `__main__.main` dispatches `cli ...` vs GUI. Calling the GUI
  entry directly makes the frozen binary ignore the CLI (bug hit and fixed).

---

## 4. Data Model (TimelineEvent)

`timestamp: datetime(UTC)`, `time_kind: M|A|C|B|E`, `source_type: filesystem|log|artifact`,
`source_path`, `description`, `host`, `user`, `severity: info|low|medium|high|critical`,
`size`, `sha256`, `tags[]`, `raw{}`, `event_id (uuid4 hex)`.
Helpers: `normalized_timestamp()`, `to_row()`, `from_row()`, `sort_key()`.

---

## 5. Conventions

- Source tree under `src/timeline_builder/`; imports are absolute from the package.
- One responsibility per module; collectors share `BaseCollector` + `CollectorContext`.
- No comments in code; behavior documented here and in the docs.
- Tests: stdlib `unittest`, each file prepends `src` to `sys.path`.
- Generated artifacts (`dist/`, `build/`, `*.tbcase`, `*.audit.jsonl`, `demo_case/`,
  `exe_demo/`, `out/`) are git-ignored.

---

## 6. Extension Guide

- **New collector:** subclass `BaseCollector`, return `CollectionResult`, emit
  `TimelineEvent`s, honor `CollectorContext` (progress/cancel/audit). Register in
  `collectors/__init__.py` and branch it in `cli.py::_resolve_kind` / `worker.py`.
- **New export format:** add `export/<fmt>_exporter.py`, expose in `export/__init__.py`,
  wire a toolbar action + `MainWindow._export()` branch.
- **New severity rule:** extend `SEVERITY_WORDS` / `LEVEL_MAP` in `collectors/logs.py`.
- **Encrypt a case:** `security.crypto.seal_file(store, dest, password)` /
  `unseal_file(...)`.

---

## 7. Glossary

- **MACB** - Modified/Accessed/Changed/Birth (filesystem time quartet).
- **EVTX** - Windows XML Event Log format.
- **Case store** - the SQLite `.tbcase` file holding a case's events/sources/meta.
- **Audit chain** - append-only SHA-256-linked log proving the action history.
- **Manifest** - JSON of artifact paths + SHA-256 hashes for integrity verification.
- **Spine** - the cross-cutting security/audit layer injected into all layers.
