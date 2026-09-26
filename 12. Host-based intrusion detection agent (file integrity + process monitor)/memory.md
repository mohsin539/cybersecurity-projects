# Project 12 — Memory (Development Journal)

## 1. Architecture Decisions

| Decision | Rationale |
|----------|-----------|
| Reactive + periodic combos (parallel) | Reactive alone fails to same-hash-win races; periodic alone windows between scans (architecture.md §7).  |
| Local SQLite over remote DB | Agent autonomous offline; fleet logic at manager (Project 11 / Project 13 pack) |
| Alert-only default | Agent never blocks by default (blocking can be first attack target — fail-open keeps availability) |
| Focused finding schema (type/severity/source) | Consistent across FIM and process; consumeable by SyslogHook → Project 13 rules directly |
| GUI worker thread + queue tick | Tk is single-threaded; all engine work offloaded to a daemon ScanWorker that posts `cycle`/`error`/`baseline_done` messages to a `queue.Queue` polled by `root.after` (~200 ms). Never call widget methods from the worker. |
| First-scan warmup (files AND procs) | Like `--baseline` for FIM, the first process cycle snapshots the landscape without findings; else every process flags as unknown on boot. |

## 2. Windows quirks (memorize — you WILL meet them again)

1. **`wmic` deprecated (Windows 11 + Server 2022+):** **resolved.** `process.py` now shells out to `PowerShell Get-CimInstance Win32_Process` (CSV-ish via `[char]0x1f` delimiters) with a `Get-Process` fallback. Verified: 280+ procs captured.
2. **Defender content scan blocks Python `open()` on flagged files:** `<?php system($_GET...` triggers Errno 22 at `open()`, not at read. Doing `Remove-Item` first + recreating with benign content avoids it. **Never ship webshell-as-fixture; use a neutral marker** (timestamps / version strings).
3. **`pathlib.Path.owner()`** isn't supported on Windows (raises); the `.owner()` call in `file_sig` is wrapped in try/except, returns `"?"`.
4. **`os.walk` + spaces/parens in dir names fine**, but the project dir has spaces + parens; keep paths quoted when shelling out (`subprocess` list-args only).
5. **NEVER name `threading.Event()` attributes `_stop` / `_wake` on a `threading.Thread` subclass** — they clobber CPython internals (`_wait_for_tstate_lock` calls `self._stop()`). Use `_stop_evt`/`_wake_evt`. This caused a real `TypeError: 'Event' object is not callable` crash.
6. **PowerShell has no heredocs** (`<<` is reserved) — write test scripts to a temp file and run with `py file.py`.
7. **`input()` raises `EOFError`** in `catch` when stdin is not a tty; `_pause_on_windows()` must guard it or successful CLI runs exit non-zero.

## 3. Conventions

- Findings: JSON lines, keys = `type` (`file_changed`/`file_new`/`file_deleted`/`proc_new`), `severity`, `path|pid`, `ts` UTC, `source=hids-agent`.
- `--baseline` flag MUST be passed for first deployment (else every file alerts). GUI offers automatic baseline build on first run.
- Never edit `hids/alert.py` severity map without updating `security.md` §5.
- SQLite bind values with `?` (never f-strings in queries).

## 4. Cross-Project Hooks

- `SiemWebhookHook` serializes finding → **Project 11 CES Event** (`action: create|exec`). Both use same envelope.
- `SyslogHook` output is natively understood by **Project 13** OSSEC/Wazuh decoders (`hids-agent[0]:` prefix).
- Process binary hashes intended to feed **Project 16** IOC store (`file_hash` indicators).

## 5. Warning-Alerts

- Don't let `--baseline` run unattended against mutating dirs (logs). Scopes exclude `*.log`/`*.tmp`/caches **by design** (`Scope.ignores`).
- File deletion detection is implemented (`FimEngine._find_deletions`): a baselined file absent from a scan and missing on disk emits `file_deleted`. It re-upserts the row so the finding is not repeated every cycle.