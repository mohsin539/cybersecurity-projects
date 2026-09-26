# Project 12 — State

## 1. Component Status

| Component | Status | Notes |
|-----------|--------|-------|
| `gui.py` GUI console | ✅ Implemented | tkinter dashboard + FIM / Processes / Findings / Settings tabs; threaded worker |
| `baseline.py` (BaselineDB, LifecycleState) | ✅ Implemented | SQLite WAL; hash-chain snapshots ready |
| `fim.py` (Scope, file_sig, FimEngine) | ✅ Implemented | hash+size+mtime; **deletion detection now emits `file_deleted`** |
| `fim.py` reactive watcher (inotify/fanotify) | 🔲 Stub (future) | Current poll-based via snapshot(); architecture.md §2.1-A |
| `process.py` (ProcMonitor, cmdline flagging) | ✅ Implemented | Linux `/proc` works; **Windows via `Get-CimInstance Win32_Process`** (wmic deprecated); warmup first cycle |
| `alert.py` (JsonlHook, SyslogHook, SiemWebhookHook) | ✅ Implemented | Project 11 CES mapping in place; `file_deleted` severity added |
| `main.py` CLI | ✅ Implemented | `--scopes/--baseline/--cycles/--no-proc`; first proc cycle warms up |
| Agent self-protection (own-file FIM) | 🔲 Not started | architecture.md §5 |
| eBPF / ETW process monitor | 🔲 Not started | architecture.md §2.1-B future |

## 2. Verified Behavior (TEST dated 2026-09-15)

CLI functional suite (scratch state dir, all PASS):
```
# Baseline (no findings)
py main.py --scopes ... --state ... --baseline            -> fim=0 proc=0
# Normal cycle (no findings)
py main.py --scopes ...                                   -> fim=0 proc=0
# Tamper: etc/passwd appended
py main.py -> file_changed high (old/new sha256 emitted)
# Delete: etc/named.conf removed
py main.py -> file_deleted high
# New file dropped in www/
py main.py -> file_new medium
# New process spawned between cycles
py main.py --cycles 2 --interval 3 -> proc_new high (binary=unknown_binary)
```

GUI smoke test (Windows, Python 3.12):
- 281–295 processes captured per scan (Windows proc monitor FIXED)
- Live findings feed populated by running worker thread
- Clean exit code 0

## 3. Known Gaps & Risks

| Gap | Risk | Priority |
|-----|------|----------|
| ~~Windows process monitor returns 0 procs~~ | **Fixed** — `Get-CimInstance Win32_Process` (+ `Get-Process` fallback) | Closed |
| ~~No file deletion detection~~ | **Fixed** — `_find_deletions()` emits `file_deleted` | Closed |
| No baseline DB tamper-detection | Attacker modifies DB to hide tampering | Medium — add hash-chain watermark (architecture.md §2.4) |
| Reactive (inotify) watcher absent | Delay in detection between scan cycles | Medium — architecture.md priority #3 |
| No retention policy on findings.jsonl | Disk fill in high-alert environments | Low — add size/time-based pruning |

Priorities: (1) DB integrity self-check, (2) reactive watcher, (3) retention.

## 4. Definition of Done for Next Milestone

- [ ] BaselineDB watermark hash field + `--verify` CLI flag
- [ ] Linux `inotify` watcher hook wired to FimEngine (supplements periodic scan)
- [ ] Findings.jsonl retention (size/time-based pruning)