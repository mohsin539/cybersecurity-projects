# state.md — Project State & Runbook

> **Purpose:** point-in-time snapshot of what is built, verified, and how to run it.
> Update this file after every functional change (ISO A.8.32 change management).
> **Last verified:** 2026-09-12 · **Version:** 1.0.0 · **Python:** 3.12 (≥3.11 required)

---

## 1. Current State: ✅ COMPLETE & VERIFIED

The Python implementation of `architecture.md` is fully built and green.

| Component | File(s) | Status | Notes |
|---|---|---|---|
| Config & validation | `portscanner/config.py` | ✅ done | fail-fast, hard caps, raw-scan authz check |
| Security controls | `portscanner/security.py` | ✅ done | gate, audit, sanitize, redact, path guard |
| Target resolver | `portscanner/resolver.py` | ✅ done | lazy CIDR/range expansion, DNS, dedupe |
| Event bus | `portscanner/events.py` | ✅ done | thread-safe pub/sub, subscriber isolation |
| Models | `portscanner/models.py` | ✅ done | frozen dataclasses, schema_version=1 |
| Rate limiting | `portscanner/ratelimit.py` | ✅ done | token bucket, backoff, adaptive controller |
| Connect engine | `portscanner/engines/connect.py` | ✅ done | timeout-mode + WSA-aware classification |
| UDP engine | `portscanner/engines/udp.py` | ✅ done | protocol payloads, ICMP-mapped states |
| Raw engines (SYN/FIN/NULL/XMAS) | `portscanner/engines/raw.py` | ✅ done | scapy optional; admin-gated at probe time |
| Scheduler | `portscanner/scheduler.py` | ✅ done | bounded pool, rate limit, retries, host-down prune |
| Service detection | `portscanner/service.py` | ✅ done | banner grab, probe DB (+ TOML ext), TLS info |
| Result store + WAL | `portscanner/store.py` | ✅ done | JSONL WAL, `--resume`, 0600 perms |
| Formatters | `portscanner/report.py` | ✅ done | table/json/jsonl/csv/greppable |
| Orchestrator | `portscanner/scanner.py` | ✅ done | SIGINT-safe, two-pass, audit-integrated |
| CLI | `portscanner/cli.py` | ✅ done | authorization gate, all flags |
| GUI (tkinter) | `portscanner/gui.py` | ✅ done | live results, auth checkbox, save report |
| Tests | `tests/test_scanner.py` | ✅ 11/11 green | unit + loopback smoke scan |
| Docs | `architecture.md`, `security.md`, `state.md`, `memory.md`, `README.md` | ✅ done | — |
| Windows executables | `portscanner.spec`, `scripts/portscan_cli.py`, `scripts/portscan_gui.py` | ✅ built | PyInstaller onedir → `dist/portscanner/portscan.exe` + `portscan-gui.exe` |

## 2. Verification Record (2026-09-12)

```
py -m unittest discover -s tests -v   →  Ran 11 tests ... OK
py -m portscanner 127.0.0.1 -p 80,443,445,3389 --yes
   → found open 445/tcp; table output rendered
audit log tail → AUTHZ granted / SCAN_START / SCAN_END recorded
```

### Packaging verification (2026-09-12, same session)

```
PyInstaller 6.22.2 (build venv .venv-build, Python 3.12.7)
dist/portscanner/portscan.exe      --help → OK; loopback scan → open port found, table output
dist/portscanner/portscan.exe … -f json -o report.json → OK, schema_version=1
dist/portscanner/portscan-gui.exe  alive after 6 s, no crash (smoke test)
py -m unittest discover -s tests -v → 11/11 OK (after service.py + scanner.py fixes)
```

Two latent bugs surfaced while testing the frozen binaries and were fixed in
source, then rebuilt:

1. `service.py` — TOML probe patterns were compiled as `str` but matched
   against `bytes` banners → `TypeError` on every scan that loaded
   `data/service-probes.toml`. Now encoded/compiled as bytes.
2. `scanner.py run()` — the WAL was closed in the scheduler `finally` block
   *before* the service pass, so any scan with service detection crashed with
   `ValueError: I/O operation on closed file`. WAL now closes after the
   service pass and report render.

### Known environment behavior (documented, not a bug)

- **RST-suppressed loopback (this machine):** refused ports return
  `TimeoutError` instead of `ECONNREFUSED`, so they classify as `filtered`
  (honest per §5.1) rather than `closed`. On stock Windows/POSIX stacks the
  same code reports `closed`. Handled in `engines/connect.py` + relaxed test
  assertion (`closed|filtered`).
- **`connect_ex()` in timeout mode returns 10035 immediately on Windows** —
  do not reintroduce it; the timeout-mode `connect()` pattern is the verified one.

## 3. How to Run

### Standalone executables (no Python required on the target machine)

```bat
dist\portscanner\portscan.exe 127.0.0.1 -p top100 --yes
dist\portscanner\portscan.exe 10.0.0.0/30 -p 22,80,443 -f json -o report.json --yes
dist\portscanner\portscan-gui.exe
```

Ship the **whole** `dist\portscanner\` folder (`portscan.exe`,
`portscan-gui.exe`, `_internal\`) — the `_internal` directory carries the
bundled Python runtime and `data\` files. A zip of that folder is the
distribution unit.

Rebuild after code changes (build tooling lives in an isolated venv):

```bash
.venv-build/Scripts/python -m PyInstaller portscanner.spec --noconfirm --clean
```

(First-time setup: `py -m venv .venv-build && .venv-build/Scripts/python -m pip install pyinstaller`.)

### From source

```bash
# CLI
py -m portscanner 127.0.0.1 -p top100 --yes
py -m portscanner 10.0.0.0/30 -p 22,80,443 -f json -o report.json --yes
py -m portscanner --resume scan.wal
py -m portscanner --gui

# GUI directly
py portscanner/gui.py

# Tests
py -m unittest discover -s tests -v

# Optional raw-socket engines (admin shell + Npcap on Windows)
pip install scapy
py -m portscanner 10.0.0.5 -s syn -p 1-1024 --yes   # elevated shell only
```

## 4. File Inventory

```
portscanner/
├── portscanner/
│   ├── __init__.py, __main__.py
│   ├── cli.py, gui.py, scanner.py
│   ├── config.py, security.py, resolver.py
│   ├── events.py, models.py, ratelimit.py
│   ├── scheduler.py, service.py, store.py, report.py
│   └── engines/  (__init__.py, base.py, connect.py, udp.py, raw.py)
├── data/ (top-ports.csv, service-probes.toml)
├── scripts/ (portscan_cli.py, portscan_gui.py — PyInstaller entry points)
├── tests/test_scanner.py
├── portscanner.spec, .gitignore
├── dist/portscanner/  ← built executables (gitignored)
├── pyproject.toml, README.md
└── architecture.md, security.md, state.md, memory.md
```

## 5. Outstanding / Next Steps

| Item | Priority | Where |
|---|---|---|
| IPv6 support (models already version-agnostic) | P2 | `resolver.py`, engines |
| Plugin engine/formatter loading (`~/.portscanner/plugins`) | P2 | `engines/__init__.py` |
| eBPF/AF_XDP fast path | P3 | architecture.md §17 |
| Distributed mode (controller + agents) | P3 | architecture.md §17 |
| Progress ETA (currently indeterminate bar) | P3 | `gui.py` |
| Single-file .exe (onefile) + icon + code signing for AV-friendly distribution | P3 | `portscanner.spec` |

## 6. Rollback / Recovery

- All artifacts are plain files; `git checkout` restores any state.
- WAL is append-only JSONL — a torn tail line is skipped on load (verified logic in `store._load_wal`).
- No external services, databases, or daemons: nothing to deprovision.
