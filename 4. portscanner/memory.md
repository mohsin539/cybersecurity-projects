# memory.md — Project Memory & Decision Record

> **Purpose:** durable context for any future session (human or AI agent).
> Read this **before** changing the codebase: it captures *why* things are the
> way they are, what was tried, and the invariants that must not be broken.
> Companion to `architecture.md` (design), `security.md` (controls),
> `state.md` (current status).

---

## 1. Project Identity

- **What:** authorized-use TCP/UDP port scanner — CLI + tkinter GUI.
- **Design reference:** `architecture.md` (Go-oriented doc; implemented in Python by decision D1).
- **Stack:** Python ≥ 3.11, **stdlib-only core**; scapy optional for raw engines.
- **Non-negotiable:** the tool exists *only* for authorized testing; the
  authorization gate (C1) and audit trail (C2) are load-bearing features, not extras.

## 2. Decision Record

| ID | Decision | Rationale | Alternatives rejected |
|---|---|---|---|
| D1 | Python 3.11+ instead of Go | User requested Python; `StrEnum`, `tomllib`, modern typing available | Go (design doc default), Rust |
| D2 | Stdlib-only runtime deps | security.md C11 (supply chain, OWASP A06); instant install; GUI via tkinter needs nothing extra | Third-party async frameworks |
| D3 | Threads + bounded `queue.Queue` instead of asyncio | Engines are blocking-socket oriented; threads keep engine code simple and portable; worker count is capped anyway (§6) | asyncio (better for 10k+ concurrent, revisit if needed) |
| D4 | Event bus (pub/sub) decoupling | UI and store must never slow or crash the scan loop (architecture.md A1/A4) | Direct callbacks |
| D5 | JSONL WAL for resume | Append-only = crash-safe; torn tail lines skipped on load (§10) | SQLite (heavier; binary diffs harder to audit) |
| D6 | Raw engines isolated in `engines/raw.py`, scapy import guarded | Unprivileged path stays dependency-free; privilege checked at probe time (C9) | Requiring admin for everything |
| D7 | `filtered` for RST-supplied timeouts | Honesty rule §5.1: silence ≠ closed. Environment-specific but *correct* | Asserting `closed` on timeout |
| D8 | GUI polls a thread-safe `queue` | Tkinter is single-threaded; `after()` pump marshals worker events safely | Direct cross-thread widget calls (unsafe) |
| D9 | Probe DB in code + optional TOML override | Small useful default set; users extend without touching Python | Full nmap-service-probes port (scope creep) |
| D10 | Audit log in `~/.portscanner/` | Per-user separation on multi-user hosts; 0600 perms possible (C2/C7) | Project-local log (leaks across users) |
| D11 | PyInstaller **onedir** packaging (`portscanner.spec`) | Instant startup, fewer AV false positives than onefile; two exes share one `_internal/`; data files bundled where `service.py`'s relative lookup already points | onefile (slow start, AV flags), Nuitka (heavier toolchain) |

## 3. Invariants (do not break)

1. **No packet is ever sent before** `config.validate()` passes and the
   authorization gate (C1) grants.
2. Every result carries **evidence**; a state is never asserted from nothing
   (§5 honesty rule — see D7).
3. All queues/channels are **bounded**; memory stays O(workers × depth), never O(jobs) (§6).
4. Machine-readable output always carries `schema_version` (§11 stability contract).
5. Raw-socket code lives **only** in `engines/raw.py` (C9).
6. Banners are **always** passed through `security.sanitize_text` before storage/report.
7. `connect_ex()` in timeout mode must **not** be reintroduced on Windows —
   it returns 10035 immediately and misclassifies (verified 2026-09-12; see state.md §2).
8. Audit failures degrade to stderr warnings, never crash the scan; scan
   results are never written to the audit log unredacted.

## 4. Gotchas & Lessons Learned (this environment)

- **Windows Python launcher:** `python`/`python3` resolve to the Store stub —
  use **`py`** for everything.
- **RST-suppressed loopback:** on this machine, refused TCP connects raise
  `TimeoutError` (no `ECONNREFUSED`), so refused ports report `filtered`.
  Stock stacks will report `closed` with the same code. Test asserts
  `closed|filtered` accordingly.
- **WSA errno surface:** Windows surfaces WSA codes (10061 etc.), not POSIX
  errno, through `OSError.errno` — mapping tables live in `engines/connect.py`.
- **Tkinter availability:** verified importable with Python 3.12 here.
- **Audit `?` in table footer:** the `probes_sent` stat is approximate in v1
  (counted as targets × ports; retries not included) — cosmetic only.
- **PyInstaller hiddenimports:** `scanner.py` uses a dynamic
  `__import__('portscanner.models', …)` and engines self-register on import,
  so the spec pulls in `collect_submodules("portscanner")` — add a new
  submodule there (or import it statically) if it ever goes missing in the exe.
- **Bundled data path:** `service.py` resolves `data/service-probes.toml`
  relative to the package `__file__`; PyInstaller points `__file__` under
  `_internal/` (onedir) or `_MEIPASS` (onefile), so spec datas entries with
  dest `"data"` resolve correctly in both modes.
- **Bugs fixed during packaging (2026-09-12),** found via frozen-exe smoke
  tests: TOML probe regexes must be compiled as **bytes** (`service.py`), and
  the WAL must stay open through the service pass (`scanner.py run()`).
  Details and verification in `state.md` §2.

## 5. Glossary (shared vocabulary)

| Term | Meaning |
|---|---|
| **Settled** | (host, port) reached a terminal state — late duplicates ignored (§8) |
| **Inconclusive** | `filtered` / `open\|filtered` / `closed\|filtered` / `unreachable` — retry-eligible |
| **WAL** | write-ahead log; append-only JSONL of every settled result, enables `--resume` |
| **Probe DB** | ordered payload/regex list for service identification (§4.5) |
| **Gate (C1)** | authorization confirmation required for non-private targets & raw scans |
| **Host-down pruning** | after k consecutive `unreachable`, remaining jobs for a host are dropped (§8) |

## 6. Session Handoff Checklist

If you (future maintainer or agent) are resuming work:

1. Read `state.md` §1–§2 for what is done and verified.
2. Run `py -m unittest discover -s tests -v` — expect 11/11 OK.
3. Respect §3 invariants; if one must change, update `security.md` §2 and the tests *together*.
4. New engine? Register it in `engines/__init__.py`, add classification tests, update architecture.md §4.4 table.
5. New output field? Bump nothing if additive; document in architecture.md §7; keep `schema_version`.
6. Record any new environment quirk in §4 above — that list saves future debugging hours.
7. Update `state.md` (status + verification record) as the last step of any change.

## 7. Prior Art & References

- nmap — scan techniques, state semantics (`nmap.org/book/man-port-scanning-basics.html`)
- architecture.md §5 — packet flows each engine implements
- ISO/IEC 27001:2022 Annex A · NIST SP 800-53 Rev.5 · OWASP Top 10 2021 — control sources for security.md
