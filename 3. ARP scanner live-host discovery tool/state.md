# State — ARP Live-Host Discovery Tool

**Version:** 1.0 · **Doc purpose:** current project state, reservation
register, decision log. This file is the canonical "where are we?" reference.
Updated whenever a milestone completes or a reservation is opened/closed.

---

## 1. Current Status

| Area | Status | Detail |
|---|---|---|
| Architecture | **Implemented** | ALL components of `archetecture.md` v1.0 built |
| Core engine | ✔ Complete | config, packets, sender (burst-send), engine, result, devices |
| GUI (PySide6) | ✔ Complete | MainWindow, scan QThread worker, table, progress, audit pane, export actions |
| Security layer | ✔ Complete | consent gate, privilege check, input/CSV/path validation, audit logging |
| Tests | ✔ **59 passed** | `pytest` green (net, packets, config, export, guard, devices) |
| Packaged `.exe` | ✔ Built | `dist\ArpScanner\ArpScanner.exe` (~8.5 MB) — offscreen launch verified |
| Docs | ✔ Complete | `archetecture.md`, `security.md`, `state.md`, `memory.md`, `README.md` |

**Last verified:** 2026-09-12 · Python **3.12.7** · PySide6-Essentials **6.11.2** ·
scapy **2.7.0** · psutil **7.2.2** · PyInstaller **6.22.2** · Npcap installed/running.

---

## 2. Reservation Register

Reservations are intentionally deferred decisions or bounded choices. Each has
an owner (always "project" unless noted), status, and close criteria.

| # | Reservation | Status | Detail / Close criteria |
|---|---|---|---|
| R-001 | Interface-name mapping psutil ↔ scapy | **OPEN (bounded)** | psutil returns friendly names (`Ethernet 2`); scapy needs Npcap device names. `resolve_interface()` handles auto-matching. Close when a full cross-OS mapping table test passes on Windows/Linux/macOS. |
| R-002 | Concurrency model change | **CLOSED (decision)** | Architecture v1 proposed per-IP async workers; implementation uses **burst-send + single capture window** (send all who-has, then listen `timeout`). Total wall time ≈ timeout regardless of host count. `workers` retained as pacing metadata. |
| R-003 | OUI vendor table is a curated subset | **OPEN** | ~140 widely deployed prefixes bundled in `devices.py`. Close when a full IEEE OUI database (or licensed source) is integrated, keeping `lookup_vendor()` API stable. No law required - optional enhancement. |
| R-004 | Consent marker storage | **CLOSED (decision)** | `%APPDATA%\ArpScanner\consent.v1` = UTC timestamp only (no identity). POSIX fallback `~/.config/arpscanner`. Privacy-preserving by design. |
| R-005 | `.exe` requires Admin + Npcap; **no auto-elevation** | **CLOSED (decision)** | Capability check surfaces guidance instead (security.md A01/least privilege). Auto-elevation would violate least privilege. |
| R-006 | Audit log volume/rotation | **CLOSED (decision)** | 5 MB rotate, single `.log.1` history, owner-only perms. Scale if deployments exceed. |
| R-007 | Code signing & hash manifest for distributable `.exe` | **OPEN (recommended)** | Close when release pipeline signs with Authenticode and publishes SHA-256 manifest (security.md §9). |
| R-008 | SBOM / dependency lockfile | **OPEN** | `requirements.txt` pins lower bounds only. Close when a release lockfile (exact pins) is published and reviewed. |
| R-009 | Reserved-address handling | **CLOSED (decision)** | `.0`/`.255` excluded by default; `include_reserved` flag opts in. Matches architecture §12. |
| R-010 | Crash reporting | **CLOSED (decision)** | Local `crash.log` via excepthook; **no telemetry/remote crash service** (privacy reservation, security.md §6). |

---

## 3. Milestone Log (what has been done)

1. **[2026-09-12] M0 — Environment:** Python 3.12.7 via `py -3.12`; Npcap present;
   network access to PyPI confirmed.
2. **[2026-09-12] M1 — Scaffold:** `pyproject.toml`, `requirements.txt`,
   package layout, entry points (`arp_scanner.app:main`, `python -m arp_scanner`).
3. **[2026-09-12] M2 — Core engine:** config/packets/sender/engine/result/devices.
   First real-scan probe correctly returned a `PermissionDenied` guidance error
   (non-admin shell) — expected behavior confirmed.
4. **[2026-09-12] M3 — Security guard:** consent gate, privilege check, target &
   CSV-injection & path validation, audit logging, atomic exports.
5. **[2026-09-12] M4 — GUI:** PySide6 MainWindow + `ScanWorker` QThread wiring,
   offscreen smoke test passed (6 interfaces enumerated, local IP/MAC resolved).
6. **[2026-09-12] M5 — Tests:** 59 pytest cases green; verified bugs found &
   fixed during test pass (CIDR mask regex 30–32, OUI prefix slice).
7. **[2026-09-12] M6 — Packaging:** `arp_scanner.spec` + `build_exe.bat`;
   `dist\ArpScanner\ArpScanner.exe` built; frozen app launched (offscreen) and
   wrote an audit log with correct UTC timestamps.
8. **[2026-09-12] M7 — Docs:** `security.md` (OWASP/ISO/NIST), `state.md`,
   `memory.md`, `README.md`.

---

## 4. Open Items / Next Steps (priority order)

1. **Fully validate a live scan as Admin** — run `.exe` (or `python run_app.py`)
   elevated on the target segment; confirm HostInfo/vendor/RTT populated end-to-end.
2. **R-007 release hardening** — code signing, SHA-256 manifest, exact-pin lockfile (R-008).
3. Restore per-IP **progress throttle** ~1k emits/scan is adequate; evaluate >/16.
4. Optional roadmap (architecture §19): ICMP cross-check, reverse-DNS names, port-scan mode, passive mode, recurring-scan UI, IPv6 (NDP/ICMPv6), full IEEE OUI DB (R-003).

---

## 5. Decision Log (ADR-style)

| ID | Decision | Rationale | Date |
|---|---|---|---|
| D-01 | **PySide6** (Qt) over Tkinter | User-selected; professional widget set; e2e packaging proven with `collect_all('PySide6')` | M0 |
| D-02 | **PySide6-Essentials** (not full PySide6) | Skips WebEngine/QML/Addons → smaller exe & install; QtWidgets covers all needs | M0 |
| D-03 | **Burst-send + single listen** (over per-IP workers) | Wall-time ≈ timeout independent of host count; scapy `AsyncSniffer` is thread-safe for capture; avoids per-socket races | M1 |
| D-04 | scapy 2.7 lazy-imports at scan time | Keeps GUI cold-start fast (~0.5 s); heavy protocol init deferred | M2 |
| D-05 | psutil for interface enumeration | Stable, cross-platform friendly-name + MAC mapping beats scapy's `conf.ifaces` for UI population | M2 |
| D-06 | `console=False` windowed exe + `crash.log` excepthook | No console leak; diagnostics via local crash file instead | M6 |
| D-07 | Consent as first-run gate, no auto-elevation | Least-privilege + authorization-by-design (security.md) | M3 |
| D-08 | Atomic export via tempfile + `os.replace` | Reader never observes partial files; fsync'd before rename | M3 |
| D-09 | Tests via captured-file process runners in this environment | Native `pip`/`pytest` piping stalls in the interactive shell; `Start-Process` + redirect proved reliable | M5 |

---

## 6. Artifacts & Locations

| Artifact | Path |
|---|---|
| Architecture | `archetecture.md` |
| Security mapping | `security.md` |
| This state doc | `state.md` |
| Conventions memory | `memory.md` |
| Source package | `arp_scanner/` |
| Tests | `tests/` (59 cases) |
| Smoke scripts | `scripts/` (`_gui_smoke.py`, `_scan_probe.py`, `_smoke_imports.py`) |
| PyInstaller spec | `arp_scanner.spec` |
| Build script | `build_exe.bat` |
| Built artifact | `dist\ArpScanner\ArpScanner.exe` |
| Runtime data (Windows) | `%APPDATA%\ArpScanner\` (`audit.log`, `consent.v1`, `crash.log`) |

---