# ARP Scanner — Live-Host Discovery Tool (GUI)

A Windows-ready ARP live-host discovery tool with a modern **PySide6 (Qt)** GUI,
implemented exactly per [`archetecture.md`](archetecture.md). Packaged as a
standalone `.exe` via PyInstaller.

## Features

- ARP who-has / is-at live-host discovery on a CIDR or IP range
- Qt GUI with background scan thread (UI never freezes), progress bar, live
  results table, audit log pane
- MAC vendor (OUI) lookup, RTT capture
- Export to CSV / JSON (atomic writes, CSV-injection sanitized)
- Security-first layer: explicit consnet banner, privilege checks, strict input
  validation, audit logging — see [`security.md`](security.md)

## Requirements

- Python 3.10+ (built against 3.12)
- **Windows:** Npcap installed (https://npcap.com) and run **as Administrator**
  (raw L2 access). Windows 10/11.

## Quick start (from source)

```powershell
py -3.12 -m venv .venv
.venv\Scripts\activate
python -m pip install -r requirements.txt
python -m pip install -e .
arp-scanner            # or: python run_app.py
```

## Build the .exe

```powershell
.\build_exe.bat
# output: dist\ArpScanner\ArpScanner.exe
```

## Usage

1. Enter a target — `192.168.1.0/24` or `192.168.1.1-192.168.1.50`.
2. Pick the interface (default: auto-detected).
3. Set timeout / retries, then **Start Scan**.
4. Results stream into the table; export from the **File** menu.

> Scan only networks you are authorized to probe. The tool displays a
> consnet notice on first launch and logs every scan to the audit log.

## Project layout

```
arp_scanner/
├── app.py          # Qt entry point
├── core/           # scan engine (config, packets, sender, engine, result, devices)
├── gui/            # PySide6 UI + background scan worker
├── report/         # CSV/JSON exporters
├── security/       # guard layer (consnet, privileges, validation, audit)
└── util/           # IP/CIDR math, logging helpers
tests/              # pytest suite
security.md         # OWASP / ISO 27001 / NIST mapping
state.md            # current project state + reservations
memory.md           # conventions & reference memory
archetecture.md     # architecture reference
```