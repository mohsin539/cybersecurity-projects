# Packet Sniffer — Raw Socket GUI (Python)

**Defensive network monitoring tool** — authorized-use only. See
`ARCHITECTURE.md` for the full security engineering design document.

## Features

- Raw socket capture (Windows `SIO_RCVALL` / Linux `AF_PACKET`, promisc mode)
- Parsers: Ethernet II, ARP, IPv4 (+fragments detected), TCP (+options),
  UDP, ICMP, DNS (with name decompression), IPv6 stub
- GUI: protocol chips, live text filter, protocol-colored packet list,
  per-layer detail tree, hex dump, stats sidebar (pps sparkline, protocol bars)
- Threat heuristics: port scan, SYN flood, cleartext credentials,
  ICMP tunneling, ARP spoofing, risky service exposure
- Persistence: SQLite (`packets.db`) — packet summaries, threat events, consent audit trail
- Exports: CSV, JSON, **PCAP** (opens directly in Wireshark)
- Zero third-party dependencies — Python 3.10+ stdlib only

## Quick Start

```bash
# Windows — MUST be elevated (Administrator terminal)
py packet_sniffer_gui.py

# Linux
sudo python3 packet_sniffer_gui.py

# No admin? Try demo mode (synthetic packets, no privileges needed)
py packet_sniffer_gui.py --demo
```

## Portable EXE (Windows)

```bash
build_exe.bat                 # or: py -m PyInstaller packet_sniffer.spec
```

Output: `dist/PacketSniffer.exe` — a single ~12.5 MB self-contained file.
Copy it anywhere (USB stick, analyst laptop) and run:

```bash
dist\PacketSniffer.exe --demo   # no privileges needed
dist\PacketSniffer.exe          # run from an Administrator prompt for capture
```

Notes: the exe is unsigned — SmartScreen may show "More info → Run anyway".
Some AVs heuristic-flag unsigned capture tools (SIO_RCVALL usage); whitelist
if so. No elevation is embedded in the manifest (least privilege) — elevate
the terminal instead when you want raw-socket capture.

## Demo mode

`--demo` generates synthetic ARP/TCP/UDP/DNS/ICMP frames through the real
parser pipeline so you can validate the UI, detail panes, threat engine and
exports without elevation. It also injects a scripted "port scan" and a
"cleartext credential" pattern so you can watch the Threats tab fire.

## Legal

Intercepting network traffic without authorization is illegal in most
jurisdictions (e.g., 18 U.S.C. § 2511, Computer Misuse Act 1990, EU GDPR
ePrivacy rules). Use only on networks you own or are explicitly authorized
to monitor. The app enforces an authorization checkbox and logs consent.
