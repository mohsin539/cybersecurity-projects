# STATE.md — Project State Snapshot

> **Purpose:** Detailed, machine-current snapshot of what is built, verified,
> and pending. Read this first when resuming work. Companion file: `memory.md`
> (why decisions were made, environment details, command history).

**Last updated:** 2026-09-09 (session 2, post-build)
**Project root:** `packet-sniffer/`
**Status:** ✅ Complete & verified — GUI + **portable exe built & launch-tested**
(`dist/PacketSniffer.exe`, 12.5 MB)

---

## 1. Component Status Matrix

| Component | File | Status | Notes |
|---|---|---|---|
| Architecture doc | `ARCHITECTURE.md` | ✅ done | C4-style design, threat model, perf engineering |
| Parsers | `parsers.py` | ✅ done & tested | ETH/ARP/IPv4/TCP/UDP/ICMP/DNS, IPv6 stub; zero-copy |
| Capture engine | `capture.py` | ✅ done & tested | Win SIO_RCVALL + Linux AF_PACKET; bounded queue |
| Storage | `storage.py` | ✅ done & tested | sqlite; batched; **drain-on-stop verified** |
| PCAP writer | `pcap_writer.py` | ✅ done & tested | libpcap format byte-validated; 500 MB rotation |
| Threat engine | `threat.py` | ✅ done & tested | cooldown dedup + severity escalation verified |
| GUI | `gui.py` | ✅ done & tested | incremental render, filters, detail/hex, threats tab |
| Theme | `gui_theme.py` | ✅ done | fonts + tag colors |
| Demo mode | `demo.py` | ✅ done & tested | synthetic traffic incl. scripted port scan |
| Entry point | `packet_sniffer_gui.py` | ✅ done | `--demo` flag support |
| Threat→DB wiring | `gui.py` | ✅ added & **verified session 2** | `_on_threat_event` persists to `events` (row content asserted) |
| Packaging | `requirements.txt`, `packet_sniffer.spec`, `build_exe.bat`, `.gitignore` | ✅ added session 2 | PyInstaller one-file exe |
| **Portable exe** | `dist/PacketSniffer.exe` | ✅ **built & launch-tested** | 12,511,589 B; demo mode verified; terminated cleanly |
| State/memory | `STATE.md`, `MEMORY.md` | ✅ added session 2 | continuity documents |

## 2. Verified Behaviors (test evidence)

All of these were executed against the real code and passed:

1. **Parse correctness** — 40/40 demo frames parse; TCP SYN/ACK ports+flags,
   DNS `example.com` query decode, ICMP "tunneling?" hint, ARP "Who has"
   summary, IPv6 stub all asserted.
2. **Threat engine** — scripted 30-port SYN sweep emits exactly
   `('PORTSCAN','medium')` once and `('PORTSCAN','high')` once (cooldown
   keyed by kind+src+severity, 10 s). CREDS and ICMP_TUNNEL fire on crafted
   payloads.
3. **PCAP writer** — global header magic `0xa1b2c3d4`, record length =
   24 + 16 + frame; Wireshark-compatible.
4. **Storage durability** — `stop()` drains queued rows before close;
   verified by counting rows after stop (1 packet + 1 event).
5. **GUI pipeline** — 150 synthetic frames through the REAL processor path:
   150 rows rendered; detail pane `▸ ETH`; hex pane shows the ARP broadcast
   frame bytes; filter `443` narrows 150→12 rows; 4 threat events displayed;
   stats sidebar totals correct.
6. **Interface discovery** — 4 interfaces found live:
   `192.168.0.102, 192.168.158.1, 192.168.42.1, 192.168.56.1`.

## 3. How To Run

```bash
cd packet-sniffer
py packet_sniffer_gui.py --demo     # no admin; synthetic traffic + scripted attacks
py packet_sniffer_gui.py            # real capture; MUST be elevated terminal

# Portable exe (ALREADY BUILT at dist/PacketSniffer.exe; rebuild with build_exe.bat)
dist\PacketSniffer.exe --demo       # portable exe demo (no privileges)
dist\PacketSniffer.exe              # real capture from elevated prompt
```

## 4. Known Limitations (accepted, by design)

| Limitation | Reason | Workaround |
|---|---|---|
| No Windows loopback capture | raw IP sockets bypass loopback path | NPcap adapter (roadmap) |
| No ARP visibility on Windows | SIO_RCVALL is IP-only | Linux capture path sees ARP |
| IPv6 is a stub | scope control | full ext-header parser (roadmap) |
| No TCP stream reassembly | scope control | Follow-TCP-stream (roadmap) |
| Exe not code-signed | no cert available | SmartScreen "More info → Run anyway" |

## 5. Pending / Next Steps

- [x] ~~Portable exe build~~ — done & launch-tested this session
- [x] ~~Threat events persisted to `events` table~~ — done & verified
- [ ] Optional: pytest suite file `tests/test_parsers.py` (test logic exists
      in session history, could be materialized)
- [ ] Roadmap items from ARCHITECTURE.md §7 (SNI/JA3, stream reassembly,
      IPv6 full parser, NPcap loopback)
- [ ] Optional: code-signing cert for the exe
- [ ] Optional: icon resource for exe (`icon='app.ico'` in spec)

## 6. File Map (all under `packet-sniffer/`)

```
ARCHITECTURE.md          design document (§ refs used throughout code)
README.md                quickstart + legal
STATE.md                 this file
MEMORY.md                decisions/environment/history
packet_sniffer_gui.py    entry point (--demo)
gui.py                   main GUI window (SnifferGUI)
gui_theme.py             theme/colors
parsers.py               protocol decoders (Packet dataclass)
capture.py               CaptureEngine, CaptureStats, list_interfaces
threat.py                ThreatAnalyzer, ThreatEvent
storage.py               Storage (sqlite), Exporter (CSV/JSON)
pcap_writer.py           PcapWriter (libpcap format)
demo.py                  synthetic frame builder + demo runner
requirements.txt         build-time deps (runtime: none)
packet_sniffer.spec      PyInstaller one-file spec
build_exe.bat            Windows build script
.gitignore               build/runtime artifacts
```
