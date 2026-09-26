# Packet Sniffer — Architecture & Security Engineering Design Document

**Author role:** Senior Cyber Security Engineer
**Classification:** Defensive security / Network monitoring / Blue-team tooling
**Intended audience:** Security engineers, SOC analysts, network defenders

---

## 1. Executive Summary

This document specifies a TCP/IP packet sniffer built on **raw sockets** with a
desktop GUI in Python (tkinter, stdlib-only). It parses link-, network- and
transport-layer protocols, presents a flow-style packet list with live
protocol/IP/port filters, byte-level hex inspection, DNS decoding, threat
analysis heuristics (port scan detection, cleartext credential flagging,
ICMP tunneling hints), CSV/PCAP export, and end-to-end **performance
telemetry** (capture → parse → UI render timings).

Design constraints:

| Constraint     | Decision                                              |
|----------------|-------------------------------------------------------|
| Dependencies   | Python stdlib only (socket, struct, threading, tkinter, sqlite3, ctypes) |
| Privileges     | Administrator (Windows: `SOCK_RAW`+`IP_HDRINCL`; Linux: `AF_PACKET` `SOCK_RAW`) |
| Throughput     | Bounded queue (25k packets), coalesced UI refresh (33 ms) |
| Portability    | Windows 10/11, Linux (kernel ≥ 3.x), macOS (BSD desc via BPF — best effort) |
| Legal posture  | Authorized monitoring only — banner gate on startup   |

---

## 2. Threat & Abuse Model (Why the guardrails exist)

A packet sniffer is dual-use. As security engineers we design **for the
defender**, and we hard-code guardrails into the product itself:

1. **Authorization gate** — the GUI refuses to start capture until the
   operator accepts an authorized-monitoring consent banner (checked box).
   Consent is logged with a UTC timestamp in `packets.db`.
2. **Ephemeral by default** — PCAP/CSV artifacts live under a writable local
   `exports/` folder. The DB stores parse summaries, not full payloads
   (first 8 bytes for dissection evidence), to reduce blast radius if the
   analyst workstation is compromised.
3. **No exfiltration** — no network calls anywhere in the codebase except
   the raw socket itself.
4. **Principle of least privilege** — the tool requests admin only for
   `SOCK_RAW`. The GUI degrades gracefully: capture fails with an explicit
   remediation hint ("Run as Administrator") instead of crashing.

---

## 3. System Architecture

### 3.1 Layered View (C4-Style Container Diagram)

```
┌─────────────────────────────────────────────────────────────────┐
│                     Presentation Layer                          │
│   Tkinter GUI (packet-sniffer/gui/main_window.py)               │
│   ┌───────────┬───────────┬───────────┬───────────┐             │
│   │ Filters   │ Packet    │ Protocol  │ Hex Dump  │             │
│   │ Toolbar   │ Treeview  │ Tree      │ Pane      │             │
│   └───────────┴───────────┴───────────┴───────────┘             │
│   ┌───────────────────────┬─────────────────────┐               │
│   │ Statistics sidebar    │ Threat Analysis tab │               │
│   └───────────────────────┴─────────────────────┘               │
└──────────────────────────┬──────────────────────────────────────┘
                           │ queue.Queue (thread-safe) — 25k bound
┌──────────────────────────▼──────────────────────────────────────┐
│                      Service Layer                              │
│   ┌────────────────────┐      ┌────────────────────────────┐   │
│   │ CaptureEngine      │      │ PacketProcessor            │   │
│   │ (producer thread)  │─────▶│ (consumer thread pool)     │   │
│   │ raw socket loop    │      │ parse → enrich → publish   │   │
│   └────────────────────┘      └────────────────────────────┘   │
│   ┌────────────────────┐      ┌────────────────────────────┐   │
│   │ FlowTracker        │      │ ThreatAnalyzer             │   │
│   │ TCP state/flags    │      │ portscan / creds / ICMP    │   │
│   └────────────────────┘      └────────────────────────────┘   │
└──────────────────────────┬──────────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────────┐
│                      Persistence Layer                          │
│   ┌──────────────────┐   ┌──────────────┐   ┌───────────────┐   │
│   │ Storage (sqlite) │   │ Exporter     │   │ PCAP writer   │   │
│   │ packets.db       │   │ CSV / JSON   │   │ (libpcap fmt) │   │
│   └──────────────────┘   └──────────────┘   └───────────────┘   │
└──────────────────────────┬──────────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────────┐
│                      Capture Layer (OS-specific)                │
│   Windows: socket(AF_INET, SOCK_RAW, IPPROTO_IP) + SIO_RCVALL  │
│   Linux:   socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))       │
│   macOS:   AF_INET/SOCK_RAW (IP only, BSD-style) — best effort │
└──────────────────────────────────────────────────────────────────┘
```

### 3.2 Data Flow (per packet)

```
NIC → OS kernel → raw socket → [CaptureEngine thread]
      → queue (bounded, drop-oldest on overflow)
      → [PacketProcessor thread]
      → parse Ethernet/IP/TCP/UDP/ICMP/ARP/DNS
      → enrich (geo-less IP intel flags, flow state, threat heuristics)
      → (a) UI queue → coalesced 33 ms flush → Treeview row
          (b) DB queue → sqlite insert (batched, 200 rows)
          (c) PCAP file → libpcap record write (if recording)
```

### 3.3 Threading Model

| Thread            | Responsibility                                        |
|-------------------|--------------------------------------------------------|
| **Main (GUI)**    | Tk mainloop only. Never touches the raw socket.        |
| **CaptureEngine** | Blocking `recvfrom` on raw socket; enqueues raw bytes. |
| **PacketProcessor** | Dequeues, parses, enriches, fans out to UI/DB/PCAP queues. |
| **UI refresher**  | `root.after(33, ...)` — drains UI queue, batch-inserts rows. |
| **DB writer**     | Own sqlite connection (sqlite objects are not thread-safe across threads). |

**Backpressure strategy:** bounded queues with drop-oldest semantics. On a
1 Gbps link under flood the sniffer must keep capturing; UI/DB loss is
preferable to socket backpressure stalling the kernel buffer.

### 3.4 Capture Subsystem (OS-specific details)

**Windows** (`socket.AF_INET`, `socket.SOCK_RAW`, `IPPROTO_IP`):

```python
s = socket.socket(AF_INET, SOCK_RAW, IPPROTO_IP)
s.bind((HOST_IP, 0))                       # bind to chosen interface IP
s.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)    # capture full IP header
s.ioctl(SIO_RCVALL, RCVALL_ON)             # promiscuous mode on interface
```

- Requires **elevated** (Administrator) process.
- Sees only IP traffic on that interface (no ARP — ARP is L2, Windows raw
  IP socket cannot observe it).
- Loopback (127.0.0.1) is **not** visible to raw sockets on Windows — the
  loopback traffic bypasses the raw-socket path. Documented limitation.

**Linux** (`socket.AF_PACKET`, `SOCK_RAW`):

```python
s = socket.socket(AF_PACKET, SOCK_RAW, socket.ntohs(0x0003))  # ETH_P_ALL
s.bind(("eth0", 0))
```

- Requires `CAP_NET_RAW` (root or capability).
- Sees full L2 frames **including ARP**.
- Supports promiscuous mode via `ioctl(SIOCGIFFLAGS/SIOCSIFFLAGS, IFF_PROMISC)`.

**macOS:** BSD-derived raw sockets (`AF_INET/SOCK_RAW`) deliver IP packets
only; BPF (`/dev/bpf*`) would be needed for full L2. Marked best-effort.

### 3.5 Parsing Pipeline

```
raw frame
  ├── L2: Ethernet II (dst MAC 6 | src MAC 6 | EtherType 2)
  │      EtherType 0x0806 → ARP
  │      EtherType 0x0800 → IPv4
  │      EtherType 0x86DD → IPv6 (stub)
  ├── L3: IPv4 header (IHL 5–15 words → options length varies)
  │      proto 1 → ICMP   proto 6 → TCP   proto 17 → UDP
  ├── L4: TCP (src/dst port, seq/ack, flags, window, options → MSS/SACK/window-scale)
  │       UDP (length, payload → DNS/NetBIOS/QUIC detection)
  └── L7: DNS (header + QD/AN/NS/AR counts + name decompression)
```

Parsing is done with `struct.unpack_from` against `memoryview` slices —
zero-copy where the stdlib allows. Malformed packets raise
`PacketParseError`, are logged, counted, and skipped — **never** crash the
capture loop (a hostile packet must not be a DoS vector against the sniffer
itself — that's a real historical bug class: CVE-2016-XXXX-style parser
panics in capture tools).

### 3.6 Persistence Schema (sqlite)

```sql
CREATE TABLE packets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL, src_ip TEXT, dst_ip TEXT, src_port INTEGER, dst_port INTEGER,
    protocol TEXT, length INTEGER, info TEXT, threat_score INTEGER,
    raw_hex TEXT
);
CREATE TABLE events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL, kind TEXT, src_ip TEXT, description TEXT, severity TEXT
);
CREATE TABLE consent (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, accepted INTEGER
);
```

`events` holds threat-analyzer output (scans, credential hits, ICMP tunnels).
`consent` is the audit trail for the authorization gate.

### 3.7 Export Formats

- **PCAP** — classic libpcap format, LINKTYPE_ETHERNET (1), correct global
  header magic `0xa1b2c3d4` (microsecond resolution). Written by
  `pcap_writer.py`. Reconstructed Ethernet+IP frames so Wireshark can open
  the export directly.
- **CSV** — flat analyst-friendly summary row per packet.
- **JSON** — machine-readable for SIEM ingestion pipelines.

---

## 4. Security Engineering Review

### 4.1 Attack surface of the sniffer itself

| Vector                        | Mitigation in this design                      |
|-------------------------------|------------------------------------------------|
| Malformed packet → parser crash | try/except per packet, `PacketParseError` containment, counter |
| GUI freeze under flood        | bounded queue + drop-oldest + coalesced render |
| Disk fill (long captures)     | PCAP max size 500 MB rotating; DB stores summaries only |
| sqlite thread corruption      | single-writer thread owns the connection       |
| Privilege creep               | admin only for socket creation; nothing else elevated |
| Sensitive data at rest        | payload truncated to 8 bytes in DB; exports are operator-initiated |

### 4.2 Threat-detection heuristics (ThreatAnalyzer)

- **Port scan** — ≥ 10 unique dst ports from one source in ≤ 30 s window,
  flag severity `medium`; ≥ 25 ports → `high`.
- **Cleartext credential** — regex on ASCII payload for `user=`, `pass=`,
  `USER`, `PASS`, `Authorization:` — flags FTP/TELNET/HTTP-basic style leaks.
- **ICMP tunnel** — payload > 32 bytes on ICMP Echo → possible
  `icmpsh`/`ptunnel` style exfiltration.
- **TCP null/Xmas/Syn flood heuristics** — flag-rate counters per source.

Each event gets a severity and is persisted to `events` and surfaced on the
Threat tab in the GUI.

### 4.3 Operational Security (OPSEC) notes

- The tool itself puts the NIC into **promiscuous mode** — observable on the
  network via switch CAM-table anomalies; use only on networks you defend.
- Exports contain raw traffic — handle per your org's data-handling policy.
- Do not run capture on a host with unencrypted remote-desktop sessions to
  other hosts if untrusted parties have console access.

---

## 5. Performance Engineering

- **Parser:** `struct.unpack_from` on `memoryview` — no intermediate copies.
- **UI:** never render per-packet. Coalesce at 30 fps (`after(33, ...)`).
  25k-row treeview cap with FIFO eviction keeps Tk responsive.
- **DB:** batched inserts every 200 packets or 5 s, whichever first.
- **Expected throughput** on a modern laptop: ~40–60k pps parse, ~10k pps
  full-pipeline (capture→parse→UI) before drops.

Telemetry counters (parse errors, drops, pps) are surfaced in the status bar
so the operator knows when they're flying blind.

---

## 6. Usage

```
py packet_sniffer_gui.py
```

- Pick interface IP in the dropdown → Authorize → Start.
- Filters: protocol chips, IP/PORT free-text.
- Double-click a row → detail pane with per-layer decode + hex dump.
- Right-click → Copy as hex / Copy summary.
- Threat tab: live events. Stats sidebar: protocol distribution.
- File menu: Export CSV / PCAP / Clear.

## 7. Limitations & Roadmap

| Limitation (accepted)                    | Roadmap idea                          |
|------------------------------------------|---------------------------------------|
| Windows loopback invisible               | NPcap loopback adapter integration    |
| No TCP stream reassembly                 | Follow-TCP-stream feature             |
| IPv6 parse-only (stub)                   | Full IPv6 + extension headers         |
| No TLS SNI extraction                    | Add SNI/JA3 fingerprinting            |

---

## 8. Legal & Ethical Use

Packet capture is lawful **only** with explicit authorization: network owner
consent, written scope, retention limits. In corporate environments, align
with your monitoring policy (e.g., an Acceptable Use Policy banner, and
GDPR/CCPA data-minimization rules for any payload capture). Unauthorized
interception of communications is a crime in most jurisdictions
(e.g., 18 U.S.C. § 2511, Computer Misuse Act 1990 s.1, etc.).

**This tool is built for defenders. Use it that way.**
