# ARP Scanner — Live-Host Discovery Tool Architecture

**Document Version:** 1.0
**Status:** Draft / Initial Architecture
**Scope:** Full system design for a network tool that discovers live (active) hosts on a local network segment using ARP (Address Resolution Protocol).

---

## Table of Contents

1. [Document Purpose](#1-document-purpose)
2. [System Overview](#2-system-overview)
3. [Goals and Non-Goals](#3-goals-and-non-goals)
4. [Technology Stack](#4-technology-stack)
5. [System Context Diagram](#5-system-context-diagram)
6. [High-Level Architecture](#6-high-level-architecture)
7. [Component Design](#7-component-design)
8. [Data Model / Schema](#8-data-model--schema)
9. [Core Workflow (Scan Lifecycle)](#9-core-workflow-scan-lifecycle)
10. [Networking Fundamentals](#10-networking-fundamentals)
11. [Concurrency & Performance Design](#11-concurrency--performance-design)
12. [Error Handling & Edge Cases](#12-error-handling--edge-cases)
13. [Security Considerations](#13-security-considerations)
14. [Observability & Logging](#14-observability--logging)
15. [Deployment & Runtime Environment](#15-deployment--runtime-environment)
16. [Configuration](#16-configuration)
17. [Testing Strategy](#17-testing-strategy)
18. [Performance Budget](#18-performance-budget)
19. [Future Extensions & Roadmap](#19-future-extensions--roadmap)
20. [Glossary](#20-glossary)

---

## 1. Document Purpose

This document defines the complete architecture for an **ARP scanning tool** used to perform live-host discovery on a local IP network. It serves as the design reference for developers, explains how each component works, and establishes the technical and operational contracts (performance, security, error handling) that the implementation must satisfy.

The tool answers the question: **"Which devices are currently active on this network segment?"** It does so by sending ARP request frames to every IP in the target subnet and recording the hosts that respond with their MAC address.

---

## 2. System Overview

An ARP scanner is a simple but powerful network reconnaissance utility:

- It operates at **Layer 2 (Data Link)** of the OSI model using the ARP protocol.
- It sends a broadcast ARP *who-has* request for a range of target IP addresses.
- Hosts that are alive respond with an ARP *is-at* reply carrying their hardware (MAC) address.
- The scanner captures, parses, and correlates responses into a structured list of live hosts.

Because ARP works only within a single broadcast domain, the tool is inherently a **local subnet scanner** — it is not designed to discover hosts across routers or on the internet.

### Key capabilities

| Capability | Description |
|---|---|
| Subnet/IP-range scanning | Scan a CIDR block (e.g. `192.168.1.0/24`) or an explicit IP range. |
| Live-host detection | Identify hosts that reply to ARP requests. |
| MAC address discovery | Capture the MAC address + vendor (OUI) of each responding device. |
| Response-time capture | Record the ARP round-trip time as a latency metric. |
| Export | Dump results to CSV / JSON / terminal table for analysis. |
| Silent / verbose modes | Toggle request/response frame detail logging. |

---

## 3. Goals and Non-Goals

### 3.1 Goals

- **Correct live-host discovery** on a local subnet with high recall (few missed hosts).
- **Fast scans**: complete a full `/24` scan (254 addresses) in under a few seconds, a `/16` in bounded time using sliding-window concurrency.
- **Human-readable output** plus machine-readable export formats.
- **Cross-platform** support where feasible (Windows, Linux, macOS).
- **Low footprint**: no heavy dependencies; usable by a single operator on a workstation.
- **Deterministic, reproducible** behavior given the same subnet and network conditions.

### 3.2 Non-Goals (Out of Scope for v1)

- **Internet-wide scanning** or cross-subnet scanning.
- **Port scanning** (that is a separate TCP/UDP-based tool).
- **OS fingerprinting** — can be added later via TTL analysis.
- **ARP cache population / static ARP entry management**.
- **MITM or ARP spoofing detection** (only passive correlation is done in v1; a detection mode may come later).
- **Persistent centralized database / multi-user web UI** (results are per-scan, saved locally).

---

## 4. Technology Stack

| Layer | Choice | Rationale |
|---|---|---|
| Scripting language | **Python 3.11+** | Readability, rich ecosystem (`scapy`, `asyncio`), fast prototyping. |
| Packet crafting / capture | **Scapy** | Cross-platform L2 packet crafting, built-in ARP class, `srp()`/`srp1()` primitives. |
| Networking abstraction | **Raw sockets / PF_PACKET (Linux)**, `AF_PACKET` fallback | For cases where we bypass Scapy for speed (optional fast path). |
| Concurrency | **asyncio + await** with Scapy's async `AsyncSniffer` or thread-pool with `srp` | Bounded concurrency keeps CPU low while overlapping slow hosts. |
| Output | Built-in `archer` table (terminal), **CSV**, **JSON** | Zero external dependency for human output; standard formats for tooling. |
| Declarative config | Standard library `argparse` + optional YAML/JSON config file | Keep CLI-first, allow config templates. |
| Testing | `pytest`, `pytest-asyncio`, optional `pytest-cov` | Standard Python testing toolchain. |
| Packaging | `setuptools` / `pyproject.toml`, `pip install -e .` | Simple installation, CL entrypoint via `console_scripts`. |

> **Note on privileges:** raw socket access (creating ARP frames) requires root/admin privileges on all major OSes. The tool must detect this and give a clear, actionable error.

---

## 5. System Context Diagram

```
                         +---------------------------+
                         |       Network Medium      |
                         |   (Layer 2 broadcast)      |
                         +-------------+-------------+
                                       ^ ARP frames (multicast/broadcast)
                                       |
        +-----------------------------+-----------------------------+
        |                          ARP Scanner                        |
        +-------------------------------------------------------------+
            |                 |                |              |
            v                 v                v              v
      +---------+       +---------+      +----------+   +-----------+
      | CLI     |       | Scanner |      | Reporter |   | Config    |
      | (Input) | ----> | Engine  | ---> | (Output) |<--| Parser    |
      +---------+       +---------+      +----------+   +-----------+
                                 |             |
                                 |             v
                                 |      +------------+
                                 |      | Exporter   |
                                 |      | (CSV/JSON) |
                                 |      +------------+
                                 v
                        +----------------+
                        | Logging /      |
                        | Observability  |
                        +----------------+
```

**External entities:**
- **Operator** — a human or automation invoking the CLI with a target subnet.
- **Network (L2 broadcast domain)** — destination for ARP frames and source of replies.
- **Filesystem** — for reading a config file and writing export artifacts.

---

## 6. High-Level Architecture

The tool is organized into **six** cohesive modules. Each module has a single responsibility and a well-defined interface.

```
arp_scanner/
├── __init__.py
├── __main__.py            # python -m arp_scanner entrypoint
├── cli.py                 # argument parsing, orchestration, exit codes
├── config.py              # config loading & validation
├── scanner/
│   ├── __init__.py
│   ├── engine.py          # scan orchestrator (scheduling, concurrency)
│   ├── packets.py         # ARP frame builder/parser
│   ├── sender.py          # low-level send/receive primitives
│   ├── result.py          # ScanResult dataclasses & aggregation
│   └── devices.py         # host normalization, OUI vendor lookup
├── report/
│   ├── __init__.py
│   ├── table.py           # terminal table rendering
│   ├── csv_export.py
│   └── json_export.py
├── util/
│   ├── net.py             # IP/CIDR math, MAC parsing, misc helpers
│   └── log.py             # logging setup (stdout/stderr, verbosity)
└── conftest.py / tests/
```

### Module responsibilities

| Module | Responsibility |
|---|---|
| `cli.py` | Parse `argv`, load config, instantiate reporter/exporter, run engine with progress reporting, map errors to exit codes. |
| `config.py` | Merge defaults + config file + CLI flags; validate subnet/range/retries; produce a frozen `ScannerConfig`. |
| `scanner/engine.py` | Compute the IP list, build worker pool, run scan with concurrency limits and timeout, dedupe responses. |
| `scanner/packets.py` | Construct ARP `who-has` requests and decode ARP `is-at` replies into neutral structs. |
| `scanner/sender.py` | Wrap the transport (Scapy `srp`/`AsyncSniffer` or raw socket) and normalize timeouts/responses. |
| `scanner/result.py` | Define `HostInfo`, `ScanResult`, and aggregation logic (upsert by IP). |
| `report/*` | Render the scan result as a table, CSV, or JSON; also produce the summary banner. |

---

## 7. Component Design

### 7.1 CLI Component (`cli.py`)

**Entry flow**

1. Parse global flags (`--verbose`, `--quiet`, `--config`, `--export`).
2. Parse/validate the target (`--subnet 192.168.1.0/24` OR `--range 192.168.1.1-192.168.1.50`, mutually exclusive).
3. Load optional config file and deep-merge with CLI overrides.
4. Check privileges (raw socket capability).
5. Invoke the engine; stream progress via a callback.
6. Render output (table/CSV/JSON) and summary.
7. Return an exit code (`0` success, `1` scan error, `2` usage/config error, `3` insufficient privileges).

**Exit code contract**

| Code | Meaning |
|---|---|
| `0` | Scan completed (even if 0 hosts found) |
| `1` | Runtime scan failure (interface down, permission revoked, interrupt) |
| `2` | Configuration / argument error |
| `3` | Insufficient privileges to open raw sockets |

### 7.2 Config Component (`config.py`)

`ScannerConfig` dataclass fields:

| Field | Type | Default | Description |
|---|---|---|---|
| `target` | `str` | required | CIDR or IP range |
| `interface` | `str \| None` | auto-select | Network interface to bind |
| `timeout` | `float` | `1.0` s | Max wait per IP for a reply |
| `retries` | `int` | `1` | Additional ARP request rounds |
| `workers` | `int` | `num_cpus * 2` | Max in-flight concurrent targets |
| `quiet` | `bool` | `False` | Suppress per-host lines |
| `verbose` | `bool` | `False` | Log every frame sent/received |
| `export_csv` | `Path \| None` | `None` | CSV output path |
| `export_json` | `Path \| None` | `None` | JSON output path |

Validation rules:
- Target must be a valid IPv4 CIDR (`/8`–`/32`) or range; reject host bits mismatch warns.
- `timeout > 0`, `0 < workers <= 1024`, `retries >= 0`.
- Exactly one of `--subnet`/`--range` must be provided.

### 7.3 Scanner Engine (`scanner/engine.py`)

The engine is the heart of the tool.

**Scan algorithm (concurrency-controlled burst):**

```
PREPARE:
  targets = expand(target)                       # list of IPv4Address
  ifl = resolve_interface(interface)             # may auto-detect
  check_privileges()

SEND (async):
  queue = asyncio.Queue(targets)
  sem = asyncio.Semaphore(workers)
  results = {}

  worker(i):
    while ip = queue.get_nowait():
       async with sem:
           reply = send_arp_request(ip, ifl, timeout)
           if reply: results.add(HostInfo.from_reply(reply))

  run N workers concurrently, gathering tasks.
  await asyncio.gather(*workers)

AGGREGATE:
  dedupe by IP, sort by IP, resolve vendor, attach RTT stats.

REPORT:
  emit HostInfo rows to reporter.
```

**Key design decisions**

- **Bounded concurrency** (`Semaphore(workers)`) prevents a `/16` scan from flooding the host/network while still overlapping slow responders.
- **Skip network/broadcast addresses** (`x.x.x.0`, `x.x.x.255`) by default; a `--no-reserve` flag can override.
- **Idempotent aggregation**: the results map is keyed on IP, later (faster) duplicate replies only update RTT min.
- **Progress callback** reports `scanned/total` every 1% to avoid spamming terminals on big subnets.

### 7.4 Packet Builder/Parser (`scanner/packets.py`)

**ARP request (who-has) frame:**

```
Ethernet (14 bytes)
  dst      = ff:ff:ff:ff:ff:ff   (broadcast)
  src      = <our MAC>
  ethertype = 0x0806             (ARP)

ARP header (28 bytes)
  htype     = 1                  (Ethernet)
  ptype     = 0x0800             (IPv4)
  hlen      = 6
  plen      = 4
  op        = 1                  (request)
  sha       = <our MAC>
  spa       = <our IP>
  tha       = 00:00:00:00:00:00  (unknown)
  tpa       = <target IP>
```

**Reply (is-at) parse contract:** `op == 2`, match target IP; extract `sha` as the host MAC.

The module exposes:
- `build_arp_request(src_ip, src_mac, target_ip) -> Ether`
- `parse_arp_reply(frame) -> ArpReply | None` (returns `None` for non-ARP/non-reply frames)

### 7.5 Sender (`scanner/sender.py`)

Abstraction over transport so the engine does not depend on Scapy directly:

```
class Sender(Protocol):
    def send_arp_request(ip, timeout) -> ArpReply | None

ScapySender:
    sock = conf.L3socket(iface=interface)
    # send Ether(dst=broadcast)/ARP(op=1) and sniff for op=2 reply,
    # honoring the per-target timeout.
```

The sender handles:
- Broadcast request transmission.
- Filtering replies to the requested `tpa`.
- Timeout bookkeeping and RTT measurement (`time.monotonic()` before/after).
- Retry rounds at the engine level, not within a single send.

### 7.6 Result Model (`scanner/result.py`)

```python
@dataclass(frozen=True, slots=True)
class HostInfo:
    ip: IPv4Address
    mac: str                     # "aa:bb:cc:dd:ee:ff" lowercase
    vendor: str | None           # from OUI database, if known
    rtt_ms: float                # min observed round-trip time
    timestamp: float             # discovery time (epoch)
    interface: str               # interface that observed the reply

@dataclass(frozen=True, slots=True)
class ScanResult:
    targets: list[IPv4Address]   # all probed IPs
    hosts: list[HostInfo]        # sorted by IP
    scanned_at: datetime
    duration_s: float
    interface: str
    config: ScannerConfig
```

### 7.7 Device/Vendor Lookup (`scanner/devices.py`)

- Bundled minimal **OUI (Organizational Unique Identifier) table** — top ~10k manufacturers — matched against the first 6 hex digits of the MAC (`aa:bb:cc` prefix).
- Unknown OUIs → `vendor=None` (rendered as `unknown`).
- Case-insensitive lookup, cached in a dict for O(1).

---

## 8. Data Model / Schema

### 8.1 JSON export schema (v1)

```json
{
  "schema_version": 1,
  "scanned_at": "2026-09-12T10:15:30Z",
  "duration_s": 2.31,
  "interface": "eth0",
  "targets_total": 254,
  "hosts_found": 12,
  "hosts": [
    {
      "ip": "192.168.1.1",
      "mac": "aa:bb:cc:dd:ee:01",
      "vendor": "RouterCorp",
      "rtt_ms": 1.2,
      "interface": "eth0"
    }
  ],
  "config": {
    "timeout": 1.0,
    "retries": 1,
    "workers": 8
  }
}
```

### 8.2 CSV export schema (v1)

```
ip,mac,vendor,rtt_ms,timestamp
192.168.1.1,aa:bb:cc:dd:ee:01,RouterCorp,1.2,2026-09-12T10:15:30Z
```

### 8.3 Terminal table

```
+---------------+------------------+-----------+--------+
| IP            | MAC              | Vendor    | RTT ms |
+---------------+------------------+-----------+--------+
| 192.168.1.1   | aa:bb:cc:dd:ee:01| RouterCorp|   1.2  |
+---------------+------------------+-----------+--------+

Summary: 12/254 hosts live on eth0 in 2.31s
```

---

## 9. Core Workflow (Scan Lifecycle)

```
  Start
    │
    ▼
  Parse args & load config ───────────► invalid → exit 2
    │
    ▼
  Verify privileges & interface ───────► no raw socket → exit 3
    │
    ▼
  Expand target → IP list
    │
    ▼
  Burst-send ARP requests (bounded concurrency)
    │                               ┌──────────────────────┐
    ├─► per IP: send who-has ───────┤  wait for is-at reply │
    │                              │  (timeout / retry)   │
    │                               └──────────────────────┘
    │                               ┌──── alive: record ───┐
    │                              └──── silent: skip ─────┘
    ▼
  Aggregate + dedupe + vendor lookup
    │
    ▼
  Render output (table / CSV / JSON) + summary
    │
    ▼
  Exit 0
```

---

## 10. Networking Fundamentals

### 10.1 Why ARP?

ARP is mandatory glue on IPv4 Ethernet networks: every IP device must answer ARP to communicate. If a host is **powered on and connected**, it will reply to a *who-has* request. Absence of a reply → host absent, firewalled L2 hook, or MAC-layer filtering. This makes ARP an excellent liveness probe — it does not rely on upper-layer protocols (ICMP/TCP) that hosts might firewall.

### 10.2 Broadcast vs. unicast replies

- Requests are **broadcast** (`dst=ff:ff:ff:ff:ff:ff`) so all hosts on the segment see them.
- Replies are typically **unicast** back to the sender — we must capture frames addressed to *our* MAC.
- Some NICs may drop-of-interest replies in promiscuous-off modes; therefore the scanner should capture at the socket level on the bound interface (optionally enabling promiscuous mode).

### 10.3 ARP cache interaction

- The OS ARP cache may produce **spurious** replies for addresses still cached from a previous session (cache entries live ~60 s–10 min on modern OSes).
- Mitigation: after a scan, the tool logs cache-based noise with a `*cached*` hint only in verbose mode; the reply is still recorded, but RTT reflects cache, not wire. v1 does **not** flush caches automatically (that would require touching `arp` tables); a `--purge-arp-cache` flag is a future option.

### 10.4 Handling non-responding hosts

Hosts may be:
- Actually down.
- Firewalled / have ARP filtering enabled (`arp_ignore`/`arp_announce` sysctls on Linux).
- On a different broadcast domain (duplicate of another host's IP in a misconfigured network).

All the above result in "no reply" and are simply not listed.

---

## 11. Concurrency & Performance Design

### 11.1 Model

- **Asyncio event loop** drives all sockets (non-blocking). Each target's send is not awaited serially; many sends are in flight, gated by `semaphore(workers)`.
- Workers are lightweight coroutines; there is **no thread- or process-per-IP** overhead.

### 11.2 Scaling rules

| Subnet | Addresses | workers | Expected wall time* |
|---|---|---|---|
| `/24` | 254 | 8 | ~1–2 s |
| `/23` | 510 | 16 | ~2–4 s |
| `/22` | 1022 | 32 | ~4–8 s |
| `/16` | 65534 | 256 | ~2–5 min |

\* assumes `timeout=1.0 s`, healthy LAN, single sender interface.

### 11.3 Throughput guards

- Cap burst rate to avoid saturating the NIC: minimum inter-send spacing applies when workers exceed a per-interface max (soft throttle).
- Non-responsive hosts dominate runtime (they cost a full `timeout`). Using **retries across rounds** with a shorter per-round timeout (`timeout/retries`) bounds total time while improving reliability.
- Duplicate replies during the wait are cheap (dedupe by IP is O(1)).

---

## 12. Error Handling & Edge Cases

| Case | Behavior |
|---|---|
| Raw socket denied | Clear message with the exact elevated-command hint; exit `3`. |
| Interface down / doesn't exist | Wall-clock error with interface name; exit `1`. |
| Invalid CIDR/range | Config validation error; exit `2`. |
| 0 hosts found | Successful scan; print `No live hosts detected` summary; exit `0`. |
| Permission revoked mid-scan | Interrupt scan, flush partial results, exit `1`. |
| Ctrl-C / SIGINT | Graceful: stop sending, print partial results + `(interrupted)` banner, exit `130`. |
| MAC collision / duplicate IP on LAN | Both replies recorded; later one wins, both logged in verbose mode. |
| Huge subnet (`/8`) | Warn (`this may take very long`) and require explicit `--yes-really` flag. |
| OUI table missing | Vendor resolution skipped with a logged warning. |
| Non-EThernet link (e.g. Wi-Fi with bridging quirks) | Proceed; note hop-count/MTU differences only in verbose logs. |

---

## 13. Security Considerations

- **Authorization**: The tool is a reconnaissance utility. It must **only** be run on networks the operator owns or is authorized to scan. The CLI prints a consent notice to stderr on first run (suppressible with `--no-warning`).
- **No payload exploitation**: ARP scanning is passive-observation of L2 liveness; it does not probe application ports, inject data, or alter host state.
- **Least privilege**: Raw sockets are the highest privilege needed. The tool otherwise operates with no sensitive data access; never store credentials.
- **Privacy**: MAC addresses and discovered hosts are sensitive identifiers. Export files must be stored with restrictive permissions (docs: `chmod 600` on Unix, ACL note on Windows). No exfiltration — output is written only to paths the operator specifies.
- **Rate throttling**: Bounded concurrency prevents the scanner from being used to flood the network unintentionally.
- **Detectability**: ARP broadcasts are visible; this is inherent to L2 discovery and cannot be fully hidden without specialized hardware.

---

## 14. Observability & Logging

| Level | Output |
|---|---|
| `ERROR` | Fatal failures, permission issues, interface errors |
| `WARN` | OUI missing, duplicate IP, huge subnet warnings |
| `INFO` | Scan start metadata, per-host dotted summaries at `--verbose` |
| `DEBUG` | Every frame hexdump (`--verbose -v`), retry events, cache hits |

Logging goes to **stderr** so that stdout stays clean for the results table / CSV / JSON piping.

---

## 15. Deployment & Runtime Environment

### 15.1 Packaging

- `pyproject.toml` with `[project.scripts] arp-scan = "arp_scanner.cli:main"`.
- Dependencies: `scapy>=2.5`, standard library for everything else.

### 15.2 Supported platforms & privilege notes

| OS | Install hint | Raw-socket requirement |
|---|---|---|
| Linux | `pip install`, run `sudo` | root (or `CAP_NET_RAW`, `CAP_NET_ADMIN`) |
| macOS | `pip install`, run `sudo` | root |
| Windows | **Npcap** must be installed (WinPcap legacy supported) | Administrator + Npcap driver |

> On Windows, Scapy binds via Npcap; the tool must detect missing Npcap and present the download URL clearly.

### 15.3 Fresh install flow

1. `python -m venv .venv` / `py -m venv .venv`
2. `.venv\Scripts\activate` (Windows) or `source .venv/bin/activate` (Unix)
3. `pip install -e .`
4. Verify: `arp-scan --subnet 192.168.1.0/24`

---

## 16. Configuration

CLI is primary; an optional config file (JSON) can pre-supply defaults:

```json
{
  "timeout": 1.0,
  "retries": 1,
  "workers": 8,
  "export_csv": "~/.arp-scan/latest.csv",
  "quiet": false
}
```

**Precedence (lowest → highest):** built-in defaults → config file → CLI flags.

---

## 17. Testing Strategy

| Layer | Tests |
|---|---|
| **Unit** | CIDR expansion, config validation, ARP frame build/parse round-trip, MAC normalization, OUI lookup, CSV/JSON serializers |
| **Integration** | Loopback/`lo` interface scan (expect self), virtual interface pair (`veth` on Linux / `Ping Loopback`) |
| **Property** | Given random valid config → engine always returns `ScanResult`; sort order; timeout respected |
| **E2E** | Run CLI against a controlled test subnet on CI (minimal fixture topology or Docker-based network) |

Key unit-testable seam: the `Sender` interface is dependency-injected into the engine, so tests can fake replies with zero privileges.

---

## 18. Performance Budget

| Metric | Budget |
|---|---|
| Latency (per reply capture) | < 100 ms overhead above wire time |
| Full `/24` scan | ≤ 3 s |
| Memory for `/16` scan | ≤ 75 MB peak |
| CPU | single core, < 10% sustained on `/24` |
| False negatives | ≤ 5% in a clean L2 LAN (bounded by lossy Wi-Fi) |

---

## 19. Future Extensions & Roadmap

| Milestone | Feature |
|---|---|
| v1.1 | ARP-cache flush option, ICMP cross-check, hostname (reverse DNS) resolution |
| v1.2 | TCP/UDP port-scan mode, OS fingerprinting via TTL |
| v1.3 | Passive mode (sniff traffic without sending), rogue-device / duplicate-IP detection |
| v2.0 | Web UI + persistent SQLite store, scheduled recurring scans, alerting on new/departed hosts |
| v2.1 | IPv6 (NDP/ICMPv6 equivalent), VLAN/QinQ support, GRE-tagged segments |

---

## 20. Glossary

| Term | Meaning |
|---|---|
| **ARP** | Address Resolution Protocol — L2 protocol mapping IPv4 → MAC. |
| **OUI** | Organizational Unique Identifier — first 24 bits of a MAC, mapping to the vendor. |
| **CIDR** | Classless Inter-Domain Routing notation, e.g. `192.168.1.0/24`. |
| **Broadcast domain** | Set of devices reachable at L2 without a router. |
| **Promiscuous mode** | NIC mode that receives all frames, not only those addressed to it. |
| **RTT** | Round-trip time measured from request send to reply receipt. |
| **who-has / is-at** | ARP op names for request (op=1) and reply (op=2). |
| **Raw socket** | Socket that bypasses protocol handling to read/write L2 frames. |