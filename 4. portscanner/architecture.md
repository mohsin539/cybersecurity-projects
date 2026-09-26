# Port Scanner — Architecture Document

> **Version:** 1.0 · **Status:** Draft · **Last updated:** 2026-09-12
>
> ⚠️ **Legal notice:** Port scanning systems you do not own or do not have written
> authorization to test may be illegal in your jurisdiction. This document describes
> the architecture of an authorized-testing tool (pentest, asset inventory, lab use).

---

## Table of Contents

1. [Overview](#1-overview)
2. [Goals & Non-Goals](#2-goals--non-goals)
3. [High-Level Architecture](#3-high-level-architecture)
4. [Component Design](#4-component-design)
   - 4.1 [CLI & Configuration](#41-cli--configuration)
   - 4.2 [Target Resolver](#42-target-resolver)
   - 4.3 [Scheduler / Concurrency Engine](#43-scheduler--concurrency-engine)
   - 4.4 [Scan Engines (Probes)](#44-scan-engines-probes)
   - 4.5 [Service Identification](#45-service-identification)
   - 4.6 [Result Store & Event Bus](#46-result-store--event-bus)
   - 4.7 [Output / Reporting](#47-output--reporting)
5. [Scan Techniques & Packet Flows](#5-scan-techniques--packet-flows)
6. [Concurrency Model](#6-concurrency-model)
7. [Data Models](#7-data-models)
8. [Port State Machine](#8-port-state-machine)
9. [Timing, Rate Limiting & Adaptivity](#9-timing-rate-limiting--adaptivity)
10. [Error Handling & Edge Cases](#10-error-handling--edge-cases)
11. [Output Formats](#11-output-formats)
12. [Project Layout](#12-project-layout)
13. [Technology Choices](#13-technology-choices)
14. [Extensibility & Plugin System](#14-extensibility--plugin-system)
15. [Testing Strategy](#15-testing-strategy)
16. [Security & Operational Considerations](#16-security--operational-considerations)
17. [Roadmap](#17-roadmap)

---

## 1. Overview

The port scanner is a network reconnaissance tool that determines which TCP/UDP
ports on a set of hosts are open, closed, or filtered, and — where possible —
identifies the service and version listening on open ports.

The design goals in order of priority:

1. **Correctness** — a result is only reported when the evidence supports it.
2. **Speed** — saturate available bandwidth/CPU with a bounded, polite concurrency model.
3. **Flexibility** — pluggable scan techniques and output formats.
4. **Observability** — full audit trail of every probe sent and response received.

Typical use cases: attack-surface inventory, validating firewall rules, CI
checks that no unexpected services are exposed, lab/CTF exploration.

---

## 2. Goals & Non-Goals

### Goals

| ID  | Goal |
|-----|------|
| G1  | Scan 65,535 TCP ports on /24 targets in minutes on commodity hardware |
| G2  | Support TCP Connect, SYN (half-open), UDP, FIN/NULL/XMAS probes |
| G3  | Configurable rate limiting, timeouts, retries, parallelism |
| G4  | Service/version detection (banner grabbing + probe matching) |
| G5  | Machine-readable output: JSON, JSONL, CSV; human output: table/greppable |
| G6  | Resumable scans and live streaming results |
| G7  | Runs unprivileged (Connect scan) *or* with raw sockets (SYN scan) |

### Non-Goals

- Exploitation or post-scan attack tooling
- Web-content crawling (a separate tool consumes our output)
- Full OS fingerprinting stack (basic TTL-based hints only)
- IPv6 in v1 (design leaves the `Address` abstraction open for it)

---

## 3. High-Level Architecture

Layered pipeline architecture. Data flows left → right; control signals flow back for rate adaptation.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              PORT SCANNER                                   │
│                                                                             │
│  ┌───────────┐   ┌──────────────┐   ┌──────────────────┐   ┌────────────┐  │
│  │    CLI    │──▶│   Config     │──▶│  Target Resolver  │──▶│  Scheduler │  │
│  │  (argparse│   │ (validated,  │   │ (CIDR expand,     │   │  (worker   │  │
│  │  /config) │   │  frozen)     │   │  DNS, dedupe,     │   │  pool +    │  │
│  └───────────┘   └──────────────┘   │  exclusions)      │   │  rate      │  │
│                                     └──────────────────┘   │  limiter)  │  │
│                                                            └─────┬──────┘  │
│                             ┌────────────────────────────────────┼─────┐  │
│                             ▼                                    ▼     │  │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                        SCAN ENGINE (Strategy)                        │  │
│  │  ┌─────────────┐ ┌─────────────┐ ┌────────────┐ ┌────────────────┐  │  │
│  │  │ TCP Connect │ │ SYN Stealth │ │    UDP     │ │ FIN/NULL/XMAS  │  │  │
│  │  └─────────────┘ └─────────────┘ └────────────┘ └────────────────┘  │  │
│  └──────────────────────────────┬───────────────────────────────────────┘  │
│                                 │ probe results (events)                   │
│                                 ▼                                          │
│  ┌──────────────────┐   ┌────────────────────┐   ┌──────────────────────┐  │
│  │  Service ID      │──▶│   Result Store     │──▶│  Output / Reporting  │  │
│  │  (banners, probes│   │ (in-memory + WAL)  │   │ (table/JSON/CSV/...) │  │
│  │  matching)       │   └────────────────────┘   └──────────────────────┘  │
│  └──────────────────┘            ▲                                          │
│                                  │                                          │
│                     ┌────────────┴────────────┐                             │
│                     │   Event Bus + Progress  │                             │
│                     │   (pub/sub, UI ticker)  │                             │
│                     └─────────────────────────┘                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

Key architectural decisions:

| Decision | Choice | Rationale |
|---|---|---|
| A1 | Pipeline of stages connected by an **event bus** | Decouples probe speed from output speed; enables streaming results |
| A2 | Scan technique as a **Strategy pattern** | Add new probe types without touching the scheduler |
| A3 | Scheduler owns **all** concurrency | One place to enforce rate limits & fairness |
| A4 | Results are immutable **events**, not mutable rows | Safe concurrent writes; trivial replay/audit |
| A5 | Raw-socket privileges isolated in one engine | Non-root fallback keeps the tool usable everywhere |

---

## 4. Component Design

### 4.1 CLI & Configuration

```go
type Config struct {
    Targets       []string        // CIDRs, hostnames, "10.0.0.1-50" ranges
    Exclude       []string        // exclusion CIDRs (safety)
    Ports         PortSpec        // "22,80,443,8000-9000" or named profiles (top100, top1000)
    ScanType      ScanType        // Connect | SYN | UDP | Fin | Null | Xmas
    Workers       int             // concurrent probes (default: CPU-bound heuristic)
    RateLimit     float64         // probes per second, 0 = unlimited
    Timeout       time.Duration   // per-probe timeout (default 1s)
    Retries       int             // re-probe on inconclusive results (default 2)
    ServiceDetect bool            // run banner grab / version probes on open ports
    OutputFormat  Format          // table | json | jsonl | csv | greppable
    OutputFile    string          // "-" for stdout
    ScanDelayJitter time.Duration // randomize probe timing (evasion, polite mode)
    SourcePort    int             // optional fixed source port
    Interface     string          // optional bind interface (raw socket engines)
    DryRun        bool            // resolve + enumerate plan, send nothing
}
```

Responsibilities:

- Parse args/env/config file (precedence: flags > env > file > defaults).
- **Validate** (fail fast): port ranges sane, CIDRs parseable, workers ≥ 1,
  raw-socket scans require elevated privileges (pre-check, not discover-at-crash).
- Freeze into an immutable value handed to all later stages (no global state).

### 4.2 Target Resolver

Turns heterogeneous target input into a flat, deduplicated work queue.

```
input strings ──▶ parse ──▶ DNS resolve ──▶ expand CIDR/range ──▶ apply excludes ──▶ dedupe ──▶ target queue
```

Details:

| Step | Behavior |
|---|---|
| Parse | Accept `host`, `host:port`, CIDR `10.0.0.0/24`, ranges `10.0.0.1-50` |
| DNS | Resolve with timeout; **keep both** hostname and resolved IPs (report shows hostname) |
| Expand | CIDRs and ranges expand lazily (channel) — a /8 never materializes in RAM |
| Exclude | Subtract exclusion CIDRs first; log what was removed (audit trail) |
| Dedupe | Set keyed by IP; count references per IP for reporting |
| Lazy feed | Emit targets on a channel so the scheduler starts before expansion finishes |

### 4.3 Scheduler / Concurrency Engine

The scheduler is the **only** component that launches probes. It owns:

1. **Work generation** — the cartesian product `targets × ports × probe-retries`,
   streamed as `ProbeJob` structs.
2. **Worker pool** — N goroutines/threads pulling `ProbeJob`s from a bounded queue.
3. **Rate limiter** — token bucket in front of the queue; workers block on acquire.
4. **Back-pressure** — bounded queue means a slow engine (e.g., UDP timeouts) slows
   generation instead of exhausting memory.
5. **Fairness** — round-robin across targets so one host doesn't starve others.

```go
type Scheduler struct {
    jobs     chan ProbeJob   // bounded, e.g. cap = workers * 4
    limiter  *rate.Limiter   // token bucket, global
    engine   ScanEngine      // strategy under test
    results  chan<- Event    // fan-in to event bus
    wg       sync.WaitGroup
}

func (s *Scheduler) Run(ctx context.Context) {
    for t := range s.targets {          // lazy target stream
        for p := range s.ports {
            s.jobs <- ProbeJob{Target: t, Port: p}
        }
    }
    close(s.jobs)
}
```

Worker lifecycle: created at start, drained via context cancellation (Ctrl-C
produces a partial report; a checkpoint file allows resume — see §16).

### 4.4 Scan Engines (Probes)

Each engine implements one interface; the scheduler is agnostic to technique.

```go
type ScanEngine interface {
    Name() string
    RequiresPrivileges() bool                 // raw sockets?
    Probe(ctx context.Context, job ProbeJob) ProbeOutcome
}

type ProbeOutcome struct {
    State    PortState    // Open | Closed | Filtered | OpenFiltered | ClosedFiltered | Unreachable
    Evidence Evidence     // what was observed: packet, errno, banner bytes...
    RTT      time.Duration
}
```

| Engine | Privilege | How it decides | Speed | Stealth |
|---|---|---|---|---|
| TCP Connect | none | `connect()` returns 0 → open; ECONNREFUSED → closed; timeout → filtered | medium | low |
| SYN (half-open) | raw socket / CAP_NET_RAW | SYN/ACK → open; RST → closed; ICMP unreachable → filtered; nothing → filtered | fast | medium |
| UDP | raw socket (for ICMP matching) | UDP reply → open; ICMP port-unreachable → closed; nothing → open\|filtered | slow | medium |
| FIN/NULL/XMAS | raw socket | RST → closed (non-Windows); nothing → open\|filtered | fast | high |

Engines with inconclusive results (`OpenFiltered`) honor `Config.Retries` — the
scheduler re-enqueues the job with an incremented attempt counter, using
exponential backoff (see §9).

**Privilege isolation:** raw-socket engines are the only code that touches
`AF_PACKET`/`SOCK_RAW`. They run behind a narrow `PacketIO` interface so they can
be mocked in tests and later swapped for eBPF/`AF_XDP` fast paths.

### 4.5 Service Identification

Runs **only on open ports**, after the discovery scan, as a second pass
(keeps the hot loop fast and lets `--no-servicedetect` skip it entirely).

```
open port ──▶ Banner Grab (read greeting, 3s)
                │
                ├─ got banner ──▶ regex/db match ──▶ (service, version)
                │
                └─ silent protocol ──▶ send probe payloads ──▶ match response
                     ("GET / HTTP/1.0\r\n\r\n", "HELP\r\n", TLS ClientHello, ...)
```

- **Database:** `data/service-probes.toml` — ordered list of
  `{ match_regex, payload, port_hints, product, version_extract }` entries,
  conceptually similar to nmap's `nmap-service-probes` but smaller and TOML-based
  so users can append their own.
- **TLS:** if banner contains a certificate or the port is a TLS hint (443, 993,
  ...), perform a handshake and extract subject/SAN/issuer + expiry into the result.
- **Confidence:** each match carries a confidence score; low-confidence matches are
  reported as `service?` rather than asserted.

### 4.6 Result Store & Event Bus

**Event bus** — a broadcast channel (pub/sub). Subscribers:

| Subscriber | Consumes | Purpose |
|---|---|---|
| Result Store | `PortResult`, `ServiceResult` | aggregation, persistence |
| Progress UI | counters, ETAs | live display |
| JSONL writer | every event | streaming machine-readable output |
| Rate Controller | latency samples, loss | adapt timing (§9) |

**Result Store** — in-memory map keyed by `(host, port)`, plus a
**write-ahead log** (JSONL append) used for crash resume. On startup with
`--resume scan.wal`, previously settled `(host, port)` entries are skipped.

Aggregation at the end folds the map into a `ScanReport` (§7.3) for final output.

### 4.7 Output / Reporting

Formatter registry keyed by `Config.OutputFormat`. All formatters consume the
same `ScanReport`; streaming formats (JSONL) subscribe to the event bus instead
so data flows during the scan.

- **table** — aligned human output, open ports first, service/version columns.
- **json / jsonl** — stable schema (versioned `schema_version` field).
- **csv** — flat rows for spreadsheets/ingest.
- **greppable** — `host,port,state,service` one-liners for shell pipelines.

---

## 5. Scan Techniques & Packet Flows

### 5.1 TCP Connect Scan

```
Scanner                          Target
   │ ── SYN ───────────────────────▶ │
   │ ◀────────────── SYN/ACK ────── │  port open
   │ ── ACK ───────────────────────▶ │
   │ ── RST (tear down) ───────────▶ │   (avoid FIN handshake; keep logs small)
   │
   │ ── SYN ───────────────────────▶ │
   │ ◀────────────── RST/ACK ─────── │  port closed
   │
   │ ── SYN ──────────── ✗ timeout ──│  filtered (drop) / open|filtered (reject)
```

Implementation: non-blocking sockets + `epoll`/`kqueue`/`IOCP` (or language
equivalent, e.g. Go's netpoller) so thousands of half-open connects proceed
in parallel without one thread per probe.

### 5.2 SYN (Half-Open) Scan

```
Scanner                          Target
   │ ── SYN ───────────────────────▶ │
   │ ◀────── SYN/ACK ────────────── │  open  ──▶ we send RST (never complete handshake)
   │ ◀────── RST/ACK ────────────── │  closed
   │ ── SYN ──────────── (silence) ──│  filtered
```

- Craft raw IP/TCP headers; sequence numbers are random per probe (ISN hygiene).
- **Sniff for replies** via a raw capture socket (BPF filter
  `tcp and src host X and (flags & 0x12) != 0 or flags & 0x04 != 0`) rather than
  one socket per port — one listener demultiplexes by `(src ip, src port, seq)`.
- Never completes the handshake → most services don't log the connection.

### 5.3 UDP Scan

UDP is connectionless, so absence of a reply is ambiguous:

| Observation | Conclusion |
|---|---|
| UDP response payload | **open** |
| ICMP port unreachable (type 3, code 3) | **closed** |
| ICMP other unreachable (net/host/proto admin) | **filtered** |
| Silence after retries | **open\|filtered** (classic for UDP) |

Service detection improves UDP yield: send protocol-appropriate payloads
(DNS query, NTP request, SNMP get) to coax responses from silent services.

### 5.4 FIN / NULL / XMAS

Flagless (NULL), FIN-only, or FIN+PSH+URG (XMAS) packets. RFC 793 says a closed
port must answer RST; open ports typically stay silent. Useful to bypass simple
stateful logging; **fails against Windows** (sends RST regardless) — the engine
tags results with a caveat when the OS is known to respond this way.

### 5.5 Fragmentation & Decoys (optional, behind a flag)

- IP fragment the probe header (8-byte fragments) to evade naive ACL inspection.
- Decoy mode sends additional packets with spoofed source IPs — **off by default**;
  requires raw sockets and clear authorization; documented for completeness only.

---

## 6. Concurrency Model

```
                 ┌──────────── Token bucket (global rate) ────────────┐
                 │                                                    │
 Target queue ──▶│  Job generator (1)  ──▶ bounded jobs chan ──▶      │
                 │                                        │           │
                 │                     ┌──────────────────┼────────┐  │
                 │                     ▼        ▼         ▼        ▼  │
                 │                  worker(1) worker(2) ... worker(N) │
                 │                     │        │         │        │  │
                 │                     └────────┴────┬────┴────────┘  │
                 │                                   ▼                │
                 │                          results chan (fan-in)     │
                 └────────────────────────────────────────────────────┘
```

- **Workers = `min(config.Workers, ulimit -n / 4)`** — file-descriptor safety.
  Connect-scan default workers: `256`; SYN/UDP: `128` (kernel packet work is heavier).
- **One socket per in-flight probe** for Connect; **one shared capture socket**
  for SYN/UDP (demux by tuple).
- **Bounded channels everywhere** — memory is O(workers × queue-depth), not O(jobs).
- **Context propagation** — every engine honors `ctx`; cancellation drains within
  one timeout window, then emits a partial report.
- **Per-host concurrency cap** (e.g. ≤ 32 in-flight probes per target) prevents
  one IDS'd host from dominating the global rate and triggering blocks.

Deadlock avoidance: job generator runs in its own goroutine; workers never
write to the job channel; results channel is consumed by a dedicated pump with
its own buffer.

---

## 7. Data Models

### 7.1 Core types

```go
type PortState string

const (
    Open           PortState = "open"
    Closed         PortState = "closed"
    Filtered       PortState = "filtered"
    OpenFiltered   PortState = "open|filtered"
    ClosedFiltered PortState = "closed|filtered"
    Unreachable    PortState = "unreachable"   // host-level network error
)

type ProbeJob struct {
    Target  Target
    Port    uint16
    Proto   Proto     // tcp | udp
    Attempt int
}

type Target struct {
    Hostname string    // original input, may be empty
    IP       net.IP    // canonical scan target
}

type PortResult struct {
    Job       ProbeJob   `json:"-"`
    State     PortState  `json:"state"`
    Evidence  Evidence   `json:"evidence,omitempty"`  // errno, ICMP type/code, flags seen
    RTT       float64    `json:"rtt_ms,omitempty"`
    Timestamp time.Time  `json:"ts"`
    Engine    string     `json:"engine"`
    Attempt   int        `json:"attempt"`
}

type ServiceResult struct {
    Host       net.IP    `json:"host"`
    Port       uint16    `json:"port"`
    Proto      Proto     `json:"proto"`
    Service    string    `json:"service"`     // "http", "ssh", "unknown"
    Product    string    `json:"product,omitempty"`
    Version    string    `json:"version,omitempty"`
    Banner     string    `json:"banner,omitempty"`  // truncated, sanitized
    Confidence float32   `json:"confidence"`        // 0..1
    TLS        *TLSInfo  `json:"tls,omitempty"`
}
```

### 7.2 Events (on the bus)

```go
type Event interface{ Type() string }

type ScanStarted    struct{ Config Config }
type TargetResolved struct{ Target Target }
type PortResultEvent struct{ PortResult }
type ServiceFoundEvent struct{ ServiceResult }
type RateAdjusted   struct{ NewRate float64; Reason string }
type ScanFinished   struct{ Duration time.Duration; Counts map[PortState]int }
```

### 7.3 Final report

```go
type ScanReport struct {
    SchemaVersion int             `json:"schema_version"` // 1
    StartedAt     time.Time       `json:"started_at"`
    FinishedAt    time.Time       `json:"finished_at"`
    Config        PublicConfig    `json:"config"`          // sanitized (no secrets)
    Hosts         []HostReport    `json:"hosts"`
    Stats         Stats           `json:"stats"`
}

type HostReport struct {
    Hostname string       `json:"hostname,omitempty"`
    IP       string       `json:"ip"`
    Ports    []PortResult `json:"ports"`   // sorted by port
    Services []ServiceResult `json:"services,omitempty"`
}

type Stats struct {
    ProbesSent     int            `json:"probes_sent"`
    Retries        int            `json:"retries"`
    CountsByState  map[string]int `json:"counts_by_state"`
    AvgRTTms       float64        `json:"avg_rtt_ms"`
}
```

---

## 8. Port State Machine

Per `(host, port)` the store tracks one state; only defined transitions are legal.

```
            ┌────────────┐   probe sent    ┌──────────────┐
            │  PENDING   │────────────────▶│ AWAITING     │
            └────────────┘                 │ RESPONSE     │
                 ▲                         └──────┬───────┘
                 │ re-enqueue (retry,             │
                 │  backoff, attempt<N)           │ classify(reply/timeout)
                 │                                ▼
        ┌────────┴────────┐              ┌────────────────────┐
        │   RETRYING      │              │  SETTLED(state)    │
        └─────────────────┘              │ open/closed/       │
                 │ attempt >= N &        │ filtered/          │
                 │ still inconclusive    │ open|filtered      │
                 └──────────────────────▶└────────────────────┘
```

Rules:

- **SETTLED is terminal** for the scan (later duplicate replies are ignored —
  late responses to already-RST'd probes are common on SYN scans).
- Retry only applies to `open|filtered` / `filtered` outcomes.
- A host that produces *only* `unreachable` across its first k probes is marked
  **host-down** and its remaining jobs are pruned (huge win on dead subnets).

---

## 9. Timing, Rate Limiting & Adaptivity

| Mechanism | Default | Notes |
|---|---|---|
| Token bucket rate | `0` (unbounded) but bounded by worker count | Global limiter; `--rate 1000` = 1k probes/sec |
| Per-probe timeout | `1000 ms` | `--timeout`; halved for LAN-detected (RTT < 5 ms) scans |
| Connect timeout vs read timeout | separate knobs | handshake ≠ banner read |
| Retries | `2` | only for inconclusive states; exponential backoff: `timeout × 2^attempt` |
| Jitter | `0` | `--jitter 20ms` randomizes send spacing (politeness/IDS) |
| Adaptive timeout | on | EWMA of RTTs; timeouts track `p95(RTT) × 3`, floor 100 ms, cap config value |

**Rate controller (closed loop):** consumes RTT samples and ICMP-source-quench /
RST-storm signals. If packet loss on closed ports exceeds a threshold (classic
sign of rate-triggered filtering), it halves the rate and logs `RateAdjusted`.
This keeps scans polite on fragile networks without user tuning.

---

## 10. Error Handling & Edge Cases

| Case | Handling |
|---|---|
| DNS failure for a target | Record `TargetResolved{error}`; exclude host; scan continues |
| Duplicate reply after RST | Ignored — state already SETTLED |
| Host reboots mid-scan (RST flood) | Closed states are consistent anyway; retry protects open|filtered |
| FD exhaustion (EMFILE) | Scheduler catches, sleeps 250 ms, retries job once, then reports `filtered` + warning |
| Local network flap | Rate controller drops rate 10×; resume-friendly |
| ICMP rate limiting by target | Backoff via retries; final state `open|filtered` with caveat |
| Proxy env vars | Connect engine honors `HTTPS_PROXY` only when `--proxy` explicitly set (never implicitly — auditability) |
| Ctrl-C (SIGINT) | Graceful: stop issuing, drain ≤1 timeout, emit partial report + WAL for `--resume` |
| SIGTERM/SIGQUIT ×2 | Second signal = hard exit without report |
| Bad flags / unprivileged SYN request | Fail fast **before** any packet is sent |

Errors are never swallowed silently: every anomaly emits an event and lands in
the report's `stats.warnings`.

---

## 11. Output Formats

**table (human)**

```
HOST          PORT   STATE  SERVICE  PRODUCT      VERSION
10.0.0.5      22     open   ssh      OpenSSH      9.6p1
10.0.0.5      80     open   http     nginx        1.25.3
10.0.0.5      443    open   https    nginx        1.25.3
10.0.0.7      3389   filtered -      -            -
```

**jsonl (streaming, one event per line)**

```json
{"schema_version":1,"type":"port_result","host":"10.0.0.5","port":22,"proto":"tcp","state":"open","engine":"syn","rtt_ms":1.2,"ts":"2026-09-12T10:00:00Z"}
{"schema_version":1,"type":"service","host":"10.0.0.5","port":22,"service":"ssh","product":"OpenSSH","version":"9.6p1","confidence":0.95}
```

**greppable**

```
10.0.0.5,22,tcp,open,ssh
10.0.0.5,80,tcp,open,http
```

Stability contract: `schema_version` gates all machine-readable output; fields
are additive-only within a major version.

---

## 12. Project Layout

```
portscanner/
├── cmd/
│   └── portscan/
│       └── main.go              # wiring: config → resolver → scheduler → output
├── internal/
│   ├── config/                  # parsing, validation, profiles (top100, top1000)
│   ├── resolve/                 # target expansion, DNS, exclusions
│   ├── engine/                  # ScanEngine implementations
│   │   ├── connect.go           #   TCP connect (non-blocking)
│   │   ├── syn.go               #   raw SYN + capture demux
│   │   ├── udp.go               #   UDP + ICMP correlation
│   │   ├── flagscan.go          #   FIN/NULL/XMAS
│   │   └── packetio/            #   raw socket abstraction (mockable)
│   ├── scheduler/               # worker pool, rate limiter, retries
│   ├── service/                 # banner grab, probe DB, TLS info
│   ├── store/                   # result store, WAL, resume
│   ├── events/                  # event bus
│   ├── report/                  # formatters: table/json/jsonl/csv/greppable
│   └── ui/                      # progress display (TTY-aware, quiet for pipes)
├── data/
│   ├── service-probes.toml      # payload/regex probe database
│   └── top-ports.csv            # frequency-ordered port lists
├── docs/
│   └── architecture.md          # this file
├── test/
│   ├── integration/             # scans against local fixtures (see §15)
│   └── fixtures/
├── LICENSE
├── Makefile
└── go.mod
```

Dependency rule: arrows point downward only
(`cmd → everything; scheduler → engine; engine → packetio`).
`report`/`ui` never import `scheduler` — they consume events only.

---

## 13. Technology Choices

| Concern | Choice | Why |
|---|---|---|
| Language | **Go** | Goroutines fit the worker-pool model; netpoller gives cheap non-blocking IO; single static binary for ops |
| Raw sockets | `golang.org/x/net` + `google/gopacket` (or `mdlayher/packet`) | Header crafting/capture without libpcap dependency where possible |
| Rate limiting | `golang.org/x/time/rate` | Standard token bucket |
| Config | stdlib `flag` + TOML (`BurntSushi/toml`) | Keep deps minimal |
| TLS inspection | stdlib `crypto/tls` | Cert parse only, no external trust validation |
| CLI UX | `fatih/color` (TTY-gated) | Color that degrades in pipes |
| Alternative stack (Python) | `asyncio` + `python-libpcap` | Fine for small scans; GIL and pacing precision make Go the default |

---

## 14. Extensibility & Plugin System

Two extension points, both interface-driven:

1. **Engines** — implement `ScanEngine`; register via `engine.Register(name, factory)`.
   A plugin binary (or Go `plugin`/shared object on Linux) is discovered from
   `~/.config/portscanner/engines/` at startup.
2. **Formatters** — implement `Formatter interface { Format(ScanReport) []byte }`
   (or subscribe to events for streaming formats); registered by name.

Planned hooks: `OnResult`, `OnHostComplete` — enough for webhook notification
("open port appeared on prod!") without making the core a plugin host framework.

Versioned stability promise: `ScanEngine`, `ProbeOutcome`, `Event`, and the JSON
schema are the only public contracts.

---

## 15. Testing Strategy

| Layer | Approach |
|---|---|
| Unit | State classification from canned packet bytes; port-spec parser; backoff math |
| Engine tests | **Loopback fixtures**: a test server binds specific ports (accept / refuse / drop) to assert all engines classify identically |
| Raw-socket engines | Docker container with `CAP_NET_RAW` + `tcpdump` assertions, run in CI (`linux` job only) |
| Scheduler | Deterministic fake clock + fake limiter; assert rate bounds, retry counts, cancellation drains |
| Concurrency races | `go test -race` mandatory in CI |
| Golden outputs | Report formatters tested against checked-in `golden/` files |
| Fuzzing | Fuzz the port-spec parser and the service-probe regex matcher (regex DoS guard) |
| Integration smoke | Scan `127.0.0.1` with 3 fixture ports; assert JSON schema conformance |

Performance gate: a benchmark scan of localhost × 10k ports must complete under
a CI time budget to catch throughput regressions.

---

## 16. Security & Operational Considerations

- **Authorization gate:** `--i-have-permission` confirmation or `I confirm I am authorized to scan these targets` typed at prompt when targets aren't loopback/private RFC1918; refusals are logged with timestamp.
- **Secrets hygiene:** config may hold proxy credentials → `PublicConfig` in reports strips them.
- **Least privilege:** engines that need raw sockets check capability first and suggest the unprivileged Connect scan on failure.
- **WAL file** contains scan intelligence — document that `scan.wal` is sensitive, default perms `0600`.
- **Resource caps:** hard caps on workers/FDs/rate so the tool can't be tuned into a DoS weapon accidentally; `--aggressive` unlocks higher limits with the same authorization gate.
- **Audit log:** every run writes `who/when/what-targets` to `~/.local/state/portscanner/audit.log` (append-only).
- **Banner sanitization:** banners are truncated (256 B) and control characters escaped before entering reports (prevents terminal escape-sequence injection).
- **Container notes:** `NET_RAW` + `NET_ADMIN` capabilities required for SYN/UDP engines; Connect scan needs none.

---

## 17. Roadmap

| Phase | Scope |
|---|---|
| v1.0 | Connect + SYN scans, TCP only, table/JSON output, rate limiter, resume via WAL |
| v1.1 | UDP scan, service detection DB, CSV/greppable, progress UI |
| v1.2 | FIN/NULL/XMAS, adaptive timing, host-down pruning, audit log |
| v2.0 | Plugin system, IPv6, decoys/fragmentation (flagged), eBPF/AF_XDP fast path, distributed scan mode (controller + agents) |
