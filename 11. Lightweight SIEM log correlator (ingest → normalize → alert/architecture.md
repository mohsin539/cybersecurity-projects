# Project 11 — Lightweight SIEM Log Correlator

> Pipeline: **Ingest → Normalize → Correlation → Alert**

A lightweight, single-node or small-cluster SIEM that collects logs from multiple sources, normalizes them into a common schema, correlates events across sources to detect multi-step attacks, and raises alerts through pluggable channels.

---

## 1. High-Level Architecture

```
                     ┌─────────────────────────────────────────────────────┐
                     │                    SIEM Core                         │
                     │                                                     │
 SOURCES             │   ┌──────────┐   ┌──────────┐   ┌──────────────┐    │
 ┌────────┐          │   │   INGEST │──▶│ NORMALIZE│──▶│  CORRELATION │    │
 │ Syslog │──────────┼──▶│  Layer   │   │  Layer   │   │    Engine    │    │
 │ Files  │──────────┼──▶│          │   │          │   │              │    │
 │ APIs   │          │   └──────────┘   └──────────┘   └──────┬───────┘    │
 │ Agents │──────────┼──▶   collect      parse/map/          │        │
 │ Windows│          │                     enrich            │         │
 │ Events │          │                                       ▼         │
 └────────┘          │                            ┌──────────────────┐    │
                     │                            │    ALERTING      │    │
                     │                            │    / STORAGE     │    │
                     │                            └──────────────────┘    │
                     └─────────────────────────────────────────────────────┘
```

**Key principle:** stateless ingest/normalize (easily parallelized) + stateful correlation (shared window/state store).

---

## 2. Component Breakdown

### 2.1 Ingest Layer
Responsible for acquiring raw data from heterogeneous sources in real-time or near-real-time.

| Component | Purpose | Notes |
|-----------|---------|-------|
| `syslog_listener` | UDP/TCP/REL P syslog collector | Supports RFC 3164/5424 |
| `file_tailer` | Watches log files for appended lines | Tracks offsets (resume on crash) |
| `api_poller` | Pulls from REST APIs / cloud SIEM | Pagination + rate-limit handling |
| `agent_receiver` | Accepts events pushed by custom agents | Auth via shared token/mTLS |
| `ingest_queue` | Buffers raw events | Backpressure — never drop silently |

**Design requirements**
- Idempotent read: each source event carries a stable `source` id + sequence number to dedupe.
- Backpressure: if the queue exceeds threshold, slow down sources rather than dropping.
- Graceful shutdown: flush in-flight batches before stopping.

### 2.2 Normalization Layer
Converts heterogeneous raw logs into the **Common Event Schema (CES)**.

CES core fields:
```
event.ts           → ISO-8601 UTC timestamp
event.source_ip    → IP (v4/v6)
event.dest_ip
event.user         → username/account
event.action       → allow | deny | auth_success | auth_failure | exec | create | ...
event.category     → authentication | network | file | process | ...
event.severity     → info | low | medium | high | critical
rule.raw           → original message (retained)
ruleset            → which rules matched
```

Pipeline steps per event:
1. **Parse** — apply parser per source type (regex / JSON / CSV / Windows EVTX).
2. **Map** — translate fields into CES (`ParseError` for unparseable → quarantine, never crash pipeline).
3. **Enrich** — add context: GeoIP, DNS lookup, asset/owner lookup, CVE tags, field normalization (port → service, `failed` vs `FAILED` → lowercase canonical).
4. **Validate** — drop or quarantine events failing schema validation.

**Design requirements**
- Parsers are **pluggable modules**; adding a new source = registering a new parser.
- Fail-open vs fail-closed: unmappable events are quarantined for review, not silently discarded.
- Enrichment calls must be cached + rate-limited to avoid I/O stalls.

### 2.3 Correlation Engine
The heart of the SIEM — detects multi-event, multi-source attack chains.

**Detection primitives**

| Primitive | Model | Example |
|-----------|-------|---------|
| Single-event rule | stateless filter on CES fields | `event.action == "auth_failure" && src_ip in BLACKLIST` |
| Threshold rule | count events over a window | ≥ 5 auth failures / 60s per source IP |
| Stateful sequence | sliding window state machine | auth_fail → auth_success on same host = brute force |
| Aggregation | summarize correlated events into incidents | group 20 alerts → 1 incident |

**Window / state store**
- Time-windowed sliding counters (e.g., 60s/5m/1h) per key (source IP, user, asset).
- In-memory with persistence snapshot to disk; on restart, rebuild state from stored events.
- Avoid stale state: TTL per window, LRU eviction for memory bounds.

**Rule structure** (declarative):
```yaml
- id: BRUTE_FORCE_SSH
  name: SSH brute-force attempt
  severity: high
  match:
    type: threshold
    window: 60s
    threshold: 5
    group_by: [event.source_ip, event.dest_ip]
    filter:
      event.category: authentication
      event.action: auth_failure
      event.dest_port: 22
```

**Correlation output** → a normalized **Alert** object with `rule_id`, `severity`, `evidence` (list of triggering events), and `incident_id` if deduped.

### 2.4 Alerting Layer
Pluggable notification channels, each implementing a common interface.

- `alert_enricher` — adds threat-intel lookups, asset criticality, MITRE ATT&CK mappings.
- `router` — routes by severity: critical → PagerDuty/sms, high → email, medium/low → UI/webhook.
- `deduper` / `suppressor_engine` — prevents alert storms (same key within window coalesces, increments `count`).
- Channels: Email (SMTP), Slack/Teams webhook, PagerDuty/opsgenie, custom webhook.
- `auto_response` hooks (optional, opt-in): trigger firewall block, quarantine user, run IOC enrichment.

### 2.5 Storage Layer
- **Raw/events store**: TSDB / time-partitioned store (e.g., ClickHouse, InfluxDB, or partitioned Parquet) — write-optimized, retention policies per tier.
- **Alerts index**: full-text searchable (e.g., OpenSearch / Elasticsearch) for the alert dashboard.
- **State store**: Redis or embedded KV for correlation windows/counters.
- Retention tiers: hot (7d), warm (30d), cold (1y) — rolled automatically.

---

## 3. Data Flow (End-to-End Walkthrough)

1. Windows agent sends EVTX auth failure → `agent_receiver`.
2. Ingest enqueues `{source: win01, seq: 4021, raw: "..."}`.
3. Normalizer parses to CES `{source_ip: 203.0.113.5, action: auth_failure, category: authentication, ...}`.
4. Enricher adds GeoIP `RU`, asset tag `DMZ`.
5. Correlation: threshold counter for `203.0.113.5 → win01` hits 5 within 60s.
6. `BRUTE_FORCE_SSH` fires → Alert object with 5 evidence events.
7. Router: severity=high, dedupe window=10m → sends to Slack + writes to alerts index.
8. Analyst sees incident in web dashboard; correlation evidence linked.

---

## 4. Projected Directory Layout

```
siem-correlator/
├── core/
│   ├── model/            # CES event & alert dataclasses
│   ├── ingest/           # syslog, file_tailer, api_poller, agent_receiver
│   ├── normalize/        # parsers/, mappers/, enrich/
│   ├── correlate/        # rules engine, windows, aggregators
│   ├── alert/            # router, dedupe, channels/
│   └── store/            # event store, alerts index, state store adapters
├── rules/                # YAML/JSON detection rules (versioned)
├── config/               # sources.yaml, enrichment.yaml, alerting.yaml
├── api/                  # REST & WebSocket for dashboard/analyst
└── test/                 # unit + golden-rule datasets (fixtures/)
```

---

## 5. Non-Functional Requirements

| Aspect | Requirement |
|--------|-------------|
| **Performance** | ≥ 10k EPS sustained on a 4-core/8GB node (batching, zero-copy parsing, non-blocking queues) |
| **Reliability** | At-least-once delivery + dedupe; crash recovery via offset/state persistence |
| **Security** | TLS for ingest; authN on agent/API; secrets in vault/env; least-privilege own fields |
| **Observability** | Pipeline metrics (events/sec, queue depth, parse-fail rate), structured logs, health checks |
| **Operability** | Hot-reloadable rules + config; graceful degradation (alert if correlation window overflows) |
| **Extensibility** | New parsers, enrichers, rules, and alert channels = drop-in modules |

---

## 6. Attack Scenario (Test Case)

**Scenario:** Supply-chain brute-force → lateral movement.
- Inputs: ssh auth failures (source A), successful login after failures (source A→B), then outbound SMB to other hosts from B.
- Expected: 3 correlated alerts → 1 incident (`initial_access`) with ATT&CK tags T1110 / T1021.
- Verification: golden dataset in `test/fixtures/bruteforce_lateral/` reproduces the incident deterministically.

---

## 7. Decision Log (Architecture Choices)

1. **Separate normalize from correlate** → keeps pipeline stateless and testable; correlation only sees clean CES.
2. **Declarative YAML rules over code** → analysts can write rules without redeploying.
3. **Time-windowed counters in an embedded store first** → KISS; move to Redis only when multi-node needed.
4. **Fail-open normalization with quarantine** → losing an event is worse than a wrongly-normalized one.