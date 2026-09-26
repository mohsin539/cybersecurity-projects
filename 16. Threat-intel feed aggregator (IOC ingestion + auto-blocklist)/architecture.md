# Project 16 — Threat-Intel Feed Aggregator (IOC Injection + Auto-Blocklist)

> Ingests indicators of compromise (IOCs) from many external and internal feeds, validates/deduplicates them, and continuously maintains an **auto-blocklist** pushed to firewalls, DNS, WAF, and SIEM.

---

## 1. High-Level Architecture

```
 INTEL SOURCES                        AGGREGATOR CORE
 ┌──────────┐    ┌─────────────────────────────────────────────┐
 │ AlienVault│──▶│  INGEST       NORMALIZE      ENRICH /        │
 │ MISP      │──▶│  adapters     (IOC schema)   VALIDATE        │
 │ AbuseIPDB │──▶│  REST/Feed    parse,          reputation,    │
 │ CIC       │──▶│  /STIX/TAXII  cidr/domain/   reverse-dns,    │
 │ Twitter/X │──▶│  /MISP-API    ipv4/6/domain   asset overlap  │
 │ CRITs/OTX │──▶│               dedupe                       │
 │ Honeypot  │──▶│                                      │       │
 │ (Proj 15) │──▶│              ┌──────────────────────┘       │
 └──────────┘    │              ▼                               │
                 │  DECISION / BLOCKLIST CORE                │
                 │  scoring ─▶ trust tiers ─▶ blocklist       │
                 │  lifecycle: active→expiring→retired        │
                 │                │                            │
                 └────────────────┼────────────────────────────┘
                                  ▼
                CONSUMERS: Shadow, pfSense, AWS SG/NACL, Cloudflare,
                CrowdSec/PIN, DNS sinkhole, WAF, SIEM (Proj 11),
                Feed API, expiry/rollback ops
```

**Two-headed design:** a *consumer-facing blocklist* (curated, safe, auto-applied) and a *full IOC store* (research-grade, requires a query key) — never mix them at the enforcement boundary.

---

## 2. Component Breakdown

### 2.1 Ingest Layer

| Adapter | Protocol | Notes |
|---------|----------|-------|
| MISP instance | MISP API / events | pull events > last check |
| AlienVault OTX | AlienVault API | pulsed indicators + timeouts |
| AbuseIPDB | AbuseIPDB API | reported IPs + confidence |
| STIX/TAXII | TAXII 2.x collection | STIX 2.0+ objects, `indicator` SDOs |
| Generic RSS/github feeds | HTTP poll | parsing white-listed formats |
| **Internal honeypot** (Proj 15) | internal webhook | direct `attacker.ip` push |
| Internal SIEM (Proj 11) | syslog/webhook | detected `src_ip` signals |
| CSV/JSON file drop | watched dir | operator-administrated |

**Ingest contract (adapter → normalize):**
```yaml
{feed_id, source_ref, ioc_type: ipv4|ipv6|cidr|domain|url|file_hash,
 value, first_seen, last_seen, confidence, tags, tlp, raw}
```

**Feed hygiene:** TTL/expiry carried per feed (`timeout` field, MISP `to`); schema-version tag; feed health — if a feed returns errors > N times it is marked degraded (no auto-drop at boundaries).

### 2.2 Normalize Layer

- Canonical IOC record: `{id, norm_type, value, list, expires, source, tags[], tlp, provenance[], derived_from[]}`.
- **Normalization rules:** case-fold domains, intent-parse `URL` → domain+path, expand CIDR vs host IP (`/24` stays a net; host IP stays a host), normalize IPv6, strip `www.` for domains, canonical hash (md5|sha1|sha256 lettercase), dedupe on `(norm_type, normalized_value)` collapsing multiple sources (provenance array grows).
- **Quality gates:**
  - Blacklist maintenance: never auto-block internal RFC1918 / link-local / multicast / broadcast ranges (inverse allow-list guard).
  - Source reputation: TLP-AMBER+ never auto-applied; only TLP:WHITE/GREEN (and internal vetted feeds) can enter auto-blocklist.
  - Confidence threshold config per feed (or global default).
  - Resolution check: for domains, resolve A/AAAA on ingest; unresolvable domains kept but flagged `unresolved` (cannot safely block w/ DNS sinkhole).

### 2.3 Validate / Enrich Layer

- **Reputation co-validation:** cross-source agreement (e.g., two independent feeds report same IP) raises confidence; conflict (one benign, one malicious) demotes.
- **Reverse DNS / whois / ASN enrichment** — adds context to support scoring, not blocking decision itself.
- **Asset-overlap check:** does the candidate IOC collide with our own infrastructure (owned ranges, our own hostnames)? Never block our own assets — override flag.
- **Live-check (optional, throttled):** for IPs, verify the indicator still serves content (e.g., domain resolves to something or IP answers) → avoid stale.

### 2.4 Decision / Blocklist Core

Trust tiers:
| Tier | Policy | Auto-enforce? |
|------|--------|---------------|
| Critical (2+ vetted feeds, high conf, or internal IDS/honeypot hit) | block immediately, log | yes |
| High | confidence≥ X | yes (configurable) |
| Median | single 3rd-party feed, medium conf | no — 24h quarantine, require approval (or low-sev auto with easy rollback) |
| Suspected | low conf or ambiguous | stored only, human review queue |

**Blocklist record:** `{value, norm_type, tier, added_by, added_at, source: feed_ids[], expires_at, rollback_plan, status}`.

**Lifecycle engine (scheduled evaluator):**
- `active` (enforced) / `quarantined` (review) / `expiring` (last 25% TTL) → re-verify feed last_seen; / `retired` (auto-backoff).

On retire → **auto-rollback** plan: push allowed-list revert to consumers, verify, then drop record. No token or dashboard obscures this: rollback is an audited first-class process.

### 2.5 Consumer Integration Layer

Push/emit mechanism configurable per consumer via **driver plugins**:

| Consumer | Mechanism | Notes |
|----------|-----------|-------|
| pfSense / OPNsense | `pfctl` + alias table via SSH/API | alias + `pfctl -t blocklist -T add` |
| AWS SG/NACL | boto3 `revoke/authorize` rule set sync | new deny rule → diff-only |
| Cloudflare lists | Cloudflare API list item ops | WAF rules + DNS rules |
| CrowdSec/PIN | CrowdSec API / CLI | `cscli decisions add` |
| DNS sinkhole (Pi-hole) | gravity `/etc/pihole/list` | domains only normalized |
| WAF (nginx/modsec) | RwLock file reload | maintain full file swap + reload |
| SIEM (Proj 11) | webhook | emit `intel_event` for ingestion/alerting |

Every driver is **idempotent** (adding an existing item is a no-op) and transactional-safe (config reload on error: if a consumer fails to accept a batch → retried, `mark_consumer_sync` field kept).

---

## 3. Data Flow (End-to-End Walkthrough)

1. Honeypot (Proj 15) reports `203.0.113.42` attacker → internal webhook.
2. Normalize: `ipv4`, canonical value ok (pub addr), TLP internal = vetted.
3. Enrich: reverse-DNS `scan.badhost.ex`, 2 external feeds also list the IP → critical tier.
4. Blocklist engine adds record; AWS NACL adapter diffs → inserts deny rule for `203.0.113.42/32`.
5. SIEM receives `intel_event` (decision push), analyst panel shows the provenance chain.
6. TTL 30d; at day 28 off-list in all feeds → `expiring` → day 30 retire → NACL remove + audit log.
7. If the IOC turns benign meanwhile (feeding error), `conflict_detect` demotes to `quarantined`, rollback fires in 1h, analyst notified.

---

## 4. Projected Directory Layout

```
threat-intel-aggregator/
├── core/
│   ├── ingest/        # adapters/: misp, otx, abuseipdb, taxii, rss, internal_honeypot, siem_hook
│   ├── normalize/     # ioc model, dedupe, canonicalizers, guards/internal-ranges
│   ├── enrich/        # reputation co-validate, rdns/asn, asset-overlap, live-check
│   ├── decision/      # tiers, quarantine/approval, lifecycle evaluator, rollback plans
│   └── consumers/     # drivers/: pfsense, aws, cloudflare, crowdesk, pihole_dns, waf, siem
├── api/               # REST: feeds, iocs (query w/ key), blocklist status, approvals, rollback
├── web/               # dashboards: feed health, blocklist, approve-queue
├── config/            # feeds.yaml, tiers.yaml, consumers.yaml, ttl defaults
└── test/              # golden feeds, guard-test (never blocks RFC1918), rollback-replay tests
```

---

## 5. Non-Functional Requirements

| Aspect | Requirement |
|--------|-------------|
| **Safety over comprehensiveness** | Guards block internal ranges/assets; tiering prevents certificate-mining feed toxicity |
| **Reliability** | Every feed poll idempotent w/ retry+backoff; lifecycle evaluator crash-safe (windowed states, replayable) |
| **Accountability** | Each blocked IOC traces to feed ✓ provenance; approval/rollback audited |
| **Security** | Feed creds in vault; TLP handling enforced; external feed payload never executed (parsers sandboxed) |
| **Scale** | 100 feeds, 10M IOCs, blocklist ≤ 200k entries, sync < 5 min per consumer |
| **Operability** | Feed-health dashboard, per-CPU metrics, structured logs, health endpoint |

---

## 6. Validation Strategy

1. **Guard tests:** synthetic fixture proves RFC1918/link-local/internal-asset/own-domain never enter auto-blocklist.
2. **Dedup fuzz:** overlapping CIDR/domain/hash normalization merges provenance — expected merge counts asserted.
3. **Consumer idempotency replay:** run a sync twice and one partial-fail → resulting firewall/dns/waf state converges (golden snapshot).
4. **Lifecycle sim:** clock-accelerated TTL → active→expiring→retired→rollback all fired in order, audit trail complete.
5. **TIP/SIEM integration test:** internal pulse from Proj 15 + Proj 11 reaches blocklist w/ correct tier (cross-project E2E).
6. **Graceful failure:** feed goes down 72h → no IOC expiry during window marked as validated (or fed), consumers untouched.

---

## 7. Decision Log (Architecture Choices)

1. **Two-headed store** (research store + auto-blocklist) keeps enforcement conservative while researchers query everything.
2. **Trust-tier auto-enforcement with explicit rollback as a flow** — balances attack-response speed with the danger of auto-blocking benign IPs.
3. **Idempotent, diff-only consumer drivers** — never full table replacement against live FW (only changed additions/removals).
4. **Internal intel (honeypot/SIEM) always outranks external** — your own detection is more trustworthy about *your* environment than a vendor feed.