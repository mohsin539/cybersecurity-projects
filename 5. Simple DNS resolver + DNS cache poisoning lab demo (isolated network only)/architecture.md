# Architecture — Simple DNS Resolver + DNS Cache Poisoning Lab Demo

**Scope:** Educational lab demo that builds (a) a simple recursive DNS resolver with a
client-facing cache, and (b) a set of DNS cache poisoning attack modules that demonstrate
how a resolver can be tricked into caching forged records — all inside a **fully isolated
network**, never touching the public internet.

---

## 1. Overview

The demo models a miniature DNS ecosystem on one isolated virtual network:

- A **client** that asks a domain name lookup.
- A **recursive resolver** that performs iterative lookups and **caches** answers.
- A tiny chain of **authoritative name servers** (root → TLD → authoritative) that hold the
  "truth" records.
- An **attacker** that observes queries and injects forged answers to poison the cache.
- An **orchestrator** that wires the scenario together, runs it end-to-end, and scores the
  outcome.

The point of the lab is to show, in a controlled sandbox, *how* and *why* the classic DNS
cache-poisoning attacks (ID guessing, bailiwick violation, Kaminsky-style) work, and what
real-world mitigation techniques (source-port randomization, random case 0x20 encoding)
do to increase attacker difficulty.

```
        isolated bridge network            (no external routing, no RPF, no internet)
   ┌──────────────────────────────────────────────────────────────────────────────┐
   │  .1 client          .2 resolver          .3 attacker      .4 root / .5 TLD  │
   │  ┌──────────┐       ┌──────────────┐    ┌───────────────┐   ┌─────────────┐  │
   │  │ client   │       │  resolver    │    │  attacker     │   │  auth → ... │  │
   │  │ (queries │ │     │  · iterative │    │  · sniffer    │   │  hierarchy  │  │
   │  │  resolve)│ │     │  · cache     │    │  · forger     │   │  (truth)    │  │
   │  └──────────┘ │     └──────────────┘    └───────────────┘   └─────────────┘  │
   └──────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Goals & Non-Goals

### Goals
- Implement a working recursive resolver that resolves names using a simulated
  authoritative hierarchy, with a TTL-aware in-memory cache.
- Implement an attack module able to **poison the cache** under controlled conditions.
- Provide deterministic, scripted scenarios that demonstrate attack success and the
  effect of defenses.
- Act as a teaching aid: every packet is logged and inspectable, cache contents are
  dumpable at any time.
- Be **safe by construction**: isolated-only, no real domain names, no external traffic.

### Non-Goals
- Production-grade DNS (no DNSSEC validation, no EDNS0, no qname minimization, no
  transport encryption — except as noted in §10 for demonstration on/off).
- Realistic internet-scale performance.
- Attacking or redirecting real infrastructure.

---

## 3. Safety & Scope (Isolated Network ONLY)

This is the **hardest design constraint** and the entire topology exists to enforce it.

| Rule | Enforcement |
|------|-------------|
| No internet access | Custom Docker bridge network, no NAT, no default gateway, `network_mode` cannot escape; all assets use RFC1918 / 172.16.238.0/24-style space |
| No real domains | All demo names use a reserved test zone rooted at `lab.local` (never in the real root zone) or `.test` / `.example` labels |
| Firewall carving | Orchestrator sets `IPTABLES`/`ufw`-style rules (lab-specific) to drop outbound UDP/53 to anything outside the lab prefix |
| Explicit kill-switch | Any packet whose destination is not within the lab subnet is logged and dropped |
| Read-only by default | Attacker module only *spoofs* on the lab net; it never sends to anything not in `lab_net` |
| Swimlane | Components are containers with no host mounts except a shared `logs/` volume |

Rationale: cache poisoning is an *off-path* identity-spoofing attack; running it against
real resolvers would be illegal and harmful. Everything here is simulated within one
private broadcast domain.

---

## 4. DNS Protocol Primer (What We Implement)

The lab implements a minimal but wire-correct DNS message codec (RFC 1035 subset):

```
 Offset  Field
 ──────  ──────────────── ──────────────── ────────────────
 0       ID         (16)  QR OPCODE AA TC RD RA Z RCODE (16 status bits)
 4       QDCOUNT    (16)  number of questions
 6       ANCOUNT    (16)  number of answers
 8       NSCOUNT    (16)  number of authority records
 10      ARCOUNT    (16)  number of additional records
 12      QUESTION...      QNAME (labels) QTYPE(16) QCLASS(16)
 ...     ANSWER RRs        NAME TYPE CLASS TTL(32) RDLENGTH(16) RDATA
 ...     AUTHORITY RRs
 ...     ADDITIONAL RRs
```

Name encoding rules handled by the codec:

- Labels using the **0x20 flag trick** (preserving/randomizing case in queries) to support
  the 0x20 defense in §10.
- Name **compression pointers** (0xC0) must be decoded so a parser cannot misread a forged
  packet; the resolver treats compressed pointers inside the RDATA of additional records
  carefully (bailiwick checks, §9.4).

Question/answer mapping is strict:

- A **question** defines QNAME + QTYPE (e.g. `A`, `AAAA`, `NS`).
- An **answer** must be a direct answer to the question.
- An **authority** RR provides NS/soa records.
- An **additional** RR is what attackers abuse to inject *out-of-scope* glue.

---

## 5. Network Topology & Addressing

Docker-compose service layout (single user-defined bridge so all nodes share one L2 domain
and a shared subnet — that shared, flat correlation is itself part of the demo, because
real off-path attacks rely on spoofed Source IPs being unverifiable):

| Node | IP (172.16.238.0/24) | Role |
|------|----------------------|------|
| `client`     | .10 | Issues resolution requests to the resolver |
| `resolver`   | .20 | Recursive resolver + cache to be attacked |
| `attacker`   | .30 | Sniffs traffic, forges spoofed responses |
| `rootns`     | .40 | Simulated root zone for `lab.local.` |
| `tldns`      | .50 | Simulated `.local` TLD |
| `authns`     | .60 | Authoritative for `demosrv.lab.local`, `www.lab.local`, etc. |
| `orchestrator` | .70 | Control plane: wires configs, runs scenarios, reads agent reports |

All servers listen on UDP/53; the resolver also listens on a **management TCP/5300**
channel used by the orchestrator to `dump-cache`, `set-defense`, and `query`.

Reserved demo zone data (the "truth" table stored on `authns`):

```
demosrv.lab.local.  A 172.16.238.61
www.lab.local.      A 172.16.238.62
api.lab.local.      A 172.16.238.63
lab.local.          NS authns.lab.local.   (authoritative NS set)
```

---

## 6. Component Architecture

All components are Python 3.11+ (`asyncio`-based UDP servers). The packet codec is
**hand-rolled** (no third-party DNS lib) so that the wire format is graded mechanically
and the 0x20 case trick is under our control.

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                               orchestrator.py                                 │
│   scenario engine · config injector · cache dumps · verdict/scoring          │
└───────┬──────────────────────────────────────────────────────────────────────┘
        │  mgmt TCP 5300           │  control / signals
        ▼                          ▼
┌───────────────┐          ┌───────────────┐
│   resolver    │◄────────►│    attacker   │
│  (UDP 53)     │   sniff+ │  (UDP 53)     │
│  · iterative  │   forge  │  · libpcap    │
│  · cache      │◄────────►│  · ID guess   │
│  · bailiwick  │ quer.    │  · baitiwick  │
│  · defenses   │ spoof.   │  violation    │
└───────┬───────┘          └───────────────┘
        │ UDP/53 iterative queries
        ▼
┌───────────────┐   ┌───────────────┐   ┌───────────────┐
│ rootns (.40)  │──►│ tldns  (.50)  │──►│ authns (.60)  │
│ zone: .local  │   │ zone: local.  │   │ zone: lab.    │
└───────────────┘   └───────────────┘   └───────────────┘
```

### 6.1 `client.py`
- Reads a list of hostnames (e.g. `demosrv.lab.local`) from stdin/config.
- Sends `A` queries to the resolver, prints answer + whether the answer came from cache.
- Reports verdict information back to the orchestrator (JSON over mgmt port).

### 6.2 `resolver.py` — the recursive resolver (crown jewel)
State machine for a query:

```
receive Q          → cache lookup
   ├─ cache hit    → respond, mark "served from cache"
   └─ cache miss   → iterative resolution:
        for ns in (root, tld, auth) in order:
            select target server (root hint → tld → auth)
            build query (QNAME, QTYPE, optional ID strategy / 0x20 case)
            send over new/ephemeral source port (randomization)
            arm timeouts + retries
            receive response → validate:
                · has matching ID?
                · has matching QNAME+QTYPE (+case-encoding if 0x20 on)?
                · source address is the server we asked?
                · bailiwick: can the response speak for this zone? (§9.4)
            on valid non-authoritative answer → recurse up the chain
   cache the final answer (respecting TTL, clamping to min TTL)
respond to client
```

Configuration knobs (all exposed to the orchestrator at runtime, so a single lab scenario
can toggle defense on/off between trials):

- `use_random_port: bool` — source port randomization
- `use_0x20: bool` — random-case query names
- `id_strategy: static | random`
- `cache_ttl_min_floor: int`
- `acceptnonauthoritative_from: ...` (attack enabling knobs, only for demo)

### 6.3 `cache.py`
In-memory TTL cache.

- **Key:** `(name_lowercase, rrtype)` normalized for lookup; the *stored* record keeps
  original case for 0x20 verification.
- **Entry:** `{ rdata, ttl_deadline, inserted_at, origin_zone, source_ns, source_port,
  forged: bool }` — provenance fields make cache dumps educational.
- **Operations:** `lookup(qname, qtype, now)`, `insert(records, now)`, `expire(now)`,
  `dump()` (used by orchestrator to snapshot the cache before/after an attack).
- **TTL behavior:** store the minimum of received TTLs, clamp to a floor when
  `cache_ttl_min_floor` is set, never cache negative/soa beyond a small cap.

### 6.4 Authoritative servers (`rootns.py`, `tldns.py`, `authns.py`)
Single class parameterized by zone file; each serves only its zone and returns the
appropiate NS referral chain upward/downward. These represent the "truth" and are the
legitimate source the resolver *should* trust.

### 6.5 `attacker.py` — the cache-poisoning lab
Passive + active halves running in one process:

- **Sniffer (passive part):** uses `scapy`/raw sockets to see resolver queries on the L2
  segment. Learns: QNAME, QTYPE, source port, transaction ID (when ID not randomized).
- **Forger (active part):** crafts spoofed responses with:
  - spoofed source IP = the authoritative server the resolver *wants* to hear from
  - attacker-chosen answer/additional records (the payload to cache)
  - the observed/guessed transaction ID
- **Attack drivers** selected per scenario (§9).

### 6.6 `packets.py` (codec)
- `encode_question`, `encode_answer`, `encode_response`
- `parse_message(buffer)` → dataclass with strict bounds checks (no buffer overruns on
  malformed input; errors → truncated/refused behavior, never a crash)
- handles label reading, pointer loops, 0x20 case preservation

### 6.7 `orchestrator.py`
- Reads scenario YAML (which attack, which defenses are on, seed for RNG, trial count).
- Starts the compose stack in ordered steps, waits for readiness on mgmt TCP.
- During a trial: flushes resolver cache, starts attacker, fires client queries, waits
  N seconds, then dumps the cache and compares against the "truth" zone to score:
  - **Poisoning succeeded** if the cache contains records not in the truth table (or
    wrong rdata for a true name).
  - Otherwise **blocked**.
- Emits structured results + logs to `logs/` and stdout.

---

## 7. Data-Flow / Sequence Diagrams

### 7.1 Legitimate iterative resolution (client → resolver → hierarchy)

```
Client  Resolver  RootNS    TLDNS   AuthNS(truth .61)
   │       │        │        │        │
   │──A──► │        │        │        │
   │       │  cache miss │    │        │
   │       │──root?───►│    │        │   (asks for lab.local NS)
   │       │◄─ref: lab.local NS@tldns │
   │       │──lab.local?────►│        │
   │       │◄─ref: lab.local NS@authns│
   │       │──www.lab.local?─────────►│
   │       │◄─ A 172.16.238.62 ──────│
   │       │  verify ID, qname, 0x20 │
   │       │  cache → store           │
   │◄A───│  (served from cache next time)
```

### 7.2 Cache poisoning (attacker wins)

```
Client  Resolver  Attacker  AuthNS
   │──A──►│           │        │
   │      │ (miss)    │        │
   │      │──query───►│        │      * attacker sees port+ID (or guesses),
   │      │           │        │
   │      │◄══spoofed response══╛      - ID correct or guessed
   │      │     additional: www.lab.local. -> 6.6.6.6
   │      │   (answer claims authority that attacker controls)
   │      │  validator skipped (demo) → stores 6.6.6.6
   │◄─────│  A 6.6.6.6 (poisoned!)
```

---

## 8. Cache Design (detail)

```
CacheEntry:
    name        : str          (lowercase key component)
    qtype       : int
    rdata       : str | list[str]
    ttl         : int          (received TTL, clamped)
    deadline    : float        (inserted_at + ttl)
    origin_zone : str          (zone that legitimately owns this name = bailiwick)
    from_ns     : str|None     (authoritative source that supplied it)
    src_port    : int
    forged      : bool         (flag set by attacker-inserted demo path / audit)
```

Insertion rules (defense-mode attitudes listed for teaching):

1. Lookup normalizes case; stored records retain case for 0x20 audit.
2. **Bailiwick check (default ON):** an additional RR may only be cached if its name is
   a subdomain of the zone for which the source server is authoritative. Attackers setting
   `www.lab.local` inside a response from a server authoritative for a *different* zone
   must be rejected.
3. TTL floor enforcement if configured.
4. **Provenance tag:** records that pass while defense is *off* are tagged `forged=True` by
   the audit layer after a cache dump comparison — this is how the lab "proves" poisoning.

---

## 9. Attack Modules

Each scenario is parameterized (RNG seed) so trials are reproducible.

### 9.1 Static transaction-ID spoofing
- Attacker presumes the resolver uses a predictable/static ID bank.
- For each observed query, respond with `ID = predicted`, spoofed source = authns.
- TODO teaching: with ID static, success probability ≈ 1 per hit.

### 9.2 Random ID guessing (birthday / hoax)
- Attacker *doesn't see* the query (ID unknown) and must guess.
- Sends many candidate responses across the same query window; success ≈
  `1 - (1 - 1/65536)^n` for n attempts before the legitimate answer lands.
- Demonstrates why 16-bit IDs alone are weak.

### 9.3 Kaminsky-style (cache-poisoning via unanswered names)
- When the attacker can't wait for the legit response to a cached name, use a *random*
  subdomain label: `x1.lab.local`, `x2.lab.local`, ... each provokes a fresh resolver
  query that won't be in cache.
- Attacker races to answer an **NS + glue additional record** for `lab.local` in that
  response.
- If poisoned, the resolver now uses the attacker's NS for the whole zone → attacker
  supplies the final A records for *any* name in the zone.
- Scenario scoring: measure how many random labels needed before first successful
  injection (i.e. time-to-poison histogram).

### 9.4 Bailiwick-violation payload injection
- A crafted *additional* section adds `victim.lab.local` (or `bigname.otherlab.local`)
  while pretending the response is for a legit in-scope name.
- Teach: without bailiwick checks, out-of-zone glue is cached → immediate cross-name
  poisoning.

---

## 10. Defenses (toggled per trial, for comparison)

| Defense | Mechanism | Effect (demo measurement) |
|---------|-----------|---------------------------|
| Transaction ID randomness | unpredictable 16-bit ID | attacker must guess → low odds (see 9.2) |
| Source-port randomization §6.2 | ephemeral random source ports | attacker doesn't know the port → extra entropy |
| 0x20 (random case) encoding | query name case is random; response must echo case | attacker cannot echo unknown case → detection odds ≈ 2^labels |
| Bailiwick enforcement §8 | only cache in-zone glue | kills injection of out-of-scope RRs |
| TTL floor | clamp small TTLs | reduces re-poison rate / replay window |
| DNSSEC (NOT implemented; documented for reference) | signed zone | makes forging provably impossible |

Lab measures *success vs. defense-encoding* and prints an "entropy budget" table so the
student sees why 0x20 vs random port vs random ID multiply together with bailiwick rules.

---

## 11. Threat Model & Safety Boundaries

- **Attacker assumed:** off-path on the same L2 segment, can spoof source IP (common on
  plain L2 networking without anti-spoofing), can sniff broadcast/observer traffic in the
  passive variant (this is the academic "passive eavesdropper" case; classic Kaminsky
  assumes seeing only the query for a random label, which the attacker generates itself).
- **Out of scope / explicitly prevented:** on-path MITM, ARP spoofing, DHCP/DNS rebinding,
  and any activity that touches hosts outside the lab bridge. Orchestrator hard-fails if
  anything beyond the lab subnet appears in a log line.
- **Container privileges:** attacker runs with `NET_RAW`/`NET_ADMIN` capabilities (for raw
  sockets); resolver and auth servers run without NET_ADMIN. Capabilities are dropped in
  production-like profiles if this lab is ever cloned.

---

## 12. Repository / Module Layout

```
.
├── architecture.md
├── README.md                    # quick-start, safety banner
├── docker-compose.yml           # isolated bridge + services
├── labenv/
│   ├── Dockerfile.*             # per-role images (thin)
│   ├── iptables-rules.sh        # outbound drop to non-lab prefixes
│   └── zones/
│       ├── root.zone
│       ├── local.zone
│       └── lab.zone             # truth records
├── src/
│   ├── packets.py               # DNS wire codec (RFC 1035 subset)
│   ├── resolver.py              # recursive resolver + validation
│   ├── cache.py                 # TTL cache + audit tags
│   ├── auth_server.py           # root/tld/auth authority (parameterized)
│   ├── attacker.py              # sniffer + forger + attack drivers
│   ├── client.py                # query driver
│   └── orchestrator.py          # scenario/runs/scoring/reporting
├── scenarios/
│   ├── 01_static_id.yaml
│   ├── 02_id_guess.yaml
│   ├── 03_kaminsky.yaml
│   ├── 04_bailiwick.yaml
│   └── 05_defense_compare.yaml
├── tests/
│   ├── test_packets.py
│   ├── test_cache.py
│   └── test_resolver_legit.py   # poison-free resolution must always pass
└── logs/                        # (runtime; volume-shared, git-ignored)
```

---

## 13. Interfaces & Configuration

- **Client → Resolver:** UDP/53 plain queries (A/AAAA/NS), mgmt TCP/5300 JSON-RPC-lite.
- **Resolver → authorities:** UDP/53 iterative queries (with defense knobs).
- **Attacker:** passive libpcap (scapy) reading L2; active spoofed UDP writes.
- **Orchestrator mgmt calls:** `flush-cache`, `dump-cache`, `set-defense
  {on,off}`, `status`, and per-trial results.
- **Scenario YAML shape:**

```yaml
name: 03_kaminsky
attack: kaminsky
defenses:                      # toggled for this trial
  random_port: true
  use_0x20: true
  bailiwick_check: true
  ttl_min_floor: 0
seed: 42
labels_to_try: 200
zone_pointer: lab.local
payload:
  type: NS
  answer: ns.evil.lab.local. 6.6.6.6
```

---

## 14. Run-Time Scenario Flow (orchestrator)

1. `docker compose up --build -d` (isolated net, hard `iptables` drop).
2. Wait for resolver readiness (probe mgmt TCP/5300).
3. For each trial in scenario:
   a. `flush-cache`, snapshot truth table.
   b. Start attacker with its drivers; arm a victim query list on the client.
   c. Trigger the client; pause `attack_window` seconds; stop attacker.
   d. `dump-cache` → diff with truth → mark `poisoned | blocked`.
   e. Record metrics (attempts, success, TTL of poisoned entries).
4. Write `logs/<scenario>-<trial>.json` + human-readable report; display summary table.
5. Verdict: out-of-net traffic → hard abort (safety tripwire).

---

## 15. Testing & Verification

- **Wire-level unit tests:** round-trip packet encode/decode; pointer-loop fuzz; malformed
  length handling.
- **Legitimacy invariant:** with defenses ON and no attacker, every resolution returns the
  truth records — this suite must always pass (guard against the demo accidentally
  teaching that resolvers are always broken).
- **Deterministic attacks:** seeded RNG → same trials produce same poisoning outcomes on a
  clean cache.
- **Safety assertions:** assert every logged packet destination is inside
  `172.16.238.0/24`; CI job aborts the run otherwise.
- Optional `pytest` runner + a one-shot `docker compose down` teardown trap (`trap`/`finally`
  so the isolated net can never persist across runs).

---

## 16. Future Work

- Add UDP/tcp fallback for truncated responses.
- Port defense comparison histogram with more repetitions to a JSON summary.
- Add EDNS0 cookie as a "modern defense" toggle (documented: binds client/server).
- Optional DNSSEC simulation (public/private key pair, signed `lab.zone`) to show
  definitive poisoning prevention.
- GUI-less but nicer REPL: `orc 03_kaminsky --visual` prints an animated packet timeline.