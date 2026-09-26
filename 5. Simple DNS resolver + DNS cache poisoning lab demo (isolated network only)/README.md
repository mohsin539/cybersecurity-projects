# Simple DNS Resolver + DNS Cache Poisoning Lab

An educational, **fully isolated** simulation of a recursive DNS resolver with a cache,
and the classic cache-poisoning attacks against it (static ID, ID guessing,
Kaminsky-style delegation poisoning, bailiwick violation). Everything runs in one
Python process on a simulated network — **no real sockets, no real domains, no internet
traffic, ever**.

> ⚠️ Safety: the "network" is an in-process router (`resolver_lab/transport.py`) that
> only routes `172.16.238.x ↔ 172.16.238.x`. Any packet aimed outside that prefix is
> dropped and counted by a tripwire; a nonzero count fails the run.

---

## Requirements

- Python 3.11+ with tkinter (standard on python.org installers; on Windows use the `py` launcher).
- No third-party packages — the runtime is stdlib-only by design.

## Quick start

```text
py main.py                 # launch the GUI (default)
py main.py --self-test     # run the 8-check CI security gate (run this first)
py main.py --list-scenarios
py main.py --headless --scenario 03_kaminsky --seed 7
py main.py --headless --scenario 05_defense_compare --seed 7
py main.py --headless --scenario 04_bailiwick --seed 7 --overrides bailiwick_check=0
py main.py --headless --scenario 02_id_guess --seed 1 --json --log
python -m resolver_lab     # same commands, package entry point
```

Headless flags: `--seed N`, `--overrides k=v,k=v` (e.g. `random_port=1,use_0x20=1,
bailiwick_check=0,ttl_floor=60,random_id=0`), `--json` (full result), `--log` (writes
`logs/lab-<scenario>-<seed>.json`).

## How it works

Nodes (all simulated objects on one flat subnet):

| Node | IP | Role |
|------|----|------|
| resolver | 172.16.238.20 | recursive, caching resolver — the attack target |
| client | 172.16.238.10 | issues victim queries |
| attacker | 172.16.238.30 | sniffs/forges; three knowledge modes |
| root / TLD / auth NS | .40 / .50 / .60 | authoritative chain holding the "truth" zone `lab.local.` |

Resolution is iterative: the resolver asks the root, follows referrals (`local.` →
`lab.local.`), validates each reply (transaction ID, source address/port, qname+qtype,
0x20 case if enabled) and caches answers. The cache is TTL-aware and every entry carries
provenance (`from_addr`, `origin_zone`, `forged` audit tag).

### The three attacker knowledge models (important!)

| Mode | What the attacker knows | Stops it |
|------|------------------------|----------|
| **blind** | nothing — must *guess* ID (+port +case). Success is a seeded probability race `P = 1-(1/p)^attempts` | entropy: random ID, random port, 0x20 |
| **eavesdrop** | everything (it sees the query on the wire) | *nothing* except bailiwick — this models an on-path L2 attacker; entropy does not help |
| **serve** | controls the zone's NS (end-game after Kaminsky) | DNSSEC (not simulated) |

### Scenarios

| ID | Attack | Expected lesson |
|----|--------|-----------------|
| `01_static_id` | predictable transaction ID → spoof wins with P≈1 | randomize IDs |
| `02_id_guess` | blind race, 21 000 guesses → P≈27 % per trial | 16-bit entropy alone is weak (run several seeds!) |
| `03_kaminsky` | random subdomain labels force fresh queries; injects a poisoned zone delegation (NS+glue) then serves evil answers | entropy (ID+port+0x20) is the only thing that stops it; bailiwick does not (the glue is in-zone) |
| `04_bailiwick` | out-of-zone record stuffed in the additional section | bailiwick check ON → blocked; OFF → poisoned |
| `05_defense_compare` | same race with increasing entropy | prints the "entropy budget" table |

### Verdicts and the forged audit

After each trial the cache is diffed against the truth table
(`resolver_lab/config.py: TRUTH`). Any entry that isn't the truth is tagged `forged=True`
and shown in red in the GUI / `FORGED` lines in headless output. `poisoned` = the victim
probe returned the evil IP `203.0.113.66` (TEST-NET-3, RFC 5737); `blocked` = it didn't.

## Reading the GUI

- **Results** tab: one row per trial (verdict, what the victim got, P(win), labels tried).
- **Cache snapshot** tab: every cached record with TTL, source, and forged tag.
- **Packet timeline** tab: every simulated datagram in order (`Q`/`R`, ID, qname).
- **Race / attacker info** panel: entropy bits, win probability, attacker stats.
- Defense checkboxes + TTL floor are per-trial overrides; scenarios may pin some
  (e.g. `01_static_id` *forces* the static ID, that's the point).

## Interpreting the numbers

`P` is the modelled single-trial probability `1-(1-p)^attempts` with
`p = 1/(2^entropy)`; entropy = 16 (random ID) + 16 (random port) + case-bits (0x20,
capped at 12). The race outcome is seeded and therefore deterministic per seed — same
seed, same verdict.

## Tests / verification

```text
py main.py --self-test
```

runs the CI gate (see `security.md §6`): legitimacy invariant, 4 000-blob parser fuzz,
one poisoned + one blocked scenario each for the relevant attacks, and the tripwire
check. Expected output: **8/8 PASS**.

## Documentation map

- `architecture.md` — full design (topology, protocol, components, scenarios)
- `security.md` — ISO 27001 / NIST CSF 2.0 / OWASP Top 10 mapping, threat model
- `reference/state.md` — current project status and verification log
- `reference/memory.md` — design decisions (ADRs) and pitfalls

## Known limitations

- The race is a probabilistic model, not a wall-clock packet flood (see
  `reference/state.md §5`).
- The eavesdrop attacker intentionally defeats entropy defenses — that's the lesson of
  scenario 04.
- No DNSSEC/EDNS0 (documented as future work in `architecture.md §16`).
