# Memory — DNS Cache Poisoning Lab (persistent knowledge bank)

This file is the project's **reservation / memory ledger**: durable knowledge, decisions
(ADR-style), DNS gotchas we learned while building, and pointers to `security.md` /
`state.md`. Treat it as the long-term memory; refresh `state.md` for the current snapshot.

> Convention: append to the relevant section; never delete history — mark superseded
> entries with ~~strikethrough~~ + a pointer instead.

---

## 1. Project memory (context vault)

- **Vision (from `architecture.md`)**: a clean-room mini-DNS ecosystem — client, recursive
  resolver + cache, root/TLD/auth authorities, and an attacker — on an **isolated
  network only**, demonstrating classic cache poisoning and the defenses against it.
- **Environment**: Windows host; Python 3.12 via the **`py`** launcher (`python` resolves
  to a Microsoft Store alias — always use `py` in scripts/CI on this machine).
  `tkinter` 8.6 available; runtime is stdlib-only by design.
- **Risk posture**: lab/training only; no production; no real sockets; tripwire-enforced
  subnet (RFC 1918 `172.16.238.0/24`) — see `security.md §4`.

---

## 2. Decisions (light ADR log)

### ADR-001 — In-process simulated network over real containers/sockets
**Status:** accepted.
**Context:** architecture.md §5 describes Docker bridge nodes. For a zero-dependency,
portable GUI lab on Windows, real containers/sockets complicate the frictionless demo.
**Decision:** implement `transport.py` as an in-process datagram router with latency ticks,
addresses `(ip, port)`, a packet timeline, and a safety tripwire. Nodes are objects, not
processes.
**Consequences:** deterministic, seed-reproducible, safe by construction. Docker/real-UDP
mode is backlog (see `state.md §6`).

### ADR-002 — Attacker models: *blind flood*, *eavesdrop*, *serve*
**Status:** accepted.
**Context:** the classic attacks differ in *visibility* AS used:
- static-ID / ID-guess = "blind" (guesses transaction ID, source port, 0x20 case);
- plain spoofing = "eavesdrop" (sniffs the query — off-path yet L2-visible);
- Kaminsky = "blind" flood of deferred-race guesses **plus** an evil NS that answers.
**Decision:** three engines in one `Attacker` node; scenario YAML picks mode + payload.
**Consequences:** honest threat model; students can see exactly *how much* the attacker
knows. See "Pitfalls" #2.

### ADR-003 — Bailiwick rule modelled as "glue/additional only for subdomain of the in-scope zone"
**Status:** accepted (simplification).
**Context:** real resolvers cache *in-zone* glue from referrals but reject out-of-scope
additional records from responses that shouldn't speak for them.
**Decision:** store `additional` RRs only when their name is a subdomain of the zone the
response context establishes (answering zone, or the delegation zone in a referral);
`evil.*`-branch glue from a rootns/tldns spoof is rejected. This stops scenario 04
(bailiwick), and correctly lets Kaminsky glue pass when it is same-zone — matching reality.
**Consequences:** Kaminsky is defeated by *entropy* (ID/port/0x20), not bailiwick — the
correct lesson.

### ADR-004 — All randomness: two streams
**Status:** accepted.
**Context:** we *need* reproducible scenarios (seeded PRNG) AND honest "0x20 case" picks
that an attacker cannot correlate.
**Decision:** scenario/trial outcomes use `random.Random(seed)`; the resolver's ephemeral
0x20 case uses `secrets`/system RNG so it is genuinely unguessable. `security.md` section
"OWASP A02" documents this split.
**Consequences:** identical seed → identical verdicts; 0x20 remains a *real* defense.

### ADR-005 — Eavesdropper sees 0x20 case (on-path = all bets off)
**Status:** accepted; intentional, documented.
**Context:** a sniffer on the same L2 segment *does* see the query name including case.
**Decision:** the eavesdrop engine replays the seen case. 0x20 therefore protects against
**blind** spoofing only. GUI note states this; the defense-compare scenario uses the blind
engine so 0x20 gains are measurable.
**Consequences:** students can't over-claim 0x20; on-path attackers need DNSSEC/EDNS0
(the backlog item).

---

## 3. DNS knowledge notes (things we must not forget)

### 3.1 Wire format essentials (RFC 1035 subset we implement)
- Header 12 bytes: ID | flags(QR/opcode/AA/TC/RD/RA/Z/rcode) | QD AN NS AR counts.
- QNAME: length-prefixed labels; trailing root byte `0x00`; `.` → `\x00`.
- Compression pointers `0xC0 0xXX` reference a prior offset; **guard against pointer
  loops** (max 128 jumps) and label-length bounds — done in `packets.py`.
- RDATA for `A` = 4 bytes; `AAAA` = 16 (use `ipaddress`); `NS`/`CNAME` = name;
  `TXT` = length-prefixed; `SOA` = mname rname + 20 bytes of 5 ints.
  **SOA is the negative-answer TTL carrier** (`authority` section, `rcode=3`).

### 3.2 Iterative resolution recap (our algorithm)
1. Start at the root; walk delegation chain: `root → local. → lab.local.`.
2. A referral is `AA=0` + `authority` NS RRs whose owner zone is a suffix of QNAME, with
   glue `additional` A records; the responder is *not* authoritative.
3. An authoritative answer is `AA=1` + answer RRs.
4. NXDOMAIN/NOERROR-empty += SOA in authority → cache a negative with SOA TTL.
5. Bailiwick: only accept/answer/store records for names the speaking server is
   authoritative for (or in-scope delegation glue). Root can't answer for `lab.*`.

### 3.3 Attack fact-sheet (the "why it works" summary used in GUI hints)
| Attack | What the attacker knows | Primary countermeasure |
|--------|--------------------------|------------------------|
| Static transaction ID | the ID value (predictable) | randomize IDs |
| Random ID guessing | nothing; probability per guess = 1/65536 | many guesses → still risky; add entropy |
| Source-port randomization | must also guess port | multiplies entropy (×~64K) |
| 0x20 case randomization | must echo unguessable case | ~2^(labels-with-case) detection |
| Bailiwick violation | can inject out-of-zone glue if unchecked | enforce bailiwick |
| Kaminsky | triggers queries for random labels | entropy again (it bypasses bailiwick when glue is same-zone) |
| DNSSEC / EDNS0 COOKIE | — | make forgery provably impossible (future sim) |

### 3.4 The Kaminsky trick in one paragraph
Poisoning a *cached name* is hard because the legit answer is usually already cached, so
fresh queries are rare. Instead: make the resolver ask about a **random, never-before-seen**
subdomain label (`r1234.lab.local`). That *forces* a new query to the parent zone. If the
attacker wins that single race (right ID/port/case), it can inject whatever delegation /
glue it wants before the true response lands. The query itself is attacker-induced, so
flooding guesses at the right label is effectively "known qname".

---

## 4. Environment commands (this machine)

```text
py --version                       # Python 3.12.7
py main.py                          # launch GUI
py main.py --self-test              # assertions gate (always run first)
py main.py --list-scenarios
py main.py --headless --scenario 03_kaminsky --seed 7 --json
py -m pytest tests                  # optional dev tests if pytest installed
ruff check resolver_lab main.py     # optional lint
```

---

## 5. Pitfalls & debugging scars

1. **`python` vs `py` on Windows**: bare `python` hits the Store alias. Always
   `py`. (Already bitten once — that's why self-test is gated.)
2. **0x20 is NOT an on-path defense.** We initially expected OS eagerly display of
   defense-compare; the eavesdrop engine keeps seeing the case. Fix taught us to
   separate attacker *knowledge models* — see ADR-005.
3. **Pointer loops**: a malicious name that points to itself must abort cleanly; our
   parse tracks a jump budget. Keep it.
4. **Race winner = first *validated* response**, not first arrival. The resolver must
   validate (id/qname/case/src-port) before caching, or the lab teaches the wrong lesson.
   The transport intentionally delivers attacker spoofs at `clock+0` and legit replies at
   `clock+latency`, so *eavesdrop* attackers win ties — realistic.
5. **Negative caching**: forgetting SOA TTL makes poisoned/absent lookups stick forever;
   clamp with the TTL floor. Cache table shows `deadline` so TTL behavior is inspectable.
6. **GUI threading**: tkinter is main-thread only. The lab runs in a worker thread and
   talks to the UI via `queue.Queue` + `root.after(100, poll)`. Never touch widgets from
   the worker.
7. **Type codes vs string type names**: the truth zone and payloads must carry *numeric*
   RR types (`TYPE_A = 1`). First build stored `('A', [...])` and the auth server silently
   answered "NOERROR + SOA in authority / zero answers" — truncating resolution. The
   legitimacy invariant caught it. When adding record types, keep numeric codes everywhere
   (`config.py`, `scenarios.py`).
8. **Legitimacy invariant is the canary**: the `--self-test` check "no attacker,
   defenses ON, resolves the truth zone" must be the *first* thing run after any resolver
   change — it caught #7 and would catch agreement bugs between server behavior and
   cache policy.
9. **Python local-variable trap in closures**: `DnsMessage.parse`'s inner `read()` once
   referenced the outer `off` while also assigning it → `UnboundLocalError`. Use an
   explicit cursor variable (`cur`) for closure-local progression.

---

## 6. Reservation notes (things to preserve across sessions)

- The **only files worth editing by hand** are `reference/*.md`, `security.md`,
  `architecture.md`, and the `resolver_lab/` + `main.py` sources.
- **Never weaken the safety defaults** without logging it in ADR-001/ADR-005 and
  `state.md §7`.
- Keep the SBOM claims in `security.md §7` true: runtime deps = stdlib alone.
- When adding a new attack scenario: (a) choose attacker *knowledge model* first,
  (b) define the "truth vs forged" probe, (c) add a row to `state.md §4`, (d) add an
  assertion to `--self-test` that the expected verdict is produced.