# State — DNS Cache Poisoning Lab

Live project-state ledger. Update after every meaningful change (per `security.md §8` and
the "update these files" convention). Versioned; each entry appends to HISTORY.

> Convention: after implementing a feature, **append** a row to HISTORY and refresh the
> "Current status" table. Keep `memory.md` for durable knowledge; keep `state.md` for the
> *current* snapshot.

---

## 1. Project snapshot

| Field | Value |
|-------|-------|
| Last updated | 2026-09-12 |
| Status | **Complete — core + GUI + docs delivered; self-test 8/8 PASS** |
| Reference docs | `architecture.md`, `security.md`, `reference/memory.md` |
| Security posture | See `security.md`; defenses default **ON** |
| Runtime | Python 3.12 (stdlib + tkinter only), Windows host |

---

## 2. Current status of architecture components (architecture.md §6/§12)

| Component | File | Status | Notes |
|-----------|------|--------|-------|
| DNS wire codec (RFC 1035 subset) | `resolver_lab/packets.py` | 🟢 Done, tested | A/AAAA/CNAME/NS/SOA/TXT; compression pointers; strict bounds |
| TTL cache + audit tags | `resolver_lab/cache.py` | 🟢 Done | provenance, TTL floor, negative caching, `forged` tag |
| Simulated transport (isolated net) | `resolver_lab/transport.py` | 🟢 Done | tripwire-on, in-process routing, packet timeline |
| Authoritative hierarchy (root/tld/auth) | `resolver_lab/auth_server.py` | 🟢 Done | referrals, glue, NXDOMAIN + SOA negatives |
| Recursive resolver + defenses | `resolver_lab/resolver.py` | 🟢 Done | ID strategies, port randomization, 0x20, bailiwick |
| Attacker engines (blind flood / eavesdrop / serve) | `resolver_lab/attacker.py` | 🟢 Done | static-ID, ID-guess, Kaminsky, bailiwick payloads |
| Scenarios + verdicts | `resolver_lab/scenarios.py`, `lab.py` | 🟢 Done, verified | 5 scenarios incl. defense-compare |
| GUI (tkinter) | `resolver_lab/gui.py` | 🟢 Done (smoke-tested) | Scenarios, defense toggles, cache/timeline/results tables |
| CLI / headless / self-test | `main.py` | 🟢 Done | `--headless`, `--self-test`, `--list-scenarios` |
| Security doc | `security.md` | 🟢 Done | ISO 27001:2022, NIST CSF 2.0, OWASP Top 10 |
| State / memory | `reference/state.md`, `reference/memory.md` | 🟢 Done | this file + memory ledger |

Legend: 🟢 operational 🟡 partial ⚪ not started 🔴 blocked

---

## 3. Verification log (run `python main.py --self-test`)

| Run | Date | Seed(s) | Result | Notes |
|-----|------|---------|--------|-------|
| CI-gate | 2026-09-12 | 3,7 | **ALL PASS (8/8)** | legitimacy, 4000-blob fuzz, 01→poisoned, 04 off→poisoned, 04 on→blocked, 03→poisoned, 03+entropy→blocked, tripwire clean |
| Headless (GUI harness) | 2026-09-12 | 7 | poisoned | `03_kaminsky`, labels tried=1, hit=rr1.lab.local. |
| Headless compare | 2026-09-12 | 7 | table | P(base)=0.274 → P(+port)=5e-6 → P(+0x20)=7.8e-5 → P(+both)=0 |

---

## 4. Scenario results (latest headless run)

> Populate from `python main.py --headless --scenario <name> --seed <n>`.

| Scenario | Seed | Defenses | Verdict | Attempts/labels | Cache poisoned entries |
|----------|------|----------|---------|-----------------|------------------------|
| `01_static_id` | 7 | static ID (natural) | `poisoned` | race p=1.0 | demosrv.lab.local. → 203.0.113.66 |
| `02_id_guess` | 1 | random ID only | `poisoned` | p=0.274 (21000 guesses) | demosrv.lab.local. → 203.0.113.66 |
| `02_id_guess` | 7 | random ID only | `blocked` | p=0.274 | — |
| `03_kaminsky` | 7 | static (natural) | `poisoned` | labels=1 | delegation lab.local.→ns1.evil.lab.local. (+glue) → www poisoned |
| `03_kaminsky` | 7 | random_id+port+0x20 | `blocked` | labels=60 | — |
| `04_bailiwick` | 7 | bailiwick off | `poisoned` | eavesdrop | api.otherlab.local. → 203.0.113.66 |
| `04_bailiwick` | 7 | bailiwick on | `blocked` | eavesdrop | — (clean NXDOMAIN) |

### ID-guess race note
With `attempts=21000` the modelled per-trial poison probability is **~27%** (`02_id_guess`,
seed 1 poisons; seed 7 blocked). Deterministic per seed — a great "shuffle the seed"
demo. Compare against `05_defense_compare` table for the entropy lesson.

---

## 5. Known issues / limitations

1. **Timing model is simplified.** The attacker floods *within a round window* keyed to
   the client query, rather than over a wall-clock DNS TTL. Educational, not a precise
   packet-timing reproduction. Documented in `memory.md`.
2. **Eavesdrop attacker sees everything** (ID, port, 0x20 case) — this models an on-path
   L2 attacker and intentionally defeats entropy defenses; pairing is on the student to
   explain (see `memory.md`, "0x20 vs on-path").
3. **One process / one OS user.** No cross-machine containers; that is a deliberate
   trade-off for zero-dependency portability.
4. **GUI is single-window, single-threaded UI with a worker thread.** Long Kaminsky runs
   show progress via the packet counter; Stop is honored between rounds.
5. **Windows + AV:** the `attacker` module name may trigger heuristic AV; see `security.md §7`.

---

## 6. Backlog

- [ ] Optional Docker mode (real UDP sockets on loopback, `--transport real`) — blocked on
      scapy/raw-packet availability on Windows CI.
- [ ] EDNS0-COOKIE / DNSSEC sim toggle (future work, architecture.md §16).
- [ ] HTML/JSON report export from GUI.
- [ ] CI workflow stub (`.github/workflows/lab.yml`): self-test + ruff + pip-audit.
- [ ] `reference/memory.md` "pitfalls" section: add notes from any new debugging sessions.

---

## 7. Checklist for opening a new session

- [ ] `git status`-equivalent: confirm tree integrity
- [ ] Run `python main.py --self-test` → all assertions PASS
- [ ] Run `python main.py --headless --scenario 03_kaminsky --seed 7 --json` → verdict recorded
- [ ] Read `reference/memory.md` decision log (ADRs) before refactoring
- [ ] Bump "Last updated" above

---

## 8. HISTORY

| Date | Change | Verified? |
|------|--------|-----------|
| 2026-09-12 | Initial scaffold: docs (`security.md`, `state.md`, `memory.md`) | yes |
| 2026-09-12 | Core sim implemented (packets/cache/transport/servers/resolver/attacker/lab) | yes (self-test) |
| 2026-09-12 | GUI + CLI entry points added | yes (headless + GUI smoke) |
| 2026-09-12 | Fixes: RR type-code bug (#7), closure cursor bug (#9), `lab.running` flag | yes (8/8 PASS after) |