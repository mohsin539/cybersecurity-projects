# Security — DNS Cache Poisoning Lab (`resolver_lab`)

This document is the security case for the **Simple DNS resolver + DNS cache poisoning lab
demo**. It exists so the lab's *own* development and operation follow the same security
disciplines it teaches, and so reviewers can map the project to three industry frameworks:

| Framework | Role in this project |
|-----------|----------------------|
| **ISO/IEC 27001:2022** | Security management baseline: assets, controls, risk, audit trail |
| **NIST CSF 2.0** | Operational posture across Govern → Identify → Protect → Detect → Respond → Recover |
| **OWASP Top 10 (2021)** | Secure-coding checklist for the Python/GUI application code |

Scope: the lab runs **only on an isolated, private, simulated network**. It must never be
able to reach, imitate, or disturb real infrastructure. See `architecture.md §3`.

---

## 1. Security Design Principles

1. **Isolation by construction.** The "network" is an in-process simulated transport
   (`resolver_lab/transport.py`). Nodes are addressed only inside `172.16.238.0/24`
   (RFC 1918 space). The transport has a hard tripwire: any packet destined outside the
   lab prefix is logged and dropped; the run aborts if drops are nonzero (called the
   *tripwire*, `TRANSPORT_SAFE`). This implements the architecture's "explicit
   kill-switch" boundary without needing Docker on the host.
2. **No real domain names.** All zones live under reserved test names: `lab.local.`
   and `evil.*` glue derived from the documentation prefixes `203.0.113.x`
   (TEST-NET-3, RFC 5737). Nothing resolves in the public DNS.
3. **No real sockets by default.** Unless explicitly enabled, no UDP/raw sockets are
   bound; the entire attack surface is memory-only, single-process.
4. **Defense-in-depth for the code itself** (they apply even to a lab):
   input validation, least privilege (no admin, no external binaries), dependency-free
   stdlib-only runtime, sealed dependency manifest, logging of every packet, and
   reproducible randomized trials (seeded RNG).
5. **Fail secure.** Defaults for the lab's *defenses* are ON (`bailiwick_check`,
   `random_port`, `use_0x20`, TTL floor). Turning them off is an explicit, UI-visible
   action — the whole point of the lab is comparing states, but the *shipped default* is
   the secured one.

---

## 2. ISO/IEC 27001:2022 Mapping

Annex A controls relevant to this project and how each is satisfied:

| Control | Title | Implementation / evidence |
|---------|-------|---------------------------|
| A.5.1 | Policies for info security | `security.md`, `architecture.md §3` safety rules |
| A.5.7 | Threat intelligence | Attack ontology modeled: static ID, birthday/ID-guess, Kaminsky, bailiwick violation (`attacker.py`) |
| A.5.8 | Info security for use of cloud services | N/A (no cloud). If shipped to a cloud CI, images build from pinned base, no private data |
| A.5.9 | Management of information security in supply chains | Stdlib-only runtime; no third-party runtime deps to vet; CI runs `pip-audit` on dev deps |
| A.5.10 | Monitoring | Packet timeline log for every simulated datagram; resolver audit events |
| A.5.11 | Centralised log management | `logs/lab-<ts>.log` (JSON-lines), scenario results JSON |
| A.5.12 | Reversible operations / rollback | Reproducible seeds → any trial replays exactly |
| A.6.7 | Off-boarding | Single-purpose sandbox; CI teardown trap removes temp envs |
| A.8.1 | Definition of roles & responsib. | Role separation in code: `resolver`, `attacker`, `auth`, `client`, `orchestrator` are separate objects with separate responsibilities |
| A.8.3 | Asset inventory | Zone tables + config (single source of truth) listed in `config.py` |
| A.8.4 | Component identification | Named nodes with RFC 1918 addresses; SBOM in `SECURITY.md §7` |
| A.8.7 | Protecting against malware | Attacker is **simulated** only; real malware not present; antivirus alert false-positive note §7 |
| A.8.8 | Coding practices | OWASP Top 10 §5 below; code review gate; no secrets in code |
| A.8.16 | Logging | Every packet, cache mutation, and verdict is logged with timestamps |
| A.8.19 | Installation of software on systems | No installer; run via standard `py` launcher; no registry writes |
| A.8.23 | Web filtering / prevention of hacking | Tripwire + "no external routes" §1 |
| A.8.25 | Secure development lifecycle | Threat modelling (§4), unit/self-tests (§6), review checklist |
| A.8.26 | Application security | Input validation for all parsed messages; fuzz harness in self-test |
| A.8.28 | Secure coding | Bounds-checked DNS parser (no buffer overrun classes in Python, but index/pointer-loop guards), case-sensitive validation |
| A.8.29 | Security testing | `--self-test` gate in CI; deterministic attack trials |
| A.5.1/A.9 | Access control | GUI is local; no network listeners; threat model §4 |
| A.8.13 | Backup | Repo + `reference/state.md` session snapshots |
| A.5.24/25 | Incident management (plan/response) | §"Incident playbook" below |

---

## 3. NIST CSF 2.0 Mapping

| Function | Capability in this lab |
|----------|------------------------|
| **Govern (GV)** | Security policies in `security.md`; risk register §4; roles separated in code |
| **Identify (ID)** | CIS asset inventory (`config.py` zones/nodes); the DNS attack taxonomy is the threat catalogue |
| **Protect (PR)** | `PR.AA` identity/access: GUI is single-user local; `PR.DS` data security: all "network" data synthetic; `PR.PS` platform security: stdlib-only, no admin, no external sockets; `PR.AT` awareness: the lab *is* the awareness training |
| **Detect (DE)** | `DE.CM` monitoring: every packet is logged and inspected; cache audit tags (`forged=True`) detect poisoning the moment it occurs |
| **Respond (RS)** | `RS.MA` mitigation: verdict engine stops the attack, dumps cache, correlates victim trуth vs poisoned value |
| **Recover (RC)** | `RC.RP` recovery: `flush-cache` + seeded replay restore a clean, comparable state |

---

## 4. Threat Model & Risk Register

Identified risks to the *lab itself* and their mitigations:

| # | Threat | Likelihood | Impact | Mitigation / Control |
|---|--------|-----------|--------|----------------------|
| T1 | Lab escaping the sandbox to real hosts | Low | High | In-process sim; tripwire drop; no host sockets; no subnet leaks (#1) |
| T2 | A student mistakes poisoned records for real DNS data | Medium | Low | Every poisoned entry tagged `forged=True`; UI warns; dedicated doc-namespace only |
| T3 | Pathological input from scenario YAML | Low | Medium | Scenarios validated by schema-aware loader; α-numeric zone/name whitelist |
| T4 | GUI/log leak of secrets or PII | Low | Low | No secrets stored at all; logs contain only synthetic names/IPs |
| T5 | Reproducibility loss (nondeterminism) | Medium | Medium | Deterministic PRNG seeds + monotonic sequence IDs; recorded seed per trial |
| T6 | Supply chain (dev tooling) | Low | Low | Dev-only deps pinned; `pip-audit` in CI; prod runtime is stdlib |

Risk appetite: the lab is **research/training-only**; no production service. Controls are
applied accordingly (proportional, no over-engineering).

### Incident response playbook (for this lab)
1. If the **tripwire** fires (packet directed outside `172.16.238.0/24`), the run halts
   immediately and `logs/` captures the offending packet.
2. If a poisoned record is ever suspected to be *believed* by a human (T2): run
   `python main.py --self-test` — it proves the resolver resolves the truth zone
   correctly with defenses ON; then `flush-cache`.
3. If nondeterminism stops a trial (T5): re-run with the recorded seed; report a bug if
   outcomes differ for an identical seed.
4. Every incident is logged with verdict + seed + full packet timeline for forensics.

---

## 5. OWASP Top 10 (2021) Applied to the Application Code

This is a desktop GUI app (not a web app), but the Top 10 still applies to its code:

| OWASP | Risk in this app | How we address it |
|-------|------------------|-------------------|
| **A01: Broken Access Control** | GUI/cache not exposing overly broad controls | Single-user local GUI; no network listeners; read-only demo functions; attacker capabilities are modeled *inside* the sim only, never on the OS |
| **A02: Cryptographic Failures** | No crypto needed — data is synthetic | Nothing sensitive is stored; seeded PRNG is used deliberately (not for security) and *documented as such*. DNS 0x20 randomization implemented properly from `secrets`/system RNG, not the seed stream |
| **A03: Injection** | Scenario/config input, GUI entry fields | Whitelist validation of names (`[a-z0-9_.-]`, length caps); integer coercion with bounds; no `eval`/`exec` anywhere; scenario YAML loader rejects unknown keys |
| **A04: Insecure Design** | The whole point is an *intentionally* vulnerable resolver | The vulnerability is controlled and quarantined in the sim; design-level controls (bailiwick, TTL floor, entropy) are implemented as the defense layer; no real exposure |
| **A05: Security Misconfiguration** | Defenses accidentally left off | Shipped defaults: defenses ON; the GUI shows defense state prominently; scenario config explicitly sets each defense; a warning banner appears when `bailiwick_check=off` |
| **A06: Vulnerable & Outdated Components** | Python stdlib | Runtime = stdlib only (3.12). Dev deps (none mandatory) are pinned in `pyproject.toml`/`requirements-dev.txt`; `pip-audit` gate; no downgrades |
| **A07: Identification & Authentication Failures** | Local app auth | Not applicable in-network; local file access protected only by host OS access control (documented) |
| **A08: Software & Data Integrity Failures** | Tampered zones / forged cache | Cache entries carry provenance + `forged` audit tag; `--self-test` asserts the legitimacy invariant each run; zones are read-only constants |
| **A09: Security Logging & Monitoring Failures** | Missing visibility of the attack | Packet timeline, cache-diff, verdict, seed — logged to `logs/*.jsonl`; GUI table surfaces every forged entry |
| **A10: Server-Side Request Forgery** | Resolver "asking" the real internet | The resolver only ever "connects" to addresses inside the lab prefix; tripwire enforces it; no outbound syscalls |

### Secure-coding invariants enforced by the self-test (`--self-test`)
- **[Legitimacy invariant]** With defenses ON and the attacker idle, resolving every zone
  name returns exactly the truth records. This suite must *always* pass.
- **[Poison detectability]** With the attacker active, any cache divergence from truth is
  tagged `forged=True` and logged.
- **[Robustness]** The DNS parser, fed malformed/truncated/pointer-loop packets, raises a
  controlled `DnsError` (never an unhandled crash, never unbounded memory).

---

## 6. Testing, Guardrails & Release Gates

| Gate | Tool | Requirement |
|------|------|-------------|
| Lint / static analysis | `ruff check src` (dev only) | No errors; no `eval`/`exec`/`pickle` of untrusted data |
| Dependency audit | `pip-audit` | Zero known-vulnerability deps (dev only) |
| Unit / logic | `python main.py --self-test` | Legitimacy, robustness, one poisoned + one blocked scenario |
| Fuzzing | `test_fuzz_packets` in self-test | 5,000 malformed blobs → no crash |
| Safety tripwire | `TRANSPORT_SAFE=1` | Every simulated packet must target `172.16.238.*`; nonzero drop ⇒ run aborts |
| Reproducibility | seeded trials | Identical seed ⇒ identical outcome, recorded in results JSON |
| Release | manual review | `security.md` checklist + `reference/state.md` updated; no secrets in diff |

---

## 7. Software Bill of Materials (SBOM)

Runtime (application): Python **3.12** + **standard library only**: `tkinter`, `asyncio`
(inactive stub), `threading`, `queue`, `dataclasses`, `ipaddress`, `heapq`, `argparse`,
`json`, `logging`, `socket` (never actively used by default), `secrets`.

Dev/test (recommended, not required): `pytest`, `ruff`, `pip-audit` — pinned in
`requirements-dev.txt`.

AV note: the presence of an "attacker" module may trip heuristic AV on some hosts. It is a
pure in-memory simulator; optional AV exclusions may be added for the `resolver_lab` tree.

---

## 8. Secrets & Privacy
- **No secrets**: no API keys, tokens, or credentials exist in this project by design.
- **No PII**: logs/cache contain only synthetic names (`*.lab.local`, TEST-NET IPs).
- Any scenario file or GUI input is treated as *untrusted data* (validated) per A03.

**Security owner:** `resolver_lab/` maintainers. Review cadence: on every architectural
change or new scenario; see `reference/state.md` for the audit checklist.