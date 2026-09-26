# Project 15 — State

## 1. Component Status

| Component | Status | Notes |
|-----------|--------|-------|
| `doors/ssh.py` (SshDoor, SshSimulator) | ✅ Implemented | banner/kex emulation, honeytoken, fake exec, cmd loop |
| `doors/http.py` (HttpDoor, HttpSimulator) | ✅ Implemented | fake admin panel + request trace, decoys |
| `engine/sessions.py` (Session) | ✅ Implemented | signals timeline, duration, sid |
| `engine/fingerprint.py` (net/payload/http + attribute) | ✅ Implemented | tool scoring + campaign sig + os guess |
| `export/events.py` (EventExporter, WebhookPusher) | ✅ Implemented | sessions.jsonl, CES envelope, blocklist push |
| `scripts/attacker_sim.py` | ✅ Implemented | hydra-like SSH replay |
| `main.py` | ✅ Implemented | `--state`, `--run-once`, `--self-test` |
| TLS door (https 8443 world) | 🔲 Not started | cert mgmt; security.md §4 |
| Rate-limiting guard enforcement in-code | 🕐 Partial | config keys exist; auth-count stop not enforced per-session yet |
| egress blackhole enforcement | 🕐 Partial | config key; actual network policy is out-of-scope (deployment) |
| Dashboard / session replay UI | 🔲 Not started | web/ dir planned |
| honeytoken CI guard (no real creds) | 🔲 Planned | grep test in CI |

## 2. Verified Behavior (SMOKE TEST dated 2026-09-13)

`py main.py --self-test` → PASS (ssh sessions=1, http sessions=4).
Attribution verified: hydra-like tool → `interactive-attacker` 0.8 + `common-username-prober` 0.4; os linux64; campaign sig present.
Full export flow: `EventExporter` wrote sessions.jsonl with severity critical for interactive-ssh session, high for http probe; CES envelope correct; blocklist hook signature ready.

Known bug fixed pre-test: `in`-list vs substring (see memory.md §2).

## 3. Known Gaps & Risks

| Gap | Risk | Priority |
|-----|------|----------|
| SSH emulation is line-based (not real SSH transport) | Real SSH clients (openssh) may not connect; only scripted attackers work | Medium — acceptable for demo, document limitation |
| No TLS on HTTP door (https 443) | Bot crawlers on 443 miss the honeypot | Medium |
| Auth-count guard not enforced in-code | Flood of auth attempts per session unbounded (config exists) | High — implement guard break |
| Windows host / Docker network config | Sessions may loopback only | Low — doc deploy in VM/container |
| No `--apply` of blocklist integration | Manual webhook config only | Medium (link with Project 16) |

Priorities: (1) enforce auth-count + session timeout guards, (2) https door, (3) blocklist webhook config end-to-end vs Project 16.

## 4. Definition of Done for Next Milestone

- [ ] Guards enforce `max_auth_attempts_per_session` and `session_timeout_s` (close socket on breach)
- [ ] Full TLS HTTP door (self-signed dev cert) with JA3 fingerprint capture
- [ ] E2E test: honeypot critical session → Project 16 aggregator ingests into blocklist history
- [ ] Dashboard: replay sessions.jsonl in /web with search by peer_ip