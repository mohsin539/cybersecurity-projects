# Project 15 — Honeypot (SSH + HTTP) with Attacker Fingerprinting

> A controlled deception host running **fake SSH and HTTP services** that attract and log real attacker interaction, then **fingerprint the attacker** (tool, TTPs, source, session shape) for detection and intel value.

---

## 1. High-Level Architecture

```
                   INTERNET / DMZ
                        │ traffic
                        ▼
┌────────────────  HONEYPOT (isolated VM/container)  ────────────────┐
│                                                                    │
│   ┌────────────────────────────────────────────────────────────┐   │
│   │   ABU-Oriented Front Doors (fabricated services)           │   │
│   │   SSH :22     HTTP :80/:443 (fake app + fake admin panel)  │   │
│   └───────────────────────────┬────────────────────────────────┘   │
│                               ▼                                     │
│   ┌────────────────────────────────────────────────────────────┐   │
│   │   SESSION / PROTOCOL EMULATION                              │   │
│   │   handshake mimics → complete banner → bounded interaction   │   │
│   │   session_state (auth, cmd input, HTTP request trace)        │   │
│   └───────────────────────────┬────────────────────────────────┘   │
│                               ▼                                     │
│   ┌────────────────────────────────────────────────────────────┐   │
│   │   FINGERPRINTING ENGINE                                     │   │
│   │   io/network: jitter, window size, TTL, banner quirks       │   │
│   │   payload: cmd tokens, hash, register-less UA parser        │   │
│   │   attribution: tool DB (hydra/medusa/nmap/metasploit/Py)    │   │
│   └───────────────────────────┬────────────────────────────────┘   │
│                               ▼                                     │
│   ┌────────────────────────────────────────────────────────────┐   │
│   │   ALERT / EXPORT LAYER                                      │   │
│   │   EVTX-ish event log → JSON stored + streamed                │   │
│   │   blocklist feed (see Project 16), SIEM (Project 11),       │   │
│   │   dashboard, email/pager                                    │   │
│   └────────────────────────────────────────────────────────────┘   │
│                                                                    │
│   Guards: rate limit, no real creds anywhere, egress blackhole     │
│          (real 'downtime' → revoke compromise), sandboxed FS       │
└─────────────────────────────────────────────────────────────────────┘
```

**Design stance:** the honeypot is a **labeled sink**. Legitimate traffic should never reach it; anything that does is suspect and exhaustively recorded. Emulation stays shallow — lure, capture, deployable as deception not full RCE bait.

---

## 2. Component Breakdown

### 2.1 Front Doors (Fabricated Services)

**SSH server** (port 22/2222)
- Handshake emulation: banners echo real-looking (`OpenSSH_8.9p1 Ubuntu`), authentication flow (password only) with configurable accept/reject policy.
- Auth surface: always "wrong password" but accept a predefined **honeytoken** credential to keep sessions interactive without real auth.
- Session cap: 1 interactive shell at a time; PTY + limited command set (`ls`, `id`, `uname`, `cat /etc/passwd`, fake `/root`, `/home/admin/.ssh`, `/tmp`).

**HTTP server** (80/443)
- Serves a **fake admin panel**: login form (logs creds), `index.html` with misconfig vibes (`default creds hint`), canned API endpoints returning misleading-but-harmless data.
- Records full request trace: method, path, query, headers, body, cookies, TLS fingerprint via JA3/JA3S.
- Path trend (e.g., `/.env`, `/wp-admin`, `/actuator`, `/admin`, `.git`, `config.php`) gives immediate attacker-stage signal.

### 2.2 Session / Protocol Emulation

- **Stateful session object** per source IP: `{conn_id, started, tls_ja3, ssh_version, auth_attempts, commands[], http_requests[], net_banner}`.
- Protocol engines adhere to RFCs just enough to be credible (SSH transport incl. key exchange phases, HTTP/1.1 with keep-alive + real-ish TLS). No real server software is installed — everything is application-layer emulation process-wide, so nothing can actually be pwned deeper than the sandbox.
- Randomized but deterministic response variation (avoid "always identical output" signatures).

### 2.3 Fingerprinting Engine

Layered attribution scores:

| Layer | Signals collected | Attribution use |
|-------|-------------------|-----------------|
| **Network/IO** | source TTL, IP MF/size patterns, initial window, packet jitter, banner order | OS `ttl→os` guess (Linux 64, Windows 128, Cisco 255); scanner behavior |
| **Protocol** | SSH banner quirks, unsupported alg proposal ordering, HTTP header casing/order, TLS cipher list (JA3) | library detection: `paramiko` vs `libssh` vs `nmap` vs `medusa` |
| **Payload/behavior** | command token sequence, username probing corpus, HTTP path sequencing + timing | tool classify: `hydra`, `davfs`, `sqlmap`, `Metasploit` payload `cmd.exe /c` vs `/bin/sh -c` |
| **Corpus/signature** | hash of first-N bytes of cmd stream, HTTP body sample | clustering: group identical payload patterns across sessions → campaign grouping |

**Output:** per-session `attribution = {tool_score: [{tool, conf}], os_guess, campaign_id, fingerprints[]}` plus raw evidence retained.

### 2.4 Alert / Export Layer

- **Event schema** (aligned to CES of Project 11): `event.category=failure|scan|pwn|recon`, `severity`, `attacker.ip`, `attrs.session_xxx`, `evidence`.
- Synchronous stream: each completed/failed session flushes a JSON event.
- Channels:
  - local `sessions/` JSONL archive
  - Wazuh/OSSEC manager (compatible with Project 13 pack, `suspicious_door` group)
  - SIEM syslog/webhook (Project 11)
  - Threat-intel blocklist feed (Project 16) — auto-push `attacker.ip` on critical signature
- Dashboard (simple web UI/`ls`-driven report) with session replay view.

---

## 3. Data Flow (End-to-End Walkthrough)

1. Scanner hits :22 with banner grab → session open, TTL 64, ωwindow 64240 → OS guess linux64.
2. Attacker runs `hydra -l root -P rockyou.txt`: 32 auths in 40s → fingerprint layer tags `hydra/hydra6`, campaign grouping "pass-list A".
3. 12th auth succeeds via honeytoken → interactive.
4. Attacker sends `id; uname -a; cat /etc/passwd; rm -rf /tmp/*; ls -la` → pattern corpus → `/bin/sh -c` + "checkcrypt" style blast → attribution `metasploit_shell` hybrid; all w/o real impact (fake FS).
5. Alert fires: `category=pwn`, severity high, `attacker.ip` pushed to Project 16 auto-blocklist.
6. Analyst replays session from dashboard archive; campaign group 2 highlighted.

---

## 4. Deployment Guards (Non-Functional Safety Rails)

- **No real creds, keys, or data** in the honeypot container; honeytokens fake.
- **Egress constrained:** allowlist DNS/HTTP only, everything else blackholed (prevents the honeypot being used as a jumping-off point — the `revoke-compromise` signal if it tries).
- **Rate limit** connection/session; jail on excessive volume (RFC: auto `/usr/bin/timeout`).
- **Isolation:** separate container/VPC, no access to prod network, all mounts read-only, ephemeral.
- **Sensitive data mutation risk:** choose carefully what `cat`/`ls` returns; never echo secrets.
- Registration/consent note in README for deployment environment (deception requires governance sign-off).

---

## 5. Projected Directory Layout

```
honeypot/
├── doors/
│   ├── ssh/           # ssh transport emulation, banner manager, session shells
│   └── http/          # http engine, fake app pages, tls (ja3) capture
├── engine/
│   ├── sessions/      # session state machine, guarantees
│   ├── fingerprint/   # collectors: net/io, protocol, payload, corpus
│   └── rules/         # attribution classifiers (tool/os/campaign)
├── export/            # event schema, writers: jsonl, wazuh, siem_webhook, blocklist_push
├── web/               # replay/dashboard UI
├── config/            # doors.yaml, banner sets, honeytokens, guards
└── test/              # harnessed attacker simulators → expected attribution output
```

---

## 6. Validation Strategy

1. **Real-tool replay:** run `hydra`, `metasploit`, `sqlmap`, `nmap`, `medusa`, `davfs` against it in CI sandbox → assert fingerprint output per tool (goldens).
2. **No-harm regression:** after each session, assert container state == pristine (mount read-only, no process escapes, `/proc/1/root` unreachable).
3. **Protocol conformance:** `ssh -v`, `curl -v`, TLS `openssl s_client` behave as normal server; no handshake errors.
4. **Performance:** 200 concurrent sessions → degradation only at session layer, exporter never blocks.
5. **AB test of fingerprint** with controlled attacker variations (Windows vs Linux TTL) → correct attribution.

---

## 7. Decision Log (Architecture Choices)

1. **Application-level emulation, not real services** — risk containment is the top design force; real sshd/origin would leak.
2. **Fingerprinting outputs intel value, not just a hit count** — attribution + campaign grouping justify the honeypot beyond "noise".
3. **Blocklist integration (Project 16) is a sink, not a loop** — honeypot pushes; blocking happens elsewhere to avoid self-DoS loops inside the deception net.
4. **Guards as hard rails, not soft warnings** — rate-limit / egress-blackhole / privilege-drop enforced at container/network boundary.