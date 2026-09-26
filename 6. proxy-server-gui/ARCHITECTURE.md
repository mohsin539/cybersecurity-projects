# Custom Proxy Server (HTTP/SOCKS5) — GUI-Based Solution Architecture

**Version:** 1.0 · **Date:** 2026-09-13 · **Status:** Draft for review
**Deployment model:** Per-workstation proxy agent (HTTP + SOCKS5) with desktop GUI, optionally managed by a central policy server.

---

## 1. Executive Summary

A lightweight, locally-installed proxy agent that runs on **every computer** in the organization. It provides:

- **HTTP/1.1 + HTTPS (CONNECT tunnel) proxying** on localhost
- **SOCKS5 proxying** (RFC 1928, with optional username/password auth and UDP ASSOCIATE)
- A **desktop GUI** for status, rules, logs, and settings
- **Privilege separation**: the network engine runs as a Windows Service (SYSTEM); the GUI runs as the logged-in user and talks to the service over a local IPC channel
- **Central management (optional)**: policies, allow/deny lists, and audit logs can be pushed/pulled from a central server — essential when deploying to hundreds of machines

The design is modular so the core engine can later be ported to Linux/macOS, or run headless on servers.

---

## 2. Goals & Non-Goals

### Goals
| # | Goal |
|---|------|
| G1 | Terminate HTTP and SOCKS5 client connections locally; relay to direct internet or upstream/parent proxies |
| G2 | Enforce access policy: allow/deny by domain, IP, port, protocol, time window |
| G3 | Full audit trail: who/what/when/where — exportable to SIEM (syslog/CEF) |
| G4 | Zero-IT-touch deployment: silent MSI install, GPO/Intune rollout, auto-start |
| G5 | GUI usable by both end users (status only) and admins (full config, elevated) |
| G6 | Survive machine reboot, network changes, service crashes (watchdog/self-heal) |
| G7 | Low overhead: < 1% CPU steady-state, < 80 MB RAM, sub-millisecond local relay |

### Non-Goals (v1)
- Caching proxy (Squid-style content caching)
- Full MITM TLS inspection (designed-for, behind a feature flag, v2)
- VPN/WireGuard tunneling, antivirus, DLP content scanning
- Load-balancing reverse proxy for published services

---

## 3. High-Level Architecture

```
                        ┌──────────────────────────────────────────────────────────┐
                        │                     WORKSTATION                          │
                        │                                                          │
  Browser / App ───────►│  ┌────────────┐   IPC (named pipe / gRPC)  ┌──────────┐  │
  (HTTP/SOCKS5 client)  │  │  Proxy Core │◄───────────────────────────►│  GUI App  │  │
                        │  │  (Service)  │                             │  (User)   │  │
                        │  └─────┬──────┘                             └────┬─────┘  │
                        │        │                                         │        │
                        │        │  ┌──────────────────────────────────────┤        │
                        │        ▼  ▼                                      │        │
                        │  ┌─────────────────┐   ┌──────────────┐  ┌──────▼─────┐  │
                        │  │  Rule Engine    │   │ Config Store │  │ Log Viewer │  │
                        │  └────────┬────────┘   │ (JSON+Reg)   │  └────────────┘  │
                        │           │            └──────────────┘                   │
                        │           ▼                                               │
                        │  ┌─────────────────┐     ┌────────────────────────────┐   │
                        │  │ Upstream Router │────►│ Outbound: Direct / Parent  │   │
                        │  └─────────────────┘     │ Proxy / PAC / Chain        │   │
                        │                          └────────────────────────────┘   │
                        │  ┌──────────────┐  ┌───────────┐  ┌────────────────────┐  │
                        │  │ Audit Logger │  │ Updater   │  │ Health/WDA Watchdog│  │
                        │  └──────┬───────┘  └───────────┘  └────────────────────┘   │
                        └─────────┼──────────────────────────────────────────────────┘
                                  │ syslog / HTTPS (outbound only)
                                  ▼
                        ┌──────────────────────┐        ┌────────────────────┐
                        │  SIEM / Log Server   │        │ Central Mgmt Server│
                        │  (Wazuh/Splunk/etc.) │        │ (policies, nodes,  │
                        └──────────────────────┘        │ fleet dashboard)   │
                                                        └────────────────────┘
```

**Key principle — two processes, one product:**

| Process | Runs as | Purpose |
|---|---|---|
| `ProxyCoreSvc` | Windows Service, LocalSystem | Listens on 127.0.0.1:8080 (HTTP), 127.0.0.1:1080 (SOCKS5), enforces policy, writes logs |
| `ProxyGUI` | Logged-in user | Dashboard, settings, log viewer; elevated admin actions via UAC |

The GUI **never** touches sockets directly — it asks the service via IPC. This prevents users bypassing policy by killing the GUI, and lets the proxy keep running with no user logged in.

---

## 4. Functional Requirements

### 4.1 Proxy Engine
- **HTTP proxy:** absolute-URI `GET/POST/PUT/DELETE/HEAD/OPTIONS/PATCH`, header handling (Hop-by-hop removal, `Via`/`X-Forwarded-For` injection optional)
- **HTTPS:** `CONNECT host:port` tunnel with blind byte relay (TCP splicing); optional MITM mode with local enterprise CA (v2, off by default)
- **SOCKS5:** no-auth (`0x00`) and username/password (`0x02`) methods, `CONNECT` + `UDP ASSOCIATE` (for DNS/QUIC-aware apps), `BIND` stub returning not-supported
- **Listeners:** configurable bind address/port (default loopback only), IPv4 + IPv6
- **Upstream modes:** Direct / HTTP parent / SOCKS5 parent / chained (proxy → proxy) / PAC URL / static per-rule routing
- **Timeouts & limits:** idle timeout, connect timeout, max connections per client IP, global max connections, per-host rate limiting (optional)

### 4.2 Rule / Policy Engine
- Rules: `Allow | Deny | Route-to-upstream` matched on: FQDN (wildcard `*.example.com`), IP/CIDR, port, protocol (http/https/socks), user/group, time window
- Ordered rule list, first-match-wins; default action configurable
- Category lists (import/export as plain text or JSON); optional DNS-based category lookup via central server
- Wildcard + regex support; hot-reload without service restart

### 4.3 GUI
| Screen | User | Admin (elevated) |
|---|---|---|
| Dashboard — proxy state, uptime, live throughput graph, active connections count | read | read |
| Connections — live table of open tunnels (proto, dst, rule hit, bytes) | read | kill connection |
| Rules — CRUD, reorder, import/export, test-a-rule simulator | ❌ | ✅ |
| Logs — filterable live view (severity, proto, dst), export CSV/JSON | read | ✅ |
| Upstreams — parent proxies, PAC URL, health status, failover order | ❌ | ✅ |
| Settings — ports, bind addr, auth mode, logging level, update channel | ❌ | ✅ |
| Diagnostics — self-test (listen, DNS, upstream reachability), connectivity trace | ✅ | ✅ |
| About / Updates — version, license, check-for-updates | read | ✅ |

### 4.4 Central Management Server (optional module)
- Fleet inventory (agents check-in with heartbeat + version + config hash)
- Push policies (signed JSON bundles) — agent pulls or server pushes via HTTPS
- Aggregated event/log collection to SIEM
- Web dashboard (read-only ops view); no per-user data beyond what policy requires

---

## 5. Component Design

### 5.1 Proxy Core Engine

**I/O model:** fully asynchronous, event-driven. One acceptor per listener; each client connection gets an async state machine, not a thread-per-connection. Target: 2,000 concurrent tunnels per workstation comfortably.

```
Listener(HTTP :8080)      Listener(SOCKS5 :1080)
        │                         │
        ▼                         ▼
  Protocol Parser ──► Session State Machine
        │                  │  1. parse request (or SOCKS5 handshake)
        │                  │  2. resolve target (DNS w/ cache)
        │                  │  3. evaluate RuleEngine ──► deny? send 403/REFUSED
        │                  │  4. select UpstreamRouter (direct/parent/PAC)
        │                  │  5. connect upstream (pool, TLS if needed)
        │                  │  6. bidirectional relay loop (zero-copy buffers)
        │                  │  7. teardown, write audit event
        ▼                  ▼
   Connection Pool    Metrics/Counters (Prometheus-style exposition)
```

**Relay loop:** two `Socket.ReceiveAsync/SendAsync` pumps with 64 KB buffers; for HTTPS CONNECT the same loop applies (no content inspection in passthrough mode). Back-pressure: stop reading from A when B's send buffer is full.

**DNS:** async resolver with 30 s TTL cache; optional "resolve via upstream proxy" mode (send hostname in CONNECT/SOCKS5 request instead of resolving locally — prevents DNS leaks).

**HTTP parent chaining:** when the selected upstream is itself a proxy, the client request is re-issued toward the parent (absolute-URI for HTTP; CONNECT for HTTPS), with `Proxy-Authorization` if the parent requires it.

### 5.2 Rule Engine
- Compiled to a matcher trie: exact FQDN map → suffix map (wildcards) → CIDR radix tree → port/proto sets; evaluation is O(len(host)) — no linear scans
- Hot reload: new rule-set built off-thread, atomically swapped (`Interlocked.Exchange`)
- Every decision is logged with: timestamp, client, proto, target, rule ID, action — this is the audit backbone
- **Test-a-rule simulator** in GUI: input "user X, CONNECT example.com:443" → shows which rule matches and why

### 5.3 Upstream Router
- Ordered upstream list with **health checks** (TCP connect probe every 30 s, configurable)
- Failover: primary → secondary → direct (if policy allows); circuit-breaker trips after N consecutive failures, half-open retry after cooldown
- PAC support: fetch + (optionally sandboxed) evaluate; cache result per destination
- Per-rule routing: e.g., `*.corp.internal → parent-internal; * → direct`

### 5.4 TLS Handling
- **v1 (passthrough):** no cert interception; SNI observed for logging only
- **v2 (MITM, flag-gated):** generate per-host leaf certs signed by an org-issued intermediate CA installed via GPO; private keys never leave the workstation; HSTS/pinning-aware bypass list (banking apps, update servers) **must** be configured
- TLS to upstream/parent proxies: verify certs, allow pinning of parent proxy cert

### 5.5 Authentication & Access Control
- Listener auth modes: `none (loopback-only default)`, `IP allowlist`, `SOCKS5 user/pass`, `HTTP Basic` (against local vault or AD/LDAP)
- GUI: Windows-integrated auth; admin screens require the built-in Administrators group (UAC prompt); config file ACL'd to Administrators
- All admin actions (rule change, upstream change, service stop) audited with the Windows username

### 5.6 Config Store
- `config.json` (signed bundle when centrally managed) + registry for machine-specific values (install ID, ports)
- Schema-versioned with migration; every change is written atomically (temp file + rename) and versioned locally (last 10 kept for rollback)
- SHA-256 manifest; central bundles are signature-verified (ed25519) before acceptance

### 5.7 Audit Logger
- Structured JSON lines, rotating daily + size-based (e.g., 100 MB × 14 days), zstd-compressed archives
- Sinks: local file, Windows Event Log, syslog (RFC 5424) / HTTPS to SIEM; buffering with disk spill so a SIEM outage never blocks proxying
- Event types: `session.start/end`, `rule.match/deny`, `upstream.failover`, `config.change`, `service.start/stop`, `update.applied`

### 5.8 Updater
- Checks signed manifests (msi + ed25519 sig) from an internal update server; staged rollout rings (canary 5% → pilot 20% → all)
- Silent upgrade via MSI major-upgrade; service restarts within a maintenance window; automatic rollback if the service fails health-check post-upgrade

### 5.9 GUI Application
- **Pattern:** MVVM; views are thin; all state comes from an `AgentClient` (IPC wrapper) with live push events (connection counters, log tail) over the same channel
- Local-only tabs (Dashboard/Diagnostics) available without elevation; config tabs call the service's admin API (service re-checks the caller's token/groups — GUI elevation is UX, not security)
- Tray icon: proxy on/off indicator, quick pause (time-boxed, audited), open dashboard
- Responsive: WinForms/WPF-style layout, dark/light theme, high-DPI aware

### 5.10 Service Host & Watchdog
- Windows Service with recovery actions (restart after 30 s ×3, then reboot flag); health endpoint on a localhost-only port reporting uptime, listener status, last-audit-hash
- Optional separate watchdog process (or scheduled task) that verifies health and restarts the service if it stops responding

---

## 6. Protocol Flow Diagrams

### 6.1 HTTPS via CONNECT (passthrough)
```
Browser            ProxyCoreSvc              RuleEngine        Upstream/Direct
  │  CONNECT api.x.com:443  │                    │                  │
  ├────────────────────────►│                    │                  │
  │                         │ evaluate(target)   │                  │
  │                         ├───────────────────►│                  │
  │                         │◄───── ALLOW ───────┤                  │
  │                         │ TCP connect api.x.com:443             │
  │                         ├───────────────────────────────────────►│
  │◄──── 200 Established ───┤                                        │
  ├──── TLS ClientHello ───►│ ========== blind relay both ways =====►│
  │◄═══════════════ encrypted tunnel (no inspection) ══════════════┤
  │                         │ log session.end (bytes, duration)      │
```

### 6.2 SOCKS5 handshake (user/pass, CONNECT)
```
Client                 ProxyCoreSvc
  │  0x05 0x02 0x00 0x02 │   ← ver5, 2 methods: no-auth, user/pass
  ├─────────────────────►│
  │◄──── 0x05 0x02 ──────┤   ← choose user/pass
  │  0x01 user len pass  │
  ├─────────────────────►│   verify against local vault / AD
  │◄──── 0x01 0x00 ──────┤   ← success
  │  0x05 0x01 0x00 ATYP │   CONNECT, domain/IP + port
  ├─────────────────────►│   → rule engine → upstream → reply 0x00
  │◄──── 0x05 0x00 ... ──┤   then byte relay
```

### 6.3 Deny flow
```
Request ─► RuleEngine ─► DENY(rule#7) ─► HTTP 403 page (branded) or SOCKS5 0x02
                                       ─► audit event (with rule ID + reason)
                                       ─► GUI live "Blocked" counter increments
```

---

## 7. Configuration Schema (illustrative)

```jsonc
{
  "schemaVersion": 3,
  "listeners": {
    "http":  { "bind": "127.0.0.1", "port": 8080, "authMode": "none" },
    "socks5":{ "bind": "127.0.0.1", "port": 1080, "authMode": "userpass",
               "credentialsRef": "vault:socks-users" }
  },
  "upstreams": [
    { "name": "parent-1", "type": "http",  "host": "10.0.0.11", "port": 3128,
      "auth": { "type": "basic", "secretRef": "vault:parent1" }, "healthCheck": true },
    { "name": "direct",   "type": "direct" }
  ],
  "routing": { "default": "direct", "failover": ["parent-1", "direct"] },
  "rules": [
    { "id": 1, "action": "deny",   "match": { "host": "*.malware-blocked.example" } },
    { "id": 2, "action": "route",  "route": "parent-1",
      "match": { "cidr": "10.0.0.0/8", "ports": [80,443] },
      "schedule": { "days": ["Mon","Tue","Wed","Thu","Fri"], "from": "08:00", "to": "20:00" } },
    { "id": 3, "action": "allow",  "match": { "host": "*" } }
  ],
  "limits": { "maxConnections": 2000, "idleTimeoutSec": 300, "connectTimeoutSec": 15 },
  "logging": { "level": "info", "syslog": { "host": "10.0.0.50", "port": 6514, "tls": true } },
  "updates": { "channel": "stable", "server": "https://updates.internal/proxy" },
  "signature": { "alg": "ed25519", "keyId": "org-pki-2026" }
}
```

Secrets (parent-proxy passwords, SOCKS users) are stored in **DPAPI-protected vault**, never in plaintext JSON.

---

## 8. IPC & APIs

### 8.1 GUI ⇄ Service (local)
- Transport: **named pipe** (`\\.\pipe\ProxyCoreCtl`), message framing with length prefix; payload = protobuf or JSON
- Auth: pipe ACL to the local user for read-only ops; admin ops require caller token membership check (service validates, not the GUI)
- Channels: request/response + server-push events (`log.tail`, `stats.tick`, `conn.update`)

Message families:
```
Status.Get        → version, uptime, listeners, throughput
Conns.List/Kill   → live sessions table
Rules.Get/Set     → full rule-set (versioned)
Upstreams.Get/Set
Logs.Query/Tail
Diag.Run          → self-test results
Config.Export/Import/Rollback
Service.Pause(seconds)/Resume
```

### 8.2 Agent ⇄ Central Server (optional)
- Outbound HTTPS only (mTLS optional), agent polls every 5 min + on-demand trigger
- `POST /v1/agents/{id}/heartbeat` → returns pending policy version
- `GET /v1/policies/{version}` (signed bundle) · `POST /v1/agents/{id}/events` (batched audit events)

---

## 9. Central Server Data Model (optional module)

```
agents(id, hostname, os, agent_version, last_seen, config_hash, group_id, status)
groups(id, name, description)
policies(id, version, group_id, payload_json, signature, created_by, created_at, active)
events(id, agent_id, ts, type, proto, src, dst_host, dst_ip, dst_port, rule_id, action, bytes_up, bytes_down, duration_ms)
upstreams(id, name, type, host, port, secret_ref)
users(id, source: local|ad, username, display_name, role: viewer|operator|admin)
audit_admin(id, ts, actor, action, target, before_json, after_json)
```

---

## 10. Security Hardening Checklist

- [ ] Default bind **127.0.0.1 only**; LAN exposure is an explicit, audited setting
- [ ] Service runs as LocalSystem with a minimal surface; no third-party drivers
- [ ] Config + rule files ACL: `SYSTEM`+`Administrators` full, `Users` none
- [ ] All binaries Authenticode-signed; update manifests ed25519-signed; installer refuses unsigned upgrades
- [ ] GUI elevation is never the security boundary — the service validates every admin call
- [ ] Deny-by-default posture available (`defaultAction: deny`) for high-security groups
- [ ] Anti-tamper: service health + config hash reported in heartbeat; SIEM alert on hash mismatch
- [ ] No secrets in logs; PII (usernames) pseudonymized in central analytics if required by policy
- [ ] MITM mode (if enabled): bypass list for pinned apps (banking, update servers, EDR) is mandatory and pre-populated
- [ ] FIPS-compliant crypto modules where policy requires (TLS via SChannel)

---

## 11. Performance & Reliability

| Metric | Target |
|---|---|
| Relay added latency (localhost) | < 1 ms p99 |
| Throughput per tunnel | ≥ 500 Mbps on 1 Gbps link |
| Concurrent tunnels | 2,000 steady-state |
| Memory | < 80 MB RSS idle, < 250 MB at load |
| CPU | < 1% idle, < 10% at 500 Mbps aggregate |
| Service crash recovery | auto-restart < 30 s, zero config loss |

Techniques: buffer pooling (`ArrayPool`), zero-copy relay, DNS cache, connection pool to parents, back-pressure, graceful degradation (drop metrics before dropping traffic).

Failure modes: upstream failover (automatic), SIEM unreachable (buffer+spill), config corrupt (auto-rollback to last good), GUI crash (proxy unaffected), disk full (rotate harder, drop oldest, keep audit deny events).

---

## 12. Deployment & Lifecycle

1. **Package:** WiX MSI (per-machine), includes service + GUI + rules + ViVeCA cert (if MITM later)
2. **Silent install flags:** `msiexec /i ProxySuite.msi /qn PORT_HTTP=8080 PORT_SOCKS=1080 MGMT_URL=https://mgmt.internal GROUP=FINANCE`
3. **Rollout:** GPO computer-assignment or Intune Win32 app; detection rule = file version + service running
4. **Post-install:** service starts, pulls group policy from central server (or falls back to embedded default-allow policy), GUI pinned to taskbar
5. **Upgrade:** MSI major upgrade, ring-based; **Rollback:** keep previous MSI + config snapshot
6. **Uninstall:** requires admin; audited; leaves audit logs on disk

---

## 13. Testing Strategy

| Layer | Tooling | Coverage |
|---|---|---|
| Unit (parsers, rule matcher, DNS cache) | xUnit/NUnit | protocol edge cases: split CONNECT, slow headers, SOCKS5 malformed |
| Integration (real sockets) | test harness spinning engine + `curl`/`Invoke-WebRequest` | allow/deny matrix, chaining, failover |
| Load | `wrk`/`vegeta`/custom tunnel churn script | 2k tunnels, 1 hr soak, fd-leak check |
| Protocol conformance | RFC 1928 test vectors, HTTP/1.1 keep-alive + pipelining cases | |
| GUI | manual checklist + UI automation (WinAppDriver/FlaUI) | all screens, elevation paths |
| Upgrade/rollback | MSI upgrade scenarios on clean + dirty VMs | |
| Security review | threat model (STRIDE) + internal pentest pass | |

---

## 14. Technology Stack — Options & Recommendation

| Layer | ⭐ Recommended | Alternative A | Alternative B |
|---|---|---|---|
| Core engine | **C# / .NET 8** async sockets (+ Kestrel/YARP ideas for HTTP paths) | Rust (tokio) — max perf, portability | Go — fast to build, single binary |
| GUI | **WPF (MVVM)** — native Windows, enterprise-friendly | Tauri/Electron web UI — cross-platform, prettier | Qt (C++/PySide) |
| IPC | Named pipes + protobuf | gRPC over localhost | plain JSON-RPC |
| Packaging | WiX MSI + GPO/Intune | MSIX | NSIS |
| Central server (opt.) | ASP.NET Core + PostgreSQL | Node/NestJS | — |
| SIEM export | syslog RFC 5424 (TLS) / CEF | direct Wazuh/Elastic agents | |

**Rationale:** .NET+WPF gives first-class Windows service support, enterprise MSI/GPO tooling, strong async I/O, and in-house maintainability; the engine layer is isolated behind interfaces so a Rust/Go port later reuses everything else unchanged.

---

## 15. Proposed Repository Layout

```
proxy-suite/
├─ src/
│  ├─ ProxyCore/            # engine library: listeners, parsers, relay, pool
│  │  ├─ Listeners/Http/    # HTTP parser, CONNECT, header filter
│  │  ├─ Listeners/Socks5/  # handshake, UDP associate
│  │  ├─ Rules/             # matcher, compiler, simulator
│  │  ├─ Upstream/          # router, health checks, PAC
│  │  ├─ Dns/               # async resolver + cache
│  │  └─ Relay/             # duplex pump, buffers
│  ├─ ProxyCoreSvc/         # Windows Service host, IPC server, watchdog hooks
│  ├─ ProxyGui/             # WPF app: Views / ViewModels / Services(AgentClient)
│  ├─ ProxyContracts/       # IPC protobuf/DTOs shared by svc+gui
│  ├─ ProxyConfig/          # schema, validation, signing, migrations
│  ├─ ProxyAudit/           # sinks: file, eventlog, syslog
│  └─ MgmtServer/           # optional ASP.NET Core central mgmt + web UI
├─ installer/               # WiX project, custom actions, CA cert scripts
├─ tests/
│  ├─ ProxyCore.Tests/      # unit
│  ├─ ProxyCore.IntegrationTests/
│  └─ Gui.Automation/
├─ docs/                    # this file, runbooks, threat model
└─ tools/                   # load scripts, rule-lint, policy-signing CLI
```

---

## 16. Phased Roadmap

| Phase | Scope | Exit criteria |
|---|---|---|
| **P1 — Engine MVP** | HTTP + SOCKS5 listeners, direct/parent routing, basic allow/deny rules, file audit log, CLI test harness | conformance + load targets met |
| **P2 — Service & GUI** | Windows service, IPC, WPF dashboard/rules/logs/settings, MSI, silent install | pilot on 10 machines, 1-week soak |
| **P3 — Policy & Ops** | rule simulator, upstream failover + health checks, syslog→SIEM, updater rings | SIEM alerts live; staged rollout to 20% |
| **P4 — Central Mgmt (opt.)** | mgmt server, group policies, fleet dashboard, heartbeat | fleet-wide deploy |
| **P5 — Advanced (opt.)** | MITM TLS inspection (flag-gated), UDP ASSOCIATE hardening, category feeds, per-user quotas | security review sign-off |

---

## 17. Risks & Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Users bypass local proxy (apps with hardcoded egress) | policy gaps | GPO-enforced WinINET/system proxy + firewall egress rules that only allow outbound via proxy/parent |
| MITM breaks pinned apps | outages | off by default; mandatory bypass list; staged enablement per group |
| Local admin tampering | policy bypass | config signing, tamper alerts to SIEM, treat workstation trust boundary honestly (document residual risk) |
| Performance regressions at scale | user experience | perf gates in CI (relay latency micro-bench), soak tests each release |
| SIEM/log volume cost | budget | event sampling tiers (deny events always, allow-events sampled) |

---

## 18. References
- RFC 7231 (HTTP/1.1 semantics), RFC 7230 §5.3.2 absolute-form for proxies
- RFC 1928 (SOCKS5), RFC 1929 (user/pass), RFC 1961 (GSSAPI, optional)
- RFC 8446 (TLS 1.3), RFC 5424 (syslog)
- NIST SP 800-53 controls mapping: AC-3, AU-2, AU-6, CM-7, SC-7
