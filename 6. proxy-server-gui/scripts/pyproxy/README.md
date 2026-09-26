# ProxySuite — Python Edition

A **dependency-free (Python stdlib only)** proxy server mirroring the C# `ProxyCore` engine's
behavior and configuration schema. No pip installs needed — just Python 3.10+.

## Quick start

```bash
py proxy_server.py                        # config.json next to this file (defaults if absent)
py proxy_server.py --config my.json
py proxy_server.py --check-config
```

- HTTP proxy:  `127.0.0.1:8080`   (absolute-URI + CONNECT tunneling)
- SOCKS5:      `127.0.0.1:1080`   (CONNECT, optional user/pass auth)
- Status file: `status.json`      (refreshed every 2 s: uptime, listeners, session metrics)
- Control:     `127.0.0.1:8085`   (TCP; commands: `STATUS`, `PING`, `STOP`)

Point your browser or curl at it:

```bash
curl -x http://127.0.0.1:8080 https://example.com/
curl --socks5-hostname 127.0.0.1:1080 https://example.com/
```

## Manual proxy IP setup (share the proxy on your LAN)

Choose what the proxy listens on via `listeners.http.bind` / `listeners.socks5.bind`
(or the CLI flags below — CLI beats config):

| bind value | meaning |
|---|---|
| `127.0.0.1` | **default** — this PC only |
| `auto` | pick this machine's LAN IPv4 automatically (recommended for sharing) |
| `0.0.0.0` or `*` | all interfaces (explicit open exposure — pair with an allowlist) |
| `192.168.1.20` | a specific manual IP |
| `myhost.local` | hostname resolved at startup |

**Client allowlist** (`security.clients.allow`) — who may *use* the proxy. Always set this
when binding beyond loopback:

```json
"security": {
  "clients": {
    "allow": ["192.168.1.0/24"],
    "deny":  ["192.168.1.100/32"]
  }
}
```

`deny` wins over `allow`; empty `allow` = all clients permitted.

> **Tip:** always include `127.0.0.1/32` in `allow` when binding beyond loopback, or local
> apps on this PC will be refused too. `set-my-ip.ps1` does this automatically.

One-shot without editing config:

```bash
py proxy_server.py --http-bind auto --socks-bind auto --allow 192.168.1.0/24
```

Interactive helper (writes `config.json` for both editions):

```powershell
powershell -ExecutionPolicy Bypass -File ..\..\set-my-ip.ps1
```

> Windows Firewall may prompt on first LAN bind — allow the app on **Private** networks.
> Clients configure: HTTP proxy `your-ip:8080`, SOCKS5 `your-ip:1080`.

## Features

| Area | Behavior |
|---|---|
| HTTP forward proxy | Absolute-URI requests, hop-by-hop header stripping, header cap, rewrite to origin-form |
| CONNECT | Full TCP tunneling with idle timeout |
| SOCKS5 | RFC 1928 (no-auth + user/pass), CONNECT only (UDP/BIND → 0x07, QUIC-bypass posture) |
| Rules | First-match-wins: `Allow` / `Deny` / `Route`, wildcard hosts (`*.example.com`), CIDR, port, protocol, user |
| Upstreams | `Direct`, HTTP parent (CONNECT), SOCKS5 parent (with auth) |
| Guards | Per-IP connection slots, connect/HTTP rate limits with temporary block, SSRF private-target deny, client-IP allowlist |
| Audit | JSONL, SHA-256 hash-chained (GENESIS → prev), size/date rotation, retention pruning — same event layout as the C# `AuditLogger` |
| Config | Same `config.json` schema as the .NET engine (see `config.sample.json`) |
| Shutdown | SIGINT/SIGTERM graceful drain + local `STOP` control command |

## Configuration

Copy `config.sample.json` → `config.json` and edit. Key sections:

- `listeners.http/socks5` — bind (`127.0.0.1` / `auto` / `0.0.0.0` / IP / hostname) + port + `authMode`
- `security.clients.allow` — CIDR allowlist for clients (recommended for LAN exposure)
- `security.socks5Users` — `{"user": "pass"}` map for SOCKS5 `Basic` auth
- `security.denyPrivateTargets` — block loopback/private/link-local/metadata targets (SSRF)
- `security.resolveViaUpstream` — forward hostnames instead of resolving locally (DNS-leak prevention)
- `rules[]` — `{ "id": 1, "action": "Deny", "match": { "host": "*.ads.example" } }`
- `limits` — connection slots, rate windows, idle/connect timeouts, header cap

Validate: `py proxy_server.py --check-config`

## Status API

`status.json` (written next to the config):

```json
{ "service": "ProxySuite-Python", "uptimeSec": 42, "listenersUp": true,
  "metrics": { "sessionsActive": 3, "sessionsTotal": 91, "deniedTotal": 2,
               "errorsTotal": 0, "bytesUp": 12345, "bytesDown": 987654 } }
```

## Tests

Offline E2E (spawns a local origin server; no internet needed):

```bash
py run_e2e_test.py
```

Checks: plain HTTP 200, CONNECT tunnel 200, SOCKS5 200, deny rule 403,
SSRF guard 403, hash-chained audit log.

## Layout notes

- Paths anchor to the config file's directory (portable layout, like the .NET engine).
- Logs: `<home>/logs/audit-YYYYMMDD-NNNNNN.jsonl`
- The local control channel binds to `127.0.0.1` only.
