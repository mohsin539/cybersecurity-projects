# Proxy Suite — GUI-Based HTTP/SOCKS5 Proxy Server

A custom, per-workstation proxy server (HTTP/1.1 + HTTPS CONNECT + SOCKS5) with a WPF desktop GUI, rule-based policy enforcement, tamper-evident audit logging, and security controls mapped to **OWASP Top 10 / NIST SP 800-53 / ISO 27001**.

## Documentation

| File | Contents |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Full solution architecture |
| [SECURITY.md](SECURITY.md) | Security implementation mapping + verification evidence |
| [STATE.md](STATE.md) | Current state, evidence log, open work items |
| [MEMORY.md](MEMORY.md) | Decision log, lessons learned, handover context |

## Quick Start — Portable (no .NET needed)

Download/copy `dist/ProxySuite-Portable-win-x64/` (or the zip) to any Windows x64 machine and run:

```bat
start-service.cmd   :: proxy engine (HTTP 127.0.0.1:8080, SOCKS5 127.0.0.1:1080)
start-gui.cmd       :: management GUI
```

Both exes are **self-contained single-file** builds — no runtime install required. `config.json`, `logs/`, and `data/` are created next to the exes; set `PROXYCORE_HOME` to relocate. Verify integrity with `SHA256SUMS.txt`.

Rebuild the portable package after code changes:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/publish-portable.ps1
```

## Development (requires .NET 9 SDK)

```bash
# Run the proxy service
 dotnet run --project src/ProxyCoreSvc

# Run the GUI (separate terminal)
dotnet run --project src/ProxyGui

# Run the test suite (28 tests)
dotnet run --project src/ProxyCore.Tests

# Release build (all 5 projects)
dotnet build ProxySuite.sln -c Release
```

### Try it

```bash
# HTTP proxy
curl -x http://127.0.0.1:8080 http://example.com/

# HTTPS via CONNECT tunnel
curl -x http://127.0.0.1:8080 https://example.com/

# SOCKS5
curl --socks5-hostname 127.0.0.1:1080 http://example.com/
```

## Solution Layout

```
src/
├─ ProxyCore/        # Engine: listeners, rules, security, audit, DNS, relay
├─ ProxyContracts/   # IPC DTOs shared by service + GUI
├─ ProxyCoreSvc/     # Service host + named-pipe IPC server
├─ ProxyGui/         # WPF app (Dashboard, Rules, Logs, Upstreams, Diagnostics)
└─ ProxyCore.Tests/  # Lightweight test runner (security + engine unit tests)
```

## Security Defaults

- Listeners bind **127.0.0.1 only**
- GUI runs **asInvoker**; the service validates every admin operation
- Secrets stored in an encrypted vault (AES-256 + HMAC + DPAPI)
- Every audit event is hash-chained (tamper-evident JSONL in `logs/`)
- Optional SSRF guard blocks loopback/private/metadata targets (`security.denyPrivateTargets`)

See [SECURITY.md](SECURITY.md) for the full control mapping.

## Configuration

Optional `config.json` next to the service binary (or set `PROXYCORE_CONFIG`). Schema is documented in [ARCHITECTURE.md §7](ARCHITECTURE.md). Example deny rule:

```json
{
  "rules": [
    { "id": 1, "action": "Deny", "match": { "host": "*.blocked.example" } },
    { "id": 2, "action": "Allow", "match": {} }
  ]
}
```
