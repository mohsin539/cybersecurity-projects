# STATE.md — Project State & Evidence Record

**Project:** Proxy Suite (GUI-based HTTP/SOCKS5 proxy, per-workstation deployment)
**Last updated:** 2026-09-15 (UTC) — manual proxy-IP setup (bind resolver + client allowlist) · **Maintained by:** development agent + owner

> Purpose: preserve durable evidence of what was built, verified, and decided. Update this file after every meaningful change. Companion doc: `MEMORY.md` (long-term context & lessons).

---

## 1. Current Phase

**P1 complete + P2 partially complete** (per ARCHITECTURE.md §16 roadmap)

| Roadmap item | Status |
|---|---|
| P1 Engine MVP (HTTP + SOCKS5 + rules + audit) | ✅ done, E2E verified |
| P2 Service & GUI | ✅ service host + IPC + WPF GUI built; Windows Service registration + MSI packaging pending |
| P3 Policy & Ops | ⬜ failover/health-check loop, syslog SIEM export, updater rings |
| P4 Central management | ⬜ |
| P5 MITM inspection | ⬜ (flag-gated by design) |

---

## 2. Component Inventory (built & verified)

| Component | Path | State |
|---|---|---|
| Config model + loader | `src/ProxyCore/Options/ProxyConfig.cs` | ✅ unit-tested (round-trip) |
| Rule engine (allow/deny/route, wildcard, CIDR) | `src/ProxyCore/Rules/RuleEngine.cs` | ✅ unit-tested (3 suites) |
| Input validation | `src/ProxyCore/Security/InputValidator.cs` | ✅ unit-tested |
| SSRF guard | `src/ProxyCore/Security/SsrfGuard.cs` | ✅ unit-tested (5 cases) |
| Rate limiter | `src/ProxyCore/Security/RateLimiter.cs` | ✅ unit-tested |
| Access guard (slots, auth, lockout) | `src/ProxyCore/Security/AccessGuard.cs` | ✅ built; lockout logic covered indirectly |
| Secret vault (AES+HMAC+DPAPI) | `src/ProxyCore/Security/SecretVault.cs` | ✅ unit-tested (round-trip) |
| Hash-chained audit log | `src/ProxyCore/Audit/AuditLogger.cs` | ✅ unit-tested + live E2E verified |
| DNS cache | `src/ProxyCore/Net/DnsCache.cs` | ✅ built (exercised via E2E) |
| Upstream router + relay | `src/ProxyCore/Net/UpstreamRouter.cs` | ✅ E2E (direct + CONNECT paths) |
| HTTP proxy listener | `src/ProxyCore/Listeners/HttpProxyListener.cs` | ✅ E2E: plain HTTP 200, CONNECT 200, deny 403 |
| SOCKS5 listener | `src/ProxyCore/Listeners/Socks5ProxyListener.cs` | ✅ E2E: handshake `05 00`, full session 200 |
| Engine orchestrator | `src/ProxyCore/ProxyEngine.cs` | ✅ E2E |
| IPC contracts | `src/ProxyContracts/IpcContracts.cs` | ✅ used by GUI↔svc |
| Service host | `src/ProxyCoreSvc/Program.cs` | ✅ E2E ran interactively |
| IPC server (named pipe + ACL) | `src/ProxyCoreSvc/IpcServer.cs` | ✅ built; GUI connected design verified via contracts |
| WPF GUI | `src/ProxyGui/*` | ✅ built (Dashboard/Rules/Logs/Upstreams/Diagnostics/Settings); live interaction pending pilot |
| Portable path engine | `src/ProxyCore/AppPaths.cs` | ✅ single-file-safe (anchors to exe dir / `PROXYCORE_HOME`) |
| Portable packaging | `scripts/publish-portable.ps1` | ✅ self-contained single-file exes + zip + SHA-256 manifest |
| Test suite | `src/ProxyCore.Tests/Program.cs` | ✅ PASS=28 FAIL=0 |
| Python proxy edition | `scripts/pyproxy/proxy_server.py` | ✅ E2E: HTTP/CONNECT/SOCKS5 200, deny 403, SSRF 403, audit chain (PASS=6 FAIL=0) |
| Manual proxy IP setup | `src/ProxyCore/Net/BindResolver.cs` + `security.clients` allowlist + `scripts/set-my-ip.ps1` | ✅ E2E: LAN bind via `auto`→192.168.0.102, allowlist admit 200 / refuse 403, CLI overrides (Python PASS=6) |

---

## 3. Verification Evidence Log

| # | Date (UTC) | Evidence | Result |
|---|---|---|---|
| 1 | 2026-09-13 | `dotnet build ProxySuite.sln -c Release` | Build succeeded, 0 errors |
| 2 | 2026-09-13 | `dotnet run --project src/ProxyCore.Tests` | PASS=28 FAIL=0 |
| 3 | 2026-09-13 | Service startup log | "HTTP proxy listening on 127.0.0.1:8080", "SOCKS5 …:1080" |
| 4 | 2026-09-13 | `curl -x http://127.0.0.1:8080 http://example.com/` | HTTP 200 |
| 5 | 2026-09-13 | `curl -x http://127.0.0.1:8080 https://example.com/` | HTTP 200 (CONNECT tunnel) |
| 6 | 2026-09-13 | `curl --socks5-hostname 127.0.0.1:1080 http://example.com/` | HTTP 200 |
| 7 | 2026-09-13 | Raw SOCKS5 greeting probe | reply bytes `05 00` (no-auth selected) |
| 8 | 2026-09-13 | Deny rule for `example.com` active | HTTP 403 to client; audit event `rule.deny` (rule 1, `Security` severity) |
| 9 | 2026-09-13 | Audit file inspection | JSONL events contain chained `prev`+`hash` fields |
| 10 | 2026-09-13 | Test artifacts cleanup | service stopped, test config removed |
| 11 | 2026-09-13 | Portable publish (`scripts/publish-portable.ps1`) | ProxyCoreSvc.exe 36.6 MB + ProxyGui.exe 62.9 MB, self-contained single-file |
| 12 | 2026-09-13 | Portable E2E: HTTP / CONNECT / SOCKS5 via portable exe | 200 / 200 / 200; audit log created next to exe (portable layout confirmed) |
| 13 | 2026-09-13 | Portable GUI launch | ProxyGui.exe window opened: "Proxy Suite - Local Proxy Agent" |
| 14 | 2026-09-13 | Distribution zip + manifest | `dist/ProxySuite-Portable-win-x64.zip` (~88 MB incl. SHA256SUMS.txt) |
| 15 | 2026-09-15 | **KI-7 root cause found & fixed**: `NamedPipeServerStreamAcl.Create` throws `UnauthorizedAccessException` when opening the next pipe instance (ACL lacked `CreateNewInstance`); unhandled exception on IPC thread killed the whole process | Fix: ACL grants `ReadWrite|CreateNewInstance` to AuthenticatedUsers; loop catches create errors with 1 s backoff; 4 max instances (was 1 — also serialized GUI requests) |
| 16 | 2026-09-15 | GUI anti-hang hardening: `AgentClient` now bounds **every** phase (2 s connect, 5 s total watchdog — write/read were unbounded); status poll skips ticks while a request is in flight | `dotnet build` 0 errors; PASS=28 FAIL=0 |
| 17 | 2026-09-15 | IPC BOM fix: per-response `StreamWriter` emitted a UTF-8 BOM into mid-stream; hoisted + `encoderShouldEmitUTF8Identifier:false` | `scripts/ipc_smoke.ps1` status.get ×3: OK 109/1/2 ms, clean JSON, no hang |
| 18 | 2026-09-15 | Portable republish with fixes + `start-pyproxy.cmd` + `pyproxy\` bundled (publish script extended) | E2E via published exes: IPC 3/3 OK; HTTP :8080 → 200; CONNECT → 200; SOCKS5 :1080 → 200; zip regenerated |
| 19 | 2026-09-15 | Python edition E2E (`scripts/pyproxy/run_e2e_test.py`, offline via local origin) | PASS=6 FAIL=0 (plain HTTP, CONNECT, SOCKS5, deny rule 403, SSRF 403, hash-chained audit) |
| 20 | 2026-09-15 | **Manual proxy IP setup**: `bind` accepts `127.0.0.1` / `localhost` / `auto` / `0.0.0.0` / manual IP / hostname (C# `BindResolver.Resolve` throws on unresolvable — fail closed; Python `resolve_bind` exits loudly). `auto` uses OS routing table (UDP connect) so VirtualBox/Hyper-V adapters don't win. New `security.clients.{allow,deny}` CIDR allowlist enforced in `AccessGuard.IsClientAllowed` + both Python handlers (deny wins; empty allow = open). Python CLI overrides: `--http-bind/--http-port/--socks-bind/--socks-port/--allow`. Interactive helper: `scripts/set-my-ip.ps1` (writes config.json for both editions, auto-includes 127.0.0.1/32) | C# PASS=28; Python bind/allowlist E2E PASS=6 (`run_bind_test.py`); published C# service E2E: `auto`→192.168.0.102, HTTP+SOCKS5 via LAN IP → 200, IPC smoke 3/3; zip regenerated |

**Environment at verification:** Windows 11 (win32), .NET SDK 9.0.300, WPF desktop pack 9.0.5, bash shell.

---

## 4. Configuration State

- Default config embedded (no `config.json` required to run): loopback binds, allow-all rule, vault at `data/vault.bin`, logs at `logs/`.
- `PROXYCORE_CONFIG` env var overrides config path (used in tests).
- Test deny-rule config used during E2E was deleted after verification (not committed).

---

## 5. Open Work Items (next up)

1. Windows Service registration (sc.exe / WiX ServiceInstall) + recovery settings.
2. Live per-connection table feed from engine (GUI Connections tab is placeholder).
3. Upstream health checks + failover loop (arch: UpstreamRouter §5.3).
4. Syslog (RFC 5424) SIEM sink in service layer.
5. WiX MSI with silent-install properties (ARCHITECTURE.md §12).
6. GUI elevation flow (UAC) for admin buttons + service-side group check hardening.

---

## 6. Known Issues / Limitations (tracked)

| ID | Item | Severity | Plan |
|---|---|---|---|
| KI-1 | Connections tab shows placeholder (empty list) | Low | P2: engine exposes session registry via IPC |
| KI-2 | SOCKS5 parent-proxy auth not implemented | Low | P2 |
| KI-3 | `service.pause` is advisory only | Low | P2: pause gates listener accept loops |
| KI-4 | CA1416 warnings in IpcServer (Windows-only APIs) | Info | Wrap with `OperatingSystem.IsWindows()` guard — cosmetic |
| KI-6 | First GUI launch is slow (single-file extraction) | Info | Documented in portable README; acceptable for portable use |
| KI-7 | Pipe "access denied" if two service instances start | **FIXED 2026-09-15** | Root cause: missing `CreateNewInstance` in pipe ACL crashed IPC thread → process exit. ACL fixed + create-loop hardened; multi-instance support (4) added |
| KI-8 | `bind: auto` picked VirtualBox adapter (192.168.56.1) instead of real LAN | **FIXED 2026-09-15** | Detection now asks the OS routing table first (UDP connect trick); NIC enumeration only fallback. Same fix in Python edition |
| KI-5 | UDP ASSOCIATE returns 0x07 (by design) | Info | Documented v1 scope |

---

## 7. Artifact Map (documentation set)

| File | Purpose |
|---|---|
| `ARCHITECTURE.md` | Full solution architecture (protocols, components, deployment) |
| `SECURITY.md` | Security implementation mapping (OWASP/NIST/ISO) + verification evidence |
| `STATE.md` | This file — state snapshot + evidence log |
| `MEMORY.md` | Long-term context, decisions, lessons learned |
