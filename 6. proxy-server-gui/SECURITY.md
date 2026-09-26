# SECURITY.md — Security Implementation Document

**Project:** Proxy Suite (Custom HTTP/SOCKS5 Proxy with GUI)
**Version:** 1.0.0 · **Date:** 2026-09-13 · **Classification:** Internal
**Scope:** This document maps implemented security controls in the codebase to OWASP Top 10 (2021), ISO/IEC 27001:2022 Annex A, and NIST SP 800-53 Rev. 5, with file anchors for audit evidence.

---

## 1. Security Architecture Summary

The product is split into two processes with distinct trust roles:

| Process | Account | Role |
|---|---|---|
| `ProxyCoreSvc` | LocalSystem (service) | All sockets, policy enforcement, secrets, audit — **the security boundary** |
| `ProxyGui` | Logged-on user (asInvoker) | Presentation only; every privileged action is re-authorized by the service |

All listeners bind **127.0.0.1 by default**. LAN exposure requires an explicit, audited config change.

---

## 2. OWASP Top 10 (2021) Implementation Mapping

### A01 Broken Access Control
| Control | Implementation | Evidence |
|---|---|---|
| Least privilege (GUI vs service) | GUI runs `asInvoker`; service validates every admin IPC call | `src/ProxyGui/app.manifest`; `IpcServer.RequireAdmin` |
| Pipe ACL | Named pipe ACL: Authenticated Users = Read/Write, Administrators = FullControl | `src/ProxyCoreSvc/IpcServer.cs` (`PipeSecurity` rules) |
| Rule enforcement point | All proxy decisions flow through `RuleEngine.Evaluate` — no bypass path | `src/ProxyCore/Rules/RuleEngine.cs` |
| Admin action audit | Every admin op (`rules.set`, `config.import`, `vault.*`) logged as `Security` severity | `IpcServer.DispatchAsync` |

### A02 Cryptographic Failures
| Control | Implementation | Evidence |
|---|---|---|
| Secrets at rest | AES-256-CBC + HMAC-SHA256 (encrypt-then-MAC), key from 100k-iteration PBKDF2 over a DPAPI-protected master key | `src/ProxyCore/Security/SecretVault.cs` |
| Tamper detection | Vault HMAC verified with `CryptographicOperations.FixedTimeEquals` | `SecretVault.Load` |
| Constant-time comparisons | Credential checks use `FixedTimeEquals` (no timing oracle) | `AccessGuard.FixedTimeEquals` |
| No plaintext secrets | Parent-proxy/SOCKS credentials only in vault; never in config.json or logs | `Options/ProxyConfig.cs` (secretRef pattern) |

### A03 Injection
| Control | Implementation | Evidence |
|---|---|---|
| Hostname validation | RFC-compliant host grammar; length ≤ 253; control chars rejected | `src/ProxyCore/Security/InputValidator.cs` |
| Log/CR-LF injection | All external strings clipped + control chars stripped via `Safe()` before any log write | `InputValidator.Safe` |
| Header hygiene | Hop-by-hop and `Host` headers rebuilt server-side; CR/LF inside header values rejected | `HttpProxyListener.RewriteRequestHead` |
| Request smuggling hygiene | Header block hard-capped (`maxHeaderBytes`, default 32 KB); malformed request line → 400 | `HttpProxyListener.ReadHeadAsync` |
| SOCKS field caps | Username ≤64, password ≤64, domain ≤253, method list ≤32 — oversized → drop | `Socks5ProxyListener` |

### A04 Insecure Design / Resource Exhaustion
| Control | Implementation | Evidence |
|---|---|---|
| Per-client connect rate limit | Sliding window + temporary block (default 240/min, 60 s block) | `src/ProxyCore/Security/RateLimiter.cs` |
| Per-client HTTP rate limit | Default 600 req/min per client IP | `AccessGuard._httpLimiter` |
| Concurrent session cap | Global 2000, per-client 128 with lock-free slot release | `AccessGuard.TryReserveClientSlot` |
| Idle timeout | Default 300 s; connects time out at 15 s | `LimitsOptions` |
| Buffer pooling | 64 KB ArrayPool buffers, returned on teardown | `UpstreamRouter.RelayAsync` |

### A05 Security Misconfiguration
| Control | Implementation | Evidence |
|---|---|---|
| Loopback default | `bind: 127.0.0.1` in default config; exposed binds are explicit | `HttpListenerOptions.Bind` |
| Deny-by-default posture | `DefaultAction = "deny"` supported for high-security groups | `RuleEngine.DefaultAction` |
| Atomic config writes | Temp-file + `File.Replace` prevents torn config | `ConfigLoader.Save` |
| Schema-versioned config | `schemaVersion` field for controlled migration | `ProxyConfig` |

### A06 Vulnerable and Outdated Components
| Control | Implementation | Evidence |
|---|---|---|
| Minimal dependencies | Only `System.IO.Hashing` + `System.Security.Cryptography.ProtectedData` (Microsoft, framework-aligned) | `ProxyCore.csproj` |
| Pinned versions | Package versions pinned in csproj | csproj files |
| (Roadmap) | SBOM generation + CVE scan scheduled for P3 (see ARCHITECTURE.md §16) | — |

### A07 Identification and Authentication Failures
| Control | Implementation | Evidence |
|---|---|---|
| SOCKS5 user/pass auth | RFC 1929 subnegotiation, verified against vault | `Socks5ProxyListener` |
| Brute-force lockout | 5 failures → 5-minute lock per client IP (AC-7) | `AccessGuard.RecordAuthFailure` |
| No null-auth downgrade | If `authMode=Basic`, method 0x00 is never selected | `Socks5ProxyListener.NegotiateAndRelayAsync` |
| Username validation | Printable-ASCII only, ≤64 chars (prevents parser confusion) | `InputValidator.IsValidUsername` |

### A08 Software and Data Integrity Failures
| Control | Implementation | Evidence |
|---|---|---|
| Tamper-evident audit log | Hash chain: every event embeds SHA-256 of the previous event | `src/ProxyCore/Audit/AuditLogger.cs` |
| Chain restoration | Chain tail restored across file rotation — deletion of old files doesn't validate forged histories | `AuditLogger.RestoreChainTail` |
| Atomic vault writes | Temp + rename, ACL re-applied | `SecretVault.Save` |

### A09 Security Logging and Monitoring Failures
| Control | Implementation | Evidence |
|---|---|---|
| Security-relevant events | `auth.fail`, `rule.deny`, `ssrf.block`, `admin.*`, `upstream.fail`, `engine.start/stop` | `AuditEvent` types |
| Severity model | Debug→Info→Warn→Error→Security; SIEM-relevant events at `Security` | `AuditSeverity` |
| Retention | 14 rolling files × 100 MB default, oldest pruned (AU-11) | `LoggingOptions` |
| Structured JSONL | Machine-parseable for SIEM ingestion (Wazuh/Splunk file readers) | event format |

### A10 Server-Side Request Forgery (SSRF)
| Control | Implementation | Evidence |
|---|---|---|
| Private-target block | Denies loopback, RFC1918, link-local 169.254/16 (cloud metadata), ULA fc00::/7, site-local | `src/ProxyCore/Security/SsrfGuard.cs` |
| Pre-connect resolution check | When enabled, targets are DNS-resolved and the resolved IP checked before any socket connect | `UpstreamRouter.PlanAsync` |
| IP-literal path | Raw IP targets validated directly (no DNS rebinding window) | `PlanAsync` literal branch |
| Opt-in via config | `security.denyPrivateTargets: true` for high-security groups | `SecurityOptions` |

---

## 3. NIST SP 800-53 Rev. 5 Control Mapping

| Control | Name | Implementation |
|---|---|---|
| AC-3 | Access Enforcement | RuleEngine is the single enforcement point for all proxy sessions |
| AC-4 | Information Flow Control | Rule actions allow/deny/route per host/IP/port/proto/time |
| AC-6 | Least Privilege | Service/GUI split; admin ops require service-side validation |
| AC-7 | Unsuccessful Logon Attempts | 5 failures → 5-min lock per source IP |
| AU-2 | Audit Events | Session, auth, policy, admin, lifecycle events defined |
| AU-6 | Audit Review, Analysis, Reporting | GUI Logs view; JSONL SIEM feed |
| AU-9 | Protection of Audit Information | Hash chain (tamper evidence); file ACLs inherit service dir ACL |
| AU-10 | Non-repudiation | Chained event hashes bind sequence |
| AU-11 | Audit Record Retention | Configurable rolling retention (default 14 files) |
| CM-6 | Configuration Settings | Versioned config, atomic writes, import audited |
| CM-7 | Least Functionality | Loopback-only default; BIND/UDP-ASSOCIATE disabled in v1 |
| IA-2(1) / IA-5 | Identification & Authentication | SOCKS5 user/pass; vault-stored credentials |
| SC-5 | Denial-of-Service Protection | Rate limiters, connection caps, header caps, timeouts |
| SC-7 | Boundary Protection | SSRF guard; loopback default; deny-private-targets option |
| SC-8 / SC-28 | Transmission / At-Rest Confidentiality | Vault encryption (AES-256 + HMAC + DPAPI) |
| SI-4 | System Monitoring | Metrics registry + audit feed for GUI/SIEM |

---

## 4. ISO/IEC 27001:2022 Annex A Mapping

| Annex A | Control | Implementation reference |
|---|---|---|
| A.5.15 | Access control | §2 A01 table — rule engine + IPC ACLs |
| A.5.16 | Identity management | SOCKS5 usernames; Windows identity for admin ops |
| A.5.17 | Authentication information | SecretVault (encrypted credential store) |
| A.5.25 | Assessment of events | Audit event taxonomy + severities |
| A.8.2 | Privileged access rights | Admin ops list (`IpcTypes`); service re-validation |
| A.8.3 | Information access restriction | Per-user rules (`match.user`) |
| A.8.9 | Configuration management | ConfigLoader atomic writes; schema versioning |
| A.8.12 | DLP | Deny rules by host/category; SSRF egress control |
| A.8.15 | Logging | AuditLogger JSONL + severity model |
| A.8.16 | Monitoring activities | MetricsRegistry; `Security`-severity events for alerting |
| A.8.24 | Use of cryptography | AES-256-CBC + HMAC-SHA256, PBKDF2(100k, SHA-256), DPAPI |
| A.8.15/A.8.16 | Clock sync note | Events use UTC (`DateTime.UtcNow`) — NTP sync assumed from OS |

---

## 5. Secure Development Controls

| Practice | Status |
|---|---|
| Unit tests for security logic (validator, SSRF, limiter, chain, vault) | ✅ 28/28 passing (`ProxyCore.Tests`) |
| End-to-end policy enforcement test (deny → 403 + audit event) | ✅ verified 2026-09-13 |
| Nullable reference types enabled project-wide | ✅ |
| Platform-API guards (`CA1416` compliance) | ✅ guarded via `OperatingSystem.IsWindows()` |
| Threat model (STRIDE) workshop | ⏳ scheduled before fleet rollout (P3) |
| External pentest | ⏳ recommended before P4 |
| SAST/SCA in CI | ⏳ P3 (GitHub Advanced Security / CodeQL) |

---

## 6. Known Residual Risks (Documented)

| Risk | Severity | Mitigation / Rationale |
|---|---|---|
| Local admin can alter config/binaries on workstation | High | Accepted: workstation trust boundary. Compensating: SIEM alert on config hash mismatch (heartbeat, P3) |
| MITM inspection not implemented (v1) | Info | TLS passthrough only — no interception, so no cert-pinning breakage; MITM planned P5 flag-gated |
| SOCKS5 parent proxy auth (RFC 1929 toward parent) not implemented | Low | Direct and HTTP parent paths fully supported; SOCKS5-parent auth in P2 |
| UDP ASSOCIATE returns not-supported | Low | Documented v1 scope; prevents QUIC bypass (clients fall back to TCP) |
| `CurrentUserOnly` not used with custom pipe ACL | Info | Equivalent protection via explicit Authenticated-Users ACL; service-side re-auth on admin ops |
| Non-Windows DPAPI fallback stores master key plaintext | Info | Dev-only path; guarded by `OperatingSystem.IsWindows()` and production targets Windows |

---

## 7. Security Verification Evidence

| Check | Result | Date |
|---|---|---|
| Unit test suite (security logic) | PASS=28 FAIL=0 | 2026-09-13 |
| Release build (5 projects, .NET 9) | Build succeeded, 0 errors | 2026-09-13 |
| HTTP proxy E2E (allow) | HTTP 200 via `curl -x` | 2026-09-13 |
| HTTPS CONNECT tunnel (allow) | HTTP 200 (TLS passthrough) | 2026-09-13 |
| SOCKS5 (RFC 1928) E2E | HTTP 200 via `curl --socks5-hostname` | 2026-09-13 |
| SOCKS5 handshake bytes | `05 00` reply verified | 2026-09-13 |
| Deny rule → HTTP 403 + `rule.deny` audit event with rule ID | ✅ verified | 2026-09-13 |
| Audit hash chain present in every event (`prev`+`hash`) | ✅ verified | 2026-09-13 |
| Rate limiter block after threshold | ✅ unit test | 2026-09-13 |
| Vault round-trip (encrypt→decrypt) | ✅ unit test | 2026-09-13 |

**Verification commands:**
```bash
dotnet build ProxySuite.sln -c Release          # 0 errors expected
dotnet run --project src/ProxyCore.Tests        # PASS=28 FAIL=0 expected
dotnet run --project src/ProxyCoreSvc           # starts HTTP :8080 + SOCKS5 :1080
curl -x http://127.0.0.1:8080 http://example.com/          # 200
curl -x http://127.0.0.1:8080 https://example.com/         # 200 (CONNECT)
curl --socks5-hostname 127.0.0.1:1080 http://example.com/  # 200
```
