# MEMORY.md — Long-Term Context & Decision Log

**Project:** Proxy Suite · **Created:** 2026-09-13
> Purpose: durable memory for future sessions — why things are the way they are, what was learned, and what to remember before changing anything. Evidence lives in `STATE.md`; this file records the *reasoning*.

---

## 1. Key Decisions (ADR-style, short form)

### D1 — Two-process privilege split (service + GUI)
- **Decision:** Proxy engine runs as a Windows Service; WPF GUI is a separate user-session process talking over a named pipe.
- **Why:** Proxy must run with no user logged in; users must not bypass policy by killing the GUI; the service is the single security boundary (service re-validates every admin call — GUI elevation is UX, not security).
- **Consequence:** IPC contract layer (`ProxyContracts`) exists; admin ops require `AdminToken` + service-side check.

### D2 — .NET 9 + WPF instead of Rust/Go/Electron
- **Decision:** C#/.NET 9 core, WPF GUI.
- **Why:** Only .NET 9 SDK was present on the machine (verified via `dotnet --list-sdks`); WPF pack 9.0.5 confirmed installed; enterprise MSI/GPO tooling and native Windows service support; in-house maintainability.
- **Alternatives rejected:** Rust (higher dev cost, no need for extreme perf at per-workstation scale), Electron (heavier, larger update surface).

### D3 — Loopback-only binds by default
- **Decision:** HTTP 127.0.0.1:8080, SOCKS5 127.0.0.1:1080 by default.
- **Why:** OWASP A05 / NIST CM-7 posture; LAN exposure is an explicit, audited config change.

### D4 — Hash-chained audit log (not just plain logs)
- **Decision:** Each JSONL audit event embeds SHA-256 of the previous event.
- **Why:** Tamper evidence (AU-9/AU-10, ISO A.8.15) at near-zero cost; SIEM can verify chain integrity; supports the bank-grade audit posture evident in the owner's environment.
- **Detail:** Chain tail restored across rotation so deleting old files doesn't help forge a consistent history.

### D5 — Secrets in DPAPI-wrapped AES vault, never in config.json
- **Decision:** `SecretVault` with AES-256-CBC + HMAC (encrypt-then-MAC), key from PBKDF2(100k, SHA-256) over a DPAPI-protected master key.
- **Why:** SC-28/ISO A.8.24; plaintext credentials in config files were an explicit non-goal.
- **Gotcha learned:** ACL lockdown must grant the current user FullControl *before* disabling inheritance, else the owner loses access (hit and fixed during tests).

### D6 — Opt-in SSRF guard, deny-by-allow-list rules
- **Decision:** `security.denyPrivateTargets` default **false**; rule engine default action **allow** (configurable to deny).
- **Why:** Per-workstation proxy blocks loopback targets users legitimately need (local intranet apps). High-security groups can flip both via config.

### D7 — SOCKS5 v1 scope: CONNECT only; UDP ASSOCIATE/BIND → 0x07
- **Why:** QUIC bypass prevention requires disabling UDP relay; documented scope (CM-7 least functionality).

### D8 — Single rule-enforcement point
- **Decision:** Every protocol path (HTTP plain, CONNECT, SOCKS5) calls `UpstreamRouter.PlanAsync` → `RuleEngine.Evaluate` before any upstream connect.
- **Why:** No bypass path; one place to audit.

---

## 2. Lessons Learned (build/environment)

1. **`.NET 9 SDK here rejects LangVersion 12.3`** → use `11.0` in `Directory.Build.props`. (C# 12 features like collection expressions must be avoided.)
2. **Implicit usings don't cover everything** — `System.Net`, `System.Text`, `System.Collections.Concurrent`, `System.Buffers`, `System.Security.Cryptography` needed explicit usings in several files.
3. **`NamedPipeServerStreamAcl.Create` rejects `PipeOptions.CurrentUserOnly` combined with a custom PipeSecurity** — dropped the flag; explicit ACL provides equivalent restriction.
4. **WPF XAML event handlers must return `void`** — async handlers should be `async void` (with try/catch), not `async Task`.
5. **`dotnet run` for the service compiles a `ProxyCoreSvc.exe`** — stale instances keep ports bound; kill via `taskkill //F //IM ProxyCoreSvc.exe` (Git Bash double-slash syntax) before re-testing.
6. **`$"...{x}..."u8` (interpolated UTF-8 literals) is C# 12+** — not available at LangVersion 11; use `Encoding.ASCII.GetBytes(...)`.
7. **Files can get corrupted mid-write when generated quickly** — always re-read critical files after writing; two files needed full rewrites (ProxyEngine.cs, tests).
8. **`byte[].Contains(byte)` needs a cast** under span-based extension resolution (`methods.Contains((byte)0x02)`).
9. **Publish recipe that worked** (self-contained single-file): `dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:EnableCompressionInSingleFile=true -p:DebugType=none` — codified in `scripts/publish-portable.ps1`.
10. **WPF single-file GUIs are ~63 MB self-contained**; compression keeps the zip at ~88 MB total for both exes.

---

## 3. Environment Facts (verified 2026-09-13)

- Windows 11, bash (Git Bash) shell; PowerShell available for process queries.
- .NET SDKs: **9.0.300** only. WPF ref pack 9.0.5 present. x86 desktop runtime absent (avoid x86 RIDs).
- NuGet connectivity OK (nuget.org 200).
- `ProxyCoreSvc` runs interactively via `dotnet run --project src/ProxyCoreSvc`; production service registration is a pending work item.

---

## 4. Things to Remember Before Future Changes

- **Single-file portability**: never use `AppContext.BaseDirectory` for data paths in published exes — it resolves to the temp extraction dir. Use `ProxyCore.AppPaths` (exe dir / `PROXYCORE_HOME`).
- **Pipe name conflicts**: a stale `ProxyCoreSvc.exe` holding `ProxyCoreCtl` makes new instances crash with `UnauthorizedAccessException` in `NamedPipeServerStreamAcl.Create` — kill stale processes before re-testing (`taskkill //F //IM ProxyCoreSvc.exe` in Git Bash).
- **Pipe ACL must include `CreateNewInstance`** (fixed 2026-09-15): `PipeAccessRights.ReadWrite` alone lets clients connect but NOT let the server open the *next* instance of an already-created named pipe — `NamedPipeServerStreamAcl.Create` then throws `UnauthorizedAccessException` on the IPC thread, and the unhandled exception killed the entire service process (was KI-7; the GUI "hang" was mostly the service dying mid-request). Grant `ReadWrite | CreateNewInstance` to AuthenticatedUsers.
- **StreamWriter on pipes emits a BOM** by default — a per-response `StreamWriter` injects `EF BB BF` between JSON lines and breaks multi-request connections. Hoist one writer per connection with `new UTF8Encoding(encoderShouldEmitUTF8Identifier: false)`.
- **Named-pipe default `maxNumberOfServerInstances: 1` serializes all clients** — the 2 s GUI status poll plus any user action would queue behind each other. Use ≥4 and a bounded `WaitForConnectionAsync` recycle loop.
- **Don't loosen the input validator** — tests assert CRLF/whitespace rejection; log injection defense depends on it.
- **Keep all policy checks inside `PlanAsync`** — new protocols/listeners must route through it (D8).
- **Audit chain depends on strict ordering** — the logger serializes writes under a lock; never make `Write` concurrent per-file.
- **Vault ACL helper** — remember D5's gotcha if touching `SetUserOnlyAcl`.
- **GUI is not trusted** — any new privileged IPC op must be added to `RequireAdmin` dispatch branch.
- **Rotation + chain tail** — `RestoreChainTail` scans newest file by name ordering; if naming changes, update it.
- **Testing pattern** — `dotnet run --project src/ProxyCore.Tests` is the fast gate (no test framework dependency, exit code signals pass/fail).

---

## 5. Suggested Next Session Starters

0. Python edition (`scripts/pyproxy/`) — stdlib-only proxy mirroring ProxyCore (HTTP+CONNECT+SOCKS5, rules, guards, hash-chained audit, `status.json`). If the owner wants it to replace the .NET service, wire the WPF GUI (or a Python/Tk GUI) to `status.json` + a small TCP control channel instead of named pipes.

1. Windows Service registration + WiX MSI (unlocks P2 exit).
2. Engine-side session registry → live Connections tab.
3. Syslog sink + Wazuh mapping (owner's environment uses Wazuh).
4. Health-check/failover loop for upstreams (ARCHITECTURE §5.3).
5. SAST/SCA pipeline (CodeQL) + SBOM before pilot rollout.

---

## 6. Glossary (project-specific)

- **Agent/Engine/ProxyCore** — the core library + listeners that do the proxying.
- **AccessGuard** — per-client admission control (rate, slots, auth, lockout).
- **Plan** (`UpstreamPlan`) — resolved decision: which upstream, resolved IP, rule hit.
- **Chain hash** — the prev-hash linkage in audit events.
- **Vault** — encrypted credential store (`data/vault.bin` + `.master`).
