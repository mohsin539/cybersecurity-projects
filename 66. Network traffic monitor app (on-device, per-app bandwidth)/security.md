# 🛡️ Security Model — Network Traffic Monitor

> **Goal:** an on-device, per-app bandwidth monitor that is safe to run as a
> standard user, leaks nothing off the machine, and exposes zero network
> attack surface outside `localhost`.

**Status:** v1.0 · applies to `server/server.js`, `server/collector.ps1`, `public/*`

---

## 1. Security Principles

| Principle | Implementation |
|-----------|----------------|
| **Least privilege** | Runs as the logged-in user — **no admin elevation**, no service install, no kernel drivers. |
| **Defense in depth** | Loopback binding + numeric validation + no external dependencies + no secrets. |
| **Minimal attack surface** | Single static HTTP server; no certs, no tokens, no cookies, no upload endpoints. |
| **Privacy by default** | All telemetry stays **on-device**. Zero egress, zero tracking, zero analytics. |
| **Fail closed** | Unparseable/oversized input is rejected before being stored or served. |

---

## 2. Threat Model (STRIDE-lite)

| Threat | Vector | Risk | Mitigation |
|--------|--------|------|------------|
| **Spoofing** | fake host header / path | Low | only exact `/api/*` routes exist; static path normalization; `path.startsWith(PUBLIC)` guard |
| **Tampering** | oversized numbers / NaN in JSON | Low | `clamp()` + regex color check + string slicing on every sample |
| **Repudiation** | missing observability | Low | `/api/health` exposes uptime, mode, sample count, last error |
| **Information disclosure** | another user reading telemetry | **Med** | server bound to `127.0.0.1`; no `0.0.0.0`; no LAN exposure |
| **DoS** | rapid requests | Low | synchronous ring buffer, bounded iteration (`slice(0,25)`); no unbounded arrays |
| **Elevation** | code injection | **Low-Med** | PowerShell `-File` path is fixed & local; process/package names are rendered as text (XSS-escaped via attribute-encoded rows), never `eval`'d |

---

## 3. Controls & Hardening

### 3.1 Network
- Server binds **`127.0.0.1:8070` only** — no `0.0.0.0`, no firewall rule opened.
- No external services, no cloud storage, no CDN (fonts/icons are system / embedded).
- HTTP only, loopback — acceptable since there is no WAN exposure.

### 3.2 Authentication / Authorization
- Read-only telemetry app → no login required.
- **No write endpoints exist**, so there is nothing an unauthenticated caller can mutate.

### 3.3 Input validation (defense in depth)
- `validate(s)` in `server.js`:
  - whitelists keys when mapping samples,
  - clamps every numeric field (`pid`, `rx`, `tx`, `conns`, bps…),
  - enforces `#rrggbb` color regex,
  - caps output at 25 apps / 6 adapters,
  - rejects non-JSON collector output.
- `decodeURIComponent` errors and path traversal attempts → `403`.

### 3.4 Child process safety
- Worker invoked via `powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File collector.ps1`.
- No user-controlled arguments are interpolated into the command line.
- Worker stderr is captured and truncated before logging.

### 3.5 Data at rest / in transit
- Data lives only in memory (ring buffer, 300 samples). No persistence yet.
- If persistence is added later, it must be `data/*.json` with `0600`-style ACLs, never HTML-safe leakage.

---

## 4. Permissions Actually Required

| Cmdlet | Admin? | Purpose |
|--------|--------|---------|
| `Get-NetTCPConnection` | No | established TCP sessions + owning PID |
| `Get-NetUDPEndpoint` | No | UDP sessions + owning PID |
| `Get-NetAdapterStatistics` | No | per-interface byte counters (Δ for bps) |
| `Get-Process` | No | PID → process name resolution |

> No `netsh`, no packet capture, no Npcap/WinPcap, no firewall mutation, no
> traffic shaping. The heuristic already yields stable per-app estimates.

---

## 5. Incident Response (honest failure modes)

1. **Collector exits non-zero** → server logs the last 300 chars of stderr and
   falls back to **simulation mode** (banner `SIM` in UI) after 2 failed ticks.
2. **Malformed JSON from worker** → sample dropped; previous snapshot kept.
3. **Path traversal on static** → `403 Forbidden`, no file disclosure.
4. **Unknown `/api/*`** → `404`; **non-GET** → `405`.

---

## 6. Checklist Before Every Release

- [ ] Server still binds `127.0.0.1` (search for `0.0.0.0` / `::`).
- [ ] No console/API logs contain process-UUIDs or user-identifying values beyond app names.
- [ ] `validate()` clamps still applied in the ingest path.
- [ ] Static path traversal guard present.
- [ ] Zero external network calls in code (`fetch` only to `/api/*`).
- [ ] `security.md` unchanged? Update if controls changed. Keep `memory.md` notes current.