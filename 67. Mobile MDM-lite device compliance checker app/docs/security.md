# Security.md — Security Architecture & Threat Model

**Project:** Mobile MDM-lite Device Compliance Checker
**Scope:** The portable local app (all modes: dashboard, ADB collection, reports).
**Status:** Reserved — living document for the reservation/sprint backlog.

---

## 1. Security posture (summary)

| Property | Value |
|---|---|
| Network exposure | **Loopback only** — server binds `127.0.0.1`; no inbound path from LAN/WAN |
| Data residency | Device telemetry never leaves the host — no outbound calls in the app |
| Authentication | **Local single-user** model; OS user session is the trust boundary |
| Integrity | Atomic state writes; corrupt state auto-quarantined |
| Audit | Security log covers enroll / scan / policy / removal lifecycle events |
| Supply chain | Runtime = Python 3.12 stdlib only (no runtime third-party deps) |

## 2. Assets & classification

| Asset | Sensitivity | Where it lives |
|---|---|---|
| Device telemetry (OS, apps, security flags) | **PII-class / sensitive** | `state.json`, memory, browser tab |
| Employee/device mapping (owner, department) | **PII-class** | `state.json` |
| Policy rule set | Internal | `state.json`, UI editor |
| Audit/security log | Internal | `state.json` |
| ADB session data | Sensitive | ephemeral (never persisted except via telemetry) |

## 3. Trust boundaries

```
 OS user session (trusted)
    │  no OS auth — single-user assumption
 ├─ Loopback HTTP (127.0.0.1)   ... only this port is reachable
 │     │  local processes can reach the API surface
 │
 ├─ ADB bridge (USB / tcp)      ... best-effort, requires platform-tools
 │
 └─ Reports                     ... HTML/JSON in local tabs; user-controlled
```

**Boundary rule:** listen address is hardcoded to loopback. See
`dashboard.py: pick_port()`/`serve()`. Do not allow `--host 0.0.0.0` in a
productionized agent.

## 4. Threat model (STRIDE)

| Threat | Likelihood | Mitigation |
|---|---|---|
| **S**poofing of API requests from local malware | Low-Med | Loopback-only; OS session assumed clean; no secrets to steal |
| **T**ampering with policy/state on disk | Med | State integrity via atomic replace; tampering only possible if attacker already has FS write → out of scope at this trust level |
| **R**epudiation | Low | Security log records event, timestamp, level, device id |
| **I**nformation disclosure over network | Low | No listening interface beyond 127.0.0.1; reports only in user-opened tabs |
| **D**enial of service (socket exhaustion/port clash) | Low | Auto-random port, daemon threads, targeted error JSON |
| **E**levation of privilege | Low | No privileged operations in app; ADB exec is user-contract only |
| **Cross-site scripting** in dashboard | Low | Content escaped everywhere; no user HTML rendered; `X-Frame-Options: DENY`, `nosniff` |

## 5. Security controls implemented

**HTTP hardening (dashboard.py):**
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Cache-Control: no-store`
- Bind enforced to `127.0.0.1`; host override documented as experimental only.

**Persistence hardening (store.py):**
- Atomic save: write `state.json.tmp` → `os.replace` onto target.
- Corruption quarantine: `state.json.corrupt-<epoch>` copy retained before rebuild.
- `R`Lock guarding every mutation (thread-safe API server).

**Audit trail (store.py · log()):**
- Levels: `info`, `warn`, `critical`.
- Events: `device_enroll`, `device_scan`, `device_remove`, `policy_update`,
  `policy_reset`, `state_load_corrupt`, `demo_seed`, plus report/lifecycle events.
- Rotation ceiling: `maxLogEntries` (default 500).

**Output encoding (report.py):**
- HTML escaping for every interpolated field (`html.escape`).

## 6. Data protection

- Encryption at rest: none in this local-trust build; rely on OS full-disk
  protection. **Reservation:** if PII is constrained, enable optional symmetric
  encryption of `state.json` keyed from a passphrase/TEE (see backlog).
- Secrets: the app stores **no credentials, tokens, or keys** by design.
- ADB: connection relies on ADB's own authorization (RSA key in `~/.android`).

## 7. Agent/agent-adjacent guidance (expansion to real MDM)

- On-device agents must use **mutual TLS** to the MDM-lite authority.
- Enrollment payloads must be **signed** (SMIME/PGP or JWS) to prevent spoofed devices.
- Telemetry channel: TLS 1.2+ only; pin or use public-trusted certs.
- Jailbreak/root flags are indicative — combine 2+ indicators before trust decisions.

## 8. Incident response (reservation)

1. **Detect:** security log shows anomalous event; run `tools/smoke_test.py` and
   review `mdm-lite.log` + `state.json`.
2. **Contain:** stop the app (`Shutdown` button), disconnect ADB/USB.
3. **Analyze:** inspect quarantined `state.json.corrupt-*`; reproduce with demo data.
4. **Eradicate/Recover:** wipe `state.json` to regenerate baseline; restore backup.
5. **Learn:** append lessons to `memory.md`.

## 9. Backlog reservations

- [ ] Optional AES-256 encryption of `state.json` (passphrase) 
- [ ] Per-device scan secrets / device attestation
- [ ] Policy files with cryptographic checksum + preview
- [ ] Minimal authentication for API surface (loopback token)
- [ ] FIPS/NIST-aligned policy templates export
- [ ] SBOM generation for the portable build