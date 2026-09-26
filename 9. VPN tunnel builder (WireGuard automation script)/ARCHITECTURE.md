# Architecture — VPN Tunnel Builder (WireGuard Automation Script)

Version 1.0  
Date: 2026-09-18  
Classification: Internal / Sensitive — Security-Relevant System

---

## 1. Purpose & Scope

The **VPN Tunnel Builder** is an automation script that provisions, configures,
monitors, and tears down **WireGuard** tunnels programmatically. Its primary
goal is to convert the error-prone, manual process of WireGuard setup into a
repeatable, auditable, and secure operation.

### 1.1 Primary Capabilities

| Capability | Description |
|---|---|
| **Tunnel Provisioning** | Create server + peer configurations (interfaces, keys, IPs, allowed IPs) |
| **Key Management** | Generate Curve25519 keys (private/public/preshared) with correct permissions |
| **Peer Lifecycle** | Add / list / edit / remove peers (clients) |
| **Apply & Reload** | Atomically apply configs via `wg-quick` / `systemd` without dropping existing tunnels |
| **Monitoring** | Show handshake state, transfer counters, last seen, health status |
| **Persistence** | Deterministic state storage, idempotent re-runs (`--dry-run`, `--force`) |
| **Audit & Logging** | Structured, tamper-resistant operational logs |

### 1.2 Non-Goals

- No end-user web UI (may be exposed via a controlled API in v2 — see §9)
- No PKI / X.509 management (WireGuard uses its own key model by design)
- No substitution for network firewall hardening of the host itself

---

## 2. High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Operator / CI Pipeline                       │
└──────────────────────────────┬──────────────────────────────────────┘
                               │ CLI / Exit Codes / Structured JSON
┌──────────────────────────────▼──────────────────────────────────────┐
│                    PRESENTATION LAYER (CLI)                         │
│  argparse/Typer subcommands: init, keygen, tunnel up/down/status,   │
│  peer add/rm/show, config validate, rollback, audit export          │
└──────────────────────────────┬──────────────────────────────────────┘
                               ▼
┌──────────────────────────────┬──────────────────────────────────────┐
│                    APPLICATION LAYER (Core)                         │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐    │
│  │ Commands   │  │  Config    │  │ Crypto ops │  │ Lifecycle  │    │
│  │ (use cases)│  │  Manager   │  │  Manager   │  │  Manager   │    │
│  └─────┬──────┘  └─────┬──────┘  └─────┬──────┘  └─────┬──────┘    │
│        └───────────────┴───────┬───────┴───────────────┘           │
│                                ▼                                   │
│                    ┌────────────────────────┐                       │
│                    │  Domain / State Model │                       │
│                    │  Tunnel, Interface,    │                       │
│                    │  Peer, KeyPair, Audit  │                       │
│                    └───────────┬────────────┘                       │
│                                ▼                                   │
│              ┌──────────────────────────────────┐                   │
│              │   Persistence (state/ + config) │                   │
│              │   Atomic writes, file locks,    │                   │
│              │   0600 permissions             │                   │
│              └──────────────┬──────────────────┘                   │
└─────────────────────────────┼──────────────────────────────────────┘
                              ▼
┌─────────────────────────────┼──────────────────────────────────────┐
│                 INTEGRATION / PLATFORM LAYER                       │
│  ┌─────────────┐ ┌──────────────┐ ┌──────────────┐ ┌─────────────┐ │
│  │ wg / wg-quick│ │ systemd     │ │ iproute2     │ │ Host Firewall│ │
│  │ (netlink)   │ │ (units/svc) │ │ (routes)     │ │ (nftables)   │ │
│  └─────────────┘ └──────────────┘ └──────────────┘ └─────────────┘ │
└─────────────────────────────┬──────────────────────────────────────┘
                              ▼
        ┌────────────────────────────────────────────┐
        │          KERNEL (WireGuard module)         │
        │     ChaCha20-Poly1305 · Curve25519         │
        │     BLAKE2s · timers · netlink socket      │
        └────────────────────────────────────────────┘
```

### 2.1 Architectural Style

- **Ports & Adapters (Hexagonal)** — domain core is pure Python/Go logic,
  unaware of OS specifics; platform adapters (`wg`, `systemd`, `nftables`)
  are injected behind interfaces. Enables unit-testing crypto/config logic
  without root.
- **Thin CLI, Fat Core** — every subcommand delegates to a use-case class;
  all business rules live in the domain layer.
- **Idempotent & Deterministic** — every command is safe to re-run; desired
  state is stored and diffed against reality.

---

## 3. Component Breakdown

### 3.1 Presentation Layer (CLI)

```
vpn-tunnel build --config server.toml --out /etc/wireguard
vpn-tunnel peer add --name laptop --allowed-ips 10.9.0.3/32
vpn-tunnel tunnel up --interface wg0
vpn-tunnel tunnel status --json   # structured output for CI
vpn-tunnel config validate --strict
vpn-tunnel rollback --snapshot 2026-09-18T00:00:00Z
```

Output modes: `text`, `json`, `quiet`. Exit codes follow sysexits convention;
`--dry-run` prints the exact commands/state changes without executing.

### 3.2 Application Layer

| Module | Responsibility | Security-Relevant Rules |
|---|---|---|
| `Commands/use_cases` | Orchestrate domain + adapters per subcommand | Validate input; never trust caller paths |
| `ConfigManager` | Parse + validate TOML/YAML config, resolve secrets | Reject unknown keys, strict schema; secret refs allowed from env/secret store only |
| `CryptoManager` | Generate/derive Curve25519 keys, PSKs, entropy checks | Use OS CSPRNG (`os.urandom` / `getrandom`), never store plaintext keys in logs |
| `LifecycleManager` | Apply/diff/rollback tunnel state | Snapshots before changes; atomic wg-quick up/down; never `--force` blindly |
| `StateModel` | Domain entities — `Tunnel`, `Interface`, `Peer`, `KeyPair`, `AuditEvent` | No secrets inside JSON exported outside the host |

### 3.3 Integration Layer (Platform Adapters)

| Adapter | Interface | Notes |
|---|---|---|
| `WireGuardAdapter` | `wg show` / `wg set` via netlink | Capture raw output, parse strictly, never shell out with user strings unescaped |
| `InterfaceAdapter` | `systemd-networkd` / `systemctl` units | Manage `wg-quick@.service` units |
| `RoutingAdapter` | `ip route`, `nftables` | Add/remove routes and firewall rules scoped to interface |
| `SysInfoAdapter` | `uname`, `/proc`, sysfs | Read-only introspection for validation |

---

## 4. Operational Workflow (Tunnel Provisioning)

```
1. detect_os_and_tools()        → verify wg, wg-quick, ip route, systemd
2. load_config()                → schema-validate; resolve env secret refs
3. plan()                       → compute desired state (interfaces, peers,
                                  keys needed, addresses, allowed-ips)
4. artifact_stage()             → write private assets to staging dir (0600)
5. preflight()                  → port free?, kernel module loaded, IPv4/IPv6,
                                  MTU sanity, subnet collision check
6. apply_stage()                → generate configs, snapshot OLD configs
7. atomic_apply()               → wg-quick up wg0 || rollback_snapshot()
8. postflight()                 → verify handshake-capable config, routes up,
                                  run connectivity test (ICMP/ping internal IP)
9. report()                     → emit status + audit event (JSON/text)
```

**Idempotency:** step 3 produces a pure function `current_state → desired_state`;
if no diff, steps 6–8 no-op and the tool exits `0` with `NOOP`.

---

## 5. Data Model & Storage

### 5.1 Entities

```
Tunnel
  ├─ name, interface (wg0), listen_port, address[] (CIDR)
  ├─ private_key_ref   → path | env | secret-store-ref (never inline)
  ├─ public_key        → derived (safe to display)
  ├─ peers[]            → Peer
  └─ mtu, fwmark, dns[]

Peer
  ├─ name, public_key, preshared_key_ref (optional)
  ├─ allowed_ips[]      → 10.9.0.3/32
  ├─ endpoint (optional), persistent_keepalive
  └─ created_by, created_at, last_handshake, transferred

KeyPair
  ├─ private_key, public_key, created_at
  └─ gated_url/storage (external vault)  → private key NEVER persisted in repo

AuditEvent
  ├─ action, target, result, actor, session_id
  ├─ before/after sha256 of affected config
  └─ timestamp, integrity_chain (hash chaining)
```

### 5.2 Storage Locations & Permissions

| Path | Content | Permissions |
|---|---|---|
| `/etc/wireguard/*.conf` | Interface configs, private keys | `0600 root:root` |
| `/var/lib/vpn-tunnel/state.json` | Pure state (no secrets) | `0644` (readable for status) |
| `/var/lib/vpn-tunnel/secrets/` | PSKs / key material | `0700 root:root`, files `0600` |
| `/var/log/vpn-tunnel/audit.log` | Hash-chained audit log | `0600` append-only (via `chattr +a` where supported) |
| `/tmp` staging | Transient artifacts | `0700` per-run temp dir, wiped on exit |

All writes use **atomic replace** (write temp + `fsync` + `rename` + fsync dir)
and an advisory file lock (`flock`) to prevent concurrent runs.

---

## 6. Technology Recommendations

| Concern | Recommendation |
|---|---|
| Language | **Go** (static binary, no runtime deps) or **Python 3.11+** (venv, faster to extend) |
| Config parsing | `tomlkit` / `strictyaml` (Python) or `viper` (Go) |
| CLI | `click`/`typer` or `cobra` |
| Validation | `pydantic` v2 (schema + type-safe) or `go-playground/validator` |
| Testing | `pytest`, `mypy`/`ruff`, property-based tests (`hypothesis`); `testcontainers` for integration |
| Packaging | Single binary + `systemd` unit; signed SHA-256 checksums |
| Secret store | integrate with `sops`, Vault agent, or systemd `LoadCredential` |

---

## 7. Security Architecture

### 7.1 Threat Model (STRIDE-per-asset)

| Asset | Threats | Controls |
|---|---|---|
| Private keys | Theft, tampering, exposure | 0600, vault/gated store, never in logs/git, HSM-grade derivation not required (kernel handles ops) |
| Config files | Tampering → rogue tunnels | root-owned 0600, config digests, snapshot+rollback, `--check` mode |
| Audit log | Repudiation | hash-chaining (`A_n = H(A_{n-1}\|\|event)`) + append-only perms |
| Host network | Lateral movement | nftables egress scoping, `AllowedIPs` minimalism |
| Supply chain | Malicious deps | dependency pinning, `pip-audit`/`govulncheck`, SBOM |
| Hardcoded creds | Secret leakage | secret-ref resolution at runtime only, `.gitignore`, secret scanning in CI |

### 7.2 ISO/IEC 27001:2022 Annex A Control Mapping

| Control | How the tool implements it |
|---|---|
| **A.5.15 Access Control** | root-only execution; least-privilege service user option; peer permissions per key |
| **A.5.10 / A.8.24 Secrets** | keys never in source control; env/vault-backed refs; cipher AES-256 at rest for keys stored on disk |
| **A.8.8 / A.8.9 Key Management** | lifecycle for keygen, rotation (`--rotate-psk`), disposal (`shred`) |
| **A.8.15 Logging / A.8.16 Monitoring** | structured audit events; handshake/uptime metrics exportable to Prometheus |
| **A.8.12 Data Leakage Prevention** | `AllowedIPs` least privilege; optional DNS routing scope |
| **A.8.20 Network Security / A.8.21 Segregation** | per-interface nftables chains; separate tunnel subnet per VLAN/segment |
| **A.8.31 Change Management** | all mutations go through snapshot+rollback; `--dry-run`; peer-reviewable diffs |
| **A.5.20 Transferring Information** | WireGuard AEAD (`ChaCha20-Poly1305`) in-kernel; outbound only on provisioned ports |
| **A.5.24 Use of Cryptography** | audited primitive suite (Curve25519, ChaCha20-Poly1305, BLAKE2s, PSK optional extra layer) |
| **A.5.28 Secure Engineering** | SDL practices: threat modeling, code review, fuzzing of parsers |
| **A.8.28 Secure Coding** | input validation, no shell interpolation of user data, safe subprocess (`exec`) usage |
| **A.6.8 / A.8.11 Data Retention & Backup** | state snapshots retained with retention policy; audit export |

### 7.3 NIST Cybersecurity Framework (CSF 2.0) Functions

| Function | Controls in the tool |
|---|---|
| **GOVERN** | documented config-as-code policy; change approval workflow; owner/operator definitions |
| **IDENTIFY** | inventory of tunnels/peers in `state.json`; asset tagging; risk assessment in README/ARCHITECTURE |
| **PROTECT** | in-kernel crypto; 0600 key files; runtime secrets; strict validation; network segmentation; least-privilege `AllowedIPs`; signed binaries |
| **DETECT** | handshake/gap monitoring, transfer anomaly detection, config drift checks (`validate` vs reality), integrity hashes |
| **RESPOND** | `tunnel down` kill-switch; rollback to last-good snapshot; audit trail reconstructs attack timeline |
| **RECOVER** | idempotent rebuild from state.json; snapshot-based restore; documented runbooks |

### 7.4 NIST SP 800-53 (Relevant Controls, Subset)

| Family | Controls |
|---|---|
| AC — Access Control | `AC-2` account mgmt (peers), `AC-3` least privilege, `AC-16` security attributes |
| SC — System & Comms | `SC-8` transmission confidentiality, `SC-13` cryptography, `SC-28` at-rest protection, `SC-7` boundary protection |
| AU — Audit & Accountability | `AU-2..6` audit events, content, log storage/retention, review |
| IA — Identification & Auth | `IA-5` authenticator management (public key = identity), `IA-11` re-auth |
| CM — Configuration Mgmt | `CM-6` config settings (baseline conf), `CM-9` config control (schema + validation) |
| SI — System Integrity | `SI-7` integrity monitoring (config hashes), `SI-12` input handling/validation |

### 7.5 OWASP Top 10 (2021) — Mapping for This System

> Context: the tool is a privileged CLI, not a web app. The list below covers
> both the CLI and the **v2 admin API** (if exposed) and its supply chain.

| # | Risk | Applicability & Mitigation |
|---|---|---|
| **A01** Broken Access Control | **High** — only root/service-user may mutate; API (v2) must enforce RBAC + CSRF-resistant auth; never run as root via web |
| **A02** Cryptographic Failures | **High** — WireGuard defaults secure; forbid weak flags (`--allowed-ips 0.0.0.0/0` warnings), reject deprecated ciphers, key rotation, keys at rest AES-256 |
| **A03** Injection | **High** — subprocess execution must avoid shell; use `subprocess` arg arrays / `exec.Cmd`; all `ip/wg` args validated against allowlists (`wg0`, CIDR regex) |
| **A04** Insecure Design | Config reference confusion; require explicit intent (`--force` / `--confirm` for destructive ops), threat modeling per §7.1 |
| **A05** Security Misconfiguration | Enforce `0600` perms, disable default credentials, validate config schema strictly, TLS for API, fail-closed defaults |
| **A06** Vulnerable Components | Dependency pinning, `pip-audit`/`govulncheck` in CI, SBOM, signed releases, kernel module version checks |
| **A07** Identification & Auth Failures | Peer keys act as auth; enforce unique names, PSK option, endpoint allowlist, audit session attribution |
| **A08** Software & Data Integrity | Signed binaries + checksums, config hashes in state, snapshot/rollback defeats partial-write tampering |
| **A09** Logging & Monitoring Failures | Structured audit logs with hash chaining; alert on repeated handshake failures; log rotation configured |
| **A10** SSRF | Relevant only if a web/API fetches remote endpoints (e.g., peer management over HTTP) — restrict to trusted hosts, validate endpoints |

### 7.6 Additional Security Requirements / Baseline

- **Fail closed:** if preflight fails → exit non-zero, apply nothing.
- **No secrets in logs:** redaction filter for anything matching `private key`/`psk`.
- **Kernel crypto only:** never reimplement ChaCha20/Curve25519 in userland.
- **Key rotation:** `--rotate-psk` per peer; documented rekey window.
- **Kill switch option:** optional policy to drop non-tunnel routes on tunnel down.
- **Security checks on boot:** `vpn-tunnel doctor` — verifies perms, module, tool versions, config digests.
- **Post-quantum consideration:** WireGuard has experimental PQ hybrid (ML-KEM) in newer kernels; plan for migration path.

---

## 8. Observability, Compliance & Audit Trail

- **Audit schema** (one event = one JSON line):

```json
{
  "v": 1,
  "ts": "2026-09-18T10:24:03Z",
  "action": "peer.add",
  "actor": "root",
  "session": "a1b2c3",
  "target": {"interface": "wg0", "peer": "laptop"},
  "result": "OK",
  "prev_hash": "sha256:4f8c...",
  "event_hash": "sha256:7e6b..."
}
```

- **Export modes:** JSONL, CSV, Syslog (RFC 5424), Splunk/CWE formatter.
- **Metrics:** handshake age, rx/tx delta per peer, up/downtime, config drift counter → Prometheus `/metrics` exporter adapter (v2).
- **Evidence for an ISMS audit:** runbook, risk register (§7.1), control mapping (§7.2–7.5), and this document serve as the Statement of Applicability inputs.

---

## 9. Roadmap / Versioning

| Version | Feature |
|---|---|
| **v1 (current)** | CLI-only provisioning/lifecycle, audit log, snapshot/rollback |
| **v1.x** | `doctor` checks, PSK rotation, systemd integration, SBOM + signed releases |
| **v2** | Optional REST/gRPC admin API (token-auth + mTLS), RBAC, metrics exporter, PQ hybrid crypto support |

---

## 10. Diagrams — Deployment Topology

```
         Internet
             │
   ┌─────────▼─────────┐        WireGuard (UDP 51820)        ┌─────────────┐
   │  Cloud VPS        │◄────────────────────────────────────►│  Client A   │
   │  (Server / Hub)   │                                      │  (laptop)   │
   │  wg0: 10.9.0.1/24 │                                      │ 10.9.0.3/32 │
   │  nftables rules   │◄────────────────────────────────────►│  Client B   │
   │  Gateway: eth0    │                                      │  (phone)    │
   │                   │                                      │ 10.9.0.4/32 │
   └─────────┬─────────┘                                      └─────────────┘
             │
   ┌─────────▼─────────┐   Site-to-Site tunnel (wg1)
   │  Branch Office    │◄──────────────────────────────▷  HQ Router / Peer
   │  Edge Router wg1  │
   └───────────────────┘
```

**Roles:** *Server* (public endpoint, Peer-of-peers) vs *Client* (initiator with
`Endpoint` set). The script supports both layouts via the `role` config key and
generates matching nftables/AllowedIPs.

---

## 11. Development & SDL Checklist

- [ ] Threat model updated for every new subcommand
- [ ] Unit tests for parsers (fuzzed: CIDR, IPv6, weird keys)
- [ ] Integration tests in disposable VM/container (root required)
- [ ] `--dry-run` tests assert no-op safety
- [ ] Secret-free repository; CI scans for keys (`gitleaks`/`trufflehog`)
- [ ] Dependency audit in CI (pip-audit / govulncheck / npm audit where applicable)
- [ ] Signed artifacts + checksums published with releases
- [ ] Code review checklist aligned to OWASP ASVS v4 L1 for the tool's category

---

*This document is a living artifact. Update it whenever the data model,
security controls, or deployment topology change.*