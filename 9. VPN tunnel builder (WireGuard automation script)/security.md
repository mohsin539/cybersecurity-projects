# Security — VPN Tunnel Builder (WireGuard Automation Console)

Version 1.0 · 2026-09-18 · Companion to `ARCHITECTURE.md`

This document describes the **implemented** security posture of the web console
(the code in this repository), maps it to ISO/IEC 27001:2022, NIST CSF 2.0,
NIST SP 800-53, and OWASP Top 10 (2021), and provides the operational security
runbook. The architecture-level threat model and CLI-era controls remain in
`ARCHITECTURE.md §7`; this file records what the web application actually does.

---

## 1. Security Model — What the Web App Is

The console is a **localhost-first administrative GUI over a privileged
configuration store**. It never listens on a public interface by default
(`run.py --host 127.0.0.1`), and it ships with strong defaults (auth on, CSRF
on, localhost-only, secret redaction on). On Windows or without `wireguard-tools`
it runs against a **deterministic simulator** — the same validation, config
generation, persistence, and audit chain execute; only the kernel tunnel is
absent.

### 1.1 Assets & Trust Boundaries

| Asset | Where it lives | Boundary |
|---|---|---|
| Tunnel/peer private keys, PSKs | `data/secrets.json` | Separate from state; never in logs, UI, or `state.json` |
| Public state (tunnels, peers, settings) | `data/state.json` | No secrets by construction; safe to export |
| Config digests / integrity | snapshots + audit chain | Hash-chained, tamper-evident |
| Auth material | salted SHA-256 hash in settings; raw token only at bootstrap | Token shown once |
| Audit trail | `data/audit.log` | Hash-chained, append-mode writes |

Trust boundaries:
- **Operator ↔ Console**: token auth + CSRF + localhost check.
- **Console ↔ Filesystem**: every write is atomic (`temp + fsync + replace +
  fsync dir`) under an advisory file lock.
- **Console ↔ `wg`**: `subprocess` with argument arrays only (no shell); every
  string reaching a command passes `core.validate` first.

---

## 2. Implemented Controls (file → control)

### 2.1 Authentication & Session (OWASP A01, A07; NIST IA-5, AC-3)

- `app/security/auth.py`
  - Token login: salted SHA-256 comparison (`hash_token`, constant-time
    `compare_digest`).
  - Bootstrap token generated once, written to `data/initial-auth.txt`,
    shown in the login page on first run, never stored in plaintext elsewhere.
  - Rotate from **Settings → reset auth token** (`new_token()` re-hashes).
  - Session cookies: `HttpOnly`, `SameSite=Lax` (`SESSION_COOKIE_HTTPONLY`,
    `SESSION_COOKIE_SAMESITE`).
  - `require_localhost_only` rejects non-local remotes with 403 unless
    explicitly disabled (off-by-default hardening).
  - `--no-auth` is an explicit operator flag that prints a warning — never a
    default.

### 2.2 CSRF (OWASP A01)

- Synchroniser token pattern (`csrf_protect`, `get_csrf_token`): a per-session
  token must be echoed back (form field `_csrf_token` or header `X-CSRF-Token`)
  on every `POST/PUT/DELETE/PATCH`.
- Exempt paths: `/api/*` (read-only status endpoint only) and the login POST.
- Every mutation route is POST-only; GET routes never mutate.

### 2.3 Input Validation & Injection (OWASP A03; NIST SI-12; ISO A.8.28)

- `app/core/validate.py` — strict, allow-listed schemas:
  - `is_wg_key`: base64 with `=` padding only, proper length.
  - `is_endpoint`: host/fqdn + numeric port, IPv6 bracket form accepted.
  - `is_interface_name`: bounded `[A-Za-z0-9_]+`, ≤ 15 chars.
  - CIDR checks via `ipaddress`; unknown keys rejected (fail closed).
- `app/security/redactor.py` — canonical scrubber (`SECRET_KEYS`) applied to
  every audit `detail` before `append`; config **previews** are
  `strip_private_key()`-redacted while the real `.conf` download is the only
  place a private key is emitted (operator action, authenticated route).
- No shell interpolation anywhere: `subprocess.run([args...])`.

### 2.4 Cryptographic Functions (OWASP A02; NIST SC-13; ISO A.5.24, A.8.9)

- `app/core/crypto.py` uses the OS CSPRNG via the `cryptography` library to
  produce WireGuard-format X25519 keys and PSKs.
- Secret material is written only to `data/secrets.json` (0600 on POSIX),
  never to `state.json`, settings, or the audit chain.
- Flask session secret persisted to `.flask_secret` (random per data dir).

### 2.5 State Integrity & Atomicity (NIST SI-7; ISO A.8.31)

- `app/persistence/store.py`
  - `_atomic_write`: `mkstemp` in target dir → write → `fsync` → `os.replace`
    → `fsync` dir. No torn files.
  - `FileLock`: advisory cross-platform lock (fcntl/msvcrt) serialises writers.
  - Defaults are **immutable-by-construction**: `_empty_state()` returns a
    fresh nested structure per call (see `state.md` — root-cause bug fixed).

### 2.6 Audit Trail (OWASP A09; NIST AU-2..6; ISO A.8.15)

- `app/persistence/audit.py`
  - `event_hash = SHA256(prev_hash | canonical(event))` — hash chaining makes
    retroactive modification detectable.
  - `verify()` replays the chain; the Audit page surfaces broken events.
  - Append mode + `fsync` per write; corrupt lines recorded as
    `audit.corrupt` events rather than silently dropped.

### 2.7 Snapshot / Recovery (NIST CP-9; ISO A.8.11)

- `app/persistence/snapshots.py` — snapshot captures `state.json` +
  `secrets.json` (full restore including keys), indexed by content-derived id,
  bounded by `snapshot_retention` (prune).
- Tunnel mutations that precede destructive actions create a snapshot first
  (`tunnel_service.build`, `remove`).

---

## 3. Compliance Mapping

### 3.1 ISO/IEC 27001:2022 Annex A (implementation standing)

| Control | Implementation status |
|---|---|
| A.5.10/A.8.24 Secrets mgmt | ✅ Keys isolated in `secrets.json`; redaction everywhere else |
| A.5.15 Access control | ✅ token auth, localhost-only, operator-only POSTs |
| A.5.24 Use of cryptography | ✅ X25519/PSK via `cryptography`; SHA-256 chains |
| A.5.28 Secure engineering | ✅ threat model in ARCHITECTURE; validation-first design |
| A.6.8/A.8.11 Backup | ✅ snapshot+rollback with retention |
| A.8.12 Leakage prevention | ✅ `AllowedIPs` minimalism; previews redacted |
| A.8.15 Logging | ✅ hash-chained audit; export route |
| A.8.28 Secure coding | ✅ argument-array subprocess; strict schemas |
| A.8.31 Change management | ✅ snapshot-before-mutate, idempotent (NOOP) builds |

### 3.2 NIST CSF 2.0

| Function | Evidence |
|---|---|
| GOVERN | settings schema + defaults; this document |
| IDENTIFY | state inventory (`state.json`); simulator flags |
| PROTECT | in-kernel crypto (real) / key handling (sim) · redaction · auth · CSRF |
| DETECT | sampler status / handshake age; audit verify (chain breaks flagged) |
| RESPOND | snapshot·rollback; kill (stop/down); audit reconstruction |
| RECOVER | idempotent rebuild from state; snapshot restore endpoint |

### 3.3 NIST SP 800-53 (subset)

`AC-2/3/16`, `SC-7/8/13/28`, `AU-2/3/4/5/6/11`, `IA-5/11`, `CM-6/9`,
`SI-7/12` — each named in the module docstrings where it is enforced.

### 3.4 OWASP Top 10 (2021) — Web console

| # | Risk | Control |
|---|---|---|
| A01 Broken Access Ctrl | token auth + localhost gating + CSRF on all mutations; POST-only writes |
| A02 Crypto Failures | CSPRNG keygen; salted hashes; keys off the wire/view |
| A03 Injection | allow-list validators before subprocess; no shell strings |
| A04 Insecure Design | fail-closed validators; idempotent operations; secret separation |
| A05 Misconfig | sane defaults (auth on, localhost-only, retention bounds) |
| A06 Vulnerable Components | pinned `flask==3.1.3`; `pip-audit` recommended in CI |
| A07 Identification/Auth | token login, rotate-from-UI, constant-time compare |
| A08 Data Integrity | atomic writes + audit hash chain + snapshot digests |
| A09 Logging Failures | structured JSONL audit; `/audit/export`; chain verify UI |
| A10 SSRF | n/a (no outbound fetch); endpoint fields validated if ever used |

---

## 4. Threat Scenarios & Mitigations

| Scenario | Mitigation |
|---|---|
| Stolen `state.json` | Contains no secrets; cannot recover keys |
| Stolen `secrets.json` | 0600 perms on POSIX; keep datadir on encrypted disk |
| Audit tampered | `verify()` detects chain break; UI flags corruption |
| CSRF from evil page | synchroniser token; SameSite=Lax; POST-only writes |
| Rogue peer key injection | public key must pass `is_wg_key`; PSK per peer |
| Replay login | session cookie secure per token; rotate from Settings |
| Port hijack after build | preflight bind-check before apply (both backends) |

---

## 5. Operating Runbook

- **First run:** `python run.py` → token in `data/initial-auth.txt`; login,
  open **Settings**, rotate token, then delete `initial-auth.txt`.
- **Start with auth:** never use `--no-auth` except on a trusted single-user
  workstation; the flag prints a warning on purpose.
- **Expose to network:** don't. Reverse-proxy behind TLS + your own auth if ever
  needed; keep `require_localhost_only` on otherwise.
- **Verify integrity:** open **Audit** → chain status should read valid.
  `audit.verify()` covers the whole file; the page shows broken events.
- **Before risky changes:** create a snapshot from the tunnel page; roll back
  from the same list.
- **Keep secrets safe:** back up `data/` (or at least `secrets.json`) to an
  encrypted location; `state.json` alone cannot rebuild keys.

---

## 6. Known Limitations (security-relevant)

- On **Windows**, config files do not get 0600-style ACLs (`_chmod_private` is
  POSIX-only). Prefer the POSIX host for sensitive deployments.
- `os.replace` + advisory `FileLock` do **not** provide security-grade locking
  (they prevent accidental concurrent writes, not malicious races).
- The console is **not** a hardened multi-user platform: one token, coarse
  operator role. Do not expose it to untrusted networks.
- Audit prune (`audit_retention_days`) rewrites the file; if strict
  append-only evidence is required, snapshot the audit file externally.

*This document is a living artifact. Update it whenever controls change.*