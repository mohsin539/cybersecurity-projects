# VPN Tunnel Builder — WireGuard Automation Console

A secure **web-based GUI** for provisioning and managing WireGuard tunnels,
implemented from `ARCHITECTURE.md`. Cross-platform: run it anywhere; on a host
with `wireguard-tools` it drives the real kernel interfaces, everywhere else it
falls back to a deterministic simulator (same configs, validation, audit —
no real tunnel).

## Quick start

```bash
python -m pip install -r requirements.txt
python run.py                      # http://127.0.0.1:8090
python run.py --no-auth            # only for trusted localhost (prints warning)
python run.py --backend simulator  # force simulation
```

On first start with auth enabled, a token is generated and written to
`data/initial-auth.txt` (and printed to the console). It is never shown again —
use **Settings → Reset auth token** to rotate it.

## Project layout

```
run.py                  entry point (waitress/Flask server + CLI flags)
app/
  core/                 domain: models, validate, crypto (X25519), config schema
  persistence/          atomic StateStore (state vs secrets), hash-chained AuditLog,
                        SnapshotManager (backup/rollback)
  platform/             WireGuard backend adapters (local `wg` vs simulator) + configgen
  services/             use cases: TunnelService, PeerService
  security/             token auth, CSRF, secret redaction
  web/                  Flask app factory, routes, templates, static assets
tests/                  pytest suite (validators, crypto vectors, audit chain, service)
scripts/build_exe.ps1   optional PyInstaller portable .exe build
```

## Security in 30 seconds

- **Auth** — salted SHA-256 token, session cookie HttpOnly/SameSite=Lax, CSRF sync-token on every POST.
- **Keys** — X25519 keys generated via `cryptography` (CSPRNG, base64 raw = WireGuard format); private keys live only in `data/secrets.json`, never in logs or `state.json`.
- **Audit** — every mutation appended to a hash-chained log; the web UI verifies the chain and flags corruption.
- **Inputs** — strict allow-listed schemas + CIDR/key/port validation before anything reaches subprocesses (which run with argument arrays, no shell).
- **Ops control** — snapshot before destroy, idempotent `NOOP` re-runs, redacted config previews, real `.conf` download handles keys like secrets.

Full control mapping (ISO 27001:2022, NIST CSF 2.0, NIST 800-53, OWASP Top 10)
lives in `security.md`.

## Credentials & data

- State (no secrets): `data/state.json`
- Secrets (0600 on POSIX): `data/secrets.json`
- Audit: `data/audit.log`
- Snapshots: `data/snapshots/`
- Generated configs: `data/confs/*.conf`

## Tests

```bash
python -m pytest tests -q
```

## Portable .exe (optional)

```powershell
# from the project root
powershell -ExecutionPolicy Bypass -File scripts/build_exe.ps1
# → dist/VpnTunnelBuilder.exe   (single file, no Python required)
```

## Docs

| File | Contents |
|---|---|
| `ARCHITECTURE.md` | Full system architecture + deployment topology |
| `security.md` | Security controls, compliance mapping, runbook |
| `state.md` | Current project state, known gaps, roadmap |
| `memory.md` | Context for future AI-assisted sessions |