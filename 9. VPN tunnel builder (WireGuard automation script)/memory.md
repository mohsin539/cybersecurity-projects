# Memory — VPN Tunnel Builder (WireGuard Automation Console)

Version 1.0 · 2026-09-18
This file is the handoff context for future AI-assisted sessions. Read it
**before** editing anything.

---

## 1. What This Project Is

A web GUI (Flask) that provisions and manages WireGuard tunnels + peers, built
from `ARCHITECTURE.md`. It runs anywhere; with `wireguard-tools` it drives real
kernel interfaces, otherwise a deterministic simulator produces the identical
configs/validation/audit with no real tunnel.

## 2. Layout & Conventions

```
run.py                  entry point (waitress; --host/--port/--data-dir/--no-auth/--no-browser/--backend)
app/
  core/                 models.py | validate.py | crypto.py | config.py
  persistence/          store.py (atomic, FileLock) | audit.py (hash chain) | snapshots.py
  platform/             backend.py (Local vs Simulator) | configgen.py
  services/             base.py (ServiceContext) | tunnel_service.py | peer_service.py
  security/             auth.py (session+CSRF) | redactor.py (SECRET_KEYS scrub)
  web/                  app.py (factory + routes) | templates/ | static/
tests/                  pytest suite (validators, crypto vectors, audit, services)
scripts/build_exe.ps1   optional PyInstaller build
```

Conventions to follow:
- **No comments unless asked**; the codebase headers already carry NIST/ISO tags.
- Every mutation: `validate → persist (atomic) → write conf → reload (best-effort)
  → audit` (see `TunnelService`, `PeerService`).
- Return shapes from use cases: `{"ok": bool, "message"|"errors"|..., ...}` and
  the web layer flashes/redirects; keep that contract stable.

## 3. Architecture Invariants (do not break)

1. **Secrets ≠ state.** `state.json` (tunnels/peers/settings) must NEVER contain
   private keys/PSKs; those live in `secrets.json`. Public status/config previews
   must be redacted (`strip_private_key`, `redactor.scrub_*`). The only route that
   emits a real private key is `/tunnels/<iface>/conf/download`.
2. **Mutable defaults are forbidden.** `App /core/config.py` uses `deepcopy` and
   `store._empty_state()` returns a fresh dict/list per call. A shallow `dict(...)`
   copy of a nested default was the root cause of a nasty cross-store bug — never
   reintroduce shared nested defaults.
3. **All writes atomic + locked.** Writes go through `_atomic_write` (temp+fsync+
   replace+fsync dir) under `FileLock`. Don't bypass it with `.write_text()` on
   store files (conf files under `confs/` are exempt).
4. **Auth/CSRF on every mutation.** POST-only writes, synchroniser CSRF token,
   localhost-only gate, salted-hash token. `/api/*` is exempt (read-only).
5. **Backend abstraction.** `base.backend` handles preflight/up/down/reload/status;
   `detect_backend(store, settings["backend"])` hot-swaps. UI must show
   `backend_is_simulated`.

## 6. Testing Rules

- Run: `python -m pytest tests -q` → **28 passed** (must stay green).
- Tests insert project root via `sys.path` at import time.
- `tmp_path` is clean on this Windows box; earlier cross-test failures were the
  shallow-default bug (§3.2), not pytest.
- Add a regression test whenever you fix a stateful bug (see
  `tests/test_services.py::test_fresh_stores_do_not_share_mutable_defaults`).

## 5. Gotchas / Environment

- **Windows**: paths with spaces/parentheses — quote everything. `chmod` is
  POSIX-only; Windows ignores 0600. No `wg` here → simulator is default.
- Python 3.12.7; Flask 3.1.3 pinned in `requirements.txt`; `cryptography`,
  waitress, PyInstaller, pytest installed.
- Run the app with `python run.py --no-auth --no-browser --backend simulator`
  to smoke-test locally without tokens/tunnels.

## 6. Key File Map for Common Tasks

| To change… | Touch |
|---|---|
| Validators / input rules | `app/core/validate.py` |
| Key/PSK generation | `app/core/crypto.py` |
| Settings schema & token logic | `app/core/config.py` |
| State/secrets/atomicity | `app/persistence/store.py` |
| Audit chain | `app/persistence/audit.py` |
| Snapshot/rollback | `app/persistence/snapshots.py` |
| WireGuard conf building | `app/platform/configgen.py` |
| Real vs simulated backend | `app/platform/backend.py` |
| Business rules (tunnel/peer) | `app/services/*.py` |
| Auth/CSRF/redaction | `app/security/*.py` |
| Routes/templates | `app/web/app.py`, `app/web/templates/*`, `static/*` |

## 7. Last Session Summary

- Built the full web console + tests; fixed the shallow-default state corruption
  bug; suite is green (**28 passed**).
- **`ruff` is installed** — run `ruff check app run.py tests` (or `ruff --fix`).
  Audited pass: 50 findings fixed; 15 style-only remain (SIM102 nesting,
  RUF012 ClassVar, unused test vars) — no functional defects.
- Two real security fixes this session: `peer.add` was silently discarding
  `validate_peer_input` results (restored fail-closed); `build`/`start` ignored
  `preflight` port checks (now `start` is blocked on port-in-use, plain build
  returns `warnings`). Confirmed via service-layer probe.
- Remaining: build the optional `.exe` (`scripts/build_exe.ps1` now exists),
  add CI grades (ruff/mypy/pip-audit), automate route tests, validate on a real
  Linux `wg` host. Details + gaps: `state.md`.

## 8. Status of the Docs

| File | Purpose | Freshness |
|---|---|---|
| `ARCHITECTURE.md` | system + security architecture, CLI-era mapping | current |
| `security.md` | implemented controls, compliance, runbook, limitations | current |
| `state.md` | done/not-done, quality gates, environment | current |
| `memory.md` | this file | current |

*Update this handoff whenever you leave a session with unfinished work.*