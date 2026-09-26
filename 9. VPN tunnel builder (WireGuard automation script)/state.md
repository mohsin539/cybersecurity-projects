# State — VPN Tunnel Builder (WireGuard Automation Console)

Version 1.0 · 2026-09-18 · "Where the project stands"

---

## 1. Current Status: FUNCTIONAL, TESTS GREEN

The web console is implemented per `ARCHITECTURE.md` and passing its test
suite. Everything below reflects the code in this repository **today**.

**Test suite:** `python -m pytest tests -q` → **28 passed**.
**Smoke test:** dashboard 200; tunnel create → peer add → detail → status API →
audit export → conf download all verified over HTTP against the simulator.

## 2. What Exists (completed)

### Backend / domain
- `app/core/` — `models` (Tunnel/Peer/AuditEvent/Snapshot), `validate` (strict
  allow-list), `crypto` (X25519/PSK via `cryptography`, RFC 7748-verified),
  `config` (strict settings schema, salted token hash).
- `app/persistence/` — `store` (atomic writes, FileLock, state/secrets split),
  `audit` (SHA-256 hash chain, `verify()`), `snapshots` (create/restore/prune).
- `app/platform/` — `backend` (`LocalBackend` via `wg`, `SimulatorBackend`,
  `detect_backend`), `configgen` (WireGuard conf builder + redaction +
  structure validator).
- `app/services/` — `TunnelService`, `PeerService` (use cases; every mutation
  = validate → persist → write conf → best-effort reload → audit).
- `app/web/` — Flask factory, session auth + CSRF + redaction hooks, 15 routes,
  8 templates, `style.css`, `app.js`.

### Entry points / docs
- `run.py` (waitress or dev server; `--host/--port/--data-dir/--no-auth/
  --no-browser/--backend`), `requirements.txt`, `README.md`,
  `ARCHITECTURE.md`, `security.md`, `state.md`, `memory.md`.

## 3. Quality Gates (commands to prove health)

```bash
python -m pytest tests -q        # 28 passed
python run.py --no-auth --no-browser --backend simulator   # boot check
```

Manually exercised end-to-end: create tunnel → add peer (generated keypair) →
detail shows peer → `/api/status/<iface>` returns simulated status with
`private_key: "REDACTED"` → `/tunnels/<iface>/conf/download` returns a real
`.conf` (with keys) → `/audit/export` returns TSV.

## 4. Known Bugs (fixed) — keep these lessons

| Bug | Root cause | Fix |
|---|---|---|
| Peers leaked across tests / fresh stores | `load_state()` returned `dict(EMPTY_STATE)` — a **shallow** copy; nested `peers`/`tunnels` lists were module-global and mutated by `.append()` | `_empty_state()` returns a fresh structure per call (`app/persistence/store.py`) |
| `is_wg_key` accepted junk | over-broad regex | `^[A-Za-z0-9+/]+={0,2}$` |
| `is_endpoint` rejected valid IPv6/ports | naive parse | rewritten (bracket form, numeric port, hostname) |
| audit `verify()` failed | included `prev_hash`/`event_hash` in payload | excluded them from the hashed payload |
| snapshots broke on missing `state.json` | strict copy | tolerate missing files; restore unlinks secrets when absent in snapshot |
| redactor `scrub_mapping` raised SyntaxError | broken docstring | fixed |
| `peer.add` validated but ignored the result | dropped `if errors:` guard during an edit | restored fail-closed validation (`app/services/peer_service.py`) |
| `build`/`start` ran even when the port was in use | preflight result discarded (`F841`) | preflight now gates **start** (ERR + no apply); plain build surfaces `warnings` (`app/services/tunnel_service.py`) |
| lint debt | 65 ruff findings, some real (above) | `ruff --fix` cleared 50; 15 style-only remain (SIM102, RUF012, test vars) — safe to leave |

## 5. Known Gaps / Not Yet Done (open)

- [ ] **Portable `.exe`** — `scripts/build_exe.ps1` now exists but the binary
      has **not** been built (PyInstaller IS installed, low priority).
- [ ] **CI** for lint (`ruff`) / type (`mypy`) / audit (`pip-audit`) — not present.
- [ ] **Real `wg` backend on a Linux host** — untested live (no `wg` on dev box);
      unit behaviour covered only via LocalBackend code paths.
- [ ] **TLS / reverse-proxy** guidance for non-local deployment (not built-in by design).
- [ ] **Multi-user / RBAC** — single operator token only (see security.md §6).
- [ ] **Audit pruning** integration with retention settings (see security.md §6).
- [ ] **`monitor_interval_sec`** settings key is stored but no background poller
      uses it yet (status is on-demand).
- [ ] **Unit tests for `web/` routes** (smoke-tested manually, not yet automated).

## 6. Environment Notes (Windows)

- Dev host: **Windows**, Python 3.12.7, Flask 3.1.3, `cryptography`, waitress,
  pytest installed. **No Go toolchain**, no `wireguard-tools` → the simulator is
  the default and flags itself as simulated.
- Project path contains spaces and parentheses — always quote paths in scripts.
- `os.replace`/`fsync`-dir patterns work but Windows ignores POSIX chmod;
  sensitive deployment should be POSIX.

## 7. Roadmap (adjusted from ARCHITECTURE §9)

| Milestone | Notes |
|---|---|
| v1.0 (this) | web console core, all tests green |
| v1.1 | automated route tests; ruff/mypy/CI; real-Linux backend validation |
| v1.2 | `.exe` build + integration test; monitoring poller; audit retention hook |
| v2 | RBAC, TLS profile, metrics exporter, PQ-hybrid crypto note |

*Keep this file updated as the project moves; it is the single source of truth
for "what is done vs not".*