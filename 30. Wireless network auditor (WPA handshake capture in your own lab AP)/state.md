# Project State - Wireless Network Auditor

> Status snapshot. Update this file whenever the project advances.

## Current milestone

**P5 - Packaging (IN PROGRESS): portable exe delivered, signing pending.**

| Phase | Scope | Status |
|---|---|---|
| P0 Skeleton | GUI shell, scope wizard, capture loop | done |
| P1 Handshake | EAPOL state machine, M1-M4 validation | done |
| P2 Evidence | SQLite vault, AES-GCM, hash chain | done |
| P3 Reports | HTML / CSV / XLSX / JSON exporters | done |
| P4 Hardening | OWASP / ISO / NIST controls wired in | done |
| P5 Packaging | PyInstaller exe, cleanup, signing | in progress |

## Verification log

- Date: 2026-09-19
- `python main.py --selftest` -> **PASSED** (scope guard rejects out-of-scope,
  capture generates aps/clients/sessions/findings, HTML verified, CSV headers ok,
  XLSX valid zip with 6 sheets, JSON schema v1, hash chain ok, DPAPI key mode).
- GUI smoke test -> **PASSED** (construct, pump events, simulate, refresh, destroy).
- `dist/WirelessAuditor.exe` built with PyInstaller 6.22.3 (16.8 MB, onefile, GUI).
- exe launch test -> **PASSED** (8 s heartbeat, no crash, terminated cleanly).

## Artifacts

- `dist/WirelessAuditor.exe` - portable onefile binary (unsigned).
- `wna_data/workspace/` - runtime vault, hash chain, keystore, reports.
- `docs/architecture.html` - colorful reference architecture.

## Remaining (P5 tail + stretch)

- [ ] Authenticode signing (OV/EV) of the exe + SBOM embed.
- [ ] Live-capture backend (TShark/dumpcap subprocess) hook when adapter present.
- [ ] Windows icon for the exe (`icon=` in the spec).
- [ ] Rotate audit log (currently unbounded in SQLite).
- [ ] Optional portable.zip bundle that ships Npcap install notes.

## Known limitations

- Live monitor-mode capture requires a compatible adapter + Npcap/admin rights;
  the simulator backend is the default so the GUI always runs.
- Reports currently export decrypted artifacts (expected - evidence handover).
- Only one DPAPI user context supported; moving the vault to another Windows
  account requires the PBKDF2 fallback or re-seal.

## How to run

    python main.py              # GUI
    python main.py --selftest   # headless verification
    build\build.bat             # rebuild the exe (selftest + PyInstaller)