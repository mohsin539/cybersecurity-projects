# 🧭 state.md — Current System State & Runtime Layout

> Live reference for the portable forensic workstation `MobileForensicsLabPortable.exe`

## 1. Delivery State (this build)

| Item | State |
|------|-------|
| Executable | `app/dist/MobileForensicsLabPortable.exe` (12.4 MB, single file, no console) |
| Source | `app/main.py` + `app/forensics/*` (pure stdlib) |
| Docs | `architecture.md` · `security.md` · this file · `memory.md` |
| Build reproducibility | `app\build.ps1` → PyInstaller `--onefile --noconsole --icon build/app.ico` |
| Platform target | Windows x64 (Python 3.12.7) |

## 2. Runtime State Machine (per case)

```
Created → Intake(open→done) → Acquisition(pending→done) → Extraction(pending→done)
        → Analysis(pending→…) → Reporting(pending→done) → Audit stages
```

Zone statuses are persisted in each case's `manifest.json` under `zones`; Dashboard tab renders LEDs:
`open/pending` dim · `done/acquired/complete` colored. Workflow does not hard-block progression — the journal records the actual audit story.

## 3. Evidence Vault Layout (auto-created beside EXE)

```
evidence_vault/
├── cases/
│   └── CSE-2026-0001/
│       ├── manifest.json          # case id/title/zones/evidence/reports
│       ├── inventory.json         # file inventory + sha256 + sqlite meta
│       ├── inventory.csv          # portable table of the same
│       ├── acquired_files/        # manual / demo exhibit registrations
│       ├── acquisition/           # <case>.ab backup target
│       ├── logical/               # logical pull root (DCIM, Pictures, …)
│       └── reports/               # signed PDF/DOCX/XML/JSON/CSV/HTML
├── journal/
│   └── audit.jsonl                # WORM hash-chain journal (app-wide)
├── keys/
│   └── signing.key                # 32-byte HMAC signing key
└── exports/                       # audit_export.json snapshots
```

Case IDs auto-increment: `CSE-<YYYY>-<NNNN>` (first free number).

## 4. Journal & Integrity State

- Journal starts with `app.started`, then `case.created` etc.; every entry: `n, ts, actor, zone, action, detail, prev, hash`.
- `verify()` recomputes the SHA-256 chain: **all-green = intact**. A single edited/deleted line = detectable (hash mismatch or broken `prev` link).
- Report manifest: each deliverable recorded in `manifest.json` → `reports[]` with `hmac_sha256`.

## 5. How to Inspect State (audit / QA workflow)

1. **Dashboard** → zone LEDs + compliance snapshot + activity log.
2. **Audit tab** → *Verify Hash Chain* (integrity), *Export Audit JSON* (snapshot to `exports/`).
3. **Extraction tab** → *Run Inventory* (reproduces `inventory.json`, same hashes = unchanged evidence).
4. **Report tab** → signatures tabulated; cross-check against `manifest.json`.
5. Manually: open `CSE-xxxx/manifest.json` — single source of truth for chain of custody per case.

## 6. Operational Notes

- **Portable**: move the EXE anywhere; vault is created next to it. Air-gap by running on an unplugged machine.
- **First run**: no wizard; vault initialized silently, journal gets `app.started`, Dashboard shows *No case open*.
- **adb**: detected on PATH or common `platform-tools` locations. No device ⇒ tool remains fully usable in *paper-mode* (demo artifacts via Intake → *Create Sample Artifact*).
- **Kill/close**: safe at any point — case manifest + journal are flushed per operation (no lazy buffers).
- **Vault backup**: replicate `cases/`, `journal/`, `keys/`; GS1-style: manifest + journal are self-describing for restore.

---
*State snapshot recorded at release · Call this file the "current known-good" reference after each rebuild or lab move.*