# memory.md — Persistent Project Memory

**Project:** Mobile MDM-lite Device Compliance Checker
**Purpose:** Reservation/reference memory for agents and maintainers — decisions,
conventions, lessons learned, file map, and next steps.

---

## 1. What this project is

A portable, local-first MDM-lite appliance: enroll mobile devices, evaluate them
against a versioned compliance policy, show a colorful compliance dashboard, and
export audit reports — as a single `.exe` that never phones home.

**Deliverables this session**
- Fully working Python app (`src/mdmcheck/`)
- Portable single-file build: `dist/MDM-Lite-Compliance-Checker.exe`
- Visual architecture: `ARCHITECTURE.html`
- Docs: `README.md`, `docs/{ARCHITECTURE,security,state,memory}.md`

## 2. Key decisions & rationale (keep)

| # | Decision | Rationale |
|---|---|---|
| D1 | Python 3.12 **stdlib only** | Zero runtime deps → tiny, robust, offline-safe PyInstaller build (8.5 MB) |
| D2 | Loopback HTTP + browser dashboard | Most attractive, testable UI; `127.0.0.1` keeps privacy story strong |
| D3 | Single `state.json` file | Portable, human-inspectable, easy backup/restore |
| D4 | Status **derived**, never stored | Single source of truth; policy change → automatic invalidation of scans |
| D5 | Severity-weighted score + critical-fail gate | Mirrors real MDM risk: one critical violation blocks compliance |
| D6 | Deterministic demo telemetry (SHA-256 seed) | Reproducible demos and tests without mocking frameworks |
| D7 | ADB collection best-effort | Real hardware support when available; graceful fallback otherwise |
| D8 | Atomic writes + quarantine recovery | No torn/corrupt state; self-heals with forensic artifact |

## 3. Conventions

- **Module layout:** one responsibility per module under `src/mdmcheck/`
  (`model`, `policy`, `engine`, `store`, `report`, `demo`, `adb`, `dashboard`, `main`).
- **Naming:** snake_case functions/files; PascalCase classes; rule ids like
  `<platform>.<group>.<name>`.
- **Statuses:** `PENDING`, `COMPLIANT`, `NON_COMPLIANT`, `ERROR`.
- **Verdicts:** `PASS`, `FAIL`, `NA`.
- **Severity:** `low | medium | high | critical`.
- **Audit levels:** `info | warn | critical`.
- **No comments in code unless asked** — code is self-documenting.
- **JSON** everywhere for interchange; `default=str` on save.

## 4. File map

```
.
├── ARCHITECTURE.html               # colorful visual architecture (open in browser)
├── README.md                       # user guide + build instructions
├── docs/
│   ├── ARCHITECTURE.md             # written architecture
│   ├── security.md                 # security.md reservation (threat model)
│   ├── state.md                    # state.md reservation (state contract)
│   └── memory.md                   # this file
├── src/
│   ├── launcher.py                 # PyInstaller entry point
│   └── mdmcheck/
│       ├── __init__.py             # version metadata
│       ├── model.py                # domain model + verdicts
│       ├── policy.py               # 14 baseline rules + validation
│       ├── engine.py               # compliance evaluation
│       ├── store.py                # state.json persistence
│       ├── demo.py                 # simulated devices
│       ├── adb.py                  # Android ADB collector
│       ├── report.py               # HTML/JSON report generators
│       ├── dashboard.py            # HTTP API server + UI hosting
│       ├── main.py                 # CLI entry
│       └── ui/index.html           # dashboard front-end
├── mobile/
│   ├── android-agent/              # Gradle-free Android agent project (Java)
│   │   ├── build.ps1               # aapt2→javac→d8→zipalign→apksigner pipeline
│   │   └── java/com/mdmlite/agent/ # collector, mirrored engine, sender, UI
│   └── ios/
│       ├── MDM-Lite-Enrollment.mobileconfig  # installable restrictions profile
│       └── MDM-LiteAgent/          # Swift package → IPA on macOS/Xcode
├── release/android/                # signed MDM-Lite-Agent.apk + keystore
├── tools/smoke_test.py             # headless test suite
└── dist/MDM-Lite-Compliance-Checker.exe   # portable build
```

## 5. Lessons learned (reservation — append with new findings)

1. **Derived fields must be materialized at the API boundary.** v1 returned raw
   device dicts lacking `status` → reports/UI showed everything PENDING. Fixed by
   adding `_with_status()` normalization in `store.{snapshot,devices,export_report}`.
2. **PyInstaller onefile + relative imports** — the entry script must be a thin
   launcher importing the package; passing a package-relative entry (`main.py`)
   breaks `from . import` under the frozen loader.
3. **`_MEIPASS` layout** — bundled assets land at `<MEIPASS>/mdmcheck/ui`, not
   `<MEIPASS>/ui`; `_resource_path()` compensates.
4. **Flaky exe health checks** — `Get-NetTCPConnection -OwningProcess` failed in
   the sandbox; parse the app's own `mdm-lite.log` for the actual URL instead.
5. **Loopback auto-ports** (port 0) maximise portability on heavily-loaded test hosts.
6. **Gradle-free APK builds are viable** — `aapt2` + `javac --release 11` + `d8.jar`
   + `jar uf` + `zipalign` + `apksigner` reproduced a v2/v3-signed installable APK.
   Flags: use `--release 11` (JDK 24 dropped old targets) and `lib/d8.jar` directly.
7. **iOS on Windows = profile + source, not IPA.** A signed `.ipa` requires macOS.
   The `.mobileconfig` (unsigned) is installable as-is — and plist XML forbids `--`
   inside comments (broke parsing; fixed with `===`).
8. **Agent push contract:** mobile agents POST real telemetry to `/api/devices`;
   the handler now stores it and evaluates as `mode=agent` (rebuilt into the exe).

## 6. Verified test matrix (this session)

| Check | Result |
|---|---|
| `tools/smoke_test.py` engine/store/report suite | ✅ PASS |
| Source server: health, state counts, devices CRUD, scans, reports, shutdown API | ✅ |
| Device status propagation to `/api/state`, JSON+HTML reports (post-fix) | ✅ 5 COMPLIANT / 1 NON_COMPLIANT |
| `.exe` (onefile, noconsole, 8.5 MB): boot → dashboard served → clean shutdown | ✅ |
| Demo fleet determinism | ✅ scores stable across runs |

## 7. Backlog / next steps (reservation)

**Functional**
- [ ] Scheduler: periodic auto-scans with status-change notifications
- [ ] Policy history + preview (compare versions before switch)
- [ ] CSV/Excel report export; batch device import (CSV)
- [ ] Force-action "remediation" tracking (ticket the failing device)

**Security**
- [ ] Optional state-file encryption (see `security.md` §9)
- [ ] Loopback auth token; SBOM for the build

**Platform**
- [ ] Real Android agent (companion APK) pushing honest telemetry
- [ ] Native iOS agent via MDM enrollment hooks
- [ ] CI/CD: build + smoke per OS (win/mac/linux onefile)

**Testing**
- [ ] Concurrent scan stress test; policy schema fuzzing
- [ ] ADB integration test on emulator (adb-mock)

## 8. Open questions

- Which departments/platforms dominate the real fleet? (shapes default policy)
- Do consumers need actionability beyond reports (blocklists, VPN kill-switch)?
- Is a central multi-tenant authority in scope for v2, or stay single-owner local?