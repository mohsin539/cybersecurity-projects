# Mobile MDM-lite Device Compliance Checker

A **portable, local-first MDM-lite** solution: enroll mobile devices (Android / iOS),
evaluate them against a configurable compliance policy, and watch live compliance
on a colorful dashboard — delivered as a single portable `.exe` that **never sends
device data off your machine**.

---

## Highlights

- 🔒 **Local-first & private** — server binds `127.0.0.1` only; zero outbound data.
- 🎨 **Colorful dashboard** — KPIs, compliance donut, fleet bars, status chips, live audit log.
- ⚙️ **Compliance engine** — 14 baseline rules, severity-weighted scoring, critical-fail gate.
- 📲 **Scan modes** — deterministic demo simulation, live ADB (real Android), manual telemetry.
- 📄 **Reports** — branded HTML + machine-readable JSON, per-device drill-down with remediation.
- 💾 **Resilient state** — single `state.json`, atomic writes, corruption auto-recovery.
- 🚀 **Portable** — single `.exe`, no installation, no runtime dependencies.

## Quick start

```powershell
# 1. Launch (auto-opens your browser at the dashboard)
.\dist\MDM-Lite-Compliance-Checker.exe

# 2. In the dashboard
#    • Dashboard — overiew KPIs & fleet status
#    • Devices   — enroll devices, run Demo/ADB scans, drill into rules
#    • Policy    — inspect/edit the 14 baseline rules (JSON editor)
#    • Reports   — export HTML/JSON audits
#    • Security Log — audit trail
#    Click "Run demo scans (all)" to see the engine in action instantly.
```

State is stored in `mdm-lite-state.json` next to the exe. Stop the app with the
**Shutdown button** (or close the console/Ctrl+C).

## 📱 Mobile companions

Real on-device agents that feed this checker live telemetry:

| Deliverable | Location | Notes |
|---|---|---|
| **Android agent APK** (signed, installable) | `release/android/MDM-Lite-Agent.apk` | Collects OS/apps/security flags, evaluates on-device, can push to the checker over LAN |
| **iOS enrollment profile** (installable) | `mobile/ios/MDM-Lite-Enrollment.mobileconfig` | Unsigned profile enforcing passcode + restrictions — installs today, no code |
| **iOS agent (Swift)** → build IPA on a Mac | `mobile/ios/MDM-LiteAgent/` | Mirrors the compliance engine; Xcode needed for a signed `.ipa` |

Agents POST telemetry to `POST /api/devices` — the checker enrolls the device and
evaluates it in **agent** mode automatically. Full instructions:
[`mobile/README.md`](mobile/README.md).

## Running from source (developers)

Requires **Python 3.12+** (stdlib only — no pip installs).

```powershell
$env:PYTHONPATH = "src"
python -m mdmcheck.main --seed-demo     # seed demo fleet + open dashboard
python -m mdmcheck.main --port 8791 --no-browser
python tools\smoke_test.py              # headless test suite
```

CLI: `--port`, `--host`, `--data <state.json path>`, `--no-browser`, `--seed-demo`, `--version`.

## Building the portable .exe

```powershell
pip install pyinstaller
pyinstaller --noconfirm --clean --onefile --noconsole `
  --name "MDM-Lite-Compliance-Checker" `
  --add-data "src\mdmcheck\ui;mdmcheck\ui" `
  --collect-submodules mdmcheck `
  "src\launcher.py"
# Output: dist\MDM-Lite-Compliance-Checker.exe
```

## Compliance model (one line)

**COMPLIANT** ⇔ no critical failure **and** severity-weighted score ≥ 80%
(low=1 · medium=2 · high=3 · critical=4). See [docs](docs/).

## Scanning real Android devices over ADB

1. Install Google **platform-tools** and put `adb` on PATH.
2. Connect a device with USB debugging enabled.
3. In **Devices → ADB** you'll see connected serials; click **ADB** on a device row.
   The collector pulls OS/build/sdk, package list and root indicators.

> No ADB? Demo and manual-telemetry modes keep everything else fully functional.

## Documentation

| File | Content |
|---|---|
| [`ARCHITECTURE.html`](ARCHITECTURE.html) | Colorful visual architecture diagram |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Written architecture |
| [`docs/security.md`](docs/security.md) | Security architecture & threat model (reservation) |
| [`docs/state.md`](docs/state.md) | State model & persistence contract (reservation) |
| [`docs/memory.md`](docs/memory.md) | Project memory, decisions & backlog |

## Project layout

```
src/mdmcheck/       # application (model, policy, engine, store, report, demo, adb, dashboard)
src/mdmcheck/ui/    # single-file dashboard front-end
mobile/             # Android agent project + iOS profile + Swift agent
release/android/    # signed MDM-Lite-Agent.apk + signing keystore
tools/smoke_test.py # headless verification
dist/               # portable .exe build
```