# Architecture — Mobile MDM-lite Device Compliance Checker

> Visual diagram: open [`ARCHITECTURE.html`](../ARCHITECTURE.html) in any browser.
> Portable build: [`dist/MDM-Lite-Compliance-Checker.exe`](../dist/MDM-Lite-Compliance-Checker.exe).

## 1. Purpose

A **local-first, privacy-preserving MDM-lite solution** that enrolls mobile devices
(Android / iOS / BYOD), evaluates each device against a configurable **compliance
policy**, produces a **colored compliance verdict** (COMPLIANT / NON_COMPLIANT /
PENDING / ERROR), and exposes a **colorful live dashboard** plus **audit reports** —
all from a single portable `.exe` with **zero telemetry leaving the machine**.

## 2. Principles

| Principle | Implementation |
|---|---|
| Local-first | Everything persists in `state.json` beside the executable; no cloud. |
| Portable | Single-file `.exe` (PyInstaller onefile), Python stdlib only. |
| Deterministic | Demo telemetry is seeded from device id (SHA-256) → reproducible demos. |
| Verdict honesty | Policy changes invalidate stale scan results (no false "compliant"). |
| Degrade gracefully | ADB is best-effort; app works fully without it (demo/manual modes). |

## 3. Logical layers

```
┌────────────────────────────────────────────────────────────────────┐
│ 1. MANAGED DEVICE LAYER                                            │
│    Android agent · iOS agent · Demo telemetry · ADB bridge         │
└───────────────────────────┬────────────────────────────────────────┘
                            │ telemetry JSON {os,apps,security,network}
┌───────────────────────────▼────────────────────────────────────────┐
│ 2. COLLECTION & INTERFACE LAYER  (127.0.0.1 loopback)              │
│    REST API · hosted Dashboard UI · scan bootstrap · health/SD     │
└───────────────────────────┬────────────────────────────────────────┘
┌───────────────────────────▼────────────────────────────────────────┐
│ 3. CORE SERVICES                                                   │
│    Device Registry · Policy Manager · Scan Orchestrator · AuditLog │
└───────────────────────────┬────────────────────────────────────────┘
┌───────────────────────────▼────────────────────────────────────────┐
│ 4. COMPLIANCE ENGINE                                               │
│    Rule evaluator (5 kinds) · severity weighting · verdict gate    │
└───────────────────────────┬────────────────────────────────────────┘
┌───────────────────────────▼────────────────────────────────────────┐
│ 5. STATE & PERSISTENCE                                             │
│    state.json · atomic writes · corruption quarantine · snapshots  │
└───────────────────────────┬────────────────────────────────────────┘
┌───────────────────────────▼────────────────────────────────────────┐
│ 6. PRESENTATION & REPORTING                                        │
│    Dark dashboard · HTML report · JSON report · device drill-down  │
└────────────────────────────────────────────────────────────────────┘
```

## 4. Component map (code)

| Component | File | Responsibility |
|---|---|---|
| `Dashboard` server + API | `src/mdmcheck/dashboard.py` | HTTP endpoints, static UI hosting, scan orchestration glue |
| Compliance engine | `src/mdmcheck/engine.py` | Per-rule verdicts, weighted scoring, final status |
| Policy definition/validation | `src/mdmcheck/policy.py` | 14 baseline rules, validation, defaults |
| Domain model | `src/mdmcheck/model.py` | `Rule`, `RuleResult`, `ScanResult`, `Device`, verdict constants |
| State store | `src/mdmcheck/store.py` | JSON persistence, atomic write, quarantine, security log |
| ADB collector | `src/mdmcheck/adb.py` | Live Android telemetry over `adb` (best-effort) |
| Demo generator | `src/mdmcheck/demo.py` | Deterministic fake devices/profiles |
| Report generator | `src/mdmcheck/report.py` | HTML + JSON audit reports |
| Entry point | `src/launcher.py` → `mdmcheck/main.py` | CLI, browser launch, shutdown handling |
| Dashboard UI | `src/mdmcheck/ui/index.html` | Single-file colorful web UI |

## 5. Compliance evaluation model

A device is evaluated as:

```
for each rule in policy:
    verdict = PASS | FAIL | NA        # NA if platform not applicable
    weight  = severity weight (low 1, medium 2, high 3, critical 4)

score = (Σ weight of PASS) / (Σ weight of PASS+FAIL)

status = COMPLIANT  iff  (no critical FAIL) AND (score ≥ threshold)
       = NON_COMPLIANT otherwise
```

Rule kinds: `version_gte`, `boolean`, `allowlist`, `denylist`, `list_contains`.

## 6. Key flows

**Enroll → Scan**
1. `POST /api/devices` registers identity in the Device Registry (scan-on-enroll optional).
2. `POST /api/devices/{id}/scan` picks a collector (`demo | adb | telemetry`).
3. Telemetry JSON is produced/collected.
4. `engine.evaluate(policy, id, platform, telemetry)` returns `ScanResult`.
5. Result is stored (previous result pushed to 20-deep history), audit log entry appended.

**Policy change**
`POST /api/policy` validates then replaces the rule set; **all existing scan results
are invalidated** (set to PENDING) so dashboards never claim compliance under a
retired policy.

**Reporting**
`GET /api/report/html?device={id}` or `GET /api/report/json` produce escaped,
branded, local-only artifacts (browser tabs / saved files).

## 7. Failure handling

| Failure | Behavior |
|---|---|
| `state.json` corrupt | Quarantined to `state.json.corrupt-<ts>`, fresh store rebuilt, critical logged |
| ADB absent / no devices | `GET /api/adb/status` reports it; scan falls back to existing/demo telemetry |
| Device not found | 404 + error JSON |
| Invalid policy JSON | 400 with the specific rule-index error |
| Port in use / random | Listener binds port `0` (auto) and prints the real URL + writes `mdm-lite.log` |

## 8. Rediscovery for a real MDM deployment

Keep the same engine and policy model, and replace the local HTTP/JSON surfaces with:
a central authority, on-device agents pushing encrypted telemetry to `mdm-lite://`
endpoints over TLS (mutual auth), signed enrollment payloads, and a sync layer for
BYOD/offline-first devices. The engine, policy schema, verdict semantics and report
models carry over unchanged.