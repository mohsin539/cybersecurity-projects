# State

Project: **Agent check-in jitter and sleep implementation study** — a portable,
GUI-first deterministic simulator to answer *"does per-agent check-in jitter +
sleep scheduling reduce herd/thundering-herd load and energy vs a strict, fully
synchronized baseline?"*

Updated: 2026-09-20 | Status: **BUILD COMPLETE, exe verified**

---

## Build status

| Gate | Status | Evidence |
|---|---|---|
| Unit tests | PASS (21 passed) | `python -m pytest -q` |
| CLI headless run | PASS (deterministic) | herd 52.40 vs 100.00 baseline; verdict PASS |
| Report exports | PASS | xlsx (5 sheets), csv, html (svg + CSP), json, seeds, sha256 manifest, zip, audit |
| Audit chain integrity | PASS | `audit.log.verify() == True` |
| exe build (onefile) | PASS | `dist\AgentJitterStudy.exe` (42.4 MB, windowed) |
| exe headless smoke | PASS | same deterministic outputs as source CLI |
| exe GUI smoke | PASS | process alive 12 s, no startup crash |
| Security docs | DONE | `docs/security.md` |

## Acceptance criteria

- [x] Portable Windows `.exe` — one file, no install, data under `%LOCALAPPDATA%\AgentJitterStudy`
- [x] Deterministic runs — seed-controlled RNG, replica streams reproducible
- [x] Jitter strategy = uniform / gaussian / poisson, magnitudes 0–100%
- [x] Sleep strategy = none / random / exponential / fixed
- [x] Thundering-herd metric (`herd_coef = peak bucket / mean bucket`)
- [x] Statistical comparisons (Mann-Whitney U, Welch t, Hedges' g, Bonferroni)
- [x] Practical-significance verdict ("candidate wins" with >=25% relative delta)
- [x] Reports: xlsx (.xlsx), csv (.csv), html (.html) + json/seeds/manifest/zip
- [x] Security: CSV/HTML injection guards, hash-chained audit log, AES-256-GCM vault (optional passphrase), scrypt KDF
- [x] CLI + GUI entry points; cancel + progress in GUI
- [x] OWASP / NIST CSF 2.0 / ISO 27001 control mappings documented

## Latest verified run (source and exe identical)

Scenario `scenarios/default.yml`, seed 42, 5 replicas, 1000 agents, 60 s interval,
25% uniform jitter, random sleep (45 s base), 600 s run:

| Metric | Candidate | Baseline |
|---|---|---|
| Herd coefficient (peak/mean) | 52.40 | 100.00 |
| Uniformity (1 - std/mean) | -120.5% | -895.0% |
| Latency p99.9 (ms) | 134.17 | 262.57 |
| Duty cycle (awake %) | 10.52 | 26.83 |
| Power draw (mAh/day-agent) | 0.7477 | 1.6748 |
| Drop rate (%) | 0.00 | 0.00 |

verdict: `PASS - Candidate improved 5 metrics vs no-jitter baseline (herd_coef (-48%), uniformity (+87%), latency_p99ms (-62%), duty_cycle (-61%)).`

## How to run

```powershell
# source, headless study + reports to $env:AGENTSTUDY_DATA_DIR\out\<run_id>\ (or default data dir)
$env:AGENTSTUDY_DATA_DIR = "$env:TEMP\ajs"
python -m src.main --cli scenarios/default.yml --print-summary

# source, GUI
python main.py

# packaged exe (GUI) or headless
.\dist\AgentJitterStudy.exe
.\dist\AgentJitterStudy.exe --cli scenarios\default.yml

# tests and (re)build
python -m pytest -q
.\build.ps1          # or build.bat  -> pip install, test gate, PyInstaller
```

## Known limitations / decisions

- Statistical power at low replica counts is weak; the tool reports both
  Bonferroni-adjusted p and practical-effect delta so verdicts stay useful at
  n=5. Raise `replicas` (scenario) for formal published claims.
- Phase is jitter-only: at `jitter_pct=0` all agents fire in the same bucket
  (true thundering herd baseline). Random initial phase was deliberately removed.
- `latency_p99ms` comparison pools per-arrival latencies across replicas
  (thousands of samples); other metrics compare per-replica KPI arrays.
- GUI `_set_tab_enabled` is a no-op stub (kept for future atomic-run UX).
- `duty_cycle` counts only the exact-DES timeline; the fast engine approximates
  it and is intended for large-fleet exploration only.

## Next steps / backlog (not started)

- Add a chart ("Buckets" SVG) into the GUI Results tab (embedded viewer or open-html).
- Bundle the scenario `.yml` editor (YAML load/save from GUI).
- Optional: publish `.exe` via `releasit`/updater or sign with a code-signing cert.
- Optional: profile and parallelize replica runs (`ProcessPoolExecutor`) for
  large `fleet_stress.yml` studies.
- Optional: add a "compare two saved runs" mode (load two `report.json` files).