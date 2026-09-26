# Memory

Working notes for the **Agent check-in jitter and sleep implementation study**.
Purpose: remember the "why" behind every non-obvious decision so future work
(and future sessions) start from the same understanding.

## 1. Project intent

A deterministic simulation study asking: does adding **jitter** (±% of the check-in
interval) and **sleep scheduling** (agents nap between check-ins) to a fleet of
agents reduce backend load peaks (thundering herd) and per-agent energy vs a
baseline where every agent checks in exactly on the same cadence?

Deliverable: a portable Windows GUI `.exe` producing `.xlsx / .csv / .html` reports
(+ `.json`, seeds, sha256 manifest, optional encrypted zip), hardened to
OWASP/NIST/ISO-27001 boints documented in `docs/security.md`.

## 2. Environment (2026-09-20)

- OS: Windows 11, Python 3.12.7 at `C:\Users\mohsi\AppData\Local\Programs\Python\Python312`
- numpy 2.5.3, customtkinter 6.0.0 (+ darkdetect), openpyxl 3.1.5, PyYAML 6.0.3,
  cryptography 50.0.1, pydantic 2.13.5, pytest 8.4.2, PyInstaller 6.22.3
- Work dir: `D:\AI Masterclass\Project\18-09-2026\39. Agent check-in jitter and sleep implementation study`
- Data dir: `%LOCALAPPDATA%\AgentJitterStudy`, override `AGENTSTUDY_DATA_DIR`

## 3. Architecture

- `src/` package, CLI+GUI entry points:
  - `src/config.py` — pydantic `Scenario` with bounds (`ge/le`) on every field
  - `src/engine/rng.py` — per-arm/per-replica seeded derivations
  - `src/engine/jitter.py` — uniform / gaussian / poisson jitter distributions
  - `src/engine/sleep.py` — none / random / exponential / fixed sleep scheduling
  - `src/engine/simulator.py` — `run_exact` (DES) and `run_fast` (vectorized)
  - `src/app/metrics.py` — herd, uniformity, latency p50/p99/p99.9, duty, power, drops
  - `src/app/stats.py` — scipy-free stats (Mann-Whitney U normal approx, Welch t,
    Hedges' g, bootstrap CI, Bonferroni)
  - `src/app/orchestrator.py` — run_study / run_arm / compare_arms / study_verdict
  - `src/security/{sanitize,audit,vault}.py` — the security layer
  - `src/reporting/` — report_data model + xlsx (openpyxl, 5 sheets), csv_writer,
    html_writer (CSP + svg chart), json, seeds, `bundle.write_full_bundle`
  - `src/presentation/gui.py` — customtkinter, 3 tabs (Design & Run, Results, Export),
    threaded run + progress + cancel
  - `src/main.py` — uniform CLI/GUI router; root `main.py` convenience shim
- Scenario YAML files in `scenarios/`; PyInstaller recipe `specs/build.spec` +
  `specs/versioninfo.txt`; `build.ps1` / `build.bat` do install→test→build.

## 4. Engine semantics (critical)

- **DES arrival-driven**: next wake = last + interval ± jitter; a sleep scheduler
  then sets a subsequent nap before the *next* wake, so sleep modifies the gap.
- **Phase = jitter-only**. At `jitter_pct=0` every agent fires in bucket 0
  (all 1000 in one column) — this is the *intended* thundering-herd baseline.
  Random initial phase was deliberately REMOVED so baseline is perfectly synchronized.
- Jitter bound `J = interval * jitter_pct / 100`; gaussian `sigma = J/4`
  (keeps ~p99.9 within bound); poisson is truncated to `[0,2J]` then re-centered
  to `[-J,+J]`.
- **numpy 2.5**: `Generator(SeedSequence(...))` raises; must use
  `np.random.Generator(np.random.PCG64(seed_seq))`. Replicas derived by
  `seed + replica_idx` after a fixed scenario seed.
- **arr_t clamp**: exact engine computes `arr_t = max(t, 0.0)` because a negative
  jitter offset at t=0 produces a *negative* wake time; without clamping those
  arrivals would inflate latencies (`done - arr_t`), pin duty at 1.0 and p99 near
  13 s. The clamp is applied on the bucket index, serving, pending, pump and
  drop-backoff paths. Present result: duty 10.5%, p99.9 134 ms.
- `run_fast` filters negative dispatch times; it is a large-fleet approximation
  (duty/attempts differ slightly from DES) — documented, not a bug.
- `duty_cycle = active_total / run_len` (fraction of wall time agents are awake);
- `herd_coef = max(bucket_counts) / mean(bucket_counts)`; 1.0 = perfectly flat.

## 5. Statistics (scipy-free)

- Mann-Whitney U: normal approximation via rank sum + tie correction.
- Welch t-test: Cochran–Cox approximation; degenerate zero-variance returns `inf`.
- Hedges' g with small-n correction; `>=0.2` = small, `>=0.5` medium, `>=0.8` large.
- Latency comparison pools **per-arrival latencies across replicas** (thousands of
  samples) for a real test; all other metrics compare per-replica KPI scalars.
- Bonferroni correction applied across metrics.
- **Verdict logic** (v2): a metric is "candidate wins" when the candidate direction
  is better AND (p<0.05 with |g|>=0.2 **OR** relative delta >=25%). This prevents
  "0 wins / CAUTION" noise at low replica counts and still flags BIG practical wins.

## 6. Bugs fixed (dated log)

- [2026-09-20] `\U0000B1` literal SyntaxError in xlsx_writer (needed `\u00b1`).
- `np.bincount` with negative indices → clamp indices to `[0, nb-1]`.
- `welch_t` ZeroDivisionError on degenerate arrays → return `(t=inf, p=0.0)`.
- Gaussian tail unbounded → `sigma = bound/4`; poisson unbounded → truncate+re-center.
- Fast engine negative times → filtered out.
- `Generator(SeedSequence)` TypeError (numpy 2.5) → `Generator(PCG64(seed_seq))`.
- `args.scenario` → `args.cli` mismatch in `src/main.py` argparse wiring.
- [2026-09-20] Negative `arr_t` inflating latencies / forcing duty=1.0 → clamp
  `arr_t = max(t, 0.0)` (see §4). Result verified: latency p99.9 candidate 134 ms,
  duty 10.5%, herd 52.4 vs 100.
- [2026-09-20] Comparison stat power too weak at default `replicas=2` → default
  replicas bumped to **5**, latency test pools arrivals, verdict adds the
  practical-delta rule (§5), comparison table adds `Δ(%)` column.
- [2026-09-20] PyInstaller spec script path resolves relative to the spec FILE,
  not CWD → switched to `SPEC` global + absolute paths. Also removed `__file__`
  (undefined under PyInstaller's exec). Rebuild clean.

## 7. Build & test cheatsheet

```powershell
$env:AGENTSTUDY_DATA_DIR = "$env:TEMP\ajs"     # isolated sandbox
python -m pytest -q                            # 21 tests
python -m src.main --cli scenarios/default.yml --print-summary
python -m PyInstaller specs\build.spec --noconfirm --clean   # onefile exe
.\build.ps1                                     # install → test gate → build
.\dist\AgentJitterStudy.exe                     # GUI smoke (window appears)
```

PyInstaller: windowed (`console=False`) — CLI mode may not echo to the waiting
terminal capture the same way; artifacts still written to the data dir.
`excludes=["pytest","matplotlib","scipy","numpy.f2py"]`, customtkinter data
collected via hook; exe ≈ 42 MB.

## 8. Gotchas to remember

- Reports: HTML CSP `script-src 'none'` = no interactivity, so charts are inline
  SVG; never inject user data into HTML without `escape_html`.
- CSV guard prefixes `-` numbers (e.g. `'-8.95`) — intentional, parse-clean.
- The GUI progress % and `--print-summary` emit to stdout only from a terminal;
  Do NOT capture-and-parse stdout as the authoritative result — read the exports.
- `python -m pytest -q` is the test gate in `build.ps1`; keep it green.
- Resuming/replaying a study uses the *same* scenario seed → outputs are
  byte-identical across runs (verified: exe == source CLI).
- GUI tab-enable stub (`_set_tab_enabled`) is inert by design; expand if an
  atomic-run lock is ever needed.

## 9. Next research (optional)

- Sweep `jitter_pct` (0→100) and `sleep_mode` to quantify the Pareto frontier
  of herd vs duty vs latency; use `fleet_stress.yml` for large fleets.
- Investigate startup transient: the t=0 burst dominates the herd metric even at
  25% jitter (600 s run); a "steady-state only" window would isolate it.
- Compare "exponential sleep" vs "random sleep" for wake-phase decorrelation.