# Memory.md — Runtime Memory Profile & Design Memory

Reserved design record covering two meanings of "memory":

1. **Runtime memory** — how much RAM the GUI bundle uses and how generation is
   isolated on a worker thread.
2. **Design memory** — the durable record of decisions, build facts, and
   pointers so the project can be resurrected quickly (a long-term memory for
   future maintainers).

---

## 1. Runtime memory

### Budget

The tool is deliberately memory-light: no `pandas`/`numpy` (excluded from the
bundle), pure-Python scoring, streaming CSV writer, and a single engagement
document held in RAM.

| Component | Approx. resident set |
|---|---|
| Tkinter shell + Treeview of N findings | tens of KB + scale with N |
| One `Engagement` object (typical 10–50 findings) | < 1–2 MB |
| CVSS scoring (per finding, pure float math) | negligible |
| XLSX build (openpyxl, 6 sheets) | spikes ~1–3 MB per write |
| HTML dashboard string | ~200–800 KB |
| **Whole bundle peak (onefile exe)** | typically **40–90 MB** (PyInstaller extracts to temp) |

### Threading / isolation

- Report generation runs on a **daemon worker thread**
  (`threading.Thread(..., daemon=True)` inside `gui._generate`).
- UI updates are marshalled to the main thread with `self.after(0, ...)`, so
  the Treeview/log are never mutated off the Tk thread.
- Generation is CPU- and IO-bounded on findings size; no unbounded growth —
  `SEVERITY_KEYS` and result dicts are recreated per run.

### Leak hygiene

- Findings rows are cleared (`tree.delete`) before re-populating.
- The log Text widget appends only; reset on `mainloop` exit (process exit
  reclaims the rest).

---

## 2. Design memory (decisions log)

### Decision log (most recent first)

| Date | Decision | Why |
|---|---|---|
| 2026-09-20 | Add Tkinter GUI + PyInstaller onefile `.exe` | Deliver the pipeline to analysts without a Python runtime; stdlib-only UI keeps the exe small and offline-capable |
| 2026-09-20 | Persist only `input_file` + `output_dir` paths | Recall navigation, never content; zero secret surface (see `state.md`) |
| 2026-09-20 | Keep all framework catalogs embedded in code | No network fetch, no data files to ship next to the exe |
| 2026-09-20 | `architecture.html` replaced by `architecture.md` | Markdown is diffable/reviewable in git and renders on any device |

### Build facts (memory for rebuilds)

- Toolchain: Python **3.12.7** · PyInstaller **6.22.3** · openpyxl **3.1.5**.
- Build: `.\build_exe.ps1` → PyInstaller → `dist\RedTeamReport.exe`
  (single file, windowed, portable, no install).
- Dev run: `python -m redteam_report.gui`; console script:
  `red-team-report-gui`.
- Test: `python -m pytest -q` (testpaths = `tests`).
- Package layout: `src/redteam_report/{cli,gui,pipeline,state_store,models,
  frameworks,analyzers,reporters}`.

### How the app is "remembered" across sessions

Inputs/outputs are recalled via `state_store` (last paths). The *design* is
remembered via the docs: `architecture.md` is the living blueprint,
`security.md` the hardening record, `state.md` the persistence contract, and
this file the runtime + decision memory.

### Reserved future memories

- Larger-input scaling: switch XLSX writer to write-only mode if findings
  exceed ~5,000 rows.
- Optional: remember window geometry + format preferences via
  `state_store` key allow-list (speculative keys listed in `state.md`).
- Optional: bundle checksum manifest in `build_exe.ps1` output.