# STATE.md — Project State Snapshot

**Snapshot date:** 2026-09-19 · **Version:** 1.0.0 · **Phase:** M0+M1 complete, M2 complete (ARCHITECTURE.md §13)

## 1. What exists and works (verified)

| Layer | Components | Status |
|---|---|---|
| Platform | `config.py` (validated, portable-mode), `store.py` (SQLite WAL, content-addressed blobs), `audit.py` (hash-chained, verified on boot), `crypto.py` (AES-256-GCM + scrypt), `trust.py` (Ed25519) | ✅ tested |
| Core | `encodings.py` (12 pure ops), `flagfinder.py` (5 flag rules + strings), `analyzer.py` (entropy, PE/ELF-lite, packer hints), `carver.py` (zip/png/jpeg, traversal-safe) | ✅ tested |
| Sandbox | `policy.py` (deny-by-default invariants), `child.py` (network/write/exec guards, task protocol), `runner.py` (Job Object caps, watchdog, fail-closed) | ✅ tested e2e |
| Application | `jobs.py` (analysis + recipes + step validation), `plugins.py` (signed allow-list), `recipecatalog.py` (8 one-click recipes) | ✅ tested |
| Presentation | `app.py` (MainWindow: dashboard, hex, strings, findings, entropy canvas, recipe builder, plugins, console), `theme.py` (dark QSS) | ✅ smoke-tested (offscreen) |
| Packaging | `rekt.spec` + `scripts/build_exe.py` → `dist/rekt-portable/` | ✅ built + verified |

## 2. Verification performed (2026-09-19)

- `pytest tests/ -q` → **50 passed** (platform, core, sandbox e2e, M2 disasm/ghidra, plugin trust flow, relative-path regression).
- Offscreen GUI smoke: sample added → analysis job → flag `flag{gui_smoke_ok}` surfaced in Findings ✓
- **Frozen-exe sandbox test**: `dist/rekt-portable/rekt.exe --rekt-sandbox-child <cfg>` analyzed a payload file and returned `flag{frozen_child_works}` ✓ (proves the file-based child protocol works without stdio).
- GUI launch: `rekt.exe --data-dir <tmp>` stayed alive 8 s, created `audit.log` + `project.db` ✓
- Portability: copied `dist/rekt-portable` to a "USB stick" temp dir → relaunched ✓

## 2b. M2 additions (2026-09-19, second session)

| Item | Status |
|---|---|
| **Disassembly pane** — Capstone 5.0.7, `rekt/core/disasm.py`, linear + recursive-descent (bounded: 20k insns), runs INSIDE the sandboxed child; GUI table with "Send selected bytes → Recipes" | ✅ tested (incl. frozen exe) |
| **Ghidra headless bridge** — `rekt/application/ghidra.py` + `backends/ghidra_scripts/ExportDecomp.java`; consent-gated (`JobKind.GHIDRA`), scratch-COPY only, hard timeout, argv-only spawn; GUI Decompiler tab with install-root picker | ✅ built; needs a local Ghidra install + Java 24 (present) to exercise end-to-end |
| **Trust store** — Ed25519 keypair generated (`trust.pub` shipped, `trust.key` git-ignored); first-party plugin **signed**; loads without Developer Mode | ✅ verified in source + frozen |
| **Demo sample** — `scripts/make_demo_sample.py` → crafted PE64 crackme (`REKT-LOCAL/demo_crackme.exe`) with decoy flag + XOR-7/base64 real flag; full solve path verified headless and in-GUI | ✅ |
| **Frozen-exe sandbox** — disasm task verified through `rekt.exe --rekt-sandbox-child` (22 rows); signed plugin discovery in `_internal/plugins` | ✅ |
| **Regression fix** — `run_job` now resolves scratch paths ABSOLUTE; a relative data dir used to make the child silently fall back to empty stdin (see MEMORY.md §3) | ✅ regression test added |

## 3. Not yet implemented (planned, by milestone)

- **M2 leftovers:** YARA rule engine; UPX unpacker integration (external binary); `.rekt` project export/signing.
- **M3:** Authenticode signing (EV cert), SBOM generation in CI, reproducible-build attestation, fuzz soak (`atheris`) over `analyzer.py`/`carver.py`.
- **v2.x:** VM-backed runner behind the same `Policy` interface; mobile RE; LLM hint engine (local model, opt-in).

## 4. Known gaps / tech debt (tracked honestly)

| Gap | Impact | Ticket-worthy |
|---|---|---|
| Plugin ops execute in-process (GUI crash risk from buggy plugins) | Medium | PLUG-1: move plugin ops to job subprocess |
| `rules/flags.txt` shipped but loader still uses built-in patterns | Low | CORE-2: load rules file at boot; verify signature |
| Watchdog class exists but isn't wired into the GUI job path | Low | APP-3: arm/disarm around AnalysisWorker |
| `_EntropyCanvas` repaints on resize without back-buffer | Low | UI-4 |
| No CI workflow yet (lint/SAST/SCA gates defined in pyproject only) | Medium | OPS-5: add `.github/workflows/ci.yml` |
| Carver caps (`MAX_CARVE_TOTAL`) not surfaced in UI | Low | UI-6 |

## 5. Environment facts (this machine)

- Windows, Python **3.12.7**, PySide6 + pyinstaller + cryptography + pytest installed via pip.
- `resource` module absent (POSIX-only) — child guard handles this; Windows caps come from Job Objects.
- Qt offscreen platform works: `QT_QPA_PLATFORM=offscreen` for headless test runs.
- Frozen child protocol requires the file-based path (`payload`/`reply` in scratch); stdio is unavailable in windowed builds.
- `REKT_GHIDRA_HOME` (or the GUI picker) points at a Ghidra install root containing `support/analyzeHeadless(.bat)`; Java 24 confirmed on this machine.
- `trust.key` = Ed25519 signing key (NEVER commit; in .gitignore). `trust.pub` is copied into `dist/rekt-portable/_internal/trust.pub` by `scripts/build_exe.py`.
- `REKT_TRUST_ED25519` env var (base64 raw pub key) is the alternate pinning channel for frozen builds.
- Build artifacts: `build/` and `dist/` are git-ignored; rebuild with `python scripts/build_exe.py`.

## 6. How to run

```bash
# source mode
python -m rekt                          # GUI (uses %LOCALAPPDATA%\rekt-data)
REKT_PORTABLE=E:\rekt-data python -m rekt
python -m rekt --data-dir D:\ctf\proj   # explicit portable dir

# tests
python -m pytest tests/ -q

# portable exe
python scripts/build_exe.py             # → dist/rekt-portable/rekt.exe
```
