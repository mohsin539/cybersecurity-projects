# Memory.md - Persistent Context for Future Sessions

Purpose: give a future agent/engineer instant orientation. Read this + state.md
before changing anything.

## 1. What this project is
A defensive-oriented SQL injection detection + vulnerable-parameter identification
tool, delivered as a **portable single-file Windows GUI exe** (Python + tkinter +
PyInstaller). Architecture is compliance-aligned (ISO 27001, NIST SP 800-53/CSF,
OWASP Top 10, PCI DSS 4.0) - see ARCHITECTURE.md.

## 2. Non-negotiable design decisions (ADRs)
- **ADR-1 Raw payloads are never persisted.** Digest-only (SHA-256). Exports are
  user-initiated. Do not "improve" this to persist values.
- **ADR-2 Detection is layered and fused.** Layer outputs feed `fuse()`; no single
  detector is the decision-maker. Preserve fusion when adding detectors.
- **ADR-3 CLI selftest is the release gate.** `build.ps1` runs `python -m src
  --selftest`; build aborts if it fails. Keep fixtures meaningful.
- **ADR-4 No network on passive analysis.** Detection tab never sends traffic;
  only the scanner (approval-gated) does HTTP calls via `requests`.
- **ADR-5 Layer 2 (grammar) must not fire on plain keyword text.** It requires
  structural context (operators/strings/comment), checked in fixtures (`q=select`
  must stay CLEAN). Do not weaken.
- **ADR-6 The exe is windowed (no console).** CLI mode still works in cmd/PowerShell
  via `SQLiDetectShield.exe --selftest` because entry honors argv before launching
  tkinter (guard in `src/__main__.py`).
- **ADR-7 Compatibility target is the installed Python 3.12 + requests only.** No
  other runtime deps; keep imports stdlib-first so PyInstaller stays clean.

## 3. Commands (run from project root)
```powershell
python -m src --selftest            # engine verification (5 fixtures)
python -m src                       # launch GUI from source
powershell -ExecutionPolicy Bypass -File build.ps1   # rebuild dist exe
.\\dist\\SQLiDetectShield.exe --selftest            # smoke test frozen exe
```

## 4. Code map (quick orientation)
- Parse/decode/digest -> `normalize.py`
- Rule corpus (Layer1) -> `rules.py` (add rules here, keep metadata fields)
- SQL grammar (Layer2) -> `tokenizer.py` (`detect_structure`)
- Heuristics (Layer3) + fusion -> `layers.py` (`fuse`: score = min(1, sum/1.5) + modifiers)
- Orchestration -> `engine.py` (`analyze_target`, `inline_analyze`, `findings_to_rows`)
- Active scanner -> `scanner.py` (`Scanner`, `PROBES`, `_DB_ERROR_MARKERS`)
- Compliance data -> `compliance.py` (ISO/NIST/OWASP/PCI lists + exporters)
- UI -> `gui.py` (`App` with 5 tabs: Detection, Scanner, Findings, Compliance, About)
- Fixtures/assertions -> `cli.py` (`RANK = {clean:0,monitor:1,flag:2,block:3}`)

## 5. Conventions
- PEP8, `from __future__ import annotations` at top, no comments unless needed
  (per repo rules), type hints on signatures.
- Rule entries: id `R-####`, weight 0..1, CWE/OWASP/FP-risk metadata mandatory.
- Guidelines: respond concisely; never commit unless explicitly asked; do not
  create docs proactively.

## 6. Gotchas / recurring pitfalls
- **PyInstaller truncation of large payloads**: keep writes/edits small in tools;
  big content gets cut (saw twice while generating docs).
- **PowerShell 5.1**: `&&` unsupported; backtick continuations break with trailing
  spaces - use single-line commands or `$LASTEXITCODE`.
- Builder used `--hidden-import requests requests.sessions`; if requests API
  changes, re-verify scan mode from frozen exe.
- Treeview tag config is applied by `App._tag_rows`; new severity tags must be
  registered there.
- Scanner `_probe` keys: GET injects into query params; POST injects into body dict.

## 7. Terminology
- verdict tiers: CLEAN/MONITOR/FLAG/BLOCK (BLOCK = best-inline default; exe is
  monitoring-only by nature).
- severity: INFO/LOW/MEDIUM/HIGH/CRITICAL.
- injection types: error/boolean/union/time/stacked/oob/generic.
- "vulnerable params" = confirmed by active scanner (type evidence from probes).

## 8. Compliance stance in one line each
- OWASP A03: the product; A01/A02/A05/A06/A08/A09/A10 supported (see compliance.py).
- ISO 27001 Annex A mapping: Section 9.1 of ARCHITECTURE.md; evidence = this repo.
- NIST CSF control mapping: Section 9.2; SDLC gates = selftest + build script.
- PCI 6.6: usable as a detection control; QSA scope approval needed for formal use.