# Project Memory — RansomLens (project 61)

Purpose of this file: durable memory so any future session (human or AI) can resume work with full context, conventions, and decisions. Keep it updated when designs change.

---

## 1. Project identity

- **Folder:** `...\61. Ransomware behavior analysis report (encryption pattern study, sample from public repo)`
- **Goal:** study ransomware **encryption behaviour** (pattern, scope, overwrite strategy, key handling) from **public-repo samples**, and produce behavior-analysis reports.
- **Delivery so far:** `architecture.md` (full reference architecture, ISO/NIST/OWASP) + a **portable non-executing GUI exe** (`dist\RansomLens.exe`) implementing the safe slices, plus `security.md`, `state.md`, and this `memory.md`.

## 2. Key decisions (why things are the way they are)

| # | Decision | Rationale |
|---|----------|-----------|
| D1 | **Non-executing workbench** — samples are read/parsed as inert bytes; there is *no* detonation, subprocess, or code eval. | Containing live malware inside a single portable exe is not safely possible; Zone-0 detonation stays with the architecture's hypervisor farm. `security.md` §9 records this as a signed deviation. |
| D2 | **Stdlib-only runtime** (tkinter, sqlite3, hashlib, struct, collections, json, threading). | Minimises supply-chain + attack surface for a binary that ingests untrusted files; PyInstaller is the only build-time dep. |
| D3 | **Hash-chained JSONL audit ledger** instead of a heavyweight audit DB. | Tamper-evident, portable, trivially verified; matches ISO A.8.15 intent at desktop scale. |
| D4 | **Evidence-pair mode** (original + `.enc` twin) boosts confidence and infers overwrite strategy. | Mirrors architecture.md §7.3 "honeypot differential" in a safe, offline way. |
| D5 | Pattern classes are **heuristic and clearly labelled** ("suspected", "statistically consistent") — never claimed as algorithm-hard proof. | Scientific honesty + analysis fraud prevention; a hard requirement for a research tool. |
| D6 | Reports embed **environment fingerprint + schema version** (`sba.pattern.v1`). | Reproducibility and downstream verification (architecture §6.6, §7.5). |
| D7 | Workspace defaults to `%LOCALAPPDATA%\RansomLens_Workspace`; config has **no secrets**. | Zero-trust posture: user-scope, no admin rights, nothing outside the user profile. |

## 3. Bugs found & fixed (lessons — do not reintroduce)

1. **Ledger `_tail()` newline bug** — the old implementation read the *last buffered line*, which was empty because JSONL ends with `\n`, so every entry got `seq=1` + `prev_hash=GENESIS` and the chain broke on verify. **Fix:** scan the file line-by-line and keep the last non-empty line. Lesson: always reason about trailing-newline semantics in append-only files for chained-hash design.
2. **Treeview iid assumption** — `on_analyze`/`on_scout` parsed `iid.startswith("row")` but `Treeview.insert()` without an explicit `iid` auto-generates `I001…`, so jobs silently emptied and the GUI showed "Add files to the queue first." **Fix:** always pass `iid=f"row{n}"`. Lesson: never couple parsing to Tk auto-generated ids.
3. **`save_report()` returns 3 values** (md path, json path, md text) — call sites must unpack 3.
4. **Tk pack() has no `height=`** — Text height must be set at construction (`height=14`), not in `.pack()`.
5. Multi-thread GUI refresh is done via a `queue.Queue` + `after(200, poll)` — never call `insert`/`destroy` from the worker thread directly.

## 4. Conventions

- Python 3.12, `from __future__ import annotations`, type hints on all public functions, stdlib only in `workbench/core`.
- `core/` layers are **GUI-free** (headless-testable); UI lives in `app.py`. Keep it that way.
- Every pipeline mutation writes an audit event (`ledger.append(ACTOR, "action", "detail", now_iso())`).
- Fingerprint schema constant lives in `models.RESULT_SCHEMA_VERSION`; bump on breaking changes.
- Reports: Markdown (human) + JSON (machine) always written side-by-side under `reports/` as `RPT_<sha12>_<ts>.*`.
- Docs live at repo root: `architecture.md`, `security.md`, `state.md`, `memory.md`. Update `state.md` verification evidence when tests change.

## 5. Commands that just work

```
python src\run.py                      # run from source
dist\RansomLens.exe                    # run the portable binary
python tools\make_fixtures.py          # regenerate ./fixtures (synthetic, non-malicious)
python -m py_compile src\run.py src\workbench\app.py ...   # compile check
.\build.ps1                            # rebuild dist\RansomLens.exe
```

## 6. Test assets & expectations (fixtures)

| Fixture | Expected class |
|---------|----------------|
| `plain.txt` | no-encryption-signature |
| `rand_encrypted.pdf` | high-entropy-payload |
| `invoice.txt.lock` | full-file-encryption, risk=True |
| `ransom_note.txt` | no-encryption-signature (plaintext heuristic) |
| `decoy_original.docx` (evidence) + `.enc` | full-file-encryption, confidence boosted, strategy "rewrite / encryption of original content" |

Note the `.pdf` wrapper depresses block-ratio below the full-file threshold — expected; do not "fix" by raising sensitivity without docs.

## 7. Roadmap items that came up (see also state.md §7)

- YARA drop-in; evidence auto-pair detection; folder corpus statistics; tests/ runner; Authenticode signing; alignment with a potential server-side Zone-0 farm per architecture §19.

## 8. Contact / audit trail

- Owner: AI Masterclass project 61. All fidelity-affecting changes should bump `__version__` in `workbench/__init__.py` and record the change here with the date.