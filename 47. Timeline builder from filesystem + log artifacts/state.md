# STATE - TimelineBuilder

Living snapshot of the project. Update this file whenever the build or its
verification results change.

- **Product:** TimelineBuilder
- **Version:** 1.0.0
- **Status:** COMPLETE / VERIFIED
- **Last updated:** 2026-09-21
- **Project path:** `D:\AI Masterclass\Project\18-09-2026\47. Timeline builder from filesystem + log artifacts`

---

## 1. Build Artifact

| Item | Value |
|---|---|
| Portable binary | `dist\TimelineBuilder.exe` |
| Size | 47,840,680 bytes (~45.6 MB) |
| SHA-256 | `030C169BD388F0675DCEC9D5EC9F9CCA8E843F26B6EBBB63EFA307BE9AEE0B3D` |
| Manifest | `dist\SHA256SUMS.txt` |
| Mode | PyInstaller `--onefile --windowed` |
| Packaging script | `build.ps1` |

> Rebuild command: `powershell -NoProfile -ExecutionPolicy Bypass -File .\build.ps1`
> The SHA-256 changes on every rebuild (non-deterministic bootloader/timestamps).

---

## 2. Toolchain (build environment)

| Component | Version |
|---|---|
| OS | Windows 11 (10.0.26200) |
| Python | 3.12.7 |
| PySide6 | 6.11.2 |
| cryptography | 50.0.1 |
| PyInstaller | 6.22.3 |

Optional: `requirements-optional.txt` (`python-evtx`) is **not** installed; native
EVTX parsing stays inactive and reports a clear, non-fatal error per file.

---

## 3. Verification Log

| Check | Command | Result |
|---|---|---|
| Unit tests | `python -m unittest discover -s tests` | 23 passed |
| Frozen CLI - demo | `TimelineBuilder.exe cli demo --dir exe_demo` | exit 0, files created |
| Frozen CLI - scan | `TimelineBuilder.exe cli scan ... --out exe_demo\case.tbcase --html ...` | exit 0, case + report created |
| Frozen CLI - verify | `TimelineBuilder.exe cli verify exe_demo\case.audit.jsonl` | exit 0 (chain intact) |
| GUI launch | `TimelineBuilder.exe` | process alive after 14s, no crash |
| Audit chain | in-app + CLI | `chain intact (10 records)` |

Historical note: the first frozen build ignored the `cli` subcommand because
`run_app.py` called the GUI entry directly. Fixed by routing through
`timeline_builder.__main__.main`, which dispatches `cli` vs GUI. Rebuilt and re-verified.

---

## 4. What Exists Today

- GUI (`ui/main_window.py`): toolbar, faceted filters, sortable table, detail
  inspector, live summary, audit-chain status, background scan worker.
- Collectors: filesystem MACB (`collectors/filesystem.py`), multi-format logs
  (`collectors/logs.py`: text, JSON, JSONL/NDJSON, CSV/TSV, EVTX-when-available).
- Analytics: `normalizer.py` (UTC, dedupe, sort, summary), `correlation.py` (bursts).
- Storage: `storage/case_store.py` (SQLite WAL, indexed, thread-safe).
- Exports: `export/` CSV, JSON, colorful standalone HTML report.
- Security: `security/` hashing, hash-chained audit, validation, integrity
  manifests, AES+PBKDF2 crypto. See `SECURITY.md`.
- CLI: `cli.py` (`scan`, `verify`, `demo`).
- Docs: `ARCHITECTURE.html`, `SECURITY.md`, `README.md`, `state.md`, `memory.md`.
- Tests: `tests/` (security, collectors, pipeline).

---

## 5. Known Issues / Limitations

1. **EVTX inactive** - `python-evtx` not installed; install the optional
   requirements to enable `.evtx` parsing.
2. **Directory scanning is kind-specific** - the CLI `--kind auto` treats a
   directory as filesystem and a file as log. To parse a *folder of logs* pass
   `--kind log` explicitly.
3. **Windows "changed" (C) time** - not exposed by `os.stat` on Windows, so the
   Change event is emitted only on POSIX (`st_ctime` meaning differs by platform).
4. **Large timelines** - GUI loads up to 100k rows per query for responsiveness;
   full data remains queryable/exportable via the store and CLI.
5. **No code signing** - `build.ps1` has no `signtool` step yet (see roadmap).

---

## 6. Roadmap / Next Steps

- [ ] Add `signtool` code-signing step to `build.ps1`.
- [ ] Artifact parsers: MFT, `$UsnJrnl`, registry hives, Prefetch, SRUM.
- [ ] Plugin SDK so collectors load from a `plugins/` folder.
- [ ] Search-syntax (fielded queries) and a histogram/viewer panel in the GUI.
- [ ] Encrypted case store wired into the GUI (crypto module is ready).
- [ ] Deterministic/reproducible builds (pinned PyInstaller + bootloader hash).
- [ ] Optional `python-evtx` bundled into the frozen exe.

---

## 7. How to Resume

1. `pip install -r requirements.txt`
2. `python -m unittest discover -s tests`  (expect 23 passed)
3. `powershell -NoProfile -ExecutionPolicy Bypass -File .\build.ps1`
4. Confirm `dist\TimelineBuilder.exe` exists and update section 1 + 3 above.
