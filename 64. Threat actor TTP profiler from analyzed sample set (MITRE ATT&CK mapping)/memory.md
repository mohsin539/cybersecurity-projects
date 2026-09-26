<div align="center">

# 🧠 MEMORY.md

### *Project Context & Long-Term Working Memory*

**Project:** Threat Actor TTP Profiler — portable GUI `.exe`, colorful MITRE ATT&CK mapping
**Owner:** Analysts + Detection Engineers
**Convention:** keep this file updated whenever architecture/behavior changes materially.

</div>

---

## 1. Project Identity

- **What it does:** Ingest analyzed sample set → extract indicators → map to MITRE ATT&CK TTPs → score confidence → attribute likely threat actor → export shareable intel.
- **Delivery:** single-file portable `.exe` (Windows 10/11 x64), offline-first, no install/admin.
- **GUI:** "Neon Sentinel" dark-cyber theme (palette in `app/theme.py`).
- **Security:** ISO 27001 · NIST CSF 2.0 · OWASP Top 10 — full mappings in `architecture.md` & `security.md`.

## 2. Key Architectural Decisions (why we did what we did)

| # | Decision | Reason |
|---|---|---|
| 1 | **PySide6 (Qt6)** GUI | Rich widgets, high-DPI, QPainter-friendly for custom charts, single-exe viable |
| 2 | **SQLite WAL + DPAPI field encryption** | Portable, zero native deps; OS-scoped key custody (no hard-coded secrets) |
| 3 | **Pure NumPy attribution** (no sklearn) | sklearn ~200 MB; NumPy keeps bundle under budget & build reproducible |
| 4 | **Curated ATT&CK dataset** in `app/data.py` | Offline-first; plan to auto-import official STIX bundle later |
| 5 | **Default-deny parsers** | Malicious samples = hostile input; sanitize/hash/quarantine (OWASP A03/A04) |
| 6 | **Rule-signature mapping** (substrings + behavior tags) | Deterministic, auditable, explainable — no black-box ML in the TTP judgment |
| 7 | **Hash-chained audit** | Tamper-evident chain gives ISO A.16 / NIST AU-3 evidence |

## 3. Module Map

| Module | Responsibility |
|---|---|
| `app/data.py` | Bundled MITRE ATT&CK tactics/techniques/groups/software + rule index |
| `app/models.py` | DTOs: Sample, EvidenceRecord, TechniqueMapping, ActorMatch, ActorProfile |
| `app/security.py` | Sanitization, hashing, SQL-safe encoding, audit chain |
| `app/store.py` | SQLite store + DPAPI vault + WAL + audit tables |
| `app/services.py` | Import pipeline, ATT&CK mapper, scorer, attributor (ProfilerEngine) |
| `app/reports.py` | HTML, ATT&CK Navigator, STIX 2.1, JSON, manifest with hashes |
| `app/theme.py` | Neon Sentinel QSS + palette tokens |
| `app/ui/widgets.py` | Custom paint: heatmap matrix, radar, kill-chain timeline |
| `app/windows.py` | MainWindow + 7 pages (Dashboard/Import/Samples/Profile/Reports/Audit/Security) |
| `main.py` | CLI + GUI entry; `--verify`, `--import`, `--profile`, `--export` |
| `build_exe.ps1` | Nuitka/PyInstaller portable .exe build + SHA-256 + optional signing |

## 4. Domain Glossary

- **TTP** — Tactics (why), Techniques (how), Procedures (specific steps). MITRE ATT&CK encodes T→P.
- **EvidenceStrength** — multiplier from number/confidence of matching rule hits.
- **SampleCoverage** — fraction of samples that evidence a technique (anti-single-flag).
- **WeightedScore** — `base_weight × evidence_strength × (0.5 + sample_coverage)`, capped 1.0.
- **Jaccard + recall blend** — actor similarity: `0.6·overlap/union + 0.4·overlap/group_len`.
- **Intel Grade** — A(≥80) · B(≥60) · C(≥40) · D(<40).

## 5. Demo/Fixture Conventions

- `samples_demo/` — 3 JSON reports: PowerDuke→APT29 theme, Sednit→APT28 theme, Agent Tesla commodity.
- Expected demo outcome: 22 mapped techniques, top actor APT1-family (broad overlap), confidence → Grade A.
- Running everything:
  ```powershell
  python -X utf8 tests/smoke_test.py      # logic pipeline
  python -X utf8 tests/gui_smoke_test.py  # renders all pages + screenshots
  python main.py --import samples_demo --name "Demo" --profile --export reports
  python main.py --verify
  ```

## 6. Lessons Learned

1. **PySide6 signals are `Signal` not `pyqtSignal`** — third-party snippets are PyQt-flavored.
2. **ctypes + 64-bit WinAPI needs explicit `argtypes`** (`LocalFree`, `CryptProtectData`) — else pointer-overflow `ArgumentError`.
3. **Nuitka UPX + PySide6** plugin required (`--enable-plugin=pyside6`) — plain onefile can miss plugins.
4. **Windows console cp1252** — emoji prints crash non-UTF8 consoles; tests use `-X utf8` or ASCII.

## 7. Conventions To Follow (do not regress)

- `scorer`: score never exceeds 1.0; evidence_strength caps at `max_signal=1.6`.
- All SQL via parameterization or whitelisted `_T` table names — never string-interpolate identifiers.
- Every report artifact shipped with `MANIFEST.sha256.json`.
- New parsers must run through `normalize_schema` + `sanitize_text` before any store write.
- Keep nested dirs: `app/ui/`, `tests/`, `docsassets/`; docs at repo root (`architecture.md`, `security.md`, `state.md`, `memory.md`).