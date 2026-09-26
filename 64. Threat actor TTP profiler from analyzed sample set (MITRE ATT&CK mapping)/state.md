<div align="center">

# 🗺️ STATE.md

### *Current Development & Runtime State Register*

| 📌 Milestone | 🟢 Status | 🎯 Target |
|---|---|---|
| M0 Skeleton + Theme | ✅ **Done** | v1.0.0 |
| M1 ATT&CK Index + Mapper | ✅ **Done** | v1.0.0 |
| M2 Scorer + Attribution | ✅ **Done** | v1.0.0 |
| M3 Reports (HTML/NAV/STIX/JSON) | ✅ **Done** | v1.0.0 |
| M4 Hardening (`--verify`, signing, audit) | ✅ **Done** | v1.0.0 |
| M5 Portable Signed Build | ✅ **Built** (not yet code-signed) | v1.0.0 |

</div>

---

## 1. Release State (v1.0.0)

| Artifact | State | Notes |
|---|---|---|
| `app/` source | ✅ complete | Python 3.12 + PySide6 |
| Nuclear-core logic | ✅ green | `tests/smoke_test.py` 5/5 |
| GUI pages | ✅ green | `tests/gui_smoke_test.py` renders 6/6 pages |
| Screenshots | ✅ captured | `docsassets/*.png` |
| `.exe` build | ✅ **`dist/TTPProfiler.exe`** (21.7 MB) | Nuitka 4.2.2 · onefile · zstd · MinGW64 |
| `.exe` self-audit | ✅ exit 0 | `TTPProfiler.exe --verify` |
| `.exe` CLI pipeline | ✅ exit 0 | 5 artifacts exported to `dist/reports` |
| `.exe` GUI launch | ✅ alive >12 s | event loop up (no crash) |
| Integrity manifest | ✅ | `dist/TTPProfiler.sha256.json` |
| Authenticode signing | 🐣 pending | EV certificate required (see `build_exe.ps1 -Sign`) |

## 2. Runtime State Register

| Key | Current Value |
|---|---|
| `workspace` default | `./workspace` (next to exe) |
| Encrypted evidence | `DPAPI → AES-256-GCM analogue` |
| Audit chain head | computed at runtime, viewable in `Audit` page |
| `samples_demo/` | 3 fixture reports (APT29/PowerDuke, Sednit, Agent Tesla) |

## 3. Test Status Matrix

| Test | Pass | Coverage |
|---|---|---|
| Import (sanitize, dedupe, quarantine) | ✅ | `tests/smoke_test.py` |
| ATT&CK mapping (22 techniques in demo) | ✅ | technique/tactic aggregation |
| Attribution ranking (top actor + confidence) | ✅ | APT1/APT28/APT29 raced |
| Report export + manifest hash verif | ✅ | 4 artifacts |
| DB persistence + load | ✅ | profiles round-trip |
| GUI render (all pages) | ✅ | offscreen grab |

## 4. Known Bugs / Tech Debt Log

| ID | Severity | Item | Status |
|---|---|---|---|
| TD-1 | Low | DPAPI raises on non-Windows — auto-fallback to plaintext requested | open |
| TD-2 | Low | Attribution favors broad generic technique sets; consider tactic-diversity weighting | open |
| TD-3 | Medium | ATT&CK dataset is curated subset; plan STIX-bundle importer | planned |
| TD-4 | Low | PDF export not yet generated (HTML→print pipeline in Reports) | planned |

## 5. Decision Log

| Date | Decision | Rationale |
|---|---|---|
| 2026-09-23 | Use PySide6 + custom QPainter widgets | Single-exe friendly, high-DPI, fast paint |
| 2026-09-23 | Standard sqlite3 + DPAPI field encryption | Portable, no native deps, key custody in OS |
| 2026-09-23 | Pure-NumPy clustering (no scikit-learn) | Shrinks bundle, removes heavy dependency |
| 2026-09-23 | `default-deny` import parsers | OWASP A04, mitigates hostile sample payloads |

## 6. Next Actions (Priority Order)

1. ✅ ~~Run `build_exe.ps1`~~ → `dist/TTPProfiler.exe` produced & verified standalone
2. ✅ ~~Run `--verify` on the built exe~~ → exit 0, DPAPI encryption active
3. ⬜ Sign with EV cert; publish SHA-256 + SBOM to release page
4. ⬜ Pilot with a real public sample set; tune weights + false-positive heuristics
5. ⬜ Add STIX-bundle ATT&CK importer to retire curation drift