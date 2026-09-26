# State.md - Current Project State

Snapshot for future sessions. Update after every significant change.

## 1. Artifacts

| Path | Role |
|---|---|
| `ARCHITECTURE.md` | Full architecture incl. compliance matrices (Section 9) |
| `security.md` | Security posture, data-handling rules, debt |
| `state.md` | This file - current state |
| `memory.md` | Persistent context / ADRs / commands for agent sessions |
| `src/__init__.py` | Version (`1.0.0`) |
| `src/rules.py` | Rule corpus (Layer 1), ~30 rules w/ CWE/OWASP metadata |
| `src/normalize.py` | Parse + deep-decode + digest (no raw persistence) |
| `src/tokenizer.py` | Layer 2 SQL-aware grammar detection |
| `src/layers.py` | Layers 1-3 + fusion engine |
| `src/engine.py` | Orchestration: `analyze_target`, `inline_analyze` |
| `src/scanner.py` | Active scanner (error/boolean/union/time probes) |
| `src/compliance.py` | Framework mapping + snapshot exports |
| `src/gui.py` | tkinter app: 5 tabs |
| `src/cli.py` | `--selftest` CI gate |
| `src/__main__.py` | Entry: GUI default, CLI if args |
| `build.ps1` | Selftest gate + PyInstaller onefile build |
| `requirements.txt` | requests, pyinstaller |
| `dist/SQLiDetectShield.exe` | **Portable GUI exe (built artifact)** |

## 2. Verification status (2026-09-19)

- `python -m src --selftest` -> **Passed 5/5** (PL_ fixtures: boolean, quote-break,
  union/version, clean, order-by)
- Edge checks: `q=select` CLEAN (no FP), `q=please select a file` CLEAN,
  `id=1' AND SLEEP(9)--` CRITICAL/BLOCK, `e=a@b.com` CLEAN.
- GUI construction smoke-tested (auto-open/close) - OK.
- Frozen exe selftest -> **Passed 5/5**.
- exe launch test -> process stays running (GUI alive).

### Built artifact
| | |
|---|---|
| File | `dist\SQLiDetectShield.exe` |
| Size | ~18.0 MB (onefile, windowed) |
| SHA-256 | `67C0718A01B805985B3DD03278D541F165B179475B0FA3F2A30F4F6DB8BD14F6` |
| Python | 3.12.7 / PyInstaller 6.22.2 / requests 2.34.2 / tk 8.6 |

## 3. What works today
- Passive detection per-parameter with severity/verdict/score + evidence panel.
- Raw HTTP request parsing + URL analysis.
- Scanner: GET/POST probes on approved targets; DB-flavor detection from error
  markers; boolean differential + time-latency + union probes; per-param results.
- Findings aggregation + JSON/CSV exports + compliance snapshot (md/json).
- Compliance tab renders ISO/NIST/OWASP/PCI mapping (readonly).
- Built-in selftest available in GUI (About tab) and CLI.

## 4. Known limitations (documented in ARCHITECTURE.md)
- Layers 4 (ML) and 5 (correlation/OOB beacon) are NOT built in this portable
  edition - roadmap for server edition.
- Ingest adapters (SPAN/TAP, inline proxy, SDK agent) are NOT in the exe; the GUI
  handles URL/raw-request/on-demand inputs only.
- Response differential needs real responses; union/time probes assume server
  behavior - fine on lab targets, noisy on CDN/cache-fronted apps.
- Findings live in memory only (by design); exports are user-initiated.

## 5. Environment
- OS: Windows 11 (win32), shell PowerShell 5.1.
- Python 3.12.7 at `C:\Users\mohsi\AppData\Local\Programs\Python\Python312`.
- Temp scratch: `C:\Users\mohsi\AppData\Local\Temp\opencode`.

## 6. Next steps (roadmap priorities)
1. Wire lint + bandit + pip-audit into CI (security.md debt #1).
2. Add raw-request paste coverage for POST body (form/JSON) selftest fixtures.
3. Persist an append-only audit journal (scanner consent + run log) for ISMS.
4. If expanding to server: ML layer + correlation (ARCHITECTURE.md phases 3-4).