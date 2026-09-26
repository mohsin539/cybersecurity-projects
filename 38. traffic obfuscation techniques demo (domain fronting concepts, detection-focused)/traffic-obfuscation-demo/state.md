# state.md

Reserved — current project state for the **Traffic Obfuscation Techniques Demo**.

---

## 1. Status Summary

| Area | Status | Notes |
|---|---|---|
| Analysis engine (generator / detection / frameworks) | DONE | deterministic, reproducible scores |
| Report exporters (.xlsx / .csv / .html / .json) | DONE | verified read-back of xlsx + csv |
| Architecture dashboard | DONE | `index.html` (5-tab interactive, animated SVG) |
| GUI desktop edition | DONE | `src/gui.py`, dark tkinter theme, 4 tabs, exports |
| Portable .exe | DONE | `dist/TrafficObfuscationDemo.exe` 29.7 MB, onefile, windowed |
| Exe verification | DONE | `--selftest` -> PASS (7 flows, 9 findings, 1 fronted) |
| Reservation docs | DONE | `security.md`, `state.md`, `memory.md` |

## 2. Component Inventory

```
traffic-obfuscation-demo/
  index.html                  interactive architecture dashboard
  traffic_obfuscation_gui.py  PyInstaller entry point -> TrafficObfuscationDemo.exe
  build_portable.ps1          one-click portable build script
  requirements.txt            runtime deps (openpyxl only)
  src/
    gui.py                    Tkinter GUI (App, _FlowCanvas, selftest)
    main.py                   CLI runner (python -m src.main)
    config.py                 paths, CDN ranges, thresholds
    generator/__init__.py     TrafficRecord + 7 deterministic scenarios
    detection/analyzers.py    5 heuristic checks -> Finding
    detection/engine.py       scoring 0-100 + verdict enum
    frameworks/__init__.py    OWASP (10) + NIST CSF (6) + ISO 27001 (8) controls
    reporting/                bundle, xlsx, csv, html, json exporters
  tools/make_icon.py          pure-python PNG/ICO encoder -> assets/app.ico
  assets/app.ico              app icon (radar glyph, violet->cyan)
  dist/TrafficObfuscationDemo.exe   portable build
  security.md / state.md / memory.md
```

## 3. Known-Good Results (reference matrix)

| Flow | Scenario | Score | Verdict | Signal |
|---|---|---|---|---|
| rec-0001 | NORMAL | 0 | benign | clean SNI==Host |
| rec-0002 | DOMAIN_FRONT | 84 | **fronted** | SNI/Host + CDN signature + TTL |
| rec-0003 | SNI_SPOOF | 68 | **suspicious** | mismatch + CDN signature |
| rec-0004 | HTTPS_TUNNEL | 0 | benign | no visible HTTP to score |
| rec-0005 | H2_SPOOF | 42 | **suspicious** | authority divergence + TTL |
| rec-0006 | BENIGN_CDN | 0 | benign | consistent front |
| rec-0007 | NORMAL | 0 | benign | clean |

Framework catalog: OWASP 10/10 relevant (8 adopt), NIST 6 (1 adopt, 4 review), ISO 7 relevant (4 adopt).

## 4. Build Status

- Build cmd: `powershell -ExecutionPolicy Bypass -File build_portable.ps1`
- Output: `dist/TrafficObfuscationDemo.exe` (onefile, `--windowed`, icon embedded, `index.html` bundled)
- Verify: `dist\TrafficObfuscationDemo.exe --selftest` -> writes `gui_selftest_ok.txt`
- Reports land beside the exe under `Reports\report_<stamp>\`

## 5. Decision Log

| # | Decision | Rationale |
|---|---|---|
| D1 | tkinter (stdlib) over customtkinter/PyQt | zero extra runtime deps in the portable build |
| D2 | Separate `_bundle_path()` (_MEIPASS) from `_runtime_dir()` (next to exe) | read-only assets vs writable report dir when frozen |
| D3 | Severity weights (5/8/16/26/38) + thresholds 40/70 | conservative, auditable scoring |
| D4 | TTL heuristic MEDIUM for fronting scenarios | made H2_SPOOF cross `suspicious`; keeps baseline clean |
| D5 | Pure-python ICO encoder (no Pillow) | icon emits with PyInstaller without extra deps |
| D6 | `sys.stdout.reconfigure(utf-8)` in CLI | cp1252 console crash on unicode checkmark |

## 6. Backlog / Next Actions

- [ ] Real pcap / TLS ClientHello ingestion (scapy or tshark feeds into the analysis pipeline)
- [ ] Exact JA3/JA4 hashing implementation (demo currently uses a JA4-a-like token)
- [ ] ECH / ESNI-aware indicators + overt-data caveats
- [ ] Unit tests (pytest) for generator, analyzers, exporters
- [ ] Authenticode signing of the portable exe
- [ ] `.zip` portable kit + optional MSIX wrapper
- [ ] Hungarian-style localization / multi-language report templates
- [ ] Live "capture" simulation mode with timestamped stream in the GUI

## 7. Blockers / Risks

- ECH adoption makes passive SNI detection degrade; pair with DNS-side analytics.
- Anycast CDN false positives for legitimate multi-homed services -> keep thresholds conservative.
- Onefile exe startup ~2-4 s (unpack to temp); acceptable for a portable tool.