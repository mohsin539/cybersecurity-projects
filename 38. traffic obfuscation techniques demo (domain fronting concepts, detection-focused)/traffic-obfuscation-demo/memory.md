# memory.md

Reserved — persistent project memory for future sessions on the **Traffic Obfuscation Techniques Demo**.

---

## 1. Project One-Liner

Synthetic, detection-focused demo of **domain fronting** and related TLS traffic-obfuscation
techniques, mapped to **OWASP Top 10**, **NIST CSF 2.0**, **ISO/IEC 27001:2022**, delivered as
an animated architecture dashboard, a Tkinter GUI, and a **portable single-file .exe**.

## 2. Quick Facts (re-learn in seconds)

- Root: `traffic-obfuscation-demo/` (inside the lab folder for project **38**).
- CLI run: `python -m src.main --formats xlsx csv html json`
- GUI dev run: `python src/gui.py` | headless check: `python src/gui.py --selftest`
- Portable build: `powershell -ExecutionPolicy Bypass -File build_portable.ps1`
- Exe verify: `dist\TrafficObfuscationDemo.exe --selftest` -> marker `gui_selftest_ok.txt`
- Dashboard: `index.html` (open in browser). Exe bundles it (`--add-data "index.html;."`).
- Reports: `output/report_<stamp>/` in dev; `Reports/report_<stamp>/` next to the exe when frozen.
- Only runtime dep: `openpyxl`. Icon: pure-python encoder `tools/make_icon.py` (no Pillow).

## 3. Architecture (6 swimlanes in `index.html`)

1. **Traffic generation & clients** — synthetic TLS ClientHello records (7 scenarios).
2. **Obfuscation techniques / fronting concepts** — Domain Fronting, SNI Spoof, HTTPS CONNECT, H2 `:authority`.
3. **CDN anycast edge / shared front** — Cloudflare/Fastly/Akamai/Google ranges in `src/config.py`.
4. **Hidden origin** — allow-listed backend steered by Host header.
5. **Detection & analytics** — 5 checks + severity-weighted scoring engine (0-100).
6. **Compliance & reporting** — framework catalogs + `.xlsx/.csv/.html/.json` exporters.

## 4. Conventions

- **Palette (GUI + dashboard)**: bg `#0b0e1f`, panel `#131a33`, accent `#8b5cf6`,
  cyan `#22d3ee`, green `#059669`, orange `#e17055`, rose `#fb7185`, gold `#fbbf24`.
- **Verdicts**: `fronted` = red, `suspicious` = orange, `benign` = green.
- **Severities**: critical `#ef4444`, high `#e17055`, medium `#f59e0b`, low `#38bdf8`, info `#64748b`.
- **Thresholds** (`src/config.py`): suspicious >= 40, fronted >= 70; weights 5/8/16/26/38.
- **Finding ref convention**: `OWASP-04`, `NIST:C`, `ISO:A8.28` -> resolved by `src/frameworks/`.
- **CDN detection** is IP-range based (synthetic IPs chosen to land in configured CDN blocks).

## 5. Data Flow

```
build_dataset()          -> [TrafficRecord]                  (src/generator)
evaluate_all()           -> {record_id: FlowVerdict}         (src/detection/engine)
analyze_record()         -> [Finding]  (5 checks, refs set)  (src/detection/analyzers)
ReportBundle.build()     -> bundle (verdicts+findings+stats) (src/reporting/bundle)
export_xlsx/csv/html/json-> artifacts
```

Score = sum of finding weights (cap 100). Fall-through: scanl checks each return a Finding or None.

## 6. GUI Structure (`src/gui.py`)

- `App(tk.Tk)` — header(Run/Progress), Notebook: Overview(cards + `_FlowCanvas` animation),
  Flow Verdicts, Findings, Framework Coverage; export bar; status bar.
- `run_analysis()` — pure logic, no Tk (enables headless `--selftest`).
- `_bundle_path()` = `_MEIPASS` when frozen (read assets); `_runtime_dir()` = exe dir (write Reports).
- `_FlowCanvas` animates dashes via `dashoffset` and moves dots with `after(30, ...)`.

## 7. Windows/PyInstaller Gotchas (already resolved)

- cp1252 console -> call `sys.stdout.reconfigure(encoding="utf-8")` at CLI start.
- `--windowed` exe prints nothing; selftest writes a **marker file** instead of stdout.
- Onefile exe extraction takes a moment at first launch — wait before the marker check.
- openpyxl pulls numpy/PIL hooks during PyInstaller analysis (harmless, bigger exe).
- Do not write reports into `_MEIPASS` (temp) — always use `_runtime_dir()`.

## 8. Reference Numbers

- 7 flows, 9 findings, 1 `fronted`, 2 `suspicious`, 4 `benign` (reference run).
- Framework catalog: OWASP 10 controls, NIST 6 functions, ISO 8 Annex A controls (7 relevant).
- Exe: `dist/TrafficObfuscationDemo.exe`, ~29.7 MB, Windows 11 (26200) / Python 3.12.7 /
  PyInstaller 6.22.3 / tkinter 8.6 / openpyxl 3.1.5.

## 9. Open Questions & Experiments

- Fold real TLS `ClientHello` bytes (scapy) into the analyzer — replace JA4-a-like token.
- Test ECH-only flow: should it shift to "detection blind spot" severity instead of benign?
- Add uncertainty/confidence to each Finding to support triage prioritization.
- Benchmark scoring thresholds against a labelled benign/malicious corpus.