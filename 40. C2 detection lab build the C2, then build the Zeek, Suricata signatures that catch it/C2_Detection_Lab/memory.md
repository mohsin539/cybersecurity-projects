# 🧠 memory.md — Project Memory Bank

> Persistent knowledge base for the C2 Detection Lab. Purpose: let any future
> session (human or AI) resume work instantly — where things are, what was
> decided, what the sharp edges are, and what the verified numbers look like.
> Updated whenever meaningful work lands.

---

## 1 · Snapshot (last verified)

| Item | Value |
|---|---|
| **Date verified** | 2026-09-20 |
| **Python** | 3.12.7 (Windows, win32) |
| **GUI stack** | stdlib tkinter + ttk · ttkbootstrap optional |
| **Libs available** | openpyxl · jinja2 · cryptography · PyInstaller 6.22.3 |
| **Tests** | `python -m pytest -q .` → **3 passed** |
| **Headless lab** | `python main.py --headless ...` → precision **1.0**, recall ~0.66–0.78, F1 ~0.80–0.88 |
| **Portable EXE** | `dist/C2DetectionLab.exe` (34 MB, SHA-256 `9B69FB1D…31B`) — built, runs `--headless` end-to-end |

---

## 2 · Map of the codebase

```text
main.py                     GUI (default) or --headless CLI entry
core/
  config.py                 LabConfig — the single source of run truth
  compliance.py             ISO / NIST CSF / 800-53 / OWASP register
  audit.py                  Auditor — SHA-256 evidence chain
  lab_runner.py             LabRunner — the L1->L5 state machine
c2_sim/
  server.py                 real loopback TCP C2 implant (TLV magic 00 7f)
  agent.py                  agent fleet w/ AES-GCM payload, interval+jitter
  bus.py                    thread-safe event bus = the "pcap"
  traffic.py                benign noise generator (precision baseline)
detectors/
  zeek.py                   generate beacon.zeek + in-process heuristic
  suricata.py               generate c2_beacon.rules + content/pcre matcher
  engine.py                 correlation + precision/recall/F1 grading
reporting/
  xlsx_report.py            openpyxl, 5 sheets + bar chart
  csv_report.py             alerts/iocs/metrics/compliance/events
  html_report.py            offline dark dashboard (canvas chart)
gui/
  app.py                    6-tab console + PIN-lock (modal)
  security.py               PinVault — salted SHA-256, lockout
  theme.py                  dark palette (matches architecture HTML)
tests/test_smoke.py         3 pytest cases
C2_Detection_Lab.spec       PyInstaller spec (--onefile --noconsole)
build_exe.ps1               build + manifest helper
requirements.txt
```

---

## 3 · Design decisions (do not silently change)

| Decision | Rationale |
|---|---|
| C2 sim binds **loopback + ephemeral port** only | lab never touches the network |
| Ground truth in `traffic_type` field | drives precision/recall; treat as read-only |
| **Both** Zeek and Suricata engines run in-process | portable GUI needs no live daemons |
| Signatures are **generated text** + replicated in matchers | give real Zeek/Suricata artifacts AND live detections |
| Report exports are **self-contained** (offline) | auditable without network |
| PIN gate **closes-process on skip** | cannot bypass RBAC (OWASP A01) |
| `events.jsonl` kept as SIEM-ready raw stream | replay + external correlation |
| Combined-heuristic: periodic + UA marker + TLV magic | keeps FP=0 in tests; FN = warm-up beacons |

---

## 4 · Known behaviours & edge cases

- **Recall < 1.0 is *expected*:** the Zeek periodic heuristic needs ≥3 beacons
  per flow to establish the pattern → early beacons are FNs by design.
  Lower `beacon_interval` or raise `agent_count` to recover them.
- **`--headless` from the windowed EXE** works but shows no console by design
  (`console=False`); CLI output only appears on a Python console run.
- **PIN lockout:** 5 wrong attempts → 60 s lockout; deleting
  `labs/state/security.json` resets to default PIN `1234` (**change it**).
- **First GUI launch** creates `labs/` automatically. Runs write to
  `labs/runs/run_<timestamp>/`.
- **Ephemeral port swap:** `server_port=0` → port chosen live; `config.json`
  stores the actual port used (don't reuse it verbatim between runs).
- Windows Defender may flag the C2 sim traffic on loopback — expected for a
  defensive-training tool; document it in user-facing notes.

---

## 5 · How to run / verify

```sh
python -m pytest -q .                       # 3 regression tests
python main.py                              # GUI console
python main.py --headless --duration 20     # CLI lab + reports
.\build_exe.ps1                             # rebuild dist/C2DetectionLab.exe
.\dist\C2DetectionLab.exe --headless --interval 0.5 --agents 2 --duration 15 --json exe_run.json
```

---

## 6 · Next ideas (backlog)

- [ ] Add **MITRE ATT&CK Navigator JSON** export (matrix heatmap per run)
- [ ] Wire optional **live Zeek/Suricata** via subprocess flags (`--use-zeek`)
- [ ] Add **code-signing step** to `build_exe.ps1` (signtool/osslsigncode hook)
- [ ] Ship `.ico` + version resource via spec (`icon=`/`version=`)
- [ ] Export report set to a **ZIP bundle** for one-click sharing
- [ ] GUI: streaming progress bar + live metric sparklines

---

## 7 · Open questions for the human

1. Default PIN `1234` — keep, or prompt-on-first-run to set a new one?
2. Do you want the lab to optionally **start real Zeek + Suricata** binaries
   in a Docker/Vagrant harness for true packet replay?
3. Target framework for the GUI prettiness: keep vanilla ttk (zero-dependency
   EXE) or switch to ttkbootstrap / CustomTkinter for more polish?