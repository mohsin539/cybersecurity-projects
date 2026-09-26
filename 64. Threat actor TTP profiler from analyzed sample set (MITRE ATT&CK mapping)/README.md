# 🛡️ Threat Actor TTP Profiler

Portable **GUI `.exe`** that turns an analyzed malware sample set into a **MITRE ATT&CK™ TTP profile** — techniques, tactics, confidence scoring, threat-actor attribution, and shareable CTI artifacts.

> Offline-first · Neon Sentinel dark-cyber UI · ISO 27001 / NIST CSF 2.0 / OWASP Top 10 hardened.

## 🚀 Quickstart

```powershell
# 1. Run (GUI)
python main.py

# 2. Headless pipeline: import → profile → export
python main.py --import samples_demo --name "Demo" --profile --export reports

# 3. Self-audit
python main.py --verify
```

## 🧪 Tests

```powershell
python -X utf8 tests/smoke_test.py       # import→map→attribute→export (logic)
python -X utf8 tests/gui_smoke_test.py   # renders all 7 pages offscreen + screenshots
```

## 📦 Build portable .exe (Windows)

```powershell
powershell -ExecutionPolicy Bypass -File .\build_exe.ps1 -Builder nuitka
# optional signing:
powershell -ExecutionPolicy Bypass -File .\build_exe.ps1 -Sign -CertThumbprint <SHA1>
```

Output: `dist/TTPProfiler.exe` + `dist/TTPProfiler.sha256.json`.

## 🗂️ Project Anatomy

| Path | Purpose |
|---|---|
| `main.py` | Entry point (GUI + `--verify` + headless) |
| `app/` | Models, services, ATT&CK engine, store, reports, Neon Sentinel theme, UI widgets |
| `samples_demo/` | 3 sample reports for demo/tests |
| `tests/` | Smoke + GUI render tests |
| `docsassets/` | UI screenshots |
| `architecture.md` | Full architecture blueprint |
| `security.md` | ISO 27001 / NIST / OWASP posture |
| `state.md` | Dev/runtime state register |
| `memory.md` | Project working memory & conventions |

## ⚠️ Disclaimer

Bundled ATT&CK data is a curated subset for offline use. Production deployments should refresh from the official MITRE STIX bundle. Use only on samples you are authorized to analyze.