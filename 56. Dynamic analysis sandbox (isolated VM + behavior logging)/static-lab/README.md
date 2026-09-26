# StaticLab — Portable PE Static Analysis Sandbox

GUI + CLI static-analysis pipeline: **strings extraction**, **PE header parsing**, **hash computation & threat-intel lookups**, with tamper-evident **audit logging** and downloadable reports. Ships as a single portable `.exe`.

> Companion to `../architecture.md` (Dynamic Analysis Sandbox blueprint). Implements the **static pipeline stage** of that architecture in a portable, offline-first tool.

---

## ✨ Highlights

- 🎛 **Attractive dark-themed GUI** (Tkinter/ttk) — tabs for Overview, PE Headers, Sections, Imports, Strings, Threat Lookups, Audit Ledger
- 🧵 **Strings** — ASCII + UTF-16LE with offsets and interest flags (URLs, IPs, emails, registry, base64, malware tokens)
- 📦 **PE parsing** — sections & entropy, imports/exports/resources, Rich header, overlay detection, Authenticode presence, data directories
- 🔑 **Hashes** — MD5/SHA-1/SHA-256/SHA-512 streaming, imphash, PE authentihash, Shannon entropy
- 🕵️ **Threat lookups** — VirusTotal v3, MalwareBazaar, AlienVault OTX, Hybrid Analysis (offline-safe if no keys)
- 🧾 **Reports** — one-click download as **HTML / JSON / TXT** + full strings dump
- 🔒 **Auditability** — append-only, hash-chained, HMAC-signed audit ledger (SQLite) with a *Verify Chain* tool
- 🔐 **Secrets** — API keys stored **DPAPI-encrypted at rest**, never plaintext
- 💾 **Portable** — single `StaticLab.exe`, no install, no admin rights for the analyst UI

---

## 🚀 Quick start

### Run from source
```powershell
cd static-lab
pip install -r requirements.txt
python -m app            # launches the GUI
```

### Headless / automation
```powershell
python -m app --cli C:\path\sample.exe --format html > report.html
python -m app --cli C:\path\sample.exe --format json | Out-File report.json
python -m app --cli C:\path\sample.exe --format txt --no-lookup
```

### Portable .exe (already built)
- `dist\StaticLab.exe` — double-click to open the GUI.
- Rebuild anytime: run `.\build.ps1` (or `.\build.ps1 -Console` for a CLI variant).

---

## 🧭 GUI workflow

1. **Browse** a file (or paste a path).
2. Press **Analyze** — pipeline stages stream in the status bar.
3. Inspect tabs; export a report or the full strings dump from **File ▸ Export**. 
4. Set API keys under **Tools ▸ API Keys / Providers** (stored encrypted).
5. Review/tamper-check the ledger under **Tools ▸ Audit Log Viewer** and **Verify Audit Chain**.

---

## 📁 Project layout

```
static-lab/
├── app/
│   ├── main.py            # entry (GUI default, --cli headless)
│   ├── config.py          # app config + DPAPI secret vault
│   ├── core/
│   │   ├── pipeline.py    # orchestrates the 8-stage analysis
│   │   ├── pe_parser.py   # PE parsing (pefile) + Rich header decoder
│   │   ├── strings_extractor.py
│   │   ├── hashing.py     # streaming digests + imphash/authentihash
│   │   ├── entropy.py     # Shannon entropy
│   │   ├── lookups.py     # VT / MalwareBazaar / OTX / Hybrid Analysis
│   │   ├── audit.py       # hash-chained, signed audit ledger
│   │   └── model.py       # dataclasses + verdict scoring
│   ├── report/            # HTML (styled, offline), JSON, TXT exporters
│   └── gui/               # themed Tkinter application
├── tests/test_core.py     # unittest suite (no network required)
├── build.ps1              # PyInstaller onefile build
├── launcher.py            # PyInstaller entry point
└── requirements.txt
```

---

## 🧪 Testing

```powershell
python -m unittest discover -s tests -v     # 12 tests, offline
```

---

## 🛡 Security posture

See [`security.md`](security.md) for the full control mapping (ISO 27001 / NIST 800-53 / OWASP Top 10) and [`state.md`](state.md) / [`memory.md`](memory.md) for implementation status and continuity notes.