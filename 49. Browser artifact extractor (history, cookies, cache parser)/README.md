# Browser Artifact Extractor

**Forensic History, Cookie & Cache Parser** — a portable, offline desktop tool that
collects and parses browser evidence from Chromium-family browsers and Firefox, then
produces signed, multi-format reports aligned to **ISO/IEC 27001:2022**, **NIST
SP 800-53 / SP 800-86** and the **OWASP Top 10:2021**.

```
   ╔══════════════════════════════════════════════════════════════════╗
   ║   Browser Artifact Extractor  v1.0.0                             ║
   ║   History · Cookies · Cache · Downloads · Bookmarks · Logins     ║
   ╚══════════════════════════════════════════════════════════════════╝
```

---

## 1. Highlights

| Capability | Detail |
|---|---|
| **Colourised GUI** | KPI dashboard, category sidebar, searchable/sortable tables, live progress, dark sidebar theme |
| **Portable .exe** | Single-file, dependency-free Windows executable built with PyInstaller (~30 MB) |
| **Offline & private** | Zero network calls. Nothing leaves the host. |
| **Read-only forensics** | Originals are never written to; live/locked databases acquired safely |
| **Evidence integrity** | SHA-256 per artefact + signed collection manifest |
| **Tamper-evident audit** | Hash-chained JSON-lines audit log (ISO 27001 A.8.15 / NIST AU-9) |
| **Six report formats** | CSV, HTML, JSON, XML, XLSX, PDF (+ Markdown and raw manifest) |
| **Opt-in secrets** | Cookie values & passwords stay masked unless explicitly enabled |
| **Compliance view** | 20 mapped controls shown *in-app* and inside every report |

---

## 2. Supported browsers

Discovered automatically (Windows paths shown; macOS/Linux paths included in code):

| Browser | Family | History | Cookies | Cache | Downloads | Bookmarks | Autofill | Logins |
|---|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| Google Chrome / Chrome Beta | Chromium | ✓ | ✓* | ✓ | ✓ | ✓ | ✓ | ✓* |
| Microsoft Edge | Chromium | ✓ | ✓* | ✓ | ✓ | ✓ | ✓ | ✓* |
| Brave | Chromium | ✓ | ✓* | ✓ | ✓ | ✓ | ✓ | ✓* |
| Opera / Opera GX | Chromium | ✓ | ✓* | ✓ | ✓ | ✓ | ✓ | ✓* |
| Vivaldi | Chromium | ✓ | ✓* | ✓ | ✓ | ✓ | ✓ | ✓* |
| Chromium | Chromium | ✓ | ✓* | ✓ | ✓ | ✓ | ✓ | ✓* |
| Yandex, Naver Whale, Arc | Chromium | ✓ | ✓* | ✓ | ✓ | ✓ | ✓ | ✓* |
| Mozilla Firefox | Firefox | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓** |

\* Chromium cookie/login values use `v10`/`v11` **AES-256-GCM** with a DPAPI-wrapped
key from `Local State`. Values decrypt on the *same Windows user profile*. `v20`
**App-Bound Encryption** (Chrome 127+) is detected and reported as `v20_appbound`
(decryption requires the browser's privileged service and is out of scope).
\*\* Firefox `logins.json` entries are NSS-encrypted; the tool extracts metadata and
flags the encrypted fields (full decryption requires `key4.db` + NSS which is not
bundled).

### Artifacts collected
- **History** — visited URLs, titles, visit counts, typed counts, timestamps, duration, transition
- **Downloads** — file, source URL, saved path, size, state, MIME
- **Cookies** — host, name, value, path, expiry, Secure/HttpOnly/SameSite
- **Bookmarks** — name, URL, folder tree, date added
- **Autofill / form data** — field, value, use counts, first/last used
- **Saved logins** — origin, username, password (opt-in), realm
- **Search terms** — keyword-to-URL mappings
- **Cache** — Chromium *Simple Cache* key/URL recovery + file metadata; Firefox `cache2` URL scanning

---

## 3. Project layout

```
browser-artifact-extractor/
├── main.py                 # Entry point (GUI default, --cli for headless)
├── build_portable.py       # PyInstaller: GUI .exe + CLI .exe
├── requirements.txt
├── core/
│   ├── models.py           # ScanResult / ScanOptions / EvidenceItem dataclasses
│   ├── paths.py            # Browser + profile discovery (Win/mac/Linux)
│   ├── decrypt.py          # DPAPI + AES-256-GCM secret unwrapping
│   ├── winio.py            # Locked-file acquisition: shared → backup → VSS
│   ├── extractors.py       # Read-only SQLite/JSON/cache parsers
│   └── engine.py           # Orchestration, hashing, statistics
├── sec/
│   ├── integrity.py        # SHA-256, evidence manifest, HMAC, hash chain
│   ├── audit.py            # Tamper-evident JSON-lines audit logger
│   └── compliance.py       # ISO 27001 / NIST / OWASP control catalogue
├── report/
│   ├── templates.py        # Escaped, colourised HTML template
│   └── exporters.py        # CSV · HTML · JSON · XML · XLSX · PDF · MD
└── ui/
    ├── theme.py            # Palette + ttk theme
    ├── widgets.py          # StatCard, ArtifactTable, SidebarNav
    └── app.py              # Main console window + export dialog
```

---

## 4. Quick start

### Run from source
```powershell
python -m pip install -r requirements.txt
python main.py                      # GUI
python main.py --cli --help         # headless help
```

### Build the portable .exe
```powershell
python build_portable.py --clean
```
Outputs:
```
dist\BrowserArtifactExtractor.exe       # GUI (windowed, one-file)
dist\BrowserArtifactExtractor-CLI.exe   # CLI (console, one-file, for automation)
```
Both are fully self-contained — copy them anywhere and run.

---

## 5. Usage

### GUI
1. **Discover Browsers** — profiles are listed with their available artifact sets.
2. Select profiles (Ctrl+click) and tick the **collection options** (categories, secret
   decryption, cache URLs, record limit).
3. **Start Scan** — KPIs, tables, evidence manifest, compliance map and audit log populate live.
4. Reports are **auto-exported** to `BAE_Output\scan_<ID>\`; use **Export Reports** to
   pick a custom folder and format set.
5. **Verify Audit Chain** proves the log has not been altered.

### CLI / automation
```powershell
BrowserArtifactExtractor-CLI.exe --cli ^
  --out D:\cases\CASE-2026-014\ ^
  --categories history,cookies,cache,downloads,logins ^
  --formats html,csv,json,xlsx,pdf ^
  --decrypt --operator "J. Analyst" --case CASE-2026-014
```

| Flag | Purpose |
|---|---|
| `--cli` | Run headless |
| `--out` | Output directory |
| `--categories` | Comma-separated artifact categories |
| `--formats` | `html,csv,json,xml,xlsx,pdf,md` |
| `--profiles` | Profile labels to include (default: all) |
| `--decrypt` | Opt-in secret decryption |
| `--max-records` | Cap records per category (0 = unlimited) |
| `--operator`, `--case` | Chain-of-custody metadata |

---

## 6. Report formats

| Format | File | Best for |
|---|---|---|
| **HTML** | `report_<ts>.html` | Human review — colourised, escaped, print-ready |
| **CSV** | `csv_<ts>\<category>.csv` + `all_artifacts_long.csv` | Excel/SQL/pandas ingest |
| **JSON** | `report_<ts>.json` | SIEM, APIs, full structured fidelity |
| **XML** | `report_<ts>.xml` | Legacy tooling / XSLT |
| **XLSX** | `report_<ts>.xlsx` | Multi-sheet analyst workbook with autofilter |
| **PDF** | `report_<ts>.pdf` | Signed/printable evidence exhibit |
| **Markdown** | `report_<ts>.md` | Issues, wikis, tickets |
| **Manifest** | `evidence_manifest_<ts>.json` | Integrity + chain of custody |

Every report carries the same header: scan ID, host, platform, operator, case ref,
timestamps, manifest SHA-256 and audit-chain validity.

---

## 7. Security & compliance

### Controls implemented in code

| Framework | Control | Implementation |
|---|---|---|
| ISO 27001:2022 | A.8.3 | Evidence copied to isolated temp; originals never modified |
| ISO 27001:2022 | A.8.10 | Temp copies and key material wiped after each run |
| ISO 27001:2022 | A.8.11 | Secrets masked unless explicit opt-in consent |
| ISO 27001:2022 | A.8.12 | No outbound network activity whatsoever |
| ISO 27001:2022 | A.8.15 | Hash-chained audit log of every action |
| ISO 27001:2022 | A.8.24 | AES-256-GCM + Windows DPAPI; SHA-256 integrity |
| NIST SP 800-53 | AU-2/AU-3 | Structured audit events (actor, host, PID, severity) |
| NIST SP 800-53 | AU-9 | SHA-256 hash chain protects audit records |
| NIST SP 800-53 | SC-8/SC-13 | Cryptography for secrets at rest |
| NIST SP 800-53 | SI-10 | Parameterised SQLite, validated paths, bounded input |
| NIST SP 800-86 | 3.2 | Per-artifact SHA-256 in signed manifest |
| NIST SP 800-86 | 3.3 | Chain of custody in every report header |
| OWASP A01/A03/A05/A06/A08/A09 | — | Access control, output escaping, safe defaults, pinned deps, integrity, logging |

The **Compliance** view lists all 20 mapped controls with their implementing module,
and the same table is embedded in the HTML/PDF/XLSX reports.

### Chain of custody
For each artifact the tool records: source path, **SHA-256**, record count, collector,
and UTC timestamp. The manifest is a canonical JSON digest (`manifest_sha256`) so a
reviewer can prove no record was added, removed or edited post-collection. The audit
log is a SHA-256 **hash chain** — every line binds the previous digest, so tampering
breaks verification (use **Verify Audit Chain**).

### Handling locked (live) databases
Chromium locks its `Cookies` DB exclusively while running. The acquisition ladder is:

1. **Shared read** — `CreateFileW` with `FILE_SHARE_READ|WRITE|DELETE`
2. **Backup semantics** — `SeBackupPrivilege` + `FILE_FLAG_BACKUP_SEMANTICS`
3. **Volume Shadow Copy** — WMI snapshot (requires **administrator**)

If a browser holds a hard lock and the tool is not elevated, the category is skipped
with a clear, actionable message and everything else still completes. Run elevated
for VSS, or close the browser, to collect those cookies.

---

## 8. Responsible use

This tool reads **personal data**. Use it only on systems you own or are explicitly
authorised to examine, under a documented legal basis (e.g. incident response
authorisation, court order, or written consent). The authorisation reference and
operator identity are captured in the audit log and every report. You are responsible
for complying with applicable privacy and computer-misuse law.

---

## 9. Troubleshooting

| Symptom | Resolution |
|---|---|
| Cookies category reports "exclusively locked" | Close the browser or run elevated (VSS) |
| Chrome cookies show `v20_appbound` | Chrome 127+ App-Bound Encryption — not supported without the browser's service |
| PDF/XLSX export fails | Ensure `reportlab` / `openpyxl` are installed (bundled in the .exe) |
| Antivirus flags the .exe | PyInstaller one-file binaries are commonly false-positived; add an exclusion or build `--onedir` |
| No browsers found | Confirm the tool runs as the same Windows user that uses the browsers |

---

## 10. License & attribution

Provided as-is for lawful digital-forensics and incident-response use. Third-party
components retain their own licenses: `cryptography` (Apache-2.0/BSD), `openpyxl`
(MIT), `reportlab` (BSD), PyInstaller (GPL with bootloader exception).
