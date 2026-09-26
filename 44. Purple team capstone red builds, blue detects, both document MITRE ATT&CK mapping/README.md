# 🧬 Purple Team Capstone — Red Builds, Blue Detects, Both Document MITRE ATT&CK

A GUI-based purple-team platform where **Red builds attack chains**, **Blue detects them in
real time**, and **both annotate the same MITRE ATT&CK technique map** — governed by
**ISO 27001**, **NIST CSF** and **OWASP Top 10**, with one-click
**.XLSX / .CSV / .HTML** report exports.

```
Delivery
├── architecture.html            ← interactive, colorful architecture dashboard (open in a browser)
└── purple_team_app/             ← working Flask web app
    ├── app.py                   ← routes, RBAC-ready, security headers, export endpoints
    ├── models.py                ← SQLAlchemy models (cases, red_attacks, blue_detections, …)
    ├── mitre_data.py            ← seeded MITRE ATT&CK technique + ISO/NIST/OWASP control registry
    ├── seed_db.py               ← demo case "Operation Phantom Basilisk"
    ├── exports.py               ← XLSX (openpyxl) · CSV · HTML renderers + digest signing
    ├── requirements.txt
    ├── purple.db                ← auto-generated on first run
    ├── static/                  ← style.css, app.js, architecture.html (copy)
    └── templates/               ← dashboard, cases, case workspace, reports
```

## Run it

```powershell
cd purple_team_app
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000 — the seed data is loaded automatically on first run.

## The purple loop (implemented)

| # | Step | Team | MITRE action |
|---|------|------|--------------|
| 1 | Launch an attack step (pick `T-Id` from the library) | 🔴 Red | tags `red_attacks.technique_id` |
| 2 | Record the verdict (`detected` / `partial` / `missed`) | 🔵 Blue | tags `blue_detections.technique_id` |
| 3 | Platform recomputes the case **alignment score** & gap list | 🧬 Both | `case.recompute_align()` |
| 4 | Export the joint evidence pack | Both | `.XLSX` / `.CSV` / `.HTML` |

## Export endpoints

| Route | Format | Contents |
|-------|--------|----------|
| `/export/xlsx?case_id=1` | `.XLSX` | 7 sheets: Summary, MITRE Mapping, Detection Gaps, Compliance, Evidence, … (openpyxl, styled) |
| `/export/csv?kind=mapping&case_id=1` | `.CSV` | technique verdicts (RFC 4180, UTF-8 BOM) |
| `/export/csv?kind=controls` | `.CSV` | ISO 27001 / NIST CSF / OWASP control registry |
| `/export/html?case_id=1` | `.HTML` | self-contained DOSS-style report (cover, TOC, verdict badges) |

All exports are rendered from **one normalized schema** (`exports._normalize`) so formats
never disagree, and every export is recorded in the append-only audit trail.

## Framework alignment

- **ISO 27001:2022** — Annex A controls mirrored in the `controls` registry (RBAC A.5.15,
  cryptography A.8.24, secure coding A.8.28, monitoring A.5.28…) with implemented/partial status.
- **NIST CSF 2.0** — Identify/Protect/Detect/Respond/Recover (Recover=Govern) mapping in
  `controls.nist_ref` + governance module in the architecture.
- **OWASP Top 10** — enforced in the platform itself: `security_headers()` CSP/HSTS/nosniff,
  ORM (no raw SQL), server-side checks; each mapped control references its `A0x` category.

## API

- `GET /api/stats` — platform counters + average alignment
- `GET /api/audit` — last 20 audit-trail entries (ISO A.5.28)

## Demo data

`seed_db.py` creates **Operation Phantom Basilisk** — a 7-step chain (phishing → public-app
exploit → PowerShell → autostart → defense-imparing → credential dumping → lateral movement)
with realistic SIEM rule references and a small detection gap to hunt.

MITRE ATT&CK is a registered trademark of MITRE. This project uses MITRE data for
educational capstone use.