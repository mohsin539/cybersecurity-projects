# Red Team Engagement Report Generator

End-to-end pipeline that turns raw red team **findings** into **CVSS v3.1**
scores, cross-indexes them against **OWASP Top 10 (2021)**, **NIST SP 800-53
Rev.5** and **ISO/IEC 27001:2022**, produces an **executive summary**, and
renders board-ready reports in **.xlsx**, **.csv** and **.html**.

```
                                                          +--------------------------+
                                                          |   FRAMEWORK CATALOGS     |
  .---------------.   .-----------------.   .----------.  |  OWASP Top 10 (2021)      |
  | RAW FINDINGS  |   | CVSS v3.1 ENGINE |   | SEVERITY |  |  NIST SP 800-53 Rev.5    |
  |  JSON input   |-->|  score_vector()  |-->|  banding |--|  ISO/IEC 27001:2022      |
  | findings.csv  |   |  base/temporal/  |   |  + risk  |  +--------------------------+
  '---------------'   |  environmental   |   '----------'
                      '-----------------'         |
                                                  v
                        .---------------------------------------.
                        |  EXECUTIVE SUMMARY ANALYZER           |
                        |  metrics, narrative, recommendations  |
                        '-------------------|-------------------'
                                            v
        .-------------.    .-------------.    .----------------.
        |  CSV files  |    | XLSX book   |    | HTML dashboard |
        '-------------'    '-------------'    '----------------'
```

## Pipeline stages

| Stage | Module | Responsibility |
|---|---|---|
| 1. Parse findings | `models/finding.py` | Validate raw findings into `Finding` objects |
| 2. CVSS scoring | `models/cvss.py` | CVSS v3.1 base/temporal/environmental equations + severity |
| 3. Framework mapping | `frameworks/catalog.py` | Map finding -> OWASP -> NIST -> ISO controls |
| 4. Analysis | `analyzers/executive.py` | Risk index, narrative, prioritized remediation |
| 5. Reporting | `reporters/*` | Colorful `.xlsx`, `.csv`, `.html` output |

## Requirements & install

Requires **Python 3.10+** and `openpyxl`.

```powershell
pip install -e .[dev]      # or: pip install -r requirements.txt
pip install -e .[gui,build]  # + desktop GUI and portable-exe tooling
```

## Desktop GUI + portable .exe

A **Tkinter GUI** wraps the same pipeline — load findings JSON, preview the
CVSS-scored table, choose formats and output folder, generate, open results.
No network, no install.

```powershell
python -m redteam_report.gui          # run the GUI from source
red-team-report-gui                   # via the installed console script
.\build_exe.ps1                       # build dist\RedTeamReport.exe (PyInstaller)
```

`dist\RedTeamReport.exe` is a single-file, portable, windowed executable that
runs without a Python runtime. Build facts live in `memory.md`; hardening
notes in `security.md`; persisted state contract in `state.md`.

## Usage

```powershell
python -m redteam_report.cli sample_findings.json --out reports
python -m redteam_report.cli sample_findings.json -o reports -f html     # HTML only
python -m redteam_report.cli sample_findings.json --list-frameworks     # catalog
```

Outputs under `reports/`: `findings.csv`, `cvss_metrics.csv`,
`framework_coverage.csv`, `severity_summary.csv`, `executive_summary.csv`,
`red_team_engagement_report.xlsx` and `red_team_engagement_report.html`.

Open **`architecture.md`** for the full-color architecture (pipeline, data
model, framework alignment) and the GUI/.exe delivery design. Companion docs:
`security.md`, `state.md`, `memory.md`.

## Extending

* New findings: extend `sample_findings.json`.
* New OWASP->NIST->ISO mappings: edit `OWASP_CROSS_MAP` in
  `frameworks/catalog.py`.
* New report format: subclass `reporters/base.py` and register it in
  `pipeline.REPORTERS`.

## Tests

```powershell
python -m pytest -q
```