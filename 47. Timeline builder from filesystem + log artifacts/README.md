# TimelineBuilder

Portable, GUI-based **timeline builder** that fuses **filesystem MACB metadata** with
**log artifacts** (text, JSON/JSONL, CSV/TSV, Windows EVTX) into one normalized,
integrity-verified forensic timeline - shipped as a single self-contained `.exe`.

Engineered against ISO/IEC 27001:2022, NIST SP 800-53 / 800-61 / 800-86 and the
OWASP Top 10 (2021). See [`ARCHITECTURE.html`](ARCHITECTURE.html) for the full
blueprint, [`SECURITY.md`](SECURITY.md) for the control mapping, and
[`state.md`](state.md) / [`memory.md`](memory.md) for build status and handover.

## Features

- **GUI** (PySide6/Qt6) with faceted filters, sortable event table, detail inspector, live summary and audit-chain status.
- **Collection**: filesystem B/A/C/M timestamps (platform-aware, symlink-safe) + multi-format log parsing with severity inference.
- **Normalization**: UTC conversion, de-duplication, global sort, burst correlation.
- **Case store**: indexed SQLite (WAL) with sources, events and metadata.
- **Exports**: CSV, JSON and a color-coded self-contained **HTML timeline report**.
- **Security**: SHA-256 integrity, tamper-evident audit hash chain, path validation, evidence manifests, optional AES case encryption, zero network egress.
- **CLI** for headless/automated use and **23 unit tests**.

## Quick Start

```powershell
pip install -r requirements.txt
.\run.ps1
```

Command line:

```powershell
# generate a sample case
python -m timeline_builder cli demo --dir demo_case

# collect a folder + log files into a unified timeline
python -m timeline_builder cli scan demo_case/data demo_case/logs/auth.log demo_case/logs/events.jsonl `
  --kind auto --out demo.tbcase --hashes `
  --csv out\timeline.csv --json out\timeline.json --html out\timeline.html

# verify the tamper-evident audit chain
python -m timeline_builder cli verify demo.audit.jsonl
```

Run the GUI with `python -m timeline_builder` or `.\run.ps1` (optionally `--case path\to\case.tbcase`).

## Build the Portable .exe

```powershell
.\build.ps1 -Install
# dist\TimelineBuilder.exe  +  dist\SHA256SUMS.txt
```

The script bundles Qt and resources via PyInstaller `--onefile --windowed` and
publishes a SHA-256 manifest for the binary.

## Testing

```powershell
python -m unittest discover -s tests -v
```

## Project Layout

```
src/timeline_builder/
  app.py / __main__.py / cli.py     entry points
  config.py / models.py             settings and the unified event schema
  normalizer.py / correlation.py    analytics
  collectors/                       filesystem.py, logs.py
  storage/                          case_store.py (SQLite)
  export/                           csv_exporter, json_exporter, html_exporter
  security/                         hashing, audit, validation, integrity, crypto
  ui/                               theme, models, worker, main_window
tests/                              security, collectors, pipeline
```

## Optional

- `pip install -r requirements-optional.txt` adds `python-evtx` for native `.evtx` parsing.

## License

Provided as-is for defensive forensic use. Validate against your organization's
policies before operational deployment.
