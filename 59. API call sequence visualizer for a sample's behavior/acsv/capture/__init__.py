"""Capture / ingest layer (architecture §5.1).

v1 ships non-intrusive capture:
- `generator` produces deterministic synthetic API traces (benign corpus).
- `importer` ingests Procmon PML, API-Monitor XML, ACSV JSON/CSV traces.
- `runner` orchestrates capture sessions (timeout, event caps, teardown).
- `etw` documents the native ETW + hook-engine extension point (v1.1+).

No executable sample is ever launched from the host by default (OWASP A04 /
ISO A.5.10).
"""