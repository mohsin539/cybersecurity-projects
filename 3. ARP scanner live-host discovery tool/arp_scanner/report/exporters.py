"""CSV / JSON export with atomic writes and injection hardening
(archetecture.md §8; security.md OWASP A03)."""

from __future__ import annotations

import csv
import io
import json
import os
import tempfile
from pathlib import Path

from arp_scanner.core.result import ScanResult
from arp_scanner.security.guard import sanitize_cell

_CSV_COLUMNS = ("ip", "mac", "vendor", "rtt_ms", "interface")


def result_to_csv(result: ScanResult) -> str:
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer)
    writer.writerow(_CSV_COLUMNS)
    for host in result.hosts_sorted:
        writer.writerow(
            [
                sanitize_cell(host.ip),
                sanitize_cell(host.mac),
                sanitize_cell(host.vendor or "unknown"),
                sanitize_cell(f"{host.rtt_ms:.2f}"),
                sanitize_cell(host.interface),
            ]
        )
    return buffer.getvalue()


def result_to_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2, sort_keys=True) + "\n"


def write_export(path: str, result: ScanResult, fmt: str) -> Path:
    """Atomically write result in csv|json format. The temp file lives in the
    same directory so os.replace() is atomic (ISO 27001 A.12.5 availability)."""
    fmt = (fmt or "").lower()
    if fmt == "json" or path.lower().endswith(".json"):
        content = result_to_json(result)
    else:
        content = result_to_csv(result)

    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=str(target.parent))
    try:
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
                fh.write(content)
                fh.flush()
                os.fsync(fh.fileno())
        except Exception:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise
        os.replace(tmp_name, target)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
    return target