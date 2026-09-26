"""CSV exporter - RFC 4180, UTF-8 with BOM. One file per entity.
"""
import csv
import os


def _write(path, header, rows):
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.writer(fh, quoting=csv.QUOTE_MINIMAL)
        w.writerow(header)
        w.writerows(rows)
    return path


def export(data, directory: str) -> dict[str, str]:
    os.makedirs(directory, exist_ok=True)
    files = {
        "aps": _write(
            os.path.join(directory, "aps.csv"),
            ["bssid", "ssid", "channel", "cipher", "first_seen", "last_seen"],
            [[a[k] for k in ("bssid", "ssid", "channel", "cipher", "first_seen", "last_seen")] for a in data.aps]),
        "clients": _write(
            os.path.join(directory, "clients.csv"),
            ["mac", "bssid", "first_seen", "last_seen"],
            [[c[k] for k in ("mac", "bssid", "first_seen", "last_seen")] for c in data.clients]),
        "sessions": _write(
            os.path.join(directory, "eapol_sessions.csv"),
            ["client", "bssid", "msgs", "complete", "started", "finished"],
            [[s.get("client"), s.get("bssid"), s.get("msgs"), s.get("complete"),
              s.get("started"), s.get("finished")] for s in data.sessions]),
        "findings": _write(
            os.path.join(directory, "findings.csv"),
            ["ts", "severity", "category", "title", "bssid", "ssid", "detail"],
            [[f.get("ts"), f.get("severity"), f.get("category"), f.get("title"),
              f.get("bssid"), f.get("ssid"), f.get("detail")] for f in data.findings]),
        "audit": _write(
            os.path.join(directory, "audit.csv"),
            ["ts", "action", "detail"],
            [[a.get("ts"), a.get("action"), a.get("detail")] for a in data.audit]),
    }
    return files