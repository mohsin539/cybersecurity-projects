"""JSON exporter - typed, schema-versioned evidence object for SIEM handover."""
import json
import os


def export(data, path: str) -> str:
    doc = {
        "schema": "wna.report.v1",
        "generated_at": data.generated_at,
        "app_version": data.app_version,
        "backend": data.backend,
        "summary": data.stats,
        "chain": data.chain,
        "aps": [dict(a) for a in data.aps],
        "clients": [dict(c) for c in data.clients],
        "eapol_sessions": [dict(s) for s in data.sessions],
        "findings": [dict(f) for f in data.findings],
        "audit": [dict(a) for a in data.audit],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, ensure_ascii=False)
    return path