"""Report engine (architecture §7.1, §7.3).

Composes AnalysisEngine output + sample/session metadata + compliance mapping
into a canonical report document, computes the report hash, and (when policy
sign_reports is on) records a signing audit event with a placeholder key.
Every generate/download is audit-logged (OWASP A08/A09).
"""

from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timezone

from ..crypto import IntegrityService
from . import exports


class ReportEngine:
    def __init__(self, services) -> None:
        self.services = services
        self.integrity = IntegrityService()

    def build_document(self, session_id: str, filters: dict | None = None) -> dict:
        svc = self.services
        session = svc.store.get_session(session_id)
        sample = svc.store.get_sample(session.get("sample_id", 0)) or {}
        analysis = svc.analysis.analyze(session_id)
        evidence_tags = self._evidence_tags(analysis)
        coverage = svc.compliance.coverage_summary(evidence_tags)
        matrix = svc.compliance.coverage_matrix(evidence_tags)
        now = datetime.now(timezone.utc)
        report_id = f"RPT-{now:%Y%m%d-%H%M%S}-{uuid.uuid4().hex[:6].upper()}"
        doc = {
            "report_id": report_id,
            "generated_at": int(time.time_ns()),
            "iso8601": now.isoformat(),
            "tool": "ACSV v1.0.0",
            "classification": "INTERNAL",
            "session_id": session_id,
            "policy_snapshot": session.get("policy_hash", ""),
            "sample": sample,
            "session": session,
            "filters": filters or {},
            "summary": self._exec_summary(analysis, sample, session),
            "methodology": {
                "capture": session.get("sandbox", "offline_replay"),
                "schema_version": "event@1.0",
            },
            "statistics": {
                k: v for k, v in analysis.items()
                if k in ("event_count", "unique_apis", "calls_per_second",
                         "top_apis", "categories", "statuses", "threads",
                         "findings", "high_value_ops")
            },
            "sequence": self._sequence_narrative(analysis),
            "call_graph": exports.graph_payload(analysis),
            "compliance": {
                "cover": coverage,
                "matrix": matrix,
            },
            "integrity": {
                "policy_hash": session.get("policy_hash", ""),
                "event_set_hash": self._event_set_hash(session_id),
            },
        }
        canonical = IntegrityService.canonical_bytes(doc)
        doc["report_sha256"] = self.integrity.sha256_hex(canonical)
        return doc

    def _evidence_tags(self, analysis: dict) -> list[str]:
        tags: set[str] = {
            "A.5.28", "A.8.15", "A.8.24", "A.5.33", "OWASP-A09", "OWASP-A08",
            "CSF-DETECT", "CSF-PROTECT", "SP800-53-AU-2", "SP800-53-SI-4",
        }
        for f in analysis.get("findings", []):
            tags.update(f.get("tags", []))
        return sorted(tags)

    def _event_set_hash(self, session_id: str) -> str:
        h = self.services.store.get_kv(f"hash:evts:{session_id}")
        if h:
            return h
        import hashlib as _hl
        acc = _hl.sha256()
        counter = 0
        for e in self.services.store.iter_events(session_id, limit=200000):
            acc.update(IntegrityService.canonical_bytes(e))
            counter += 1
        acc = acc.hexdigest()
        if counter:
            self.services.store.set_kv(f"hash:evts:{session_id}", acc)
        return acc

    @staticmethod
    def _exec_summary(analysis: dict, sample: dict, session: dict) -> dict:
        criticals = [f for f in analysis.get("findings", []) if f.get("severity") == "critical"]
        highs = [f for f in analysis.get("findings", []) if f.get("severity") == "high"]
        return {
            "sample_name": sample.get("name", "unknown"),
            "sample_sha256": sample.get("sha256", ""),
            "event_count": analysis.get("event_count", 0),
            "unique_apis": analysis.get("unique_apis", 0),
            "findings_total": len(analysis.get("findings", [])),
            "findings_critical": len(criticals),
            "findings_high": len(highs),
            "session_status": session.get("status", ""),
        }

    @staticmethod
    def _sequence_narrative(analysis: dict) -> str:
        top = analysis.get("top_apis", [])[:6]
        steps = " -> ".join(name for name, _ in top if name)
        return f"Dominant call path: {steps}"

    # -------------------------------------------------------------- download
    def render_and_save(self, session_id: str, fmt: str, target_dir, filters: dict | None = None) -> dict:
        svc = self.services
        fmt = fmt.lower()
        if fmt not in ("json", "csv", "html", "pdf", "stix"):
            raise ValueError(f"unsupported format: {fmt}")
        if fmt not in svc.policy.allowed_export_formats:
            raise PermissionError(f"format {fmt} disabled by policy")
        doc = self.build_document(session_id, filters)
        session = svc.store.get_session(session_id)
        name = (svc.store.get_sample(session.get("sample_id", 0)) or {}).get("name", "sample")
        safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in name)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        filename = f"ACSV-{stamp}-{safe}.{fmt}"
        content, suffix = exports.render(doc, fmt, session_id, svc)
        target = target_dir / filename
        target.write_bytes(content)
        sha256 = self.integrity.sha256_hex(content)
        svc.audit.record("REPORT_GENERATE", {
            "report_id": doc["report_id"], "session_id": session_id,
            "format": fmt, "filename": filename, "report_sha256": sha256,
            "size": len(content),
        })
        if svc.policy.sign_reports:
            svc.audit.record("REPORT_SIGN", {
                "report_id": doc["report_id"], "signature": "ed25519-pending",
            })
        svc.add_report_row(doc["report_id"], session_id, fmt, filename, sha256, len(content),
                           filters or {})
        return {"report_id": doc["report_id"], "path": str(target), "sha256": sha256,
                "size": len(content), "format": fmt}