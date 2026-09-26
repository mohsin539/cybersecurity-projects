"""Core aggregate services coherent facade.

Composes ConfigService, EventStore, AuditService, DPAPIStore, RedactionService,
ComplianceService and SampleIntake into one `AppServices` container wired by
the GUI and CLI entry points.
"""

from __future__ import annotations

from pathlib import Path

from .audit import AuditService
from .compliance import ComplianceService
from .config import ConfigService
from .crypto import DPAPIStore
from .redaction import RedactionService, default_patterns
from .store import EventStore
from .version import APP_NAME, APP_VERSION  # noqa: F401 (re-export)


class AppServices:
    def __init__(self, base_dir: Path | None = None) -> None:
        config = ConfigService(base_dir=base_dir)
        self.config = config
        self.policy = config.policy
        self.dapi = DPAPIStore(config.data_dir)
        self.store = EventStore(config.data_dir)
        patterns = config.policy.redact_patterns if config.policy else list(default_patterns())
        self.redaction = RedactionService(
            patterns=patterns, enabled=(config.policy.redact_pii if config.policy else True)
        )
        self.audit = AuditService(
            config.data_dir, self.dapi, enabled=bool(config.policy and config.policy.audit_enabled)
        )
        self.compliance = ComplianceService()
        from .analysis.engine import AnalysisEngine
        self.analysis = AnalysisEngine(self.store)
        from .report.engine import ReportEngine
        self.report_engine = ReportEngine(self)
        from .intake import SampleIntake
        self.intake = SampleIntake(self.store, self.audit)
        self.record("APP_START", {"version": APP_VERSION, "policy_hash": config.policy_snapshot_hash()})

    # ------------------------------------------------------------ shortcuts
    def record(self, action: str, payload: dict, actor: str | None = None) -> str | None:
        return self.audit.record(action, payload, actor)

    def add_report_row(self, report_id: str, session_id: str, fmt: str, filename: str,
                       sha256: str, size: int, filters: dict) -> None:
        self.store.add_report(report_id, session_id, fmt, filename, sha256, size, filters)

    def close(self) -> None:
        try:
            self.audit.record("APP_EXIT", {"clean": True})
        except Exception:
            pass
        self.audit.close()
        self.store.close()