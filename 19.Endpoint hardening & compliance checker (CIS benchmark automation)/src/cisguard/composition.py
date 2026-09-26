"""Composition root: wire collectors (real Windows or test doubles)."""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

from cisguard.application.report_service import HistoryStore, ReportService
from cisguard.application.scan_service import ScanService


@dataclass(slots=True)
class AppContext:
    scan_service: ScanService
    reports: ReportService
    history: HistoryStore

    @classmethod
    def open(cls, data_dir: Path, *, use_test_collectors: bool = False) -> "AppContext":
        data_dir = Path(data_dir)
        data_dir.mkdir(parents=True, exist_ok=True)
        if use_test_collectors or sys.platform != "win32":
            from cisguard.infrastructure.test_collectors import (
                FakeAuditpol, FakeCommands, FakeDefender, FakeRegistry, FakeServices, FakeSystem,
            )

            scan = ScanService(
                registry=FakeRegistry({}), services=FakeServices({}),
                commands=FakeCommands({}), auditpol=FakeAuditpol({}),
                defender=FakeDefender({}), system=FakeSystem(),
            )
        else:
            from cisguard.infrastructure.windows_collectors import (
                WinAuditpolCollector, WinCommandCollector, WinDefenderCollector,
                WinRegistryCollector, WinServiceCollector, WinSystemCollector,
            )

            scan = ScanService(
                registry=WinRegistryCollector(), services=WinServiceCollector(),
                commands=WinCommandCollector(), auditpol=WinAuditpolCollector(),
                defender=WinDefenderCollector(), system=WinSystemCollector(),
            )
        return cls(
            scan_service=scan,
            reports=ReportService(),
            history=HistoryStore(data_dir / "history.db"),
        )

    def close(self) -> None:
        self.history.close()
