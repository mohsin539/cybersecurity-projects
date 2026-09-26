"""Shared test fixtures + helpers."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from acsv.config import ConfigService  # noqa: E402
from acsv.store import EventStore  # noqa: E402
from acsv.crypto import DPAPIStore  # noqa: E402
from acsv.audit import AuditService  # noqa: E402
from acsv.redaction import RedactionService  # noqa: E402
from acsv.compliance import ComplianceService  # noqa: E402
from acsv.services import AppServices  # noqa: E402


@pytest.fixture(scope="session")
def base_dir():
    return ROOT


@pytest.fixture
def services(tmp_path):
    root = tmp_path / "root"
    (root / "data").mkdir(parents=True, exist_ok=True)
    svc = AppServices(base_dir=root)
    yield svc
    svc.close()


@pytest.fixture
def sample(services):
    return services.intake.register_virtual(name="t.bin")