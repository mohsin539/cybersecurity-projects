"""Web App Fuzzer - data models."""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


def _uid(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


@dataclass
class Parameter:
    name: str
    location: str
    value: str
    source: str = "scraped"


@dataclass
class Endpoint:
    method: str
    url: str
    params: List[Parameter] = field(default_factory=list)
    content_type: Optional[str] = None


@dataclass
class FuzzCase:
    module: str
    payload_id: str
    payload: str
    marker: str
    method: str
    url: str
    param_name: str
    location: str
    params: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    category: str = ""


@dataclass
class Finding:
    module: str
    title: str
    severity: str
    confidence: float
    owasp: str
    cwes: List[str]
    nist_controls: List[str]
    iso_controls: List[str]
    ssdf_tasks: List[str]
    remediation: str
    evidence: Dict[str, Any]
    url: str
    param: str
    payload_id: str
    created: float = field(default_factory=time.time)
    id: str = field(default_factory=lambda: _uid("FIND"))

    def traceability_line(self) -> str:
        return (
            f"{self.id} | {self.module} | {self.title} | {self.severity} "
            f"| OWASP {self.owasp} | CWE {','.join(self.cwes)} "
            f"| NIST {','.join(self.nist_controls)} | ISO {','.join(self.iso_controls)}"
        )