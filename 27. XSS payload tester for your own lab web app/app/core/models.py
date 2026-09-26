"""XSS Payload Tester - data models."""
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
class Candidate:
    module: str
    category: str
    vector_name: str
    context: str
    strategy: str
    token: str
    payload: str
    method: str
    url: str
    param_name: str
    params: Dict[str, str] = field(default_factory=dict)

    @property
    def proof_url(self) -> str:
        from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode

        parsed = urlparse(self.url)
        merged = dict(parse_qsl(parsed.query, keep_blank_values=True))
        merged.update(self.params)
        return urlunparse(parsed._replace(query=urlencode(merged)))


@dataclass
class Finding:
    module: str
    title: str
    severity: str
    confidence: float
    verdict: str
    cvss_score: float
    cvss_vector: str
    owasp: str
    cwes: List[str]
    nist_controls: List[str]
    iso_controls: List[str]
    ssdf_tasks: List[str]
    remediation: str
    evidence: Dict[str, Any]
    url: str
    param: str
    vector_name: str
    context: str
    strategy: str
    payload: str
    created: float = field(default_factory=time.time)
    id: str = field(default_factory=lambda: _uid("FIND"))

    def traceability_line(self) -> str:
        return (
            f"{self.id} | {self.module} | {self.title} | {self.severity} "
            f"| OWASP {self.owasp} | CWE {','.join(self.cwes)} "
            f"| NIST {','.join(self.nist_controls)} | ISO {','.join(self.iso_controls)}"
        )