"""Framework taxonomy and cross-framework mapping types.

A single finding is indexed in three security frameworks at once:

* OWASP Top 10 (2021)      -> developer/appsec weakness category
* NIST SP 800-53 Rev.5     -> security control family + control id
* ISO/IEC 27001:2022       -> Annex A (2022 revision) control

`FrameworkControl` is a generic container so that OWASP categories,
NIST controls and ISO Annex A controls share one shape for reporting.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List


@dataclass(frozen=True)
class FrameworkControl:
    """A single control / category inside a framework."""

    framework: str            # e.g. "OWASP Top 10 2021"
    code: str                 # e.g. "A03"
    name: str                 # e.g. "Injection"
    family: str               # e.g. "Application Security"
    description: str = ""
    reference_url: str = ""
    related: tuple = field(default_factory=tuple)  # related codes (e.g. NIST ids)

    @property
    def display_code(self) -> str:
        return self.code


@dataclass
class FrameworkMapping:
    """All framework coverage for a single finding."""

    finding: object
    owasp: FrameworkControl
    nist_controls: List[FrameworkControl] = field(default_factory=list)
    iso_controls: List[FrameworkControl] = field(default_factory=list)

    def all_controls(self) -> List[FrameworkControl]:
        return [self.owasp, *self.nist_controls, *self.iso_controls]

    def framework_matrix(self) -> Dict[str, str]:
        """Row for framework-coverage tables: finding -> each framework."""
        return {
            "Finding ID": self.finding.id,
            "Title": self.finding.title,
            "OWASP Top 10": self.owasp.code,
            "OWASP Category": self.owasp.name,
            "NIST Controls": ", ".join(c.code for c in self.nist_controls),
            "ISO 27001 Controls": ", ".join(c.code for c in self.iso_controls),
        }