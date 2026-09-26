"""CVSS v3.1 base score calculation (FIRST specification, vector string format).

Used so findings carry an industry-consistent severity (OWASP guidance, ISO
27001 A.8.8 risk classification). Defaults model reflected XSS:
AV:N, AC:L, PR:N, UI:R, S:C, C:L, I:L, A:N.
"""

from __future__ import annotations

from dataclasses import dataclass, field

_METRIC_OPTIONS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {"N": 0.85, "L": 0.62, "H": 0.27},
    "UI": {"N": 0.85, "R": 0.62},
    "S": {"U": 6.42, "C": 7.52},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}


@dataclass(frozen=True)
class Cvss:
    vector: str = field(default="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N")

    def parse(self) -> dict[str, str]:
        metrics: dict[str, str] = {}
        for chunk in self.vector.split("/"):
            if ":" in chunk:
                k, v = chunk.split(":", 1)
                metrics[k] = v
        return metrics

    def base_score(self) -> float:
        m = self.parse()
        av = _METRIC_OPTIONS["AV"][m.get("AV", "N")]
        ac = _METRIC_OPTIONS["AC"][m.get("AC", "L")]
        pr = _METRIC_OPTIONS["PR"][m.get("PR", "N")]
        ui = _METRIC_OPTIONS["UI"][m.get("UI", "R")]
        scope = m.get("S", "C")
        c, i, a = m.get("C", "L"), m.get("I", "L"), m.get("A", "N")

        isc_base = 1 - ((1 - _METRIC_OPTIONS["C"][c]) * (1 - _METRIC_OPTIONS["I"][i]) * (1 - _METRIC_OPTIONS["A"][a]))
        impact = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15
        impact = impact if scope == "C" else 6.42 * isc_base

        if impact <= 0:
            return 0.0
        exp = 8.22 * av * ac * pr * ui
        score = 0.0
        if scope == "U":
            score = min(impact + exp, 10.0)
        else:
            score = min(1.08 * (impact + exp), 10.0)
        return round(score, 1)

    def severity(self) -> str:
        s = self.base_score()
        if s == 0.0:
            return "info"
        if s < 4.0:
            return "low"
        if s < 7.0:
            return "medium"
        if s < 9.0:
            return "high"
        return "critical"

    @staticmethod
    def for_context(context: str, executed: bool) -> "Cvss":
        """Risk-adjust the baseline vector per injection context."""
        scope = "U" if context == "dom" else "C"
        vector = f"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:{scope}/C:L/I:L/A:N"
        return Cvss(vector=vector)


def rate(context: str, executed: bool) -> tuple[str, float, str]:
    """Return (severity, cvss_score, cvss_vector) for a reported context."""
    cvss = Cvss.for_context(context, executed)
    return cvss.severity(), cvss.base_score(), cvss.vector