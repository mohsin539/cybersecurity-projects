"""CVSS v3.1 Base / Temporal / Environmental scoring engine.

Implements the FIRST-approved CVSS v3.1 specification:
https://www.first.org/cvss/v3.1/specification-document

Supported surface: parse and validate full CVSS v3.1 vectors and compute
Base, Temporal and Environmental scores with the official equations.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Optional

# ---------------------------------------------------------------------------
# Metric value tables (CVSS v3.1 specification)
# ---------------------------------------------------------------------------

_METRIC_VALUES: Dict[str, Dict[str, float]] = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
    "AC": {"L": 0.77, "H": 0.44},
    "PR_U": {"N": 0.85, "L": 0.62, "H": 0.27},  # scope unchanged
    "PR_C": {"N": 0.85, "L": 0.68, "H": 0.50},  # scope changed
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.00},
    # Temporal
    "E": {"U": 0.91, "P": 0.94, "F": 0.97, "H": 1.00, "X": 1.00},
    "RL": {"O": 0.95, "T": 0.96, "W": 0.97, "U": 1.00, "X": 1.00},
    "RC": {"C": 1.00, "R": 0.96, "U": 0.92, "X": 1.00},
    # Environmental
    "CR": {"L": 0.50, "M": 1.00, "H": 1.50, "X": 1.00},
    "IR": {"L": 0.50, "M": 1.00, "H": 1.50, "X": 1.00},
    "AR": {"L": 0.50, "M": 1.00, "H": 1.50, "X": 1.00},
}

_METRIC_ABBREVIATIONS = {
    "AV": "Attack Vector",
    "AC": "Attack Complexity",
    "PR": "Privileges Required",
    "UI": "User Interaction",
    "S": "Scope",
    "C": "Confidentiality Impact",
    "I": "Integrity Impact",
    "A": "Availability Impact",
    "E": "Exploit Code Maturity",
    "RL": "Remediation Level",
    "RC": "Report Confidence",
    "CR": "Confidentiality Requirement",
    "IR": "Integrity Requirement",
    "AR": "Availability Requirement",
    "MAV": "Modified Attack Vector",
    "MAC": "Modified Attack Complexity",
    "MPR": "Modified Privileges Required",
    "MUI": "Modified User Interaction",
    "MS": "Modified Scope",
    "MC": "Modified Confidentiality Impact",
    "MI": "Modified Integrity Impact",
    "MA": "Modified Availability Impact",
}

_METRIC_VALUE_MEANING = {
    "AV": {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"},
    "AC": {"L": "Low", "H": "High"},
    "PR": {"N": "None", "L": "Low", "H": "High"},
    "UI": {"N": "None", "R": "Required"},
    "S": {"U": "Unchanged", "C": "Changed"},
    "C": {"H": "High", "L": "Low", "N": "None"},
    "I": {"H": "High", "L": "Low", "N": "None"},
    "A": {"H": "High", "L": "Low", "N": "None"},
    "E": {"X": "Not Defined", "U": "Unproven", "P": "Proof-of-Concept", "F": "Functional", "H": "High"},
    "RL": {"X": "Not Defined", "O": "Official Fix", "T": "Temporary Fix", "W": "Workaround", "U": "Unavailable"},
    "RC": {"X": "Not Defined", "U": "Unknown", "R": "Reasonable", "C": "Confirmed"},
    "CR": {"X": "Not Defined", "L": "Low", "M": "Medium", "H": "High"},
    "IR": {"X": "Not Defined", "L": "Low", "M": "Medium", "H": "High"},
    "AR": {"X": "Not Defined", "L": "Low", "M": "Medium", "H": "High"},
    "MAV": {"X": "Not Defined", "N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"},
    "MAC": {"X": "Not Defined", "L": "Low", "H": "High"},
    "MPR": {"X": "Not Defined", "N": "None", "L": "Low", "H": "High"},
    "MUI": {"X": "Not Defined", "N": "None", "R": "Required"},
    "MS": {"X": "Not Defined", "U": "Unchanged", "C": "Changed"},
    "MC": {"X": "Not Defined", "H": "High", "L": "Low", "N": "None"},
    "MI": {"X": "Not Defined", "H": "High", "L": "Low", "N": "None"},
    "MA": {"X": "Not Defined", "H": "High", "L": "Low", "N": "None"},
}

_SEVERITY_THRESHOLDS = (
    (9.0, "Critical"),
    (7.0, "High"),
    (4.0, "Medium"),
    (0.1, "Low"),
    (0.0, "None"),
)


class Severity(str, Enum):
    """CVSS v3.1 qualitative severity rating."""

    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    NONE = "None"

    @property
    def hex_color(self) -> str:
        return {
            Severity.CRITICAL: "#E03131",
            Severity.HIGH: "#F76707",
            Severity.MEDIUM: "#FAB005",
            Severity.LOW: "#40C057",
            Severity.NONE: "#868E96",
        }[self]

    @property
    def css_class(self) -> str:
        return self.value.lower()


def severity_from_score(score: float) -> Severity:
    """Map a numeric score to its qualitative severity rating."""
    for threshold, label in _SEVERITY_THRESHOLDS:
        if score >= threshold:
            return Severity(label)
    return Severity.NONE


def _roundup(value: float, decimals: int) -> float:
    """CVSS roundup: round UP to nearest 10^-decimals."""
    factor = 10 ** decimals
    return math.ceil(value * factor - 1e-9) / factor


@dataclass
class BaseScore:
    """Base sub-scores (exposed for transparency / reporting)."""

    iss: float = 0.0
    impact: float = 0.0
    exploitability: float = 0.0
    score: float = 0.0
    severity: Severity = Severity.NONE


@dataclass
class CVSS3Result:
    """Fully computed CVSS v3.1 result for a given vector."""

    vector: str
    base: BaseScore = field(default_factory=BaseScore)
    temporal_score: Optional[float] = None
    environmental_score: Optional[float] = None
    valid: bool = True
    validation_errors: list = field(default_factory=list)
    metrics: Dict[str, str] = field(default_factory=dict)

    @property
    def severity(self) -> Severity:
        return self.base.severity

    @property
    def base_score(self) -> float:
        return self.base.score

    @property
    def temporal_severity(self) -> Optional[Severity]:
        if self.temporal_score is None:
            return None
        return severity_from_score(self.temporal_score)

    @property
    def environmental_severity(self) -> Optional[Severity]:
        if self.environmental_score is None:
            return None
        return severity_from_score(self.environmental_score)

    def describe_metric(self, key: str) -> str:
        meaning = _METRIC_VALUE_MEANING.get(key, {})
        value = self.metrics.get(key, "X")
        return f"{_METRIC_ABBREVIATIONS.get(key, key)}: {meaning.get(value, value)}"


class CVSS3Engine:
    """Parses and scores CVSS v3.1 vectors."""

    BASE_METRICS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
    TEMPORAL_METRICS = ("E", "RL", "RC")
    ENVIRONMENTAL_METRICS = (
        "MAV", "MAC", "MPR", "MUI", "MS", "MC", "MI", "MA", "CR", "IR", "AR",
    )

    def __init__(self, vector: str) -> None:
        self.vector = vector
        self._metrics: Dict[str, str] = {}
        self._errors: list = []
        self._scope_changed = False
        self._modified_scope_changed = False
        self._parse()

    # -- parsing -----------------------------------------------------------
    def _parse(self) -> None:
        raw = self.vector.strip()
        if not raw.upper().startswith("CVSS:3.1/"):
            self._errors.append("Vector must start with 'CVSS:3.1/'")
            return

        body = raw.split("/", 1)[1]
        if not body:
            self._errors.append("Empty metric section. Expected e.g. AV:N/AC:L/...")
            return

        allowed = self.BASE_METRICS + self.TEMPORAL_METRICS + self.ENVIRONMENTAL_METRICS
        for chunk in body.split("/"):
            chunk = chunk.strip()
            if not chunk:
                continue
            parts = chunk.split(":")
            if len(parts) != 2:
                self._errors.append(f"Malformed metric segment: '{chunk}'")
                continue
            key, value = parts[0].upper(), parts[1].upper()
            if key not in allowed:
                self._errors.append(f"Unknown metric key '{key}'.")
                continue
            if key in self._metrics:
                self._errors.append(f"Duplicate metric '{key}'.")
                continue
            self._metrics[key] = value

        self._validate_required()
        self._validate_values()
        self._scope_changed = self._metrics.get("S") == "C"
        # Modified scope reflects base scope unless explicitly overridden
        self._modified_scope_changed = self._metrics.get(
            "MS", self._metrics.get("S", "U")
        ) == "C"

    def _validate_required(self) -> None:
        for metric in self.BASE_METRICS:
            if metric not in self._metrics:
                self._errors.append(f"Missing required base metric '{metric}'.")

    _ALLOWED_VALUES = {
        "AV": ("N", "A", "L", "P"), "AC": ("L", "H"), "PR": ("N", "L", "H"),
        "UI": ("N", "R"), "S": ("U", "C"), "C": ("H", "L", "N"), "I": ("H", "L", "N"),
        "A": ("H", "L", "N"), "E": ("X", "U", "P", "F", "H"),
        "RL": ("X", "O", "T", "W", "U"), "RC": ("X", "C", "R", "U"),
        "MAV": ("X", "N", "A", "L", "P"), "MAC": ("X", "L", "H"),
        "MPR": ("X", "N", "L", "H"), "MUI": ("X", "N", "R"), "MS": ("X", "U", "C"),
        "MC": ("X", "H", "L", "N"), "MI": ("X", "H", "L", "N"), "MA": ("X", "H", "L", "N"),
        "CR": ("X", "L", "M", "H"), "IR": ("X", "L", "M", "H"), "AR": ("X", "L", "M", "H"),
    }

    def _validate_values(self) -> None:
        for key, value in self._metrics.items():
            if key in self._ALLOWED_VALUES and value not in self._ALLOWED_VALUES[key]:
                self._errors.append(f"Invalid value '{value}' for metric '{key}'.")

    def _value(self, key: str) -> float:
        """Lookup numeric value of a metric key, raising on invalid."""
        value = self._metrics.get(key)
        table_key = key
        if key == "PR":
            table_key = "PR_C" if self._scope_changed else "PR_U"
        if key in ("C", "I", "A"):
            table_key = "CIA"
        try:
            return _METRIC_VALUES[table_key][value]
        except (KeyError, TypeError):
            raise ValueError(f"Invalid value '{value}' for metric '{key}'.") from None

    def _base_metrics(self) -> Dict[str, str]:
        return {k: self._metrics.get(k) for k in self.BASE_METRICS}

    # -- scoring -----------------------------------------------------------
    def _base_scores(self) -> BaseScore:
        result = BaseScore()
        c = self._value("C")
        i = self._value("I")
        a = self._value("A")
        iss = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a)
        result.iss = iss

        if self._scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
        else:
            impact = 6.42 * iss
        result.impact = impact

        result.exploitability = (
            8.22 * self._value("AV") * self._value("AC")
            * self._value("PR") * self._value("UI")
        )

        if impact <= 0:
            result.score = 0.0
        else:
            result.score = min(_roundup(impact + result.exploitability, 1), 10.0)
        result.severity = severity_from_score(result.score)
        return result

    def _temporal_score(self, base: BaseScore) -> float:
        if base.impact <= 0:
            return 0.0
        base_roundup = min(_roundup(base.impact + base.exploitability, 1), 10.0)
        e = self._value("E")
        rl = self._value("RL")
        rc = self._value("RC")
        return min(_roundup(base_roundup * e * rl * rc, 1), 10.0)

    def _env_metric_value(self, base_key: str, modified_key: str, ms_changed: bool) -> float:
        value = self._metrics.get(modified_key, self._metrics.get(base_key))
        if value == "X" or value is None:
            value = self._metrics.get(base_key)
        if modified_key in ("MAV", "MAC", "MPR", "MUI"):
            table = {"MAV": "AV", "MAC": "AC", "MPR": "PR", "MUI": "UI"}[modified_key]
            if table == "PR":
                table = "PR_C" if ms_changed else "PR_U"
            return _METRIC_VALUES[table][value]
        if modified_key in ("MC", "MI", "MA"):
            return _METRIC_VALUES["CIA"][value]
        if modified_key in ("CR", "IR", "AR"):
            return _METRIC_VALUES[modified_key][value]
        raise ValueError(f"Unhandled modified metric {modified_key}")

    def _environmental_score(self, base: BaseScore) -> float:
        ms_changed = self._modified_scope_changed

        mc = self._env_metric_value("C", "MC", ms_changed)
        mi = self._env_metric_value("I", "MI", ms_changed)
        ma = self._env_metric_value("A", "MA", ms_changed)
        cr = self._env_metric_value("C", "CR", ms_changed)
        ir = self._env_metric_value("I", "IR", ms_changed)
        ar = self._env_metric_value("A", "AR", ms_changed)

        isc = min(1.0 - (1.0 - mc * cr) * (1.0 - mi * ir) * (1.0 - ma * ar), 0.915 if not ms_changed else 0.916)

        if ms_changed:
            impact = 7.52 * (isc - 0.029) - 3.25 * ((isc - 0.02) ** 15)
        else:
            impact = 6.42 * isc

        mav = self._env_metric_value("AV", "MAV", ms_changed)
        mac = self._env_metric_value("AC", "MAC", ms_changed)
        mpr = self._env_metric_value("PR", "MPR", ms_changed)
        mui = self._env_metric_value("UI", "MUI", ms_changed)
        exploitability = 8.22 * mav * mac * mpr * mui

        if impact <= 0:
            return 0.0
        return min(_roundup(impact + exploitability, 1), 10.0)

    def score(self) -> CVSS3Result:
        """Compute all scores for the parsed vector."""
        result = CVSS3Result(vector=self.vector, valid=self._errors == [])
        result.validation_errors = list(self._errors)
        result.metrics = dict(self._metrics)
        if not result.valid:
            return result

        base = self._base_scores()
        result.base = base
        if any((k in self._metrics for k in self.TEMPORAL_METRICS)):
            result.temporal_score = self._temporal_score(base)
        if any((k in self._metrics for k in self.ENVIRONMENTAL_METRICS)):
            result.environmental_score = self._environmental_score(base)
        return result


def score_vector(vector: str) -> CVSS3Result:
    """Convenience wrapper that parses and scores a CVSS v3.1 vector."""
    return CVSS3Engine(vector).score()