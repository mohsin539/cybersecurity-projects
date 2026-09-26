"""Regex-based pattern matcher for PII/PHI/PCI detection."""

import re
from typing import Any

from ..core.models import DataClassification, RedactionStrategy, SensitiveEntity

# Rule definitions - each rule combines regex pattern + metadata
PII_PATTERNS: dict[str, dict[str, Any]] = {
    "SSN": {
        "pattern": r"\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b",
        "classification": DataClassification.CRITICAL,
        "strategy": RedactionStrategy.FULL_REDACT,
        "context_keys": ["ssn", "social", "tax_id", "taxid"],
    },
    "CREDIT_CARD": {
        "pattern": r"\b(?:\d{4}[- ]?){3}\d{4}\b",
        "classification": DataClassification.HIGH,
        "strategy": RedactionStrategy.PARTIAL_MASK,
        "context_keys": ["card", "ccn", "ccv", "credit"],
        "validator": "luhn",
    },
    "EMAIL": {
        "pattern": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        "classification": DataClassification.MEDIUM,
        "strategy": RedactionStrategy.TOKENIZE,
        "context_keys": ["email", "mail", "user"],
    },
    "PHONE": {
        "pattern": r"\b(\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
        "classification": DataClassification.MEDIUM,
        "strategy": RedactionStrategy.PARTIAL_MASK,
        "context_keys": ["phone", "mobile", "cell", "tel"],
    },
    "IP_ADDRESS": {
        "pattern": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        "classification": DataClassification.MEDIUM,
        "strategy": RedactionStrategy.PSEUDONYMIZE,
        "context_keys": ["ip", "address", "client_ip", "remote"],
    },
    "PASSWORD_SUSPECT": {
        "pattern": r"(?i)(password|passwd|pwd|secret)[=:]\s*[^\s,;]+",
        "classification": DataClassification.CRITICAL,
        "strategy": RedactionStrategy.FULL_REDACT,
        "context_keys": [],
    },
    "API_KEY_SUSPECT": {
        "pattern": r"(?i)(api[-_]?key|apikey|token|auth)[=:]\s*[A-Za-z0-9_\-\.]{8,}",
        "classification": DataClassification.CRITICAL,
        "strategy": RedactionStrategy.FULL_REDACT,
        "context_keys": [],
    },
    "DATE_OF_BIRTH": {
        "pattern": r"\b\d{4}[-/]\d{2}[-/]\d{2}\b",
        "classification": DataClassification.MEDIUM,
        "strategy": RedactionStrategy.PARTIAL_MASK,
        "context_keys": ["dob", "birth", "birthdate"],
    },
    "COORDINATES": {
        "pattern": r"\b(-?\d{1,3}\.\d+),\s?(-?\d{1,3}\.\d+)\b",
        "classification": DataClassification.LOW,
        "strategy": RedactionStrategy.GENERALIZE,
        "context_keys": ["lat", "lon", "coord", "gps"],
    },
    "MEDICAL_RECORD": {
        "pattern": r"\bMRN[:\s-]*\d{4,12}\b",
        "classification": DataClassification.CRITICAL,
        "strategy": RedactionStrategy.TOKENIZE,
        "context_keys": ["mrn", "medical", "patient"],
    },
}


def luhn_check(card_number: str) -> bool:
    """Validate a credit card number using the Luhn algorithm."""
    digits = [int(c) for c in card_number if c.isdigit()]
    if len(digits) < 13:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


class PatternDetector:
    """Fast-path regex-based detection. Targets ~50k lines/sec."""

    def __init__(self, rules: dict | None = None):
        self._compiled = {}
        rules = rules or PII_PATTERNS
        for name, rule in rules.items():
            self._compiled[name] = {
                "regex": re.compile(rule["pattern"]),
                "classification": rule["classification"],
                "strategy": rule["strategy"],
                "context_keys": rule.get("context_keys", []),
                "validator": rule.get("validator"),
            }

    def detect(self, line: str) -> list[SensitiveEntity]:
        """Find all pattern matches in a log line."""
        entities: list[SensitiveEntity] = []
        for entity_type, rule in self._compiled.items():
            for match in rule["regex"].finditer(line):
                value = match.group(0)

                # Optional validators (e.g., Luhn for credit cards)
                if rule["validator"] == "luhn" and not luhn_check(value):
                    continue

                entities.append(
                    SensitiveEntity(
                        entity_type=entity_type,
                        value=value,
                        start=match.start(),
                        end=match.end(),
                        confidence=0.99 if rule["validator"] == "luhn" else 0.95,
                        classification=rule["classification"],
                        strategy=rule["strategy"],
                    )
                )
        return entities
