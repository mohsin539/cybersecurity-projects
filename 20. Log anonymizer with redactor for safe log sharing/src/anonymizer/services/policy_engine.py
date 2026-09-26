"""Policy engine - declarative redaction policy management.

Policies determine which data classes are permitted in a log-sharing
destination and which redaction strategy applies (ISO 27001 A.5.12,
Data Minimization / GDPR Art. 5).
"""

import json
from dataclasses import dataclass, field

from ..core.models import DataClassification, RedactionStrategy


@dataclass
class RedactionRule:
    """One rule inside a policy."""

    strategy: RedactionStrategy
    apply_to: list[str] = field(default_factory=list)  # entity types, e.g. ["EMAIL"]
    data_classes: list[str] = field(default_factory=list)  # e.g. ["MEDIUM"]
    fallback: RedactionStrategy | None = None


@dataclass
class LoadedPolicy:
    """A parsed sharing policy."""

    id: str
    description: str
    allowed_data_classes: list[str]
    rules: list[RedactionRule]
    export_format: str = "json"
    retention_days: int = 30
    approval_required: bool = True
    audit_all_access: bool = True

    def allows(self, classification: DataClassification) -> bool:
        return classification.name in self.allowed_data_classes

    def strategy_for(
        self,
        entity_type: str,
        classification: DataClassification,
        default_strategy: RedactionStrategy,
    ) -> RedactionStrategy:
        for rule in self.rules:
            if entity_type in rule.apply_to or classification.name in rule.data_classes:
                return rule.strategy
        # If class not permitted at all, force full redaction (defense in depth)
        if not self.allows(classification):
            return RedactionStrategy.FULL_REDACT
        return default_strategy or RedactionStrategy.FULL_REDACT


class PolicyEngine:
    """Loads and resolves redaction policies."""

    def __init__(self, default_policy: LoadedPolicy | None = None):
        self._policies: dict[str, LoadedPolicy] = {}
        if default_policy:
            self._policies[default_policy.id] = default_policy

    def register(self, policy: LoadedPolicy) -> None:
        self._policies[policy.id] = policy

    @classmethod
    def from_dict(cls, data: dict) -> LoadedPolicy:
        # Accept either a single policy dict or a {"policies": [...]} wrapper
        if isinstance(data, dict) and "policies" in data:
            policies = data["policies"]
            if len(policies) != 1:
                raise ValueError("from_dict accepts a single policy; use from_json for multiples")
            data = policies[0]

        rules = [
            RedactionRule(
                strategy=RedactionStrategy[rule_raw["strategy"]],
                apply_to=rule_raw.get("apply_to", []),
                data_classes=rule_raw.get("data_classes", []),
                fallback=RedactionStrategy[rule_raw["fallback"]]
                if rule_raw.get("fallback")
                else None,
            )
            for rule_raw in data.get("redaction_rules", [])
        ]
        return LoadedPolicy(
            id=data["id"],
            description=data.get("description", ""),
            allowed_data_classes=data.get("allowed_data_classes", []),
            rules=rules,
            export_format=data.get("export_format", "json"),
            retention_days=data.get("retention_days", 30),
            approval_required=data.get("approval_required", True),
            audit_all_access=data.get("audit_all_access", True),
        )

    @classmethod
    def from_json(cls, path: str) -> "PolicyEngine":
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        engine = cls()
        for policy_data in data.get("policies", []):
            engine.register(cls.from_dict(policy_data))
        return engine

    def get(self, policy_id: str) -> LoadedPolicy | None:
        return self._policies.get(policy_id)

    def list_ids(self) -> list[str]:
        return list(self._policies.keys())
