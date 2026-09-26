"""Core anonymization service tying everything together."""

import json
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from ..core.models import DetectionResult, RedactionStrategy, SensitiveEntity
from ..detection import DetectionEngine
from ..redaction import RedactionContext, Redactor
from ..security import AuditTrail, InputValidator
from .policy_engine import LoadedPolicy, PolicyEngine


@dataclass
class AnonymizationRequest:
    """User request model."""

    lines: list[str]
    policy_id: str = "default"
    date_shift_days: int = 0
    token_salt: str | None = None


@dataclass
class AnonymizationResult:
    """Output of the pipeline for one request."""

    request_id: str
    policy_id: str
    redacted_lines: list[str]
    entity_stats: dict = field(default_factory=dict)
    total_processing_ms: float = 0.0
    audit_events: int = 0
    chain_root: str = ""


class AnonymizerService:
    """Stateless orchestration layer with pluggable dependencies."""

    def __init__(
        self,
        detection_engine: DetectionEngine | None = None,
        redactor: Redactor | None = None,
        audit_trail: AuditTrail | None = None,
        validator: InputValidator | None = None,
        policy_engine: PolicyEngine | None = None,
        policy_file: str | None = None,
    ):
        self.detection = detection_engine or DetectionEngine()
        self.validator = validator or InputValidator()
        self.audit = audit_trail or AuditTrail()
        self.policies = policy_engine or PolicyEngine()
        self._base_redactor = redactor or Redactor()

        if not self.policies.list_ids():
            self.policies.register(
                LoadedPolicy(
                    id="default",
                    description="Secure-by-default: all PII fully redacted",
                    allowed_data_classes=["SAFE", "LOW"],
                    rules=[],
                )
            )

        # Load additional policies from config if present
        self._load_policy_config(policy_file)

    def _load_policy_config(self, policy_file: str | None = None) -> None:
        # Resolve config relative to the caller's cwd OR the package root
        package_root = Path(__file__).resolve().parents[3]
        candidates = []
        if policy_file:
            candidates.append(policy_file)
        candidates.extend(
            [
                "config/policies.json",
                "config/policies.yaml",
                str(package_root / "config" / "policies.json"),
                str(package_root / "config" / "policies.yaml"),
            ]
        )
        for path in candidates:
            p = Path(path)
            if not p.exists():
                continue
            if p.suffix == ".json":
                with open(p, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                for policy_data in data.get("policies", []):
                    self.policies.register(PolicyEngine.from_dict(policy_data))
                return
            # Optional YAML support when PyYAML is available
            try:
                import yaml
            except ImportError:
                continue
            with open(p, "r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
            for policy_data in data.get("policies", []):
                policy = PolicyEngine.from_dict(policy_data)
                self.policies.register(policy)
            return

    def anonymize(self, request: AnonymizationRequest) -> AnonymizationResult:
        """Run the full pipeline: validate -> detect -> redact -> audit."""
        start = time.perf_counter()
        request_id = str(uuid.uuid4())
        policy = self.policies.get(request.policy_id) or self.policies.get("default")

        # 1. Validate (OWASP A03)
        lines = self.validator.validate_batch(request.lines)

        redactor = Redactor(
            context=RedactionContext(
                policy_id=policy.id,
                date_shift_days=request.date_shift_days,
                token_salt=request.token_salt or "",
            )
        )

        redacted_lines = []
        entity_counts = {}
        audit_events = 0

        for line in lines:
            # 2. Detect
            result: DetectionResult = self.detection.analyze(line)

            # 3. Policy resolution: adjust strategy per policy
            resolved_entities: list[SensitiveEntity] = []
            for ent in result.entities:
                # Explicit date-shift request overrides policy (temporal analysis)
                if request.date_shift_days and ent.entity_type in (
                    "DATE_OF_BIRTH",
                    "TIMESTAMP",
                ):
                    ent.strategy = RedactionStrategy.DATE_SHIFT
                else:
                    ent.strategy = policy.strategy_for(
                        ent.entity_type, ent.classification, ent.strategy
                    )
                resolved_entities.append(ent)

            # 4. Redact
            redacted = redactor.redact_many(line, resolved_entities)
            redacted_lines.append(redacted)

            # 5. Audit each redaction (tamper-evident, immutable)
            for ent in resolved_entities:
                original_piece = line[ent.start : ent.end]
                if original_piece != ent.value:
                    original_piece = ent.value
                redacted_piece = redacted
                self.audit.record_redaction(
                    original_value=original_piece,
                    redacted_value=redacted_piece,
                    action="REDACT" if ent.strategy.name != "TOKENIZE" else "TOKENIZE",
                    data_class=ent.classification.name,
                    entity_type=ent.entity_type,
                    policy_applied=policy.id,
                    confidence=ent.confidence,
                    search_salt=request.token_salt,
                )
                entity_counts[ent.entity_type] = entity_counts.get(ent.entity_type, 0) + 1
                audit_events += 1

        elapsed = (time.perf_counter() - start) * 1000
        return AnonymizationResult(
            request_id=request_id,
            policy_id=policy.id,
            redacted_lines=redacted_lines,
            entity_stats=entity_counts,
            total_processing_ms=round(elapsed, 2),
            audit_events=audit_events,
            chain_root=self.audit.chain_root,
        )
