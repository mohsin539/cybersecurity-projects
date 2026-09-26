"""Core redaction engine implementing all anonymization strategies.

Supported strategies (ISO 27001 A.8.11 Data Masking aligned):
  - FULL_REDACT     : complete value replacement
  - PARTIAL_MASK    : keep last N chars, mask the rest
  - TOKENIZE        : reversible surrogate via secure hash
  - PSEUDONYMIZE    : deterministic non-reversible alias (analytics)
  - GENERALIZE      : bucket/range based generalization
  - DATE_SHIFT      : temporal offset preserving trends
  - CONTEXTUAL      : structural placeholder replacement
"""

import hashlib
import hmac
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import ClassVar

from ..core.models import RedactionStrategy, SensitiveEntity


@dataclass
class RedactionContext:
    """Runtime context for the redaction pass."""

    policy_id: str = "default"
    date_shift_days: int = 0  # for DATE_SHIFT
    generalization_map: dict[str, str] = field(default_factory=dict)
    token_salt: str = ""  # per-tenant salt
    token_prefix: str = "TOK_"
    keep_last_chars: int = 4  # for PARTIAL_MASK
    mask_char: str = "*"
    default_placeholder: str = "[REDACTED]"


class Redactor:
    """Applies the correct strategy to each detected entity."""

    def __init__(
        self,
        context: RedactionContext | None = None,
        token_callback: Callable[[str], str] | None = None,
    ):
        self.context = context or RedactionContext()
        self._token_callback = token_callback

    # ---- Strategy implementations ----

    def _full_redact(self, value: str, entity: SensitiveEntity) -> str:
        return self.context.default_placeholder

    def _partial_mask(self, value: str, entity: SensitiveEntity) -> str:
        keep = self.context.keep_last_chars
        if len(value) <= keep:
            return value
        visible = value[-keep:]
        mask_count = len(value) - keep
        return self.context.mask_char * mask_count + visible

    def _tokenize(self, value: str, entity: SensitiveEntity) -> str:
        # Prefer a caller-provided vault callback (reversible token)
        if self._token_callback:
            return self._token_callback(value)
        # Fallback: deterministic HMAC-derived token (non-reversible)
        return self._hmac_token(value, entity.entity_type)

    def _hmac_token(self, value: str, entity_type: str) -> str:
        payload = f"{entity_type}:{value}".encode()
        digest = hmac.new(
            key=self.context.token_salt.encode() or b"anonymizer",
            msg=payload,
            digestmod=hashlib.sha256,
        ).hexdigest()[:16]
        return f"{self.context.token_prefix}{digest}"

    def _pseudonymize(self, value: str, entity: SensitiveEntity) -> str:
        # Stable alias, suitable for analytics cross-referencing
        digest = hashlib.blake2b(
            f"{self.context.token_salt}:{value}".encode(), digest_size=8
        ).hexdigest()
        return f"P-{digest.upper()}"

    def _generalize(self, value: str, entity: SensitiveEntity) -> str:
        if entity.entity_type == "COORDINATES":
            return self._generalize_coordinates(value)
        if value in self.context.generalization_map:
            return self.context.generalization_map[value]
        return self._range_value(value)

    @staticmethod
    def _generalize_coordinates(value: str) -> str:
        tokens = re.findall(r"-?\d+\.\d+", value)
        out = []
        for tok in tokens[:2]:
            coord = float(tok)
            out.append(f"{round(coord - 0.5, 1)}-{round(coord + 0.5, 1)}")
        return "; ".join(out) if out else "[GENERALIZED]"

    @staticmethod
    def _range_value(raw: str) -> str:
        """Generalize a numeric value into a coarse range (k-anonymity).

        If the value sits exactly on a bucket boundary the window is
        shifted one bucket down so the exact value is never exposed as
        a range endpoint.
        """
        cleaned = re.sub(r"[^\d.]", "", raw)  # strip letters/signs/space
        try:
            num = float(cleaned)
        except ValueError:
            return "[GENERALIZED]"
        # Determine magnitude for coarse bucketing
        if num >= 1_000_000:
            bucket = 250_000
        elif num >= 10_000:
            bucket = 5_000
        else:
            bucket = 100
        start = int(num // bucket) * bucket
        if num - start == 0 and num != 0:
            start = int((num - bucket) // bucket) * bucket
        return f"{start}-{start + bucket - 1}"

    def _date_shift(self, value: str, entity: SensitiveEntity) -> str:
        import datetime as dt

        if self.context.date_shift_days == 0:
            return self.context.default_placeholder
        # Preserve date-only vs datetime rendering
        date_only = re.fullmatch(r"\d{4}-\d{2}-\d{2}", value) is not None
        try:
            if date_only:
                parsed = dt.date.fromisoformat(value)
                return (parsed + dt.timedelta(days=self.context.date_shift_days)).isoformat()
            parsed = dt.datetime.fromisoformat(value)
            return (parsed + dt.timedelta(days=self.context.date_shift_days)).isoformat()
        except ValueError:
            return self.context.default_placeholder

    def _contextual(self, value: str, entity: SensitiveEntity) -> str:
        return entity.context_key or "[ID]"

    # ---- Dispatch ----

    _STRATEGY_MAP: ClassVar[dict] = {
        RedactionStrategy.FULL_REDACT: _full_redact,
        RedactionStrategy.PARTIAL_MASK: _partial_mask,
        RedactionStrategy.TOKENIZE: _tokenize,
        RedactionStrategy.PSEUDONYMIZE: _pseudonymize,
        RedactionStrategy.GENERALIZE: _generalize,
        RedactionStrategy.DATE_SHIFT: _date_shift,
        RedactionStrategy.CONTEXTUAL: _contextual,
    }

    def redact(self, line: str, entities: list[SensitiveEntity]) -> str:
        """Apply redaction to a log line, replacing matches in order."""
        if not entities:
            return line

        # Work right-to-left so index offsets stay valid
        chunks = []
        cursor = len(line)
        for ent in reversed(entities):
            strategy = self._STRATEGY_MAP.get(ent.strategy, self._full_redact)
            replacement = strategy(self, ent.value, ent)
            chunks.append(line[ent.end : cursor])
            chunks.append(replacement)
            cursor = ent.start
        chunks.append(line[:cursor])
        return "".join(reversed(chunks))

    def redact_many(self, line: str, entities: list[SensitiveEntity]) -> str:
        """Alias with overlap merging (no overlapping replacements)."""
        # Merge overlapping entities (keep higher-confidence)
        merged: list[SensitiveEntity] = []
        for ent in sorted(entities, key=lambda e: (e.start, -e.confidence)):
            if merged and ent.start < merged[-1].end:
                # Overlap: keep the more confident / higher-class one
                if ent.confidence > merged[-1].confidence:
                    merged[-1] = ent
                continue
            merged.append(ent)
        return self.redact(line, merged)


def apply_redaction(line: str, entities: list[SensitiveEntity]) -> str:
    """Convenience one-shot function."""
    return Redactor().redact(line, entities)
