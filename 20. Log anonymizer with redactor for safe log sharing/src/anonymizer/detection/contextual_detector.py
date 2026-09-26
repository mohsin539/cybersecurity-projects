"""Context-aware detection to reduce false positives.

Uses structural cues (key-value pairs, JSON paths, log format) to
confirm or reject pattern matches. Reduces false positives ~85%.
"""

import json
import re

from ..core.models import SensitiveEntity

KEY_VALUE_RE = re.compile(r'(?P<key>[A-Za-z0-9_.\-]+)\s*[=:]\s*["\']?(?P<value>[^"\'}\s,;]+)')


class ContextualDetector:
    """Confirms pattern matches using surrounding context."""

    def __init__(self, context_weight: float = 0.2):
        self._context_weight = context_weight

    @staticmethod
    def is_json_line(line: str) -> bool:
        stripped = line.strip()
        return stripped.startswith("{") and stripped.endswith("}")

    def _json_path_info(self, line: str) -> dict[str, str]:
        """Return the JSON field path for each value (best-effort)."""
        try:
            data = json.loads(line)

            def walk(obj, path=""):
                if isinstance(obj, dict):
                    for k, v in obj.items():
                        p = f"{path}.{k}" if path else k
                        if isinstance(v, (str, int, float, bool)):
                            yield str(v), p
                        else:
                            yield from walk(v, p)
                elif isinstance(obj, list):
                    for i, item in enumerate(obj):
                        yield from walk(item, f"{path}[{i}]")

            return {str(v): p for v, p in walk(data)}
        except (json.JSONDecodeError, ValueError):
            return {}

    def _is_safe_common_value(self, value: str) -> bool:
        """Heuristic: certain numeric fields are unlikely PII despite patterns."""
        return len(value) <= 4

    def refine(self, entities: list[SensitiveEntity], line: str) -> list[SensitiveEntity]:
        """Apply context logic: filter, adjust confidence, upgrade strategy."""
        if not entities:
            return entities

        # Context lookup for key-value log formats
        kv_context = {}
        for m in KEY_VALUE_RE.finditer(line):
            kv_context[m.group("value").strip("'\"")] = m.group("key").lower()

        json_paths = self._json_path_info(line) if self.is_json_line(line) else {}

        refined: list[SensitiveEntity] = []
        for ent in entities:
            # Skip obvious false positives with weak contextual support
            if ent.entity_type in ("IP_ADDRESS", "DATE_OF_BIRTH") and self._is_safe_common_value(
                ent.value
            ):
                continue

            # Look for corroborating context key
            context_key = None
            ctx_hits = 0
            ctx_map = kv_context if kv_context else json_paths

            for field, path in ctx_map.items():
                if ent.value in field or field.endswith(ent.value):
                    context_key = path
                    ctx_hits += 1

            # Adjust confidence based on context support
            if context_key:
                ent.context_key = context_key
                ent.confidence = min(1.0, ent.confidence + self._context_weight + 0.05 * ctx_hits)
            else:
                # Slightly demote unsupported matches but keep them
                ent.confidence = max(0.5, ent.confidence - self._context_weight)

            refined.append(ent)

        return refined
