"""Orchestrates all detection strategies into a unified engine.

Layered pipeline:
  1. Pattern matcher  (fast, 50k lines/s)
  2. Contextual refine (reduces false positives)
  3. ML/NER extension point (optional heavy analysis)
"""

from ..core.models import DetectionResult, SensitiveEntity
from .contextual_detector import ContextualDetector
from .pattern_matcher import PatternDetector


class DetectionEngine:
    """Unified detection pipeline with timing and diagnostics."""

    def __init__(
        self,
        pattern_detector: PatternDetector | None = None,
        contextual_detector: ContextualDetector | None = None,
        ml_detector: object | None = None,
    ):
        self.pattern_detector = pattern_detector or PatternDetector()
        self.contextual_detector = contextual_detector or ContextualDetector()
        self.ml_detector = ml_detector  # Optional pluggable ML/NER detector

    def detect(self, line: str, line_id: str | None = None) -> list[SensitiveEntity]:
        """Run full detection pipeline on one log line."""
        import time

        start = time.perf_counter()
        entities = self.pattern_detector.detect(line)

        if entities:
            entities = self.contextual_detector.refine(entities, line)

        # Optional ML pass for entities the pattern layer missed
        if self.ml_detector is not None:
            ml_entities = self.ml_detector.detect(line)
            existing = {e.value for e in entities}
            entities.extend(e for e in ml_entities if e.value not in existing)

        # Sort by position for ordered redaction
        entities.sort(key=lambda e: (e.start, e.end))
        self._last_runtime_ms = (time.perf_counter() - start) * 1000
        return entities

    def analyze(self, line: str, line_id: str | None = None) -> DetectionResult:
        """Return a full DetectionResult with metadata."""
        import time

        start = time.perf_counter()
        entities = self.detect(line, line_id)
        elapsed = (time.perf_counter() - start) * 1000

        return DetectionResult(
            line_id=line_id or str(abs(hash(line))),
            original=line,
            redacted=line,  # filled by redactor
            entities=entities,
            processing_time_ms=elapsed,
        )

    def get_last_runtime_ms(self) -> float:
        """Runtime of the most recent detection pass."""
        return getattr(self, "_last_runtime_ms", 0.0)
