"""Shannon entropy helpers."""

from __future__ import annotations

import math
from collections import Counter


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte, 0.0 .. 8.0."""
    if not data:
        return 0.0
    c = Counter(data)
    length = len(data)
    h = 0.0
    for count in c.values():
        p = count / length
        if p > 0:
            h -= p * math.log2(p)
    return h


def classify_entropy(entropy: float) -> str:
    """Human-friendly label for an entropy value."""
    if entropy < 4.0:
        return "Low (plain text / padding)"
    if entropy < 6.0:
        return "Medium (code)"
    if entropy < 7.2:
        return "High (compressed data)"
    return "Very High (encrypted / packed)"