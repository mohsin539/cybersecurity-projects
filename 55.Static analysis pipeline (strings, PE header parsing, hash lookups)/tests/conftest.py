"""Shared fixtures — a valid minimal PE and a scratch case directory."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from helpers import build_minimal_pe  # noqa: E402


@pytest.fixture
def minimal_pe(tmp_path: Path) -> Path:
    """A real, parseable PE32 (with suspicious embedded strings + overlay)."""
    return build_minimal_pe(tmp_path / "sample.exe")


@pytest.fixture
def not_pe(tmp_path: Path) -> Path:
    p = tmp_path / "notes.txt"
    p.write_text("hello world this is not a binary at all\n", "utf-8")
    return p


@pytest.fixture
def high_entropy_bytes() -> bytes:
    """>= MIN_HIGH_ENTROPY_LENGTH printable ASCII with entropy close to 6+."""
    import random

    rnd = random.Random(0xC0FFEE)
    alphabet = "".join(chr(i) for i in range(33, 127))
    parts = []
    while len("".join(parts)) < 256:
        parts.append("".join(rnd.choice(alphabet) for _ in range(64)))
    return "".join(parts).encode("ascii")