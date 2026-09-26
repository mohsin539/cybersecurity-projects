"""Deterministic RNG infrastructure.

Every study uses numpy SeedSequence so a given (seed, replica) reproduces
byte-identical runs. The registry is persisted on reports for replay audit
(NIST PR.DS / ISO 27001 A.8.9).
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field

import numpy as np


@dataclass
class SeedRegistry:
    """Tracks which child seeds were spawned for which experiment cell."""

    master_seed: int
    cells: list[dict] = field(default_factory=list)

    def spawn(self, cell_id: str, count: int) -> list[np.random.Generator]:
        ss = np.random.SeedSequence(self.master_seed)
        child = ss.spawn(count)
        entry = {
            "cell": cell_id,
            "master_seed": self.master_seed,
            "child_entropy": [c.entropy for c in child],
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        self.cells.append(entry)
        # numpy>=2.5: Generator() requires a BitGenerator instance, not a SeedSequence
        return [np.random.Generator(np.random.PCG64(c)) for c in child]

    def to_json(self) -> str:
        return json.dumps(
            {"master_seed": self.master_seed, "cells": self.cells}, indent=2, sort_keys=True
        )


def seed_chain(seed: int, cell: str, count: int) -> tuple[list[np.random.Generator], SeedRegistry]:
    reg = SeedRegistry(master_seed=seed % 2**32)
    return reg.spawn(cell, count), reg