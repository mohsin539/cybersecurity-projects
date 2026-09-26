"""Per-process traffic attribution port.

Attribution is *derived*: operating systems do not expose "bytes used by
process X" directly, so an adapter samples cumulative per-process I/O
counters at two instants and reports the delta over the elapsed wall time.
The application layer consumes the normalised deltas only.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict


@dataclass(frozen=True)
class ProcessTrafficDelta:
    """Bytes a single process transferred during one sampling interval."""

    pid: int
    name: str
    bytes_sent: int  # >= 0, clamped by the adapter
    bytes_recv: int  # >= 0, clamped by the adapter


class ProcessTrafficPort(ABC):
    """Port for sampling per-process network I/O counters."""

    @abstractmethod
    def sample(self) -> Dict[int, ProcessTrafficDelta]:
        """Return per-process byte deltas since the previous call.

        The first invocation on a fresh sampler establishes a baseline and
        therefore returns all-zero deltas. Implementations must be safe to
        call repeatedly on a background thread.
        """
