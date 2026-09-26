"""Shared types for report generators."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict


@dataclass
class ReportResult:
    """Paths of every artifact written by a report generator."""

    format: str
    files: Dict[str, Path] = field(default_factory=dict)

    def add(self, kind: str, path: Path) -> None:
        self.files[kind] = path

    @property
    def primary(self) -> Path:
        if self.files:
            return next(iter(self.files.values()))
        return Path("")


class BaseReporter:
    """Common contract shared by all report generators."""

    def __init__(self, output_dir: Path) -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _stamp(self, name: str, ext: str) -> Path:
        return self.output_dir / f"{name}.{ext}"

    def write(self, findings, summary, mappings) -> ReportResult:
        raise NotImplementedError