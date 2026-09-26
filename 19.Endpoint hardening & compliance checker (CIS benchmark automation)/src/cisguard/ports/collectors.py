"""Collector ports — the ONLY way domain code reads system state.

Implementations must be strictly READ-ONLY (INV-2, security.md §2).
"""

from __future__ import annotations

from typing import Protocol


class RegistryCollector(Protocol):
    def read_value(self, hive: str, path: str, value: str) -> str | int | None:
        """Return value data or None if missing. Never writes."""
        ...


class ServiceCollector(Protocol):
    def query(self, name: str) -> str:
        """Return one of: Running | Stopped | Disabled | NotFound."""
        ...


class CommandCollector(Protocol):
    def run(self, argv: list[str]) -> str:
        """Run a FIXED whitelisted argv (from catalog only); return stdout."""
        ...


class AuditpolCollector(Protocol):
    def subcategory(self, name: str) -> dict[str, bool]:
        """Return {'Success': bool, 'Failure': bool} for an audit subcategory."""
        ...


class DefenderCollector(Protocol):
    def preference(self, name: str) -> str:
        """Return MPPreference value as string ('' if unavailable)."""
        ...

    def preferences(self, names: list[str]) -> dict[str, str]:
        """Batch fetch; default loops preference() unless overridden."""
        ...


class SystemCollector(Protocol):
    def hostname(self) -> str: ...

    def os_caption(self) -> str: ...
