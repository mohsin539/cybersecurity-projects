"""Scan configuration model and validation (archetecture.md §7.2)."""

from __future__ import annotations

from dataclasses import dataclass

DEFAULTS = {
    "interface": "auto",
    "timeout": 1.0,
    "retries": 1,
    "workers": 16,
    "quiet": False,
    "verbose": False,
    "include_reserved": False,
    "allow_large": False,
}


class ConfigError(ValueError):
    """Raised for invalid scan configuration."""


@dataclass(frozen=True)
class ScannerConfig:
    target: str
    interface: str = DEFAULTS["interface"]
    timeout: float = DEFAULTS["timeout"]
    retries: int = DEFAULTS["retries"]
    workers: int = DEFAULTS["workers"]
    quiet: bool = DEFAULTS["quiet"]
    verbose: bool = DEFAULTS["verbose"]
    include_reserved: bool = DEFAULTS["include_reserved"]
    allow_large: bool = DEFAULTS["allow_large"]

    def validate(self) -> "ScannerConfig":
        errors: list[str] = []
        if not isinstance(self.timeout, (int, float)) or not (0.05 <= self.timeout <= 60):
            errors.append("timeout must be between 0.05 and 60 seconds")
        if not isinstance(self.retries, int) or not (0 <= self.retries <= 10):
            errors.append("retries must be an integer between 0 and 10")
        if not isinstance(self.workers, int) or not (1 <= self.workers <= 1024):
            errors.append("workers must be an integer between 1 and 1024")
        if errors:
            raise ConfigError("Invalid configuration: " + "; ".join(errors))
        return self


def build_config(**overrides) -> ScannerConfig:
    """Merge defaults with caller overrides and validate basic ranges."""
    values: dict = {}
    for key, default in DEFAULTS.items():
        values[key] = overrides.get(key, default)
    values["target"] = overrides.get("target", "")
    return ScannerConfig(**values).validate()