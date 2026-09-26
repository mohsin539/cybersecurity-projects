from __future__ import annotations

import re
from pathlib import Path

MAX_PATH_LEN = 4096
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
_UNSAFE_NAME = re.compile(r'[<>:"/\\|?*\x00-\x1f]')


class ValidationError(ValueError):
    pass


def validate_source_path(path: str | Path, must_exist: bool = True) -> Path:
    if path is None:
        raise ValidationError("source path is required")
    text = str(path)
    if "\x00" in text:
        raise ValidationError("source path contains a null byte")
    if not text.strip():
        raise ValidationError("source path is empty")
    if len(text) > MAX_PATH_LEN:
        raise ValidationError("source path exceeds maximum length")
    resolved = Path(text).expanduser()
    try:
        resolved = resolved.resolve(strict=False)
    except OSError as exc:
        raise ValidationError(f"cannot resolve source path: {exc}") from exc
    if must_exist and not resolved.exists():
        raise ValidationError(f"source path does not exist: {resolved}")
    return resolved


def ensure_within(base: str | Path, target: str | Path) -> Path:
    base_resolved = Path(base).resolve(strict=False)
    target_resolved = Path(target).resolve(strict=False)
    try:
        target_resolved.relative_to(base_resolved)
    except ValueError as exc:
        raise ValidationError(f"path escapes base directory: {target_resolved}") from exc
    return target_resolved


def sanitize_filename(name: str, fallback: str = "artifact") -> str:
    if not name:
        return fallback
    cleaned = _UNSAFE_NAME.sub("_", name)
    cleaned = _CONTROL_CHARS.sub("", cleaned).strip(" .")
    if not cleaned:
        return fallback
    if len(cleaned) > 180:
        stem, dot, suffix = cleaned.rpartition(".")
        if dot and len(suffix) <= 12:
            cleaned = stem[: 180 - len(suffix) - 1] + "." + suffix
        else:
            cleaned = cleaned[:180]
    return cleaned


def clamp_int(value: int, low: int, high: int) -> int:
    return max(low, min(high, int(value)))


def validate_severity(value: str, allowed: set[str]) -> str:
    if value not in allowed:
        raise ValidationError(f"unexpected severity: {value}")
    return value
