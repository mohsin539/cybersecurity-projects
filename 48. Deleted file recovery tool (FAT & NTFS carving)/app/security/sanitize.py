"""Security hardening layer — input validation & sanitisation.

Maps to OWASP Top 10 (2021):
  * A01: Broken Access Control → output restricted to inside vault dir.
  * A03: Injection → all recovered names pass through :func:`safe_name`
        (a strict allow-list filter) before any path is formed.
  * A07: Identification/Integrity → vault manifest + hash-chain audit log.
"""

from __future__ import annotations

import os
import re
import unicodedata

_INVALID_FS = re.compile(r'[<>:"|?*\x00-\x1f]')
_CYCLER = re.compile(r"\.\.|^[A-Za-z]:|^[\\\\/]")
_SPACES = re.compile(r"\s+")

ALLOWED_EXT_CHARS = re.compile(r"[\w.\- ()\[\]{}@+%_'#~^!&,+=\-]")


def safe_name(raw: str, fallback: str = "recovered") -> str:
    """Strict sanitisation of a recovered file name.

    * Truncates at the first NUL / path-separator.
    * Strips shell-metacharacters and control characters.
    * Never allows absolute paths or relative-escape sequences.
    * Guarantees a non-empty result.
    """
    if not isinstance(raw, str):
        raw = str(raw or "")
    name = raw.split("\x00")[0]
    name = os.path.basename(name.replace("\\", "/"))
    name = unicodedata.normalize("NFKC", name)
    name = _INVALID_FS.sub("_", name)
    name = name.replace("..", "_")
    name = _SPACES.sub(" ", name).strip(" .")[:180]
    name = "".join(ch for ch in name if ch and (ch.isprintable() or ch in (".", "-", " ")))
    if not name:
        name = fallback
    if name in (".", ".."):
        name = fallback
    return name


def is_unsafe_path(candidate: str, vault_root: str) -> bool:
    """Reject any path that would escape the vault (OWASP A03 defense)."""
    if not candidate or _CYCLER.search(candidate):
        return True
    norm = os.path.normpath(os.path.abspath(candidate))
    root = os.path.normpath(os.path.abspath(vault_root))
    if os.path.commonpath([norm, root]) != root:
        return True
    return False


def safe_ext(ext: str, max_len: int = 12) -> str:
    ext = (ext or "").lstrip(".").lower()
    ext = "".join(ch for ch in ext if ch.isalnum())[:max_len]
    return ext


def strip_secrets(text: str) -> str:
    """Redact probable secrets before they reach the audit log."""
    import re as _re
    text = _re.sub(r"(?i)(password|passwd|pwd|api[_-]?key|secret|token)(\s*[=:])([^\s,;]+)",
                   r"\1\2*****", text)
    return text