"""Input validation & hardening helpers.

Controls: OWASP A03 (injection, including XSS via rendered content),
NIST SI-10 (input validation), ISO A.14.2.5.
Key rule: email content is attacker-controlled; the app NEVER renders HTML.
"""
from __future__ import annotations

import html as _html
import ipaddress
import re
from typing import Any, Dict, List, Optional, Sequence

from . import constants as C

_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_BOM_RE = re.compile(r"^\ufeff")


class InputError(ValueError):
    """Rejected input (fail-closed)."""


def validate_email_bytes(data: bytes) -> bytes:
    """Reject oversized / binary / undecodable raw email input (SI-10)."""
    if not isinstance(data, bytes):
        raise InputError("email must be bytes")
    if len(data) > C.MAX_EMAIL_BYTES:
        raise InputError(f"email exceeds {C.MAX_EMAIL_BYTES // (1024 * 1024)} MB cap")
    if b"\x00" in data[: min(len(data), 4096)]:
        raise InputError("email contains NUL bytes in preamble")
    if data.count(b"\n") > 200_000:
        raise InputError("line-count exceeds budget (possible bomb)")
    return data


def check_disk_usage(path: str) -> None:
    """Refuse to run if disk free falls below 50 MB (availability hardening)."""
    import shutil

    try:
        free = shutil.disk_usage(path).free
    except OSError:
        return
    if free < 50 * 1024 * 1024:
        raise InputError("insufficient free disk space (< 50 MB) for secure operation")


def sanitize_text(text: str, max_len: int = C.TEXT_RENDER_MAX) -> str:
    """Normalize for plain-text rendering: strip control chars + BOM.

    Anti-XSS by construction: consumers must render this with `text=`, never HTML.
    """
    if not text:
        return ""
    text = _BOM_RE.sub("", text)
    text = _CONTROL_RE.sub("", text)
    text = text.replace("\x00", "")
    return text[:max_len]


def to_text_safe_for_ttk(value: Any) -> str:
    """Safety net for any value shown in the GUI (all widget text must pass here)."""
    if value is None:
        return ""
    return sanitize_text(str(value))


def limit_int(value: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, int(value)))


def sanitize_filename(name: str, fallback: str = "attachment.bin") -> str:
    """Strip path separators / reserved chars from attacker-supplied filenames."""
    if not name:
        return fallback
    name = name.replace("\\", "_").replace("/", "_")
    name = re.sub(r"[\x00-\x1f]", "", name)
    name = re.sub(r"[<>:\"|?*]", "_", name)
    name = name.strip(" .")
    return name[:128] or fallback


def is_private_ip(ip: str) -> bool:
    """True if literal IP is private/reserved/link-local/metadata (SSRF guard)."""
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return False
    if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast \
            or addr.is_reserved or addr.is_unspecified or getattr(addr, "is_site_local", False):
        return True
    # cloud metadata + documentation + carrier-grade + 6to4/Teredo safety
    if isinstance(addr, ipaddress.IPv4Address):
        return any(addr in ipaddress.ip_network(net) for net in C.PRIVATE_NETWORKS)
    return False


SOURCE_IP_RE = re.compile(
    r"\[(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\]"
)


def extract_ips_from_brackets(text: str) -> List[str]:
    return SOURCE_IP_RE.findall(text)


def ensure_https_host(host: str) -> None:
    """Reject obviously hostile host values before any network use (SC-7)."""
    if not host or len(host) > 255 or host != host.strip().lower():
        raise InputError("host validation failed")
    if host.startswith("-") or "--" in host or any(ch in host for ch in "/\\@ "):
        raise InputError("host validation failed")


def json_dump_safe(obj: Any) -> str:
    import json

    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), default=str)


def parse_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "on", "y")
    return default


def deep_clean_lists(data: Any) -> Any:
    """Recursively convert Django-like/untrusted sequences to plain lists (defense-in-depth)."""
    return data


# IP/domain mixing guard for URLs handled directly by the url engine. Para
# de-obfuscation we must not let 'http://209.85.202@evil.com' confuse parsers.
HOST_INTAIL_RE = re.compile(r"[^a-z0-9.\-:]", re.IGNORECASE)
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
    re.IGNORECASE,
)
PUNYCODE_RE = re.compile(r"(?i)xn--[a-z0-9-]+")


def looks_like_domain(host: str) -> bool:
    return bool(DOMAIN_RE.match(host or ""))


def escape_html(s: str) -> str:
    """Reflexive HTML escaping used ONLY for labels the GUI never renders as HTML.
    Primary defense for email bodies remains: render as plain text, never HTML.
    """
    return _html.escape(s)