"""Input parsing and validation (architecture.md section 6.1).

- parse_ipv4:      "192.168.10.77" -> 32-bit unsigned int
- parse_cidr:      "26" or "/26"   -> 0..32
- parse_netmask:   "255.255.255.192" -> prefix length (contiguity enforced)
- parse_prefix:    accepts either CIDR text or a dotted netmask (GUI convenience)
"""
from __future__ import annotations

from .result import Err, Ok, Result

MAX_OCTET = 255
MASK32 = 0xFFFFFFFF


def parse_ipv4(text: str | None) -> Result[int, str]:
    """Parse a dotted-quad IPv4 address into an unsigned 32-bit integer."""
    if text is None:
        return Err("IP address is empty.")
    s = str(text).strip()
    if not s:
        return Err("IP address is empty.")

    parts = s.split(".")
    if len(parts) != 4:
        return Err(f"'{s}' must have exactly 4 octets separated by dots (got {len(parts)}).")

    value = 0
    for i, part in enumerate(parts, start=1):
        if not part.isdigit():
            return Err(f"Octet {i} ('{part}') is not a valid number.")
        if len(part) > 3:
            return Err(f"Octet {i} ('{part}') is too long (max 3 digits).")
        if len(part) > 1 and part[0] == "0":
            return Err(f"Octet {i} ('{part}') has a leading zero.")
        n = int(part)
        if n > MAX_OCTET:
            return Err(f"Octet {i} ({n}) is out of range 0-255.")
        value = (value << 8) | n
    return Ok(value)


def parse_cidr(text: str | None) -> Result[int, str]:
    """Parse a prefix length ('26', '/26') into an int 0..32."""
    if text is None:
        return Err("Prefix length is empty.")
    s = str(text).strip().lstrip("/")
    if not s:
        return Err("Prefix length is empty.")
    if not s.isdigit():
        return Err(f"Prefix '{s}' must be a whole number 0-32.")
    if len(s) > 2:
        return Err(f"Prefix '{s}' is out of range 0-32.")
    n = int(s)
    if n > 32:
        return Err(f"Prefix /{n} is out of range 0-32.")
    return Ok(n)


def parse_netmask(text: str | None) -> Result[int, str]:
    """Parse a dotted subnet mask into a contiguous prefix length."""
    parsed = parse_ipv4(text)
    if parsed.is_err():
        return Err(f"Subnet mask: {parsed.error}")
    mask = parsed.unwrap()
    ones = bin(mask).count("1")
    expected = (MASK32 << (32 - ones)) & MASK32
    if mask != expected:
        return Err("Subnet mask is not contiguous (example of valid mask: 255.255.255.0).")
    return Ok(ones)


def parse_prefix(text: str | None) -> Result[int, str]:
    """Accept either CIDR text ('26', '/26') or a dotted mask ('255.255.255.192')."""
    if text is None:
        return Err("Prefix length is empty.")
    s = str(text).strip()
    if "." in s:
        return parse_netmask(s)
    return parse_cidr(s)
