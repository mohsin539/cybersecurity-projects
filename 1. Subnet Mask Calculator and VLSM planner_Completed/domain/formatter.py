"""Display formatting helpers (architecture.md section 6.4).

Kept import-free from the rest of the domain so ip_core can use it safely.
"""
from __future__ import annotations


def format_binary_mask(cidr: int) -> str:
    """e.g. cidr 26 -> '11111111.11111111.11111111.11000000'."""
    cidr = max(0, min(32, cidr))
    bits = "1" * cidr + "0" * (32 - cidr)
    return ".".join(bits[i:i + 8] for i in range(0, 32, 8))


def format_hex_ip(ip: int) -> str:
    return f"0x{ip & 0xFFFFFFFF:08X}"


def format_int(n: int) -> str:
    return f"{n:,}"


def format_pct(value: float) -> str:
    return f"{value:.1f}%"


def format_range(first: str, last: str) -> str:
    return first if first == last else f"{first} - {last}"
