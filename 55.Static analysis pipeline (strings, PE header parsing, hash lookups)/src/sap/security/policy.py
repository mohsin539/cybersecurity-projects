"""PolicyGuard — single chokepoint for evidence integrity + zone containment.

Enforces (architecture.md §9.1/§9.2):
- samples open READ-ONLY (no O_CREAT / O_TRUNC / O_WRONLY ever present)
- all writes are contained inside one reserved sandbox root
- intel egress is gated: disabled by default, allowlisted hosts only,
  sha256-hex payloads only, daily cap enforced
- sample size + magic-based format gates fail closed
"""
from __future__ import annotations

import re
from pathlib import Path

import os


class PolicyViolation(Exception):
    """Any policy rule broken — pipeline must fail closed."""


O_BINARY = getattr(os, "O_BINARY", 0)

# Architecture.md §5.1 / §15: default sample cap 2 GiB (configurable).
DEFAULT_MAX_SAMPLE_BYTES = 2 * 1024 * 1024 * 1024

# Known PE magic suffixes used for format gating.
PE_MAGIC = (b"MZ",)

_SHA256_RE = re.compile(r"[0-9a-fA-F]{64}")


def open_evidence(path: str | os.PathLike) -> int:
    """Open a sample for READ-ONLY access only.

    The fd contract is enforced at the operating-system level: the flags passed
    to os.open() can never create, truncate or write the file.
    """
    fd = os.open(os.fspath(path), os.O_RDONLY | O_BINARY)
    return fd


def gate_sample_size(size_bytes: int, max_bytes: int = DEFAULT_MAX_SAMPLE_BYTES) -> None:
    """Fail closed on absurd/zero/negative sizes (DoS guard, architecture.md §15)."""
    if not isinstance(size_bytes, int) or size_bytes <= 0:
        raise PolicyViolation(f"sample size {size_bytes!r} is not a positive integer")
    if size_bytes > max_bytes:
        raise PolicyViolation(f"sample size {size_bytes} exceeds policy cap {max_bytes}")


def gate_pe_magic(head: bytes) -> bool:
    """True when the leading bytes look like a PE (MZ). Non-blocking signal."""
    return head.startswith(PE_MAGIC)


class SandboxPolicy:
    """Bounds every write operation to a single reserved writable root."""

    def __init__(self, root: str | os.PathLike):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def resolve(self, *parts: str) -> Path:
        """Resolve a path and guarantee it stays inside the sandbox root."""
        p = self.root.joinpath(*parts).resolve()
        if p != self.root and self.root not in p.parents:
            raise PolicyViolation(f"path escapes the reserved sandbox root: {p}")
        return p

    def write(self, *parts: str) -> Path:
        """Resolve + create parent dirs for an in-sandbox write target."""
        p = self.resolve(*parts)
        p.parent.mkdir(parents=True, exist_ok=True)
        return p


class EgressGate:
    """Hashed-only, allowlisted, throttled egress (architecture.md §8.2).

    Default policy is DENY. Lookups can be switched on explicitly per-org,
    still constrained to allowlisted hosts, sha256-hex payloads and a daily cap.
    """

    DEFAULT_ALLOWLIST = (
        "api.virustotal.com",
        "misp.example.org",
        "urlhaus.abuse.ch",
        "threatfox.abuse.ch",
    )

    def __init__(
        self,
        allowed: bool = False,
        daily_cap: int = 500,
        allowlist: tuple[str, ...] = DEFAULT_ALLOWLIST,
    ):
        self.allowed = bool(allowed)
        self.daily_cap = int(daily_cap)
        self.allowlist = tuple(allowlist)
        self._count = 0

    @property
    def used(self) -> int:
        return self._count

    def check(self, host: str, payload: str) -> None:
        """Validate one egress call. Raises PolicyViolation on any breach."""
        if not self.allowed:
            raise PolicyViolation("intel egress disabled by policy (offline-first)")
        if host not in self.allowlist:
            raise PolicyViolation(f"intel host not allowlisted: {host!r}")
        if self._count >= self.daily_cap:
            raise PolicyViolation(f"daily egress cap exceeded ({self.daily_cap})")
        if not _SHA256_RE.fullmatch(payload):
            raise PolicyViolation("egress payload must be a sha256 hex digest (hashes only)")
        self._count += 1