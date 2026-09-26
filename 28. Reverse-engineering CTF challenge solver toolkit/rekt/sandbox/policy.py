"""Policy model + authorization (deny-by-default). OWASP A01/A04, NIST AC-3/AC-6."""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from enum import Enum


class JobKind(str, Enum):
    ANALYSIS = "ANALYSIS"        # REkt pure analyzers inside the sandboxed child
    SAMPLE_EXEC = "SAMPLE_EXEC"  # executing the untrusted sample itself
    GHIDRA = "GHIDRA"            # Ghidra headless decompilation of a scratch COPY


class RiskClass(str, Enum):
    PURE = "PURE"          # side-effect free (encoding ops)
    FS_READ = "FS_READ"    # reads the artifact only
    EXEC = "EXEC"          # runs code — needs explicit per-session consent


@dataclass(frozen=True, slots=True)
class Policy:
    """Immutable job policy. Defaults are the strictest safe profile."""

    kind: JobKind = JobKind.ANALYSIS
    timeout_s: int = 120
    max_memory_mb: int = 1024
    max_cpu_seconds: int = 60
    allow_network: bool = False          # A01: network is always denied in v1.0
    allow_write_outside_scratch: bool = False
    allow_exec: bool = False             # required for SAMPLE_EXEC
    max_output_bytes: int = 8 * 1024 * 1024

    def __post_init__(self) -> None:
        if self.timeout_s < 5 or self.timeout_s > 3600:
            raise ValueError("timeout_s out of range [5, 3600]")
        if self.max_memory_mb < 64 or self.max_memory_mb > 8192:
            raise ValueError("max_memory_mb out of range [64, 8192]")
        if self.kind is JobKind.SAMPLE_EXEC and not self.allow_exec:
            raise ValueError("SAMPLE_EXEC requires allow_exec=True")
        if self.allow_network:
            raise ValueError("network egress is not permitted in this build")  # A01 invariant
        if self.allow_write_outside_scratch:
            raise ValueError("writes outside scratch are not permitted in this build")

    def to_json(self) -> str:
        d = asdict(self)
        d["kind"] = self.kind.value
        return json.dumps(d, sort_keys=True)

    @staticmethod
    def from_json(raw: str) -> "Policy":
        d = json.loads(raw)
        d["kind"] = JobKind(d["kind"])
        return Policy(**d)


def check_consent(policy: Policy, developer_mode: bool, session_consents: set[str]) -> str | None:
    """Return a rejection reason, or None when the policy may proceed."""
    if policy.kind is JobKind.SAMPLE_EXEC and not developer_mode:
        return "Sample execution requires enabling Developer Mode this session."
    if policy.kind is JobKind.SAMPLE_EXEC and JobKind.SAMPLE_EXEC.value not in session_consents:
        return "Sample execution requires explicit per-session consent."
    if policy.kind is JobKind.GHIDRA and JobKind.GHIDRA.value not in session_consents:
        return "Ghidra analysis requires explicit confirmation for this session."
    return None
