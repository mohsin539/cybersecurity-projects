"""Configuration parsing & validation (architecture.md §4.1).

Fail-fast validation happens here, before any packet is sent.
"""
from __future__ import annotations

import enum
import re
from dataclasses import dataclass, field

from .models import Proto

MAX_TARGETS = 4096                 # resource caps (security.md: DoS control)
MAX_PORT = 65535


class ScanType(enum.StrEnum):
    CONNECT = "connect"
    UDP = "udp"
    SYN = "syn"                # requires admin/root; raw socket
    FIN = "fin"                # requires admin/root; raw socket
    NULL = "null"
    XMAS = "xmas"


@dataclass(frozen=True)
class Config:
    """Immutable after validation — handed to all stages (no global state)."""
    targets: tuple[str, ...]
    exclude: tuple[str, ...]
    ports: tuple[int, ...]
    scan_type: ScanType
    workers: int
    rate_limit: float           # probes/sec, 0 = unbounded (still bounded by workers)
    timeout_s: float
    retries: int
    service_detect: bool
    output_format: str          # table | json | jsonl | csv | greppable
    output_file: str
    jitter_ms: int
    per_host_cap: int           # max in-flight probes per target
    resume_wal: str
    authorized: bool            # result of the authorization gate


class ConfigError(ValueError):
    pass


_PORT_SPEC_RE = re.compile(r"^\s*\d+\s*(?:-\s*\d+\s*)?$")

TOP_100 = (20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 88, 110, 111, 123, 135,
           137, 138, 139, 143, 161, 162, 389, 443, 445, 465, 500, 514, 515,
           548, 587, 623, 636, 873, 902, 993, 995, 1080, 1433, 1521, 1723,
           2049, 2375, 2376, 3000, 3306, 3389, 4444, 5060, 5432, 5555, 5601,
           5666, 5900, 5984, 6379, 6443, 8000, 8008, 8009, 8080, 8081, 8089,
           8443, 8888, 9200, 9300, 11211, 15672, 27017, 32768, 49152, 49154,
           49155, 54321, 55555)


def parse_ports(spec: str) -> tuple[int, ...]:
    """Parse '22,80,443,8000-9000' or profile names (top100). Bounded parse."""
    spec = spec.strip().lower()
    if spec in ("top100", "top-100"):
        return tuple(sorted(set(TOP_100)))
    if spec in ("all", "1-65535"):
        return tuple(range(1, MAX_PORT + 1))
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if not _PORT_SPEC_RE.match(part):
            raise ConfigError(f"invalid port spec fragment: {part!r}")
        if "-" in part:
            lo_s, hi_s = part.split("-", 1)
            lo, hi = int(lo_s), int(hi_s)
            if lo > hi:
                raise ConfigError(f"port range inverted: {part!r}")
        else:
            lo = hi = int(part)
        if not (1 <= lo <= MAX_PORT and 1 <= hi <= MAX_PORT):
            raise ConfigError(f"ports out of range 1-65535: {part!r}")
        ports.update(range(lo, hi + 1))
        if len(ports) > MAX_PORT:
            raise ConfigError("port expansion too large")
    if not ports:
        raise ConfigError("empty port specification")
    return tuple(sorted(ports))


def _validate_target_string(t: str) -> str:
    """Reject strings with control chars / obvious injection before anything
    touches DNS or the filesystem (OWASP A03). We do NOT parse CIDRs with
    regex beyond charset checks — ipaddress module is authoritative."""
    if len(t) > 253 + 64:  # max hostname + /NN suffix
        raise ConfigError(f"target too long: {t[:32]!r}...")
    if not re.fullmatch(r"[0-9A-Za-z.\-/:_,]+", t):
        raise ConfigError(f"target contains forbidden characters: {t[:32]!r}...")
    return t


def validate(
    targets: list[str],
    ports_spec: str,
    scan_type: str = "connect",
    *,
    workers: int = 256,
    rate_limit: float = 0.0,
    timeout_s: float = 1.0,
    retries: int = 2,
    service_detect: bool = True,
    output_format: str = "table",
    output_file: str = "-",
    jitter_ms: int = 0,
    per_host_cap: int = 32,
    resume_wal: str = "",
    authorized: bool = False,
) -> Config:
    if not targets:
        raise ConfigError("no targets given")
    if len(targets) > MAX_TARGETS:
        raise ConfigError(f"too many targets (>{MAX_TARGETS}) — reduce scope")

    cleaned = tuple(_validate_target_string(t) for t in targets)
    ports = parse_ports(ports_spec)

    try:
        st = ScanType(scan_type.lower())
    except ValueError:
        raise ConfigError(
            f"unknown scan type {scan_type!r}; "
            f"choose one of: {', '.join(t.value for t in ScanType)}"
        ) from None

    if st != ScanType.CONNECT and st != ScanType.UDP:
        if not authorized:
            raise ConfigError(
                f"scan type {st.value} requires raw sockets (admin/root) and "
                "explicit authorization confirmation (--yes / GUI checkbox)"
            )

    if not (1 <= workers <= 2048):
        raise ConfigError(f"workers out of range: {workers}")
    if not (0.05 <= timeout_s <= 60):
        raise ConfigError(f"timeout out of range 0.05-60s: {timeout_s}")
    if not (0 <= retries <= 5):
        raise ConfigError(f"retries out of range 0-5: {retries}")
    if rate_limit < 0:
        raise ConfigError("rate_limit must be >= 0")
    if output_format not in ("table", "json", "jsonl", "csv", "greppable"):
        raise ConfigError(f"unknown output format: {output_format!r}")
    if not (0 <= jitter_ms <= 1000):
        raise ConfigError("jitter must be 0-1000 ms")
    if not (1 <= per_host_cap <= 512):
        raise ConfigError("per_host_cap must be 1-512")

    return Config(
        targets=cleaned,
        exclude=(),
        ports=ports,
        scan_type=st,
        workers=workers,
        rate_limit=rate_limit,
        timeout_s=timeout_s,
        retries=retries,
        service_detect=service_detect,
        output_format=output_format,
        output_file=output_file,
        jitter_ms=jitter_ms,
        per_host_cap=per_host_cap,
        resume_wal=resume_wal,
        authorized=authorized,
    )
