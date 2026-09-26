"""VLSM allocation engine (architecture.md section 6.3).

Classic descending algorithm: requirements are sorted largest-first and each is
allocated the smallest aligned block that fits it. Failures do not abort the
plan — every requirement gets a result (subnet or explained failure), which is
what makes the tool useful for learning.
"""
from __future__ import annotations

from dataclasses import dataclass

from . import ip_core
from .result import Err, Ok, Result


@dataclass(frozen=True)
class VLSMRequirement:
    name: str
    hosts: int


@dataclass(frozen=True)
class VLSMSubnet:
    name: str
    hosts_needed: int
    hosts_allocated: int
    network: str
    mask: str
    cidr: int
    broadcast: str
    first_host: str
    last_host: str
    utilization: float          # percent 0-100
    start: int                  # numeric extents (overlap tests / visualizer)
    end: int


@dataclass(frozen=True)
class VLSMFailure:
    name: str
    hosts: int
    reason: str


@dataclass(frozen=True)
class VLSMGap:
    start: int
    end: int
    size: int


@dataclass(frozen=True)
class VLSMPlan:
    base_network: int
    base_cidr: int
    subnets: tuple[VLSMSubnet, ...]
    failures: tuple[VLSMFailure, ...]
    gaps: tuple[VLSMGap, ...]
    leftover_start: int | None
    leftover_end: int | None
    total_addresses: int
    allocated_addresses: int

    @property
    def used_percent(self) -> float:
        if self.total_addresses == 0:
            return 0.0
        return self.allocated_addresses / self.total_addresses * 100

    @property
    def wasted_addresses(self) -> int:
        return self.total_addresses - self.allocated_addresses


def plan_vlsm(base_ip: int, base_cidr: int,
              requirements: list[VLSMRequirement] | tuple[VLSMRequirement, ...]
              ) -> Result[VLSMPlan, str]:
    """Allocate subnets inside base_ip/base_cidr for the given requirements."""
    if not 0 <= base_cidr <= 32:
        return Err(f"Base prefix /{base_cidr} is out of range 0-32.")
    if not requirements:
        return Err("Add at least one subnet requirement.")

    base_net = ip_core.network_of(base_ip, base_cidr)
    base_bc = ip_core.broadcast_of(base_ip, base_cidr)
    total = base_bc - base_net + 1

    # Stable descending sort: equal sizes keep their input order.
    ordered = sorted(requirements, key=lambda r: -r.hosts)

    subnets: list[VLSMSubnet] = []
    failures: list[VLSMFailure] = []
    gaps: list[VLSMGap] = []
    current = base_net

    for req in ordered:
        if req.hosts < 0:
            failures.append(VLSMFailure(req.name, req.hosts,
                                        "Host count must be 0 or more."))
            continue

        cidr = ip_core.cidr_for_hosts(req.hosts)
        size = ip_core.total_addresses(cidr)

        if cidr < base_cidr:
            failures.append(VLSMFailure(
                req.name, req.hosts,
                f"Needs /{cidr} ({size:,} addresses) — larger than base /{base_cidr} "
                f"({total:,} addresses)."))
            continue

        # Align to the block boundary; any skipped space is recorded as a gap.
        if current % size:
            aligned = ((current + size - 1) // size) * size
            if aligned + size - 1 > base_bc:
                failures.append(VLSMFailure(
                    req.name, req.hosts,
                    "No aligned block boundary left inside the base network."))
                continue
            gaps.append(VLSMGap(current, aligned - 1, aligned - current))
            current = aligned

        if current + size - 1 > base_bc:
            failures.append(VLSMFailure(
                req.name, req.hosts,
                f"Needs {size:,} addresses but only "
                f"{max(0, base_bc - current + 1):,} left in the base network."))
            continue

        net = current
        bc = net + size - 1
        allocated = ip_core.usable_hosts(cidr)
        subnets.append(VLSMSubnet(
            name=req.name,
            hosts_needed=req.hosts,
            hosts_allocated=allocated,
            network=ip_core.ip_to_string(net),
            mask=ip_core.ip_to_string(ip_core.cidr_to_mask(cidr)),
            cidr=cidr,
            broadcast=ip_core.ip_to_string(bc),
            first_host=ip_core.ip_to_string(ip_core.first_host(net, cidr)),
            last_host=ip_core.ip_to_string(ip_core.last_host(net, cidr)),
            utilization=(req.hosts / allocated * 100) if allocated else 0.0,
            start=net,
            end=bc,
        ))
        current = bc + 1

    leftover_start: int | None = None
    leftover_end: int | None = None
    if current <= base_bc:
        leftover_start, leftover_end = current, base_bc

    allocated_total = sum(s.end - s.start + 1 for s in subnets)
    return Ok(VLSMPlan(
        base_network=base_net,
        base_cidr=base_cidr,
        subnets=tuple(subnets),
        failures=tuple(failures),
        gaps=tuple(gaps),
        leftover_start=leftover_start,
        leftover_end=leftover_end,
        total_addresses=total,
        allocated_addresses=allocated_total,
    ))
