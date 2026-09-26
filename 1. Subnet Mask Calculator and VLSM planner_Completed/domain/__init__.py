"""Pure domain layer — zero GUI imports, fully unit-testable.

Mirrors architecture.md section 3 ("Domain: pure TypeScript → here pure Python").
"""
from .result import Err, Ok, Result
from .ip_parser import parse_cidr, parse_ipv4, parse_netmask, parse_prefix
from .ip_core import (
    SubnetInfo,
    broadcast_of,
    cidr_for_hosts,
    cidr_to_mask,
    cidr_to_wildcard,
    classify,
    describe,
    first_host,
    ip_from_octets,
    ip_to_string,
    is_private,
    last_host,
    mask_to_cidr,
    network_of,
    total_addresses,
    usable_hosts,
)
from .vlsm_planner import (
    VLSMFailure,
    VLSMGap,
    VLSMPlan,
    VLSMRequirement,
    VLSMSubnet,
    plan_vlsm,
)
from . import formatter

__all__ = [
    "Err", "Ok", "Result",
    "parse_cidr", "parse_ipv4", "parse_netmask", "parse_prefix",
    "SubnetInfo", "broadcast_of", "cidr_for_hosts", "cidr_to_mask",
    "cidr_to_wildcard", "classify", "describe", "first_host",
    "ip_from_octets", "ip_to_string", "is_private", "last_host",
    "mask_to_cidr", "network_of", "total_addresses", "usable_hosts",
    "VLSMFailure", "VLSMGap", "VLSMPlan", "VLSMRequirement", "VLSMSubnet",
    "plan_vlsm", "formatter",
]
