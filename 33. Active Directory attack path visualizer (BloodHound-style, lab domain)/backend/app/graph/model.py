"""Domain model for the AD graph (BloodHound-style schema, condensed).

Node kinds: user, group, computer, domain, gpo, ou, container
Edge kinds (with BloodHound equivalents):
    member_of            (MemberOf)
    admin_on / rdp_on    (AdminTo / CanRDP)
    owns                 (Owns)
    all_extended_rights  (AllExtendedRights)
    force_change_pw      (ForceChangePassword)
    add_member           (AddMember)
    dcsync               (DCSync)
    generic_all          (GenericAll)
    generic_write        (GenericWrite)
    write_dacl           (WriteDacl)
    write_owner          (WriteOwner)
    allowed_to_delegate  (AllowedToDelegate)
    has_session          (HasSession)
    gplink               (GPLink -> GpLink)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

NODE_KINDS = {"user", "group", "computer", "domain", "gpo", "ou",
              "container", "ca", "cert_template"}

EDGE_KINDS = {
    "member_of", "admin_on", "rdp_on", "owns", "all_extended_rights",
    "force_change_pw", "add_member", "dcsync", "generic_all",
    "generic_write", "write_dacl", "write_owner", "allowed_to_delegate",
    "has_session", "gplink",
    # ADCS (ESC1–ESC8 modeling)
    "enroll", "autoenroll", "manage_certificates", "manage_ca",
    "published_on",
}

# Privilege weights used by risk scoring (0..1), calibrated to AD abuse value.
EDGE_WEIGHTS: dict[str, float] = {
    "dcsync": 1.00,
    "generic_all": 0.95,
    "owns": 0.90,
    "write_owner": 0.85,
    "write_dacl": 0.80,
    "all_extended_rights": 0.75,
    "generic_write": 0.70,
    "force_change_pw": 0.60,
    "add_member": 0.60,
    "allowed_to_delegate": 0.55,
    "admin_on": 0.80,
    "rdp_on": 0.30,
    "member_of": 0.0,   # weight resolved via target tier
    "has_session": 0.0,  # weight resolved via source/target kinds
    "gplink": 0.20,
    # ADCS: enrollment alone is only a primitive — real risk comes from the
    # template flags (rules.py ESC1–ESC8). manage_ca == CA takeover.
    "enroll": 0.45,
    "autoenroll": 0.50,
    "manage_certificates": 0.90,
    "manage_ca": 1.00,
    "published_on": 0.0,
}


@dataclass(slots=True)
class Node:
    id: str                      # e.g. "user:svc_sql"
    kind: str
    label: str                   # display name
    domain: str = ""
    props: dict[str, Any] = field(default_factory=dict)
    tier: int | None = None      # 0 = Tier-0 (admin model), None = unclassified

    def to_dict(self, props: bool = True) -> dict[str, Any]:
        d = {"id": self.id, "kind": self.kind, "label": self.label,
             "domain": self.domain, "tier": self.tier}
        if props:
            d["props"] = self.props
        return d


@dataclass(slots=True)
class Edge:
    source: str
    target: str
    kind: str
    # e.g. {"path": "C:\\Finance\\", "rights": "AllExtendedRights"} free-form
    props: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"source": self.source, "target": self.target,
                "kind": self.kind, "props": self.props}
