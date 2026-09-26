"""Detection rules for AD misconfigurations — the BloodHound-style "findings"
engine, mapped to MITRE ATT&CK and to control frameworks.

Covers classic AD abuse (kerberoasting, ACL, tiering, GPP) plus ADCS
certified-pre-owned-domain attacks ESC1–ESC8 and constrained/RBCD delegation.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from app.graph.store import GraphStore, STORE


@dataclass(slots=True)
class Finding:
    id: str
    title: str
    severity: str            # critical | high | medium | low | info
    category: str
    description: str
    affected: list[dict[str, str]]
    mitre: list[str]
    remediation: str
    evidence: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "title": self.title, "severity": self.severity,
            "category": self.category, "description": self.description,
            "affected": self.affected, "mitre": self.mitre,
            "remediation": self.remediation, "evidence": self.evidence,
        }


@dataclass(slots=True)
class Rule:
    id: str
    title: str
    severity: str
    category: str
    description: str
    mitre: list[str]
    remediation: str
    check: Callable[[GraphStore], list[dict[str, str]]]


# ---------------------------------------------------------------- checks ----
def _kerberoastable(s: GraphStore) -> list[dict[str, str]]:
    out = []
    for n in s.nodes():
        if n.kind == "user" and n.props.get("spn") and n.props.get("enabled", True):
            why = ("privileged + SPN" if n.props.get("admin_count")
                   else "SPN present (TGS requestable)")
            out.append({"id": n.id, "label": n.label, "why": why})
    return out


def _asrep_roastable(s: GraphStore) -> list[dict[str, str]]:
    return [
        {"id": n.id, "label": n.label,
         "why": f"no pre-auth; pwd age "
                f"{n.props.get('password_last_set_days', '?')}d"}
        for n in s.nodes()
        if n.kind == "user" and n.props.get("no_preauth")
        and n.props.get("enabled", True)
    ]


def _dcsync_non_da(s: GraphStore) -> list[dict[str, str]]:
    out = []
    for e in s.edges():
        if e.kind != "dcsync":
            continue
        src, tgt = s.node(e.source), s.node(e.target)
        if not src or not tgt:
            continue
        if tgt.kind == "domain" and src.tier != 0:
            out.append({"id": src.id, "label": src.label, "why":
                        "DCSync rights without Tier-0 status"})
    return out


def _password_age(s: GraphStore) -> list[dict[str, str]]:
    return [
        {"id": n.id, "label": n.label,
         "why": f"password age {n.props.get('password_last_set_days', '?')} days"}
        for n in s.nodes()
        if n.kind == "user" and n.props.get("enabled", True)
        and isinstance(n.props.get("password_last_set_days"), int)
        and n.props["password_last_set_days"] > 90
    ]


def _helpdesk_reset_tier0(s: GraphStore) -> list[dict[str, str]]:
    out = []
    for e in s.edges():
        if e.kind != "force_change_pw":
            continue
        src, tgt = s.node(e.source), s.node(e.target)
        if src and tgt and tgt.tier == 0 and src.tier != 0:
            out.append({"id": e.source, "label": src.label, "why":
                        f"can reset password of Tier-0 '{tgt.label}'"})
    return out


def _unconstrained_delegation(s: GraphStore) -> list[dict[str, str]]:
    out = []
    for n in s.nodes():
        if n.kind == "computer" and n.props.get("unconstrained"):
            out.append({"id": n.id, "label": n.label, "why":
                        "unconstrained delegation: any inbound auth yields "
                        "a forwardable TGT"})
    return out


def _overbroad_rdp(s: GraphStore) -> list[dict[str, str]]:
    out = []
    for e in s.edges():
        if e.kind != "rdp_on":
            continue
        src, tgt = s.node(e.source), s.node(e.target)
        if src and tgt and "domain users" in src.label.lower():
            out.append({"id": e.target, "label": tgt.label,
                        "why": "Domain Users can RDP (lateral movement vector)"})
    return out


def _gpp_passwords(s: GraphStore) -> list[dict[str, str]]:
    return [
        {"id": n.id, "label": n.label, "why":
         "GPO references cpassword (MS14-025 legacy GPP) — decryptable by "
         "any authenticated user"}
        for n in s.nodes()
        if n.kind == "gpo" and n.props.get("gpp_password")
    ]


def _tier0_sessions_on_workstations(s: GraphStore) -> list[dict[str, str]]:
    out = []
    for e in s.edges():
        if e.kind != "has_session":
            continue
        src, tgt = s.node(e.source), s.node(e.target)
        if not src or not tgt:
            continue
        if src.tier == 0 and tgt.kind == "computer" and tgt.tier != 0:
            out.append({"id": e.target, "label": tgt.label, "why":
                        f"Tier-0 account '{src.label}' has session here — "
                        "credential theft reaches DA"})
    return out


def _nested_privileged_groups(s: GraphStore) -> list[dict[str, str]]:
    out = []
    for e in s.edges():
        if e.kind != "member_of":
            continue
        src, tgt = s.node(e.source), s.node(e.target)
        if src and tgt and tgt.kind == "group" and tgt.tier == 0 \
                and src.kind == "group" and src.tier != 0:
            out.append({"id": e.source, "label": src.label, "why":
                        f"nested into Tier-0 group '{tgt.label}' — "
                        "breaks tiering model"})
    return out


# ---------------------- ADCS: ESC1–ESC8 (certified pre-owned domain) --------
CONTROL_EDGES = {"enroll", "autoenroll", "generic_all", "all_extended_rights",
                 "write_dacl", "write_owner", "owns", "generic_write"}


def _esc_enrollment_eligibility(s: GraphStore, template_id: str) -> list[str]:
    """Principals holding enroll/autoenroll (or stronger) on a template,
    including one level of group nesting (lab-scale expansion)."""
    direct: set[str] = set()
    for e in s.edges():
        if e.target == template_id and e.kind in CONTROL_EDGES:
            direct.add(e.source)
    expanded: set[str] = set()
    for pid in direct:
        n = s.node(pid)
        if n and n.kind == "group":
            for e in s.edges():
                if e.kind == "member_of" and e.target == pid:
                    expanded.add(e.source)
    return sorted(direct | expanded)


def _esc1(s: GraphStore) -> list[dict[str, str]]:
    """ESC1: enrollee-supplies-SAN + client auth + no manager approval."""
    out: list[dict[str, str]] = []
    for n in s.nodes():
        if n.kind != "cert_template":
            continue
        p = n.props
        if not (p.get("client_auth") and p.get("enrollee_supplies_subject")
                and not p.get("requires_manager_approval")):
            continue
        for pid in _esc_enrollment_eligibility(s, n.id):
            principal = s.node(pid)
            if not principal:
                continue
            out.append({"id": pid, "label": principal.label, "why":
                        f"can enroll on '{n.label}' (ENROLLEE_SUPPLIES_SUBJECT,"
                        " no approval) → forge SAN of any principal incl. "
                        "Domain Admin"})
    return out


def _esc2(s: GraphStore) -> list[dict[str, str]]:
    """ESC2: no EKU (Any Purpose) — cert usable for anything incl. subCA."""
    out: list[dict[str, str]] = []
    for n in s.nodes():
        if n.kind != "cert_template" or not n.props.get("any_purpose"):
            continue
        for pid in _esc_enrollment_eligibility(s, n.id):
            principal = s.node(pid)
            if principal:
                out.append({"id": pid, "label": principal.label, "why":
                            f"can enroll on '{n.label}' — no EKU "
                            "(Any Purpose; may enable subCA enrollment)"})
    return out


def _esc3(s: GraphStore) -> list[dict[str, str]]:
    """ESC3: enrollment-agent template — request certs on behalf of others."""
    out: list[dict[str, str]] = []
    for n in s.nodes():
        if n.kind != "cert_template" or not n.props.get("enrollment_agent"):
            continue
        for pid in _esc_enrollment_eligibility(s, n.id):
            principal = s.node(pid)
            if principal:
                out.append({"id": pid, "label": principal.label, "why":
                            f"enrollment-agent rights on '{n.label}' — "
                            "request certs on behalf of other principals"})
    return out


def _esc4(s: GraphStore) -> list[dict[str, str]]:
    """ESC4: vulnerable ACL on the template object itself."""
    out: list[dict[str, str]] = []
    for n in s.nodes():
        if n.kind != "cert_template":
            continue
        flagged = n.props.get("vulnerable_template_acl")
        for e in s.in_edges(n.id):
            if e.kind in {"generic_write", "generic_all", "write_dacl",
                          "write_owner", "owns", "all_extended_rights"}:
                principal = s.node(e.source)
                if principal and (flagged or e.kind != "generic_write"):
                    out.append({"id": e.source, "label": principal.label,
                                "why": f"'{e.kind}' on template '{n.label}' "
                                "— rewrite template into ESC1 conditions"})
    return out


def _esc5(s: GraphStore) -> list[dict[str, str]]:
    """ESC5: vulnerable ACL on the CA object / CA server (manage_ca path)."""
    out: list[dict[str, str]] = []
    for e in s.edges():
        if e.kind not in {"manage_ca", "manage_certificates", "generic_all",
                          "write_dacl", "write_owner", "owns"}:
            continue
        tgt = s.node(e.target)
        if not tgt or tgt.kind != "ca":
            continue
        principal = s.node(e.source)
        if not principal:
            continue
        if e.kind == "manage_certificates" and principal.tier == 0:
            continue  # legitimate CA operator
        out.append({"id": e.source, "label": principal.label, "why":
                    f"'{e.kind}' on CA '{tgt.label}' — CA takeover: issue "
                    "arbitrary certs, rogue subCA, or theft of CA key"})
    return out


def _esc7(_s: GraphStore) -> list[dict[str, str]]:
    """ESC7: non-Tier-0 principals holding ManageCA/ManageCertificates.
    (Represented by manage_ca/manage_certificates edges in the graph.)"""
    out: list[dict[str, str]] = []
    for e in _s.edges():
        if e.kind not in {"manage_ca", "manage_certificates"}:
            continue
        principal = _s.node(e.source)
        ca = _s.node(e.target)
        if not principal or not ca or ca.kind != "ca":
            continue
        if principal.tier == 0:
            continue
        out.append({"id": e.source, "label": principal.label, "why":
                    f"{'ManageCA' if e.kind == 'manage_ca' else 'ManageCertificates'}"
                    f" on '{ca.label}' without Tier-0 — CA access-control drift"})
    return out


def _esc9(_s: GraphStore) -> list[dict[str, str]]:
    """ESC9/ESC10 weak mapping: no security extension / weak SID mapping —
    spoofing via userOID/UPN manipulation (CVE-2022–41404 family)."""
    out: list[dict[str, str]] = []
    for n in _s.nodes():
        if n.kind != "cert_template" or not n.props.get("no_security_extension"):
            continue
        for pid in _esc_enrollment_eligibility(_s, n.id):
            principal = _s.node(pid)
            if principal:
                out.append({"id": pid, "label": principal.label, "why":
                            f"template '{n.label}' lacks security extension "
                            "(ESC9) — weak certificate→account mapping"})
    return out


# ------------------------------ Delegation: constrained + RBCD --------------
def _constrained_delegation(s: GraphStore) -> list[dict[str, str]]:
    """Classic constrained delegation (T1558.002): any service on the target
    user can be impersonated with S4U2self + S4U2proxy."""
    out: list[dict[str, str]] = []
    for e in s.edges():
        if e.kind != "allowed_to_delegate":
            continue
        if e.props.get("unconstrained"):
            continue  # covered by F-DELEG-001
        if e.props.get("delegation") != "constrained":
            continue
        src, tgt = s.node(e.source), s.node(e.target)
        if not src or not tgt:
            continue
        services = ", ".join(e.props.get("services", [])) or "any"
        out.append({"id": e.source, "label": src.label, "why":
                    f"constrained delegation to '{tgt.label}' (services: "
                    f"{services}) — S4U2self/S4U2proxy impersonation; "
                    "protocol transition adds any-service risk"})
    return out


def _rbcd(s: GraphStore) -> list[dict[str, str]]:
    """Resource-based constrained delegation (T1558.002/T1136): principals
    with write access to msDS-AllowedToActOnBehalfOfOtherIdentity can add
    themselves and impersonate any user to the resource."""
    out: list[dict[str, str]] = []
    for e in s.edges():
        if e.kind != "allowed_to_delegate":
            continue
        if e.props.get("delegation") != "rbcd":
            continue
        src, tgt = s.node(e.source), s.node(e.target)
        if not src or not tgt:
            continue
        out.append({"id": e.source, "label": src.label, "why":
                    f"RBCD entry against '{tgt.label}' — S4U impersonation "
                    "of any domain user to that host; verify who can write "
                    "msDS-AllowedToActOnBehalfOfOtherIdentity"})
    return out


def _rbcd_write_acl(s: GraphStore) -> list[dict[str, str]]:
    """Principals that can WRITE the RBCD attribute on computers (the actual
    escalation primitive) — generic write/all or extended rights on a host."""
    out: list[dict[str, str]] = []
    for e in s.edges():
        if e.kind not in {"generic_write", "generic_all", "write_dacl",
                          "write_owner", "all_extended_rights"}:
            continue
        tgt = s.node(e.target)
        if not tgt or tgt.kind != "computer":
            continue
        src = s.node(e.source)
        if not src or src.tier == 0:
            continue
        out.append({"id": e.source, "label": src.label, "why":
                    f"'{e.kind}' on '{tgt.label}' — can set "
                    "msDS-AllowedToActOnBehalfOfOtherIdentity (RBCD takeover)"})
    return out


# ------------------------------------------------------------- registry -----
RULES: list[Rule] = [
    Rule("F-DCSYNC-001", "Non-tiered DCSync rights", "critical", "acl",
         "A principal outside Tier-0 holds DCSync (DS-Replication-Get-Changes "
         "+ All) on the domain — equivalent to domain domination.",
         ["T1003.006"], "Remove the ACE; grant replication rights only to "
         "dedicated Tier-0 DC-sync accounts; alert on Replication Admin "
         "Access events (4662).", _dcsync_non_da),
    Rule("F-KRB-001", "Kerberoastable accounts", "high", "kerberoasting",
         "Accounts with SPNs are exposed to offline TGS ticket cracking.",
         ["T1558.003"], "Use gMSA (random 240+ char passwords); scrub "
         "unnecessary SPNs; monitor TGS requests (4769 with RC4).",
         _kerberoastable),
    Rule("F-ASREP-001", "AS-REP roastable accounts", "high",
         "kerberoasting", "Accounts without Kerberos pre-authentication "
         "allow offline AS-REP cracking.",
         ["T1558.004"], "Re-enable pre-auth; migrate to gMSA; audit 4768 "
         "without pre-auth flag.", _asrep_roastable),
    Rule("F-DELEG-001", "Unconstrained delegation", "critical", "delegation",
         "Computers with unconstrained delegation cache forwardable TGTs of "
         "any user authenticating to them.",
         ["T1558.004"], "Disable unconstrained delegation; use resource-"
         "based constrained delegation; protect with 'Account is sensitive "
         "+ cannot be delegated' for Tier-0.", _unconstrained_delegation),
    Rule("F-TIER-001", "Helpdesk password reset on Tier-0", "high",
         "tiering", "Non-tiered operators can reset Tier-0 credentials — "
         "helpdesk compromise equals domain compromise.",
         ["T1098"], "Enforce tiering: reset rights only within the same "
         "tier; JIT/PIM for Tier-0 resets.", _helpdesk_reset_tier0),
    Rule("F-RDP-001", "Over-broad interactive logon rights", "medium",
         "lateral_movement", "Broad groups hold RDP on servers — cheap "
         "lateral movement once a workstation is compromised.",
         ["T1021.001"], "Restrict RDP to tiered admin groups; enable "
         "LAPS/Windows LAPS; NLA + smart card where possible.",
         _overbroad_rdp),
    Rule("F-GPP-001", "Legacy Group Policy Preferences cpassword", "critical",
         "gpo", "GPP cpassword values are AES-encrypted with a publicly "
         "known key — equivalent to plaintext credentials in SYSVOL.",
         ["T1552.006"], "Remove GPP passwords; MS14-025 hotfix; sweep "
         "SYSVOL for legacy XML; rotate affected secrets.", _gpp_passwords),
    Rule("F-SESS-001", "Tier-0 credentials on lower-tier hosts", "high",
         "tiering", "Tier-0 sessions on member servers/workstations expose "
         "domain-domination credentials to credential theft.",
         ["T1003"], "Enforce credential guard; block Tier-0 logons to lower "
         "tiers via GPO (Deny logon locally); use PAW architecture.",
         _tier0_sessions_on_workstations),
    Rule("F-NEST-001", "Nested privileged group membership", "medium",
         "tiering", "Groups nested into Tier-0 groups break the tiering "
         "model and hide true privilege.",
         ["T1078"], "Flatten privileged groups; audit nested membership "
         "quarterly; use role-based access with attestations.",
         _nested_privileged_groups),
    Rule("F-PWD-001", "Stale service-account passwords", "medium",
         "credential_hygiene", "Passwords older than 90 days on service "
         "accounts violate rotation policy and widen cracking exposure.",
         ["T1078.002"], "Rotate; prefer gMSA; integrate with vault "
         "(CyberArk/HashiCorp) for automatic rotation.",
         _password_age),

    # ---- ADCS ESC1–ESC8 ----------------------------------------------------
    Rule("F-ESC1-001", "ADCS ESC1 — enrollee supplies subject", "critical",
         "adcs", "Templates with ENROLLEE_SUPPLIES_SUBJECT + client auth + "
         "no approval let any enrollee mint a cert as Domain Admin.",
         ["T1649"], "Disable 'Supply in the request'; require manager "
         "approval; publish only to constrained groups; audit certIssuance "
         "events (4887).", _esc1),
    Rule("F-ESC2-001", "ADCS ESC2 — no EKU (Any Purpose)", "high", "adcs",
         "Templates without EKU constraints are valid for any purpose, "
         "including enrollment-agent and subCA misuse paths.",
         ["T1649"], "Set explicit EKUs; remove unauthenticated-enrollment "
         "groups; enforce approval for sensitive templates.", _esc2),
    Rule("F-ESC3-001", "ADCS ESC3 — enrollment agent misconfiguration",
         "high", "adcs", "Enrollment-agent templates allow requesting certs "
         "on behalf of other principals.",
         ["T1649"], "Restrict EA templates to dedicated PKI operators; "
         "enable approval; CA audit on certificate requests.", _esc3),
    Rule("F-ESC4-001", "ADCS ESC4 — vulnerable template ACL", "critical",
         "adcs", "Write/GenericAll access on a template object lets an "
         "attacker rewrite it into an ESC1 condition.",
         ["T1649"], "Delegate template management to PKI Admins only; "
         "remove generic write ACEs; monitor template ACL changes.",
         _esc4),
    Rule("F-ESC5-001", "ADCS ESC5 — vulnerable CA object ACL", "critical",
         "adcs", "Control of the CA object/server permits arbitrary "
         "certificate issuance and rogue subCA creation.",
         ["T1649"], "Restrict CA ACEs to PKI Admins; patch CA server; "
         "monitor for new subCA certificates (CertUtil, 4886/4887).",
         _esc5),
    Rule("F-ESC7-001", "ADCS ESC7 — non-tiered CA access", "high", "adcs",
         "ManageCA/ManageCertificates held outside Tier-0 — CA control-plane "
         "drift enables approval bypass and issuance abuse.",
         ["T1649"], "Align CA access with tiering; JIT for CA operator "
         "rights; alert on membership changes.", _esc7),
    Rule("F-ESC9-001", "ADCS ESC9/10 — weak certificate mapping", "high",
         "adcs", "Templates lacking the security extension (or weak "
         "UPN/DNS mapping) enable spoofing when mapping attributes are "
         "writable.",
         ["T1649"], "Enable strong mapping (szOID_NTDS_CA_SECURITY_EXT); "
         "May 2022+ DC patches; block UPN writes outside tier 0.", _esc9),

    # ---- Delegation abuse ---------------------------------------------------
    Rule("F-DELEG-002", "Constrained delegation abuse paths", "high",
         "delegation", "Constrained delegation permits S4U2self/S4U2proxy "
         "impersonation of delegated users to listed services; protocol "
         "transition widens it to any service.",
         ["T1558.002"], "Remove unused delegation entries; prefer RBCD with "
         "tight resource ACLs; flag Tier-0 accounts "
         "'sensitive, cannot be delegated'.", _constrained_delegation),
    Rule("F-DELEG-003", "RBCD entries on hosts", "high", "delegation",
         "msDS-AllowedToActOnBehalfOfOtherIdentity entries allow S4U "
         "impersonation of any user to the resource.",
         ["T1558.002"], "Clear unauthorized RBCD entries; restrict who can "
         "write the attribute; monitor 4662 on the attribute.", _rbcd),
    Rule("F-DELEG-004", "Writable RBCD attribute via ACL", "critical",
         "delegation", "Non-tiered principals can write the RBCD attribute "
         "on computers — direct escalation to impersonate any user on that "
         "host.",
         ["T1558.002", "T1558.004"], "Remove generic-write ACEs from "
         "computer objects; LAPS-tier delegation only; alert on ACL edits "
         "to computer objects.", _rbcd_write_acl),
]


def run_all_rules(store: GraphStore = STORE) -> list[Finding]:
    findings: list[Finding] = []
    for rule in RULES:
        try:
            affected = rule.check(store)
        except Exception:  # a broken rule must not kill the scan
            affected = []
        if not affected:
            continue
        findings.append(Finding(
            id=rule.id, title=rule.title, severity=rule.severity,
            category=rule.category, description=rule.description,
            affected=affected, mitre=rule.mitre,
            remediation=rule.remediation,
            evidence={"rule": rule.id, "count": len(affected)},
        ))
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3,
                      "info": 4}
    findings.sort(key=lambda f: severity_order.get(f.severity, 9))
    return findings


def findings_summary(findings: list[Finding]) -> dict[str, Any]:
    by_sev: dict[str, int] = {"critical": 0, "high": 0, "medium": 0,
                              "low": 0, "info": 0}
    by_cat: dict[str, int] = {}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        by_cat[f.category] = by_cat.get(f.category, 0) + 1
    # Composite risk index (bank-style, for board reporting)
    score = (by_sev["critical"] * 25 + by_sev["high"] * 12
             + by_sev["medium"] * 5 + by_sev["low"] * 1)
    return {"total": len(findings), "by_severity": by_sev,
            "by_category": by_cat,
            "risk_index": min(score, 100),
            "risk_raw": score}  # uncapped: sensitive to single-finding deltas
