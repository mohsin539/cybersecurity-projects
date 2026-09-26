"""Lab domain seed: CORP.LAB — a bank-flavored AD lab with realistic risk.

Deliberately planted misconfigurations (all common in real bank domains):
  - svc_sql SPN            -> kerberoastable -> DA path
  - helpdesk operator      -> ForceChangePassword on Tier-0 exec
  - 2 service accounts     -> AS-REP roastable (no pre-auth)
  - Domain Users group     -> RDP on jump host (over-broad)
  - legacy DCSync          -> non-DA principal with DCSync on domain
  - gMSA-eligible account with static password instead
  - unconstrained delegation on a file server
  - GPP password in SYSVOL-referenced GPO (legacy MS14-025 pattern)
Everything is synthetic; no real credentials are used.
"""
from __future__ import annotations

from app.graph.model import Edge, Node
from app.graph.store import STORE


def _user(uid: str, label: str, **props) -> Node:
    return Node(f"user:{uid}", "user", label, "CORP.LAB", props)


def _group(gid: str, label: str, tier: int | None = None) -> Node:
    return Node(f"group:{gid}", "group", label, "CORP.LAB", {}, tier)


def _comp(cid: str, label: str, **props) -> Node:
    return Node(f"computer:{cid}", "computer", label, "CORP.LAB", props)


def seed_lab_domain() -> None:
    if STORE.node("domain:CORP.LAB"):
        return  # idempotent

    # ---- Domain & OUs -----------------------------------------------------
    STORE.add_node(Node("domain:CORP.LAB", "domain", "CORP.LAB", "CORP.LAB",
                        {"functional_level": "2016"}, tier=0))

    for ou, desc in {
        "ou:tier0": "Tier-0 / Identity Admins",
        "ou:tier1": "Tier-1 / Application Ops",
        "ou:workstations": "Workstations",
        "ou:servers": "Member Servers",
    }.items():
        STORE.add_node(Node(ou, "ou", desc, "CORP.LAB"))

    # ---- Users ------------------------------------------------------------
    users = {
        # uid, label, props, tier
        "da_admin": ("CORPLAB\\da_admin", {"enabled": True, "admin_count": True,
                                           "last_logon_days": 2}, 0),
        "krbtgt": ("krbtgt", {"enabled": False, "admin_count": True}, 0),
        "cfo_jane": ("CORPLAB\\jane.doe (CFO)", {"enabled": True,
                     "title": "CFO", "high_value": True}, None),
        "ciso_marc": ("CORPLAB\\marc.reyes (CISO)", {"enabled": True,
                      "title": "CISO", "admin_count": True}, 0),
        "helpdesk_bob": ("CORPLAB\\bob.hander (L1 Helpdesk)",
                         {"enabled": True, "title": "L1 Support"}, None),
        "svc_sql": ("CORPLAB\\svc_sql", {"enabled": True, "spn": True,
                    "password_last_set_days": 240, "description":
                    "MSSQL service account (prod-core-db01)"}, None),
        "svc_backup": ("CORPLAB\\svc_backup", {"enabled": True,
                       "no_preauth": True, "password_last_set_days": 500},
                       None),
        "svc_legacy": ("CORPLAB\\svc_legacy_batch", {"enabled": True,
                       "no_preauth": True, "password_last_set_days": 900},
                       None),
        "banking_app": ("CORPLAB\\banking_app_svc", {"enabled": True,
                        "description": "Runs core-banking API pool"}, None),
        "jdoe": ("CORPLAB\\john.doe", {"enabled": True,
                 "title": "Payments Ops"}, None),
    }
    for uid, (label, props, tier) in users.items():
        n = _user(uid, label, **props)
        n.tier = tier
        STORE.add_node(n)

    # ---- Groups -----------------------------------------------------------
    groups = {
        "domain_admins": ("Domain Admins", 0),
        "schema_admins": ("Schema Admins", 0),
        "enterprise_admins": ("Enterprise Admins", 0),
        "administrators": ("BUILTIN\\Administrators", 0),
        "domain_users": ("Domain Users", None),
        "helpdesk_ops": ("GG-Helpdesk-Operators", None),
        "payment_ops": ("GG-Payments-Operations", None),
        "server_admins": ("GG-Server-Admins", 1),
        "sql_admins": ("GG-SQL-Admins", 1),
    }
    for gid, (label, tier) in groups.items():
        STORE.add_node(_group(gid, label, tier))

    # ---- Computers --------------------------------------------------------
    computers = {
        "dc01": ("CORPLAB-DC01", {"os": "Windows Server 2019", "role": "DC"},
                 0),
        "dc02": ("CORPLAB-DC02", {"os": "Windows Server 2019", "role": "DC"},
                 0),
        "core_db01": ("BANK-CORE-DB01", {"os": "Windows Server 2022",
                      "role": "Core Banking SQL"}, None),
        "jump01": ("BANK-JUMP-01", {"os": "Windows Server 2022",
                   "role": "Admin jump host"}, 1),
        "file01": ("BANK-FILE-01", {"os": "Windows Server 2016",
                   "role": "File services", "unconstrained": True}, None),
        "wk001": ("BANK-WK-001", {"os": "Windows 11"}, None),
    }
    for cid, (label, props, tier) in computers.items():
        n = _comp(cid, label, **props)
        n.tier = tier
        STORE.add_node(n)

    # ---- GPOs -------------------------------------------------------------
    STORE.add_node(Node("gpo:gpo_laps", "gpo", "GPO-LAPS-Deployment",
                        "CORP.LAB", {"status": "enabled"}))
    STORE.add_node(Node("gpo:gpo_legacy", "gpo", "GPO-Legacy-Print-Drivers",
                        "CORP.LAB", {"status": "enabled",
                                     "gpp_password": True}))

    # ---- ADCS: issuing CA + cert templates (ESC1–ESC8 modeling) ----------
    E = lambda s, k, t, **p: STORE.add_edge(Edge(s, t, k, p))  # noqa: E731

    STORE.add_node(Node("ca:corp-issuing-01", "ca",
                        "CORPLAB-ISSUING-01", "CORP.LAB",
                        {"role": "issuing", "os": "Windows Server 2019"},
                        tier=0))
    STORE.add_edge(Edge("ca:corp-issuing-01", "domain:CORP.LAB",
                        "manage_ca"))
    cert_templates = {
        # gid: (label, flags) — one ESC1, one ESC2, one ESC4, one ESC9
        "esc1": ("Bank-Auth-Enroll", {"client_auth": True,
                                       "enrollee_supplies_subject": True,
                                       "requires_manager_approval": False}),
        "esc2": ("Bank-Any-Purpose", {"client_auth": False,
                                      "any_purpose": True,
                                      "enrollee_supplies_subject": False}),
        "esc4": ("Bank-Workstation-Auth", {"client_auth": True,
                                            "enrollee_supplies_subject": False,
                                            "vulnerable_template_acl": True}),
        "esc9": ("Bank-Smartcard-Weak", {"client_auth": True,
                                          "enrollee_supplies_subject": False,
                                          "no_security_extension": True}),
    }
    for tid, (label, flags) in cert_templates.items():
        STORE.add_node(Node(f"cert_template:{tid}", "cert_template", label,
                            "CORP.LAB", flags))
        STORE.add_edge(Edge(f"cert_template:{tid}", "ca:corp-issuing-01",
                            "published_on"))
    # ESC1: jdoe may enroll with SAN = anyone (no approval)
    E("user:jdoe", "enroll", "cert_template:esc1")
    # ESC2: payments group can request any-purpose certs
    E("group:payment_ops", "enroll", "cert_template:esc2")
    # ESC4: svc_backup has GenericWrite (vulnerable ACL) on template
    E("user:svc_backup", "generic_write", "cert_template:esc4")
    # ESC9: broad autoenroll with weak mapping template
    E("group:domain_users", "autoenroll", "cert_template:esc9")
    # ESC5/ESC7: CA control-plane drift (classic in real domains)
    E("group:server_admins", "generic_all", "ca:corp-issuing-01")
    E("user:svc_backup", "manage_certificates", "ca:corp-issuing-01")

    # ---- Delegation: constrained + RBCD pairs ----------------------------
    E("computer:file01", "allowed_to_delegate", "user:cfo_jane",
      delegation="constrained", services=["cifs", "HTTP"])
    E("computer:core_db01", "allowed_to_delegate", "user:da_admin",
      delegation="rbcd", note="msDS-AllowedToActOnBehalfOfOtherIdentity "
      "set by GG-SQL-Admins (GenericWrite on core_db01)")

    # ---- Edges ------------------------------------------------------------
    E = lambda s, k, t, **p: STORE.add_edge(Edge(s, t, k, p))  # noqa: E731

    # Domain membership
    for u in users:
        E(f"user:{u}", "member_of", "group:domain_users")

    # Tier-0 / privileged membership
    E("user:da_admin", "member_of", "group:domain_admins")
    E("user:ciso_marc", "member_of", "group:domain_admins")
    E("group:domain_admins", "member_of", "group:administrators")
    E("group:server_admins", "member_of", "group:administrators")
    E("user:helpdesk_bob", "member_of", "group:helpdesk_ops")
    E("user:jdoe", "member_of", "group:payment_ops")
    E("user:svc_sql", "member_of", "group:sql_admins")

    # Helpdesk abuse: password reset on Tier-0 CFO-scoped exec account
    E("user:helpdesk_bob", "force_change_pw", "user:cfo_jane",
      rights="ResetPassword", note="Helpdesk delegation without tiering")
    # Actually: jane is not Tier-0; the abuse target is CISO
    E("user:helpdesk_bob", "force_change_pw", "user:ciso_marc")

    # Kerberoastable path: svc_sql -> SQL admins -> Administrators
    E("user:svc_sql", "admin_on", "computer:core_db01")
    E("group:sql_admins", "generic_all", "computer:core_db01")

    # AS-REP roastables with legacy ACL
    E("user:svc_backup", "generic_write", "group:server_admins")
    E("user:svc_legacy", "all_extended_rights", "group:payment_ops")

    # Over-broad RDP via Domain Users (jump host hardening gap)
    E("group:domain_users", "rdp_on", "computer:jump01")

    # DCSync from a non-DA service account (legacy migration leftover)
    E("user:banking_app", "dcsync", "domain:CORP.LAB")

    # Unconstrained delegation on file server
    E("computer:file01", "allowed_to_delegate", "domain:CORP.LAB",
      unconstrained=True)

    # Sessions & admin patterns
    E("user:da_admin", "has_session", "computer:jump01")
    E("user:ciso_marc", "has_session", "computer:wk001")
    E("user:jdoe", "has_session", "computer:wk001")
    E("group:server_admins", "admin_on", "computer:file01")
    E("group:server_admins", "admin_on", "computer:jump01")

    # Owns / ACL abuse chains
    E("user:svc_backup", "owns", "group:payment_ops")

    # GPO links
    E("gpo:gpo_laps", "gplink", "ou:workstations")
    E("gpo:gpo_legacy", "gplink", "ou:servers")
    E("computer:file01", "member_of", "ou:servers")
    E("computer:jump01", "member_of", "ou:servers")
    E("computer:core_db01", "member_of", "ou:servers")
    E("computer:wk001", "member_of", "ou:workstations")
    E("user:da_admin", "member_of", "ou:tier0")
    E("user:ciso_marc", "member_of", "ou:tier0")

    STORE.prune_dangling()
