import uuid

RULE_FIELDS = ["event_id", "data_source", "observable"]

BUILTIN_RULES = [
    {"id": "SIG-T1021-002-smb-adminshare", "name": "SMB Admin Share Access",
     "level": "high", "technique": "T1021.002", "p_detect": 0.95, "p_fp": 0.0,
     "observables": {"admin_share_access"}, "event_ids": set(),
     "source": "security", "desc": "Admin-share access (5145/5140) to C$/ADMIN$"},
    {"id": "SIG-T1021-002-svccreate", "name": "Service Create over SMB",
     "level": "high", "technique": "T1021.002", "p_detect": 0.9, "p_fp": 0.0,
     "observables": {"svc_create"}, "event_ids": {"7045"},
     "source": "system", "desc": "New service whose image path sits in an admin share"},
    {"id": "SIG-T1021-006-winrm", "name": "WinRM Remote PowerShell",
     "level": "high", "technique": "T1021.006", "p_detect": 0.96, "p_fp": 0.0,
     "observables": {"explicit_creds", "psh_remote", "priv_assigned"}, "event_ids": set(),
     "source": "any", "desc": "Explicit credentials + PowerShell remoting (4648/4104/4672)"},
    {"id": "SIG-T1021-001-rdp", "name": "RDP Logon",
     "level": "medium", "technique": "T1021.001", "p_detect": 0.93, "p_fp": 0.02,
     "observables": {"rdp_logon", "inbound_3389"}, "event_ids": set(),
     "source": "any", "desc": "Logon type 10 (RDP) or inbound 3389 flow"},
    {"id": "SIG-T1550-002-nthash", "name": "Pass-the-Hash NTLM",
     "level": "critical", "technique": "T1550.002", "p_detect": 0.92, "p_fp": 0.0,
     "observables": {"network_logon", "ntlm_auth", "wmi_remote_exec"}, "event_ids": set(),
     "source": "any", "desc": "NTLM logon type 3 + RC4/NTLMv2 from non-baseline host"},
    {"id": "SIG-T1550-003-krbrelay", "name": "Pass-the-Ticket Kerberos",
     "level": "critical", "technique": "T1550.003", "p_detect": 0.88, "p_fp": 0.0,
     "observables": {"tgt_req", "tgs_req", "krb_logon"}, "event_ids": set(),
     "source": "any", "desc": "4218/4768/4769 ticket usage from unusual source"},
    {"id": "SIG-T1558-003-rc4", "name": "Kerberoasting RC4 TGS",
     "level": "high", "technique": "T1558.003", "p_detect": 0.98, "p_fp": 0.0,
     "observables": {"tgs_rc4"}, "event_ids": {"4769"},
     "source": "security", "desc": "RC4-encrypted TGS requests against service SPNs"},
    {"id": "SIG-T1021-003-dcom", "name": "DCOM Remote Activation",
     "level": "high", "technique": "T1021.003", "p_detect": 0.85, "p_fp": 0.0,
     "observables": {"dcom_connect", "dce_rpc", "remote_thread"}, "event_ids": set(),
     "source": "any", "desc": "DCOM activation (135) + MMC/dllhost remote thread"},
    {"id": "SIG-T1570-toolxfer", "name": "Lateral Tool Transfer to Shares",
     "level": "medium", "technique": "T1570", "p_detect": 0.9, "p_fp": 0.01,
     "observables": {"share_write", "file_create", "smb_bytes"}, "event_ids": set(),
     "source": "any", "desc": "Tool binary written to admin share over SMB"},
    {"id": "SIG-T1078-anom", "name": "Anomalous Valid Account Logon",
     "level": "high", "technique": "T1078", "p_detect": 0.7, "p_fp": 0.05,
     "observables": {"network_logon", "first_seen"}, "event_ids": {"4624"},
     "source": "security", "desc": "First-seen host-user combination (behavioral)"},
    {"id": "SIG-T1047-wmi", "name": "WMI Remote Process Execution",
     "level": "high", "technique": "T1047", "p_detect": 0.9, "p_fp": 0.0,
     "observables": {"wmi_process", "wmi_remote_exec", "dcom_connect"}, "event_ids": set(),
     "source": "any", "desc": "Win32_Process.Create via WmiPrvSE over DCOM"},
    {"id": "SIG-T1543-003-psexec", "name": "PsExec-style Service Install",
     "level": "high", "technique": "T1543.003", "p_detect": 0.95, "p_fp": 0.0,
     "observables": {"svc_create", "pipe_connect", "share_write"}, "event_ids": set(),
     "source": "any", "desc": "PSEXESVC service + pipe over ADMIN$ share"},
    {"id": "SIG-T1021-004-ssh", "name": "SSH Remote Session",
     "level": "medium", "technique": "T1021.004", "p_detect": 0.8, "p_fp": 0.01,
     "observables": {"ssh_auth"}, "event_ids": set(),
     "source": "any", "desc": "Successful SSH auth over 22"},
    {"id": "SIG-T1087-acct", "name": "Account Discovery via LDAP",
     "level": "low", "technique": "T1087", "p_detect": 0.75, "p_fp": 0.02,
     "observables": {"ldap_query", "new_process"}, "event_ids": set(),
     "source": "any", "desc": "LDAP user enumeration + net user /domain"},
    {"id": "SIG-T1018-hostdisc", "name": "Remote System Discovery",
     "level": "low", "technique": "T1018", "p_detect": 0.7, "p_fp": 0.03,
     "observables": {"dns_burst", "new_process"}, "event_ids": set(),
     "source": "any", "desc": "Hostname/DNS resolution bursts + nltest"},
    {"id": "GEN-0001-backup-remote", "name": "High-value account remote use",
     "level": "high", "technique": None, "p_detect": 0.0, "p_fp": 0.12,
     "observables": {"benign_admin_logon"}, "event_ids": {"4624"},
     "source": "security", "desc": "Behavioral: svc_backup logon from non-console host"},
    {"id": "GEN-0002-share-write", "name": "Write to administrative share",
     "level": "high", "technique": None, "p_detect": 0.0, "p_fp": 0.15,
     "observables": {"benign_admin_logon", "share_write"}, "event_ids": {"5145"},
     "source": "security", "desc": "Behavioral: any write to ADMIN$/C$"},
]


def rule_matches(rule, record):
    r_obs = rule.get("observables") or set()
    rec_obs = record.get("observable")
    if r_obs and rec_obs not in r_obs:
        return False
    r_eid = rule.get("event_ids") or set()
    if r_eid and record.get("event_id") not in r_eid:
        return False
    r_src = rule.get("source")
    if r_src and r_src != "any" and record.get("data_source") != r_src:
        return False
    return True


def evaluate_run(run, rng):
    records = run["records"]
    detections = []
    for rule in BUILTIN_RULES:
        matched = [r for r in records if rule_matches(rule, r)]
        tech_rule = rule["technique"] is not None
        for rec in matched:
            fired = False
            if tech_rule:
                if rng.random() < rule["p_detect"]:
                    fired = True
            else:
                if rec["is_benign"] and rng.random() < rule["p_fp"]:
                    fired = True
            if fired:
                detections.append(_make_detection(run, rule, rec))
                break
    return detections


def _confidence(rule):
    sev = rule["level"]
    base = {"critical": 0.95, "high": 0.85, "medium": 0.7, "low": 0.55}
    return min(0.99, base.get(sev, 0.6) + (0.5 - rule["p_detect"]) * 0.1)


def _make_detection(run, rule, rec):
    return {
        "detection_id": "DET-%06d" % (uuid.uuid4().int % 1000000),
        "run_id": run["run_id"],
        "rule_id": rule["id"],
        "rule_name": rule["name"],
        "technique_id": run["technique_id"] if rule["technique"] == run["technique_id"] else None,
        "rule_technique": rule["technique"],
        "level": rule["level"],
        "confidence": round(_confidence(rule), 2),
        "event_id": rec.get("event_id"),
        "data_source": rec["data_source"],
        "observable": rec.get("observable"),
        "source": run["source"],
        "target": run["target"],
        "user": run["user"],
        "ground_truth_match": rule["technique"] == run["technique_id"],
        "tp": rule["technique"] == run["technique_id"],
        "fp": rule["technique"] is not None and rule["technique"] != run["technique_id"],
        "is_lab": True,
        "ts": round(run["ts"], 2),
    }


def expected_rule_ids(technique_id):
    return [r["id"] for r in BUILTIN_RULES if r["technique"] == technique_id]


def rule_stats():
    return {"total": len(BUILTIN_RULES),
            "technique_rules": sum(1 for r in BUILTIN_RULES if r["technique"]),
            "generic_rules": sum(1 for r in BUILTIN_RULES if not r["technique"])}