import hashlib
import json
import random
import time
import uuid

from . import LAB_TAG, SITE

TOPOLOGY = [
    {"host": "DC01", "ip": "10.24.43.10", "role": "Domain Controller + DNS + CA", "tier": "Tier-0"},
    {"host": "FS01", "ip": "10.24.43.11", "role": "File Server", "tier": "Tier-1"},
    {"host": "WK-WIN11", "ip": "10.24.43.12", "role": "Workstation", "tier": "Tier-1"},
    {"host": "WK-SRV2019", "ip": "10.24.43.13", "role": "Server role host", "tier": "Tier-1"},
    {"host": "ATK01", "ip": "10.24.43.20", "role": "Adversary Harness", "tier": "Tier-2"},
    {"host": "NSM01", "ip": "10.24.43.254", "role": "Network Security Monitor (SPAN)", "tier": "n/a"},
]

IDENTITIES = [
    {"user": "emp.admin", "purpose": "Tier-0 privileged admin", "anchor": "Kerberoasting target"},
    {"user": "svc_sql", "purpose": "Service account SPN", "anchor": "T1558.003 Kerberoasting"},
    {"user": "svc_backup", "purpose": "High-privilege backup", "anchor": "T1550.002/.003"},
    {"user": "emp.barker", "purpose": "Tier-1 office user", "anchor": "T1078"},
    {"user": "emp.chen", "purpose": "Tier-1 office user", "anchor": "T1078"},
]

TECHNIQUES = [
    {
        "technique_id": "T1021.002",
        "name": "SMB / Windows Admin Shares",
        "tactic": "lateral-movement",
        "severity": "high",
        "source": "ATK01",
        "target": "WK-SRV2019",
        "user": "corp\\emp.admin",
        "data_sources": ["security", "sysmon", "zeek"],
        "coins": "mvp",
        "notes": "net use \\\\target\\C$; copy + remote execute via admin shares over 445.",
        "steps": [
            {"observable": "network_logon", "event_id": "4624", "data_source": "security",
             "fields": {"logon_type": "3", "logon_process": "NtLmSsp", "auth_package": "NTLM"}},
            {"observable": "admin_share_access", "event_id": "5145", "data_source": "security",
             "fields": {"share_name": "ADMIN$", "access_mask": "WriteData"}},
            {"observable": "admin_share_access", "event_id": "5140", "data_source": "security",
             "fields": {"share_name": "C$", "access_mask": "ReadData"}},
            {"observable": "svc_create", "event_id": "7045", "data_source": "system",
             "fields": {"service_name": "PSEXESVC", "image_path": "C:\\Windows\\ADMIN$\\PSEXESVC.exe"}},
            {"observable": "new_process", "event_id": "4688", "data_source": "security",
             "fields": {"process": "cmd.exe", "parent_process": "services.exe"}},
        ],
    },
    {
        "technique_id": "T1021.006",
        "name": "Windows Remote Management (WinRM)",
        "tactic": "lateral-movement",
        "severity": "high",
        "source": "ATK01",
        "target": "WK-WIN11",
        "user": "corp\\emp.admin",
        "data_sources": ["security", "sysmon", "zeek"],
        "coins": "mvp",
        "notes": "WinRM Invoke-Command over 5985/5986; logon type 3 + 4648.",
        "steps": [
            {"observable": "explicit_creds", "event_id": "4648", "data_source": "security",
             "fields": {"logon_type": "3", "target_server": "WK-WIN11"}},
            {"observable": "network_logon", "event_id": "4624", "data_source": "security",
             "fields": {"logon_type": "3", "logon_process": "Advapi", "auth_package": "Negotiate"}},
            {"observable": "priv_assigned", "event_id": "4672", "data_source": "security",
             "fields": {"privileges": ["SeTcbPrivilege", "SeBackupPrivilege"]}},
            {"observable": "new_process", "event_id": "4688", "data_source": "security",
             "fields": {"process": "powershell.exe", "parent_process": "wsmprovhost.exe"}},
            {"observable": "psh_remote", "event_id": "4104", "data_source": "powershell",
             "fields": {"script": "Invoke-Command -ComputerName WK-WIN11"}},
        ],
    },
    {
        "technique_id": "T1021.001",
        "name": "Remote Desktop Protocol (RDP)",
        "tactic": "lateral-movement",
        "severity": "medium",
        "source": "ATK01",
        "target": "WK-WIN11",
        "user": "corp\\emp.barker",
        "data_sources": ["security", "zeek"],
        "coins": "mvp",
        "notes": "RDP login to workstation over 3389; logon type 10.",
        "steps": [
            {"observable": "rdp_logon", "event_id": "4624", "data_source": "security",
             "fields": {"logon_type": "10", "logon_process": "User32", "auth_package": "Negotiate"}},
            {"observable": "inbound_3389", "event_id": "none", "data_source": "zeek",
             "fields": {"proto": "tcp", "dport": "3389", "service": "rdp"}},
            {"observable": "new_process", "event_id": "4688", "data_source": "security",
             "fields": {"process": "cmd.exe", "parent_process": "explorer.exe"}},
        ],
    },
    {
        "technique_id": "T1550.002",
        "name": "Pass-the-Hash",
        "tactic": "lateral-movement",
        "severity": "critical",
        "source": "ATK01",
        "target": "WK-SRV2019",
        "user": "corp\\svc_backup",
        "data_sources": ["security", "suricata"],
        "coins": "mvp",
        "notes": "NTLM PtH (wmiexec/smbexec) using stolen hash; RC4 NTLM logon type 3.",
        "steps": [
            {"observable": "network_logon", "event_id": "4624", "data_source": "security",
             "fields": {"logon_type": "3", "logon_process": "NtLmSsp", "auth_package": "NTLM"}},
            {"observable": "ntlm_auth", "event_id": "8004", "data_source": "ntlm",
             "fields": {"auth_protocol": "NTLMv2", "package": "NTLM"}},
            {"observable": "wmi_remote_exec", "event_id": "4688", "data_source": "security",
             "fields": {"process": "cmd.exe", "parent_process": "WmiPrvSE.exe"}},
        ],
    },
    {
        "technique_id": "T1550.003",
        "name": "Pass-the-Ticket",
        "tactic": "lateral-movement",
        "severity": "critical",
        "source": "ATK01",
        "target": "WK-SRV2019",
        "user": "corp\\svc_sql",
        "data_sources": ["security"],
        "coins": "v1",
        "notes": "Replay of a forged/reused Kerberos TGS toward a target host.",
        "steps": [
            {"observable": "tgt_req", "event_id": "4768", "data_source": "security",
             "fields": {"ticket_opts": "0x40810010", "user": "svc_sql"}},
            {"observable": "tgs_req", "event_id": "4769", "data_source": "security",
             "fields": {"ticket_encryption": "0x17", "service": "WK-SRV2019$"}},
            {"observable": "krb_logon", "event_id": "4624", "data_source": "security",
             "fields": {"logon_type": "3", "auth_package": "Kerberos"}},
        ],
    },
    {
        "technique_id": "T1558.003",
        "name": "Kerberoasting",
        "tactic": "credential-access",
        "severity": "high",
        "source": "ATK01",
        "target": "DC01",
        "user": "corp\\emp.barker",
        "data_sources": ["security"],
        "coins": "v1",
        "notes": "SPN TGS-REQ with RC4 encryption to harvest service hashes.",
        "steps": [
            {"observable": "tgs_rc4", "event_id": "4769", "data_source": "security",
             "fields": {"ticket_encryption": "0x17", "service": "MSSQLSvc/sql.corp.local", "count": "8"}},
            {"observable": "tgs_rc4", "event_id": "4769", "data_source": "security",
             "fields": {"ticket_encryption": "0x17", "service": "svc_backup/corp.local"}},
        ],
    },
    {
        "technique_id": "T1021.003",
        "name": "Distributed COM (DCOM)",
        "tactic": "lateral-movement",
        "severity": "high",
        "source": "ATK01",
        "target": "WK-WIN11",
        "user": "corp\\emp.admin",
        "data_sources": ["security", "sysmon", "zeek"],
        "coins": "mvp",
        "notes": "MMC20.Application ExecuteShellCommand via DCOM over 135.",
        "steps": [
            {"observable": "dcom_connect", "event_id": "5156", "data_source": "security",
             "fields": {"proto": "TCP", "dest_port": "135", "dir": "Outbound"}},
            {"observable": "dce_rpc", "event_id": "none", "data_source": "zeek",
             "fields": {"proto": "tcp", "app": "dce_rpc", "endpoint": "6d4740x20MMC"}},
            {"observable": "remote_thread", "event_id": "8", "data_source": "sysmon",
             "fields": {"source_proc": "mmc.exe", "target_proc": "dllhost.exe"}},
            {"observable": "new_process", "event_id": "1", "data_source": "sysmon",
             "fields": {"process": "cmd.exe", "parent_process": "dllhost.exe"}},
        ],
    },
    {
        "technique_id": "T1570",
        "name": "Lateral Tool Transfer",
        "tactic": "lateral-movement",
        "severity": "medium",
        "source": "ATK01",
        "target": "FS01",
        "user": "corp\\emp.admin",
        "data_sources": ["security", "sysmon", "zeek"],
        "coins": "mvp",
        "notes": "copy/certutil/BITS transfer of tools to ADMIN$ shares over SMB.",
        "steps": [
            {"observable": "share_write", "event_id": "5145", "data_source": "security",
             "fields": {"share_name": "ADMIN$", "relative_target": "tool.exe", "access_mask": "WriteData"}},
            {"observable": "file_create", "event_id": "11", "data_source": "sysmon",
             "fields": {"path": "C:\\Windows\\ADMIN$\\tool.exe"}},
            {"observable": "smb_bytes", "event_id": "none", "data_source": "zeek",
             "fields": {"proto": "tcp", "dport": "445", "sent_bytes_large": "true"}},
        ],
    },
    {
        "technique_id": "T1078",
        "name": "Valid Accounts",
        "tactic": "lateral-movement",
        "severity": "high",
        "source": "ATK01",
        "target": "WK-SRV2019",
        "user": "corp\\emp.chen",
        "data_sources": ["security"],
        "coins": "v1",
        "notes": "Replay of legit-but-anomalous domain credential (first-seen host-user).",
        "steps": [
            {"observable": "network_logon", "event_id": "4624", "data_source": "security",
             "fields": {"logon_type": "3", "user": "emp.chen", "logon_process": "NtLmSsp"}},
            {"observable": "first_seen", "event_id": "4624", "data_source": "security",
             "fields": {"logon_type": "3", "workstation_new": "true"}},
        ],
    },
    {
        "technique_id": "T1047",
        "name": "Windows Management Instrumentation (WMI)",
        "tactic": "lateral-movement",
        "severity": "high",
        "source": "ATK01",
        "target": "WK-SRV2019",
        "user": "corp\\emp.admin",
        "data_sources": ["security", "sysmon", "zeek"],
        "coins": "mvp",
        "notes": "wmic /node: /user: + Invoke-WmiMethod remote command.",
        "steps": [
            {"observable": "dcom_connect", "event_id": "5156", "data_source": "security",
             "fields": {"proto": "TCP", "dest_port": "135", "dir": "Outbound"}},
            {"observable": "wmi_process", "event_id": "1", "data_source": "sysmon",
             "fields": {"process": "cmd.exe", "parent_process": "WmiPrvSE.exe"}},
            {"observable": "wmi_remote_exec", "event_id": "4688", "data_source": "security",
             "fields": {"process": "cmd.exe", "parent_process": "WmiPrvSE.exe"}},
        ],
    },
    {
        "technique_id": "T1543.003",
        "name": "Windows Service (PsExec-style)",
        "tactic": "lateral-movement",
        "severity": "high",
        "source": "ATK01",
        "target": "WK-SRV2019",
        "user": "corp\\emp.admin",
        "data_sources": ["security", "sysmon", "system"],
        "coins": "mvp",
        "notes": "Copy PSEXESVC.exe then sc create + start for remote execution.",
        "steps": [
            {"observable": "share_write", "event_id": "5145", "data_source": "security",
             "fields": {"share_name": "ADMIN$", "relative_target": "PSEXESVC.exe"}},
            {"observable": "svc_create", "event_id": "7045", "data_source": "system",
             "fields": {"service_name": "PSEXESVC", "image_path": "C:\\Windows\\ADMIN$\\PSEXESVC.exe"}},
            {"observable": "pipe_connect", "event_id": "18", "data_source": "sysmon",
             "fields": {"pipe": "PSEXESVC-"}},
            {"observable": "new_process", "event_id": "4688", "data_source": "security",
             "fields": {"process": "cmd.exe", "parent_process": "services.exe"}},
        ],
    },
    {
        "technique_id": "T1021.004",
        "name": "SSH",
        "tactic": "lateral-movement",
        "severity": "medium",
        "source": "ATK01",
        "target": "WK-SRV2019",
        "user": "corp\\svc_backup",
        "data_sources": ["security", "zeek"],
        "coins": "v1",
        "notes": "OpenSSH remote session over 22.",
        "steps": [
            {"observable": "ssh_auth", "event_id": "none", "data_source": "zeek",
             "fields": {"proto": "tcp", "dport": "22", "service": "ssh", "auth_success": "true"}},
            {"observable": "network_logon", "event_id": "4624", "data_source": "security",
             "fields": {"logon_type": "3", "logon_process": "Ssp", "auth_package": "Negotiate"}},
        ],
    },
    {
        "technique_id": "T1087",
        "name": "Account Discovery",
        "tactic": "discovery",
        "severity": "low",
        "source": "ATK01",
        "target": "DC01",
        "user": "corp\\emp.barker",
        "data_sources": ["security", "zeek"],
        "coins": "v1",
        "notes": "net user /domain + ADSI queries to map accounts.",
        "steps": [
            {"observable": "ldap_query", "event_id": "none", "data_source": "zeek",
             "fields": {"proto": "tcp", "dport": "389", "service": "ldap", "query": "user"}},
            {"observable": "new_process", "event_id": "4688", "data_source": "security",
             "fields": {"process": "net.exe", "cmdline": "net user /domain"}},
        ],
    },
    {
        "technique_id": "T1018",
        "name": "Remote System Discovery",
        "tactic": "discovery",
        "severity": "low",
        "source": "ATK01",
        "target": "DC01",
        "user": "corp\\emp.barker",
        "data_sources": ["security", "zeek"],
        "coins": "v1",
        "notes": "nltest /dclist + ping sweep to map victims.",
        "steps": [
            {"observable": "dns_burst", "event_id": "22", "data_source": "sysmon",
             "fields": {"query": "corp.local", "count": "12"}},
            {"observable": "new_process", "event_id": "4688", "data_source": "security",
             "fields": {"process": "nltest.exe", "cmdline": "nltest /dclist:corp.local"}},
        ],
    },
]

BENIGN_SOURCES = ["DC01", "WK-WIN11", "WK-SRV2019", "FS01"]
BENIGN_USERS = ["emp.barker", "emp.chen", "svc_sql", "SYSTEM"]
APPROVED_IP = {"DC01": "10.24.43.10", "WK-WIN11": "10.24.43.12", "WK-SRV2019": "10.24.43.13", "FS01": "10.24.43.11"}


def _host_ip(host):
    for t in TOPOLOGY:
        if t["host"] == host:
            return t["ip"]
    return "10.24.43.20"


def _benign_record(rng, run_id, source, target):
    variants = [
        {"observable": "benign_admin_logon", "event_id": "4624", "data_source": "security",
         "fields": {"logon_type": "3", "logon_process": "NtLmSsp", "auth_package": "NTLM",
                    "user": rng.choice(BENIGN_USERS), "source_ip": APPROVED_IP.get(rng.choice(BENIGN_SOURCES))}},
        {"observable": "scheduled_job", "event_id": "4688", "data_source": "security",
         "fields": {"process": "powershell.exe", "parent_process": "svchost.exe",
                    "cmdline": "maintenance.ps1"}},
        {"observable": "patch_service", "event_id": "7045", "data_source": "system",
         "fields": {"service_name": "PATCHAGENT", "image_path": "C:\\Program Files\\PatchAgent\\pa.exe"}},
        {"observable": "rdp_console", "event_id": "4624", "data_source": "security",
         "fields": {"logon_type": "10", "logon_process": "User32", "user": "emp.chen"}},
    ]
    v = rng.choice(variants)
    return {"observable": v["observable"], "event_id": v["event_id"], "data_source": v["data_source"],
            "fields": v["fields"], "is_benign": True, "technique_id": None}


def _step_record(step, run_id, technique_id, source, target, user, idx):
    fields = dict(step["fields"])
    fields.setdefault("user", user)
    if step["event_id"].isdigit():
        fields.setdefault("source_ip", _host_ip(source))
        fields.setdefault("target_ip", _host_ip(target))
    return {
        "observable": step["observable"],
        "event_id": step["event_id"],
        "data_source": step["data_source"],
        "fields": fields,
        "is_benign": False,
        "technique_id": technique_id,
        "source": source,
        "target": target,
        "step": idx,
    }


def new_run_id(technique_id):
    return "r%s_%s" % (time.strftime("%Y%m%d_%H%M%S"), technique_id.replace(".", "-"))


def run_technique(technique, rng=None):
    rng = rng or random.Random()
    run_id = new_run_id(technique["technique_id"])
    source = technique["source"]
    target = technique["target"]
    user = technique["user"]
    records = [_step_record(s, run_id, technique["technique_id"], source, target, user, i)
               for i, s in enumerate(technique["steps"])]
    for _ in range(rng.randint(1, 3)):
        records.append(_benign_record(rng, run_id, source, target))
    payload = {
        "run_id": run_id,
        "technique_id": technique["technique_id"],
        "technique_name": technique["name"],
        "source": source,
        "target": target,
        "user": user,
        "ts": time.time(),
        "records": records,
        "record_count": len(records),
        "is_lab": LAB_TAG,
        "site": SITE,
    }
    payload["sha256"] = hashlib.sha256(json.dumps(
        {"run_id": run_id, "technique_id": technique["technique_id"], "records": records},
        sort_keys=True).encode()).hexdigest()
    return payload


def seed():
    return {"techniques": len(TECHNIQUES), "hosts": len(TOPOLOGY), "identities": len(IDENTITIES)}


def technique_map():
    return {t["technique_id"]: t for t in TECHNIQUES}