"""Embedded MITRE ATT&CK index (curated, STIX 2.1-style, vendor-neutral subset).

Offline-bundled dataset used by the mapping/attribution engines.
Can be regenerated from the official enterprise-attack STIX bundle.
"""
from __future__ import annotations

# ---------------------------------------------------------------------------
# Tactics (canonical order)
# ---------------------------------------------------------------------------
TACTICS = [
    {"id": "TA0043", "name": "Reconnaissance",          "short": "reconnaissance"},
    {"id": "TA0042", "name": "Resource Development",     "short": "resource-development"},
    {"id": "TA0001", "name": "Initial Access",           "short": "initial-access"},
    {"id": "TA0002", "name": "Execution",                "short": "execution"},
    {"id": "TA0003", "name": "Persistence",              "short": "persistence"},
    {"id": "TA0004", "name": "Privilege Escalation",     "short": "privilege-escalation"},
    {"id": "TA0005", "name": "Defense Evasion",          "short": "defense-evasion"},
    {"id": "TA0006", "name": "Credential Access",        "short": "credential-access"},
    {"id": "TA0007", "name": "Discovery",                "short": "discovery"},
    {"id": "TA0008", "name": "Lateral Movement",         "short": "lateral-movement"},
    {"id": "TA0009", "name": "Collection",               "short": "collection"},
    {"id": "TA0011", "name": "Command and Control",      "short": "command-and-control"},
    {"id": "TA0010", "name": "Exfiltration",             "short": "exfiltration"},
    {"id": "TA0040", "name": "Impact",                   "short": "impact"},
]

TACTIC_SHORT_TO_ID = {t["short"]: t["id"] for t in TACTICS}

# ---------------------------------------------------------------------------
# Techniques
# ---------------------------------------------------------------------------
# fields: id, name, tactics (shorts), url, description
TECHNIQUES = {
    "T1592": {"id": "T1592", "name": "Gather Victim Host Information", "tactics": ["reconnaissance"], "desc": "Collect host/OS/VM details prior to action."},
    "T1587": {"id": "T1587", "name": "Develop Capabilities", "tactics": ["resource-development"], "desc": "Build malware, exploits and tooling."},
    "T1608": {"id": "T1608", "name": "Stage Capabilities", "tactics": ["resource-development"], "desc": "Upload malicious content to adversary-controlled infrastructure."},
    "T1566": {"id": "T1566", "name": "Phishing", "tactics": ["initial-access"], "desc": "Deliver payloads via spearphishing."},
    "T1195": {"id": "T1195", "name": "Supply Chain Compromise", "tactics": ["initial-access"], "desc": "Compromise third-party software/hardware or their distribution mechanism."},
    "T1190": {"id": "T1190", "name": "Exploit Public-Facing Application", "tactics": ["initial-access"], "desc": "Exploit internet-facing software vulnerability."},
    "T1078": {"id": "T1078", "name": "Valid Accounts", "tactics": ["initial-access", "persistence", "privilege-escalation", "defense-evasion"], "desc": "Use compromised legitimate credentials."},
    "T1059": {"id": "T1059", "name": "Command and Scripting Interpreter", "tactics": ["execution"], "desc": "Execute code via interpreters (cmd, powershell, WMI, VBA)."},
    "T1204": {"id": "T1204", "name": "User Execution", "tactics": ["execution"], "desc": "User executes malicious payload."},
    "T1047": {"id": "T1047", "name": "Windows Management Instrumentation", "tactics": ["execution"], "desc": "Leverage WMI for execution and info gathering."},
    "T1053": {"id": "T1053", "name": "Scheduled Task/Job", "tactics": ["execution", "persistence", "privilege-escalation"], "desc": "Schedule jobs for execution/persistence."},
    "T1547": {"id": "T1547", "name": "Boot or Logon Autostart Execution", "tactics": ["persistence", "privilege-escalation"], "desc": "Persist via autostart locations (Run keys, startup)."},
    "T1543": {"id": "T1543", "name": "Create or Modify System Process", "tactics": ["persistence", "privilege-escalation"], "desc": "Install services or start-up daemons."},
    "T1546": {"id": "T1546", "name": "Event Triggered Execution", "tactics": ["persistence", "privilege-escalation"], "desc": "Persist via event/trigger mechanisms (COM hijack, WMI events)."},
    "T1055": {"id": "T1055", "name": "Process Injection", "tactics": ["defense-evasion", "privilege-escalation"], "desc": "Inject code into other processes."},
    "T1068": {"id": "T1068", "name": "Exploitation for Privilege Escalation", "tactics": ["privilege-escalation"], "desc": "Exploit vulnerability to gain higher privileges."},
    "T1548": {"id": "T1548", "name": "Abuse Elevation Control Mechanism", "tactics": ["privilege-escalation", "defense-evasion"], "desc": "Bypass UAC or misuse sudo."},
    "T1036": {"id": "T1036", "name": "Masquerading", "tactics": ["defense-evasion"], "desc": "Rename/replace binaries to evade detection."},
    "T1070": {"id": "T1070", "name": "Indicator Removal on Host", "tactics": ["defense-evasion"], "desc": "Delete logs, timestamps, artifacts of activity."},
    "T1027": {"id": "T1027", "name": "Obfuscated Files or Information", "tactics": ["defense-evasion"], "desc": "Encrypt, pack, XOR payloads."},
    "T1140": {"id": "T1140", "name": "Deobfuscate/Decode Files or Information", "tactics": ["defense-evasion"], "desc": "Decode/pack payloads at runtime."},
    "T1218": {"id": "T1218", "name": "Signed Binary Proxy Execution", "tactics": ["defense-evasion"], "desc": "Abuse signed Microsoft binaries (mshta, rundll32, regsvr32)."},
    "T1562": {"id": "T1562", "name": "Impair Defenses", "tactics": ["defense-evasion"], "desc": "Disable AV/EDR/firewall."},
    "T1003": {"id": "T1003", "name": "OS Credential Dumping", "tactics": ["credential-access"], "desc": "Dump credentials (lsass, SAM, NTDS)."},
    "T1110": {"id": "T1110", "name": "Brute Force", "tactics": ["credential-access"], "desc": "Password guessing/spraying."},
    "T1056": {"id": "T1056", "name": "Input Capture", "tactics": ["collection", "credential-access"], "desc": "Capture keystrokes/credentials via hooks."},
    "T1555": {"id": "T1555", "name": "Credentials from Password Stores", "tactics": ["credential-access"], "desc": "Extract credentials from vaults/browsers."},
    "T1082": {"id": "T1082", "name": "System Information Discovery", "tactics": ["discovery"], "desc": "Enumerate host OS, CPU, hostname."},
    "T1057": {"id": "T1057", "name": "Process Discovery", "tactics": ["discovery"], "desc": "List running processes."},
    "T1083": {"id": "T1083", "name": "File and Directory Discovery", "tactics": ["discovery"], "desc": "Enumerate files/directories of interest."},
    "T1016": {"id": "T1016", "name": "System Network Configuration Discovery", "tactics": ["discovery"], "desc": "Gather local network config (ipconfig, netstat)."},
    "T1018": {"id": "T1018", "name": "Remote System Discovery", "tactics": ["discovery"], "desc": "Discover other hosts on the network."},
    "T1518": {"id": "T1518", "name": "Software Discovery", "tactics": ["discovery"], "desc": "List installed software/security tools."},
    "T1021": {"id": "T1021", "name": "Remote Services", "tactics": ["lateral-movement"], "desc": "Admin shares, SMB/WinRM/RDP/SSH movement."},
    "T1570": {"id": "T1570", "name": "Lateral Tool Transfer", "tactics": ["lateral-movement"], "desc": "Copy/post tooling to remote hosts."},
    "T1563": {"id": "T1563", "name": "Remote Service Session Hijacking", "tactics": ["lateral-movement"], "desc": "Hijack existing remote sessions."},
    "T1005": {"id": "T1005", "name": "Data from Local System", "tactics": ["collection"], "desc": "Collect data from local sources."},
    "T1074": {"id": "T1074", "name": "Data Staged", "tactics": ["collection"], "desc": "Stage data before exfiltration."},
    "T1071": {"id": "T1071", "name": "Application Layer Protocol", "tactics": ["command-and-control"], "desc": "C2 over HTTP/HTTPS/DNS/SMTP."},
    "T1573": {"id": "T1573", "name": "Encrypted Channel", "tactics": ["command-and-control"], "desc": "C2 over custom encryption/TLS."},
    "T1105": {"id": "T1105", "name": "Ingress Tool Transfer", "tactics": ["command-and-control"], "desc": "Download additional tooling from C2."},
    "T1090": {"id": "T1090", "name": "Proxy", "tactics": ["command-and-control"], "desc": "Route traffic via proxies."},
    "T1568": {"id": "T1568", "name": "Dynamic Resolution", "tactics": ["command-and-control"], "desc": "Resolve C2 via fast flux / DDNS."},
    "T1041": {"id": "T1041", "name": "Exfiltration Over C2 Channel", "tactics": ["exfiltration"], "desc": "Exfiltrate data over existing C2."},
    "T1567": {"id": "T1567", "name": "Exfiltration Over Web Service", "tactics": ["exfiltration"], "desc": "Exfiltrate via cloud/web services."},
    "T1030": {"id": "T1030", "name": "Data Transfer Size Limits", "tactics": ["exfiltration"], "desc": "Split exfiltration to evade thresholds."},
    "T1486": {"id": "T1486", "name": "Data Encrypted for Impact", "tactics": ["impact"], "desc": "Ransomware file encryption."},
    "T1489": {"id": "T1489", "name": "Service Stop", "tactics": ["impact"], "desc": "Stop critical services/processes."},
    "T1531": {"id": "T1531", "name": "Account Access Removal", "tactics": ["impact"], "desc": "Lock/delete user accounts."},
    "T1498": {"id": "T1498", "name": "Network Denial of Service", "tactics": ["impact"], "desc": "DoS the victim network."},
}

# ---------------------------------------------------------------------------
# Software (malware/tools) — used to enrich attribution
# ---------------------------------------------------------------------------
SOFTWARE = {
    "S0416": {"id": "S0416", "name": "Komplex", "group": "G0016", "techniques": ["T1071", "T1105", "T1059"]},
    "S0531": {"id": "S0531", "name": "PowerDuke", "group": "G0016", "techniques": ["T1071", "T1105", "T1055"]},
    "S0409": {"id": "S0409", "name": "Sednit", "group": "G0007", "techniques": ["T1071", "T1105", "T1027"]},
    "S0331": {"id": "S0331", "name": "Agent Tesla", "group": None, "techniques": ["T1059", "T1071", "T1041", "T1567", "T1056"]},
    "S0296": {"id": "S0296", "name": "Bankshot", "group": "G0020", "techniques": ["T1021", "T1105", "T1486"]},
    "S0462": {"id": "S0462", "name": "MuddyWater Tools", "group": "G0069", "techniques": ["T1071", "T1059", "T1003", "T1082"]},
}

# ---------------------------------------------------------------------------
# Groups (threat actors) — probable technique sets from public research
# ---------------------------------------------------------------------------
GROUPS = {
    "G0006": {
        "id": "G0006", "name": "APT1", "aliases": ["Comment Crew"],
        "techniques": ["T1027", "T1105", "T1566", "T1059", "T1082", "T1005", "T1071", "T1041"],
        "software": [],
    },
    "G0007": {
        "id": "G0007", "name": "APT28", "aliases": ["Fancy Bear", "Sofacy"],
        "techniques": ["T1566", "T1105", "T1567", "T1027", "T1071", "T1041", "T1016", "T1047", "T1518"],
        "software": ["S0409"],
    },
    "G0016": {
        "id": "G0016", "name": "APT29", "aliases": ["Cozy Bear", "The Dukes"],
        "techniques": ["T1078", "T1071", "T1055", "T1105", "T1573", "T1543", "T1053", "T1562", "T1027", "T1041"],
        "software": ["S0416", "S0531"],
    },
    "G0020": {
        "id": "G0020", "name": "Lazarus Group", "aliases": ["Hidden Cobra"],
        "techniques": ["T1059", "T1105", "T1486", "T1055", "T1057", "T1082", "T1068", "T1041", "T1021"],
        "software": ["S0296"],
    },
    "G0045": {
        "id": "G0045", "name": "FIN7", "aliases": ["Carbanak", "Navigator Group"],
        "techniques": ["T1566", "T1059", "T1071", "T1041", "T1003", "T1190", "T1021", "T1518"],
        "software": [],
    },
    "G0096": {
        "id": "G0096", "name": "APT41", "aliases": ["Winnti Group"],
        "techniques": ["T1566", "T1078", "T1003", "T1573", "T1105", "T1543", "T1053", "T1068", "T1486"],
        "software": [],
    },
}

TECHNIQUE_TACTICS = {t["id"]: t["tactics"] for t in TECHNIQUES.values()}

# ---------------------------------------------------------------------------
# Rule-based signature index  (technique_keyword / observable patterns)
# Each rule fires when any `patterns` substring is found in evidence text,
# or any `behaviors` keyword tag is present.
# ---------------------------------------------------------------------------
RULES = [
    {"id": "R-001", "technique": "T1566", "patterns": ["spearphish", "attachment", "macro", ".docm", "malicious document"], "behaviors": ["email:attachment", "macro:autoopen"], "base_weight": 0.85},
    {"id": "R-002", "technique": "T1190", "patterns": ["exploit exploit", "cve-2", "cve-201", "cve-202", "httpd exploit", "webshell"], "behaviors": ["exploit:web"], "base_weight": 0.8},
    {"id": "R-003", "technique": "T1078", "patterns": ["valid account", "stolen credential", "pass-the-hash", "ptt", "kerberos ticket"], "behaviors": ["auth:impersonation"], "base_weight": 0.75},
    {"id": "R-004", "technique": "T1059", "patterns": ["powershell -enc", "powershell.exe", "cmd /c", "wmicexec", "rundll32", "wscript", "cscript", "powershell script"], "behaviors": ["exec:cmd", "exec:powershell"], "base_weight": 0.8},
    {"id": "R-005", "technique": "T1047", "patterns": ["win32_process.create", "wmi", "roboexec", "wmiprvse"], "behaviors": ["exec:wmi"], "base_weight": 0.7},
    {"id": "R-006", "technique": "T1053", "patterns": ["schtasks", "create scheduled task", "at.exe", "task scheduler"], "behaviors": ["persistence:scheduled_task"], "base_weight": 0.8},
    {"id": "R-007", "technique": "T1547", "patterns": ["hkcu\\software\\microsoft\\windows\\currentversion\\run", "hklm\\software\\microsoft\\windows\\currentversion\\run", "startup folder", "registry run key", "autorun"], "behaviors": ["persistence:runkey", "persistence:startup"], "base_weight": 0.8},
    {"id": "R-008", "technique": "T1543", "patterns": ["create service", "sc create", "new service", "driver service", "service install"], "behaviors": ["persistence:service"], "base_weight": 0.75},
    {"id": "R-009", "technique": "T1546", "patterns": ["com handler", "wmi event subscription", "image file execution options", "ifefo", "appinit_dlls"], "behaviors": ["persistence:com_hijack", "persistence:wmi_event"], "base_weight": 0.75},
    {"id": "R-010", "technique": "T1055", "patterns": ["createremotethread", "queueuserapc", "process hollowing", "inject", "mapper alloc", "virtualallocex"], "behaviors": ["evasion:injection"], "base_weight": 0.85},
    {"id": "R-011", "technique": "T1068", "patterns": ["local privilege escalation", "lpe", "uac bypass attempt", "kernel exploit"], "behaviors": ["privesc:exploit"], "base_weight": 0.8},
    {"id": "R-012", "technique": "T1548", "patterns": ["uac bypass", "cmstp", "eventvwr", "fodhelper", "sdclt"], "behaviors": ["privesc:uac"], "base_weight": 0.7},
    {"id": "R-013", "technique": "T1036", "patterns": ["masquerade", "spoofed filename", "legit path", "svchost clone", "renamed file"], "behaviors": ["evasion:masquerade"], "base_weight": 0.65},
    {"id": "R-014", "technique": "T1070", "patterns": ["deleted logs", "timestomp", "antiforensic", "clear event log", "evt logs clear", "rm -rf", "del .log"], "behaviors": ["evasion:log_tamper"], "base_weight": 0.8},
    {"id": "R-015", "technique": "T1027", "patterns": ["upx", "packed", "xored", "encrypted payload", "encrypted blob", "base64", "custom packer", "high entropy", "obfuscation"], "behaviors": ["evasion:packed", "evasion:obfuscation"], "base_weight": 0.8},
    {"id": "R-016", "technique": "T1140", "patterns": ["decrypt payload", "decode routine", "rc4", "aes decrypt", "loadstring"], "behaviors": ["evasion:decode"], "base_weight": 0.7},
    {"id": "R-017", "technique": "T1218", "patterns": ["mshta", "rundll32.exe javascript", "regsvr32 scrobj", "cmstp", "certutil -urlcache"], "behaviors": ["exec:lolbin"], "base_weight": 0.8},
    {"id": "R-018", "technique": "T1562", "patterns": ["disable av", "disable firewall", "stop service win", "delete policy key", "patch av", "tamper protection bypass"], "behaviors": ["evasion:defense_disable"], "base_weight": 0.9},
    {"id": "R-019", "technique": "T1003", "patterns": ["lsass", "minidump", "ntds.dit", "sam hive", "secrets dump", "mimikatz", "kerberos dump"], "behaviors": ["cred:dump", "cred:lsass"], "base_weight": 0.95},
    {"id": "R-020", "technique": "T1110", "patterns": ["brute force", "password spray", "dictionary attack", "401 unauthorized retry"], "behaviors": ["cred:brute"], "base_weight": 0.8},
    {"id": "R-021", "technique": "T1056", "patterns": ["keylogger", "keyboard hook", "getasynckeystate", "log keystroke", "screen capture"], "behaviors": ["collection:keylog"], "base_weight": 0.9},
    {"id": "R-022", "technique": "T1555", "patterns": ["browser credential", "cookies dump", "credential vault", "chrome login data", "firefox logins"], "behaviors": ["cred:vault"], "base_weight": 0.85},
    {"id": "R-023", "technique": "T1082", "patterns": ["hostname", "systeminfo", "os version", "cpu info", "machine guid", "computer name"], "behaviors": ["discovery:systeminfo"], "base_weight": 0.7},
    {"id": "R-024", "technique": "T1057", "patterns": ["process list", "tasklist", "enumerate processes", "toolhelp32", "processsnapshot"], "behaviors": ["discovery:processes"], "base_weight": 0.7},
    {"id": "R-025", "technique": "T1083", "patterns": ["find file", "dir /s", "enumerate directory", "search for documents", "exc.dll"], "behaviors": ["discovery:files"], "base_weight": 0.65},
    {"id": "R-026", "technique": "T1016", "patterns": ["ipconfig", "netstat", "arp table", "dns servers", "network adapter config"], "behaviors": ["discovery:netconf"], "base_weight": 0.65},
    {"id": "R-027", "technique": "T1018", "patterns": ["net view", "active directory query", "ldap sweep", "nbtstat"], "behaviors": ["discovery:remote_hosts"], "base_weight": 0.7},
    {"id": "R-028", "technique": "T1518", "patterns": ["installed software", "av detect", "enumerate av", "wmic product"], "behaviors": ["discovery:software"], "base_weight": 0.6},
    {"id": "R-029", "technique": "T1021", "patterns": ["smb", "admin share", "winrm", "psremoting", "psexec service", "rdp session", "ssh"], "behaviors": ["lateral:remote_service"], "base_weight": 0.85},
    {"id": "R-030", "technique": "T1570", "patterns": ["copy to remote host", "scp transfer", "admin share drop", "file copy remote"], "behaviors": ["lateral:tool_transfer"], "base_weight": 0.8},
    {"id": "R-031", "technique": "T1563", "patterns": ["session hijack", "tscon", "steal rdp session"], "behaviors": ["lateral:session_hijack"], "base_weight": 0.8},
    {"id": "R-032", "technique": "T1005", "patterns": ["collect documents", "harvest files", "zip documents", "grab credentials files", "download sensitive"], "behaviors": ["collection:local_data"], "base_weight": 0.8},
    {"id": "R-033", "technique": "T1074", "patterns": ["staging directory", "temp staging", "data staging", "7z archive stage"], "behaviors": ["collection:staged"], "base_weight": 0.7},
    {"id": "R-034", "technique": "T1071", "patterns": ["http beacon", "https post", "c2 domain", "dns tunnel", "http request user-agent", "botnet c2"], "behaviors": ["c2:http", "c2:dns"], "base_weight": 0.85},
    {"id": "R-035", "technique": "T1573", "patterns": ["encrypted c2", "tls custom cert", "obfuscated beacon", "rc4 channel"], "behaviors": ["c2:encrypted"], "base_weight": 0.8},
    {"id": "R-036", "technique": "T1105", "patterns": ["download next stage", "ingress tool transfer", "fetch second payload", "download.exe", "stager download"], "behaviors": ["c2:ingress_tool"], "base_weight": 0.85},
    {"id": "R-037", "technique": "T1090", "patterns": ["proxy", "socks", "redirector", "tor exit"], "behaviors": ["c2:proxy"], "base_weight": 0.65},
    {"id": "R-038", "technique": "T1568", "patterns": ["fast flux", "dynamic dns", "ddns", "domain generation alg", "dga"], "behaviors": ["c2:dynamic_resolution"], "base_weight": 0.8},
    {"id": "R-039", "technique": "T1041", "patterns": ["exfil over c2", "data to c2", "post documents", "upload via beacon"], "behaviors": ["exfil:c2_channel"], "base_weight": 0.85},
    {"id": "R-040", "technique": "T1567", "patterns": ["exfil to cloud", "upload to pastebin", "gmail exfil", "google docs exfil", "cloud storage upload"], "behaviors": ["exfil:webservice"], "base_weight": 0.8},
    {"id": "R-041", "technique": "T1030", "patterns": ["chunked exfil", "size limit bypass", "split upload"], "behaviors": ["exfil:size_limits"], "base_weight": 0.6},
    {"id": "R-042", "technique": "T1486", "patterns": ["ransom note", "file extension change", ".encrypted", "encrypt user files", "bitlocker", "delete shadow copies", "vssadmin delete"], "behaviors": ["impact:ransomware", "impact:file_encrypt"], "base_weight": 0.95},
    {"id": "R-043", "technique": "T1489", "patterns": ["kill service", "stop sql", "disable backup", "process kill", "taskkill"], "behaviors": ["impact:service_stop"], "base_weight": 0.8},
    {"id": "R-044", "technique": "T1531", "patterns": ["delete accounts", "lock accounts", "disable user"], "behaviors": ["impact:account_removal"], "base_weight": 0.8},
    {"id": "R-045", "technique": "T1498", "patterns": ["udp flood", "syn flood", "ddos", "amplification"], "behaviors": ["impact:dos"], "base_weight": 0.8},
]

# ---- quality of life helpers --------------------------------------------------
def technique(id_: str):
    return TECHNIQUES.get(id_)

def tactic(id_: str):
    for t in TACTICS:
        if t["id"] == id_:
            return t
    return None

def rule_index():
    return {
        r["id"]: r for r in RULES
    }