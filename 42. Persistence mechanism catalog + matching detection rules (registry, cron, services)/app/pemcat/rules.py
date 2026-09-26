import re

SEVERITY_BASE = {"critical": 100, "high": 70, "medium": 45, "low": 20}

BUILTIN_RULES = [
    {
        "id": "PEM-CAT-0001",
        "name": "Suspicious Registry Autostart in writable location",
        "technique": "T1547.001",
        "severity": "high",
        "status": "active",
        "logic": {
            "artifact_type": ["registry"],
            "mechanism_contains": ["CurrentVersion\\Run", "CurrentVersion\\RunOnce", "RunServices"],
            "image_path_contains": ["appdata", "temp", "public", "/tmp", "/var/tmp", "downloads", "c:\\users\\public"],
            "new_only": True,
        },
    },
    {
        "id": "PEM-CAT-0002",
        "name": "Service binary hosted in writable user directory",
        "technique": "T1543.003",
        "severity": "high",
        "status": "active",
        "logic": {
            "artifact_type": ["service"],
            "image_path_contains": ["appdata", "temp", "c:\\users\\public", "/tmp", "/var/tmp", "/dev/shm"],
            "new_only": False,
        },
    },
    {
        "id": "PEM-CAT-0003",
        "name": "Cron job executing from world-writable directory",
        "technique": "T1053.003",
        "severity": "medium",
        "status": "active",
        "logic": {
            "artifact_type": ["cron"],
            "image_path_contains": ["/tmp", "/var/tmp", "/dev/shm", "/home/"],
            "new_only": False,
        },
    },
    {
        "id": "PEM-CAT-0004",
        "name": "Scheduled task runs elevated binary from temp",
        "technique": "T1053.005",
        "severity": "high",
        "status": "active",
        "logic": {
            "artifact_type": ["scheduled_task"],
            "image_path_contains": ["temp", "appdata", "public", "downloads"],
            "payload_contains": [["run_as", "system"], ["run_as", "administrator"]],
            "new_only": False,
        },
    },
    {
        "id": "PEM-CAT-0005",
        "name": "WMI Event Subscription with command-line consumer",
        "technique": "T1546.001",
        "severity": "critical",
        "status": "active",
        "logic": {
            "artifact_type": ["wmi"],
            "mechanism_contains": ["wmi"],
            "new_only": False,
        },
    },
    {
        "id": "PEM-CAT-0006",
        "name": "Startup folder payload in AppData",
        "technique": "T1547.001",
        "severity": "medium",
        "status": "active",
        "logic": {
            "artifact_type": ["startup"],
            "image_path_contains": ["appdata"],
            "new_only": False,
        },
    },
    {
        "id": "PEM-CAT-0007",
        "name": "AppInit_DLLs or IFEO Debugger modification",
        "technique": "T1546.002",
        "severity": "high",
        "status": "active",
        "logic": {
            "artifact_type": ["registry"],
            "mechanism_contains": ["IFEO", "AppInit", "Winlogon"],
            "new_only": False,
        },
    },
    {
        "id": "PEM-CAT-0008",
        "name": "Obfuscated command line (encoded powershell)",
        "technique": "T1059.001",
        "severity": "medium",
        "status": "active",
        "logic": {
            "command_line_regex": r"(powershell|pwsh).*(-enc|-encodedcommand|\$\()",
            "new_only": False,
        },
    },
    {
        "id": "PEM-CAT-0009",
        "name": "System binary name impersonated in writable path",
        "technique": "T1036.005",
        "severity": "high",
        "status": "active",
        "logic": {
            "artifact_type": ["service", "registry", "scheduled_task", "startup"],
            "impersonation": {
                "names": ["svchost", "explorer", "ctfmon", "rundll32", "lsass", "winlogon"],
                "writable": ["appdata", "temp", "public", "/tmp", "/var/tmp", "downloads"],
            },
            "new_only": False,
        },
    },
]


def _contains(value, needles):
    value = (value or "").lower()
    return [needle for needle in needles if needle.lower() in value]


def _payload_contains(payload, pairs):
    hit = []
    for key, needle in pairs:
        value = payload.get(key)
        if value and needle.lower() in str(value).lower():
            hit.append("{0}={1}".format(key, value))
    return hit


def evaluate_rule(rule, record, storage, fingerprint):
    logic = rule.get("logic") or {}
    reasons = []

    wanted = logic.get("artifact_type")
    if wanted and record.get("artifact_type") not in wanted:
        return None

    if logic.get("new_only") and record.get("is_baselined"):
        return None

    if storage.is_allowlisted(fingerprint):
        return None

    mech_hits = _contains(record.get("mechanism"), logic.get("mechanism_contains", []))
    img_hits = _contains(record.get("image_path"), logic.get("image_path_contains", []))
    if mech_hits:
        reasons.append("mechanism:" + ",".join(mech_hits))
    if img_hits:
        reasons.append("image_path:" + ",".join(img_hits))

    cmd_hits = []
    regex = logic.get("command_line_regex")
    if regex:
        try:
            if re.search(regex, (record.get("command_line") or ""), re.IGNORECASE):
                cmd_hits.append("regex")
        except re.error:
            pass
    if cmd_hits:
        reasons.append("command_line:" + ",".join(cmd_hits))

    payload_hits = _payload_contains(record.get("payload") or {}, logic.get("payload_contains", []))
    if payload_hits:
        reasons.append("payload:" + ",".join(payload_hits))

    impression = logic.get("impersonation")
    if impression:
        names = impression.get("names", [])
        writable = impression.get("writable", [])
        name_hits = _contains(record.get("image_path"), names)
        wri_hits = _contains(record.get("image_path"), writable)
        if name_hits and wri_hits:
            reasons.append("impersonation:{} in {}".format(
                ",".join(name_hits), ",".join(wri_hits)))

    has_condition = bool(
        logic.get("mechanism_contains") or logic.get("image_path_contains")
        or logic.get("payload_contains") or logic.get("command_line_regex")
    )
    if not has_condition:
        return None

    if not reasons:
        return None

    confidence = min(0.4 + 0.2 * len(reasons), 1.0)
    return RuleMatch(rule, record, confidence, reasons)


class RuleMatch:
    __slots__ = ("rule", "record", "confidence", "reasons")

    def __init__(self, rule, record, confidence, reasons):
        self.rule = rule
        self.record = record
        self.confidence = confidence
        self.reasons = reasons


def run_matching(storage, records=None):
    if records is None:
        records = storage.list_records()
    rules = storage.rules(status="active")
    matches = []
    for record in records:
        fingerprint = record.get("fingerprint_sha256")
        for rule in rules:
            try:
                result = evaluate_rule(rule, record, storage, fingerprint)
            except Exception:
                continue
            if result is None:
                continue
            base = SEVERITY_BASE.get(str(rule.get("severity") or "medium").lower(), 45)
            score = round(base * result.confidence, 2)
            match = {
                "fingerprint_sha256": fingerprint,
                "rule_id": rule.get("rule_id"),
                "rule_name": rule.get("name"),
                "technique": rule.get("technique"),
                "severity": rule.get("severity"),
                "confidence": round(result.confidence, 2),
                "score": score,
                "evidence": {
                    "reasons": result.reasons,
                    "mechanism": record.get("mechanism"),
                    "image_path": record.get("image_path"),
                },
            }
            matches.append(match)
            inserted = storage.add_match(match)
            if inserted is None:
                matches.pop()
    return matches


def summarize(matches):
    by_severity = {}
    for m in matches:
        sev = str(m.get("severity") or "unknown")
        by_severity[sev] = by_severity.get(sev, 0) + 1
    by_technique = {}
    for m in matches:
        tech = str(m.get("technique") or "unknown")
        by_technique[tech] = by_technique.get(tech, 0) + 1
    return {"by_severity": by_severity, "by_technique": by_technique}