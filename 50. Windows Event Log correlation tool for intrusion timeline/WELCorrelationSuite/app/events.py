"""Event ingestion & normalization.

Collects Windows Event Log data using the native `wevtutil` binary (no
third-party modules required), parses rendered XML into a normalized
event dictionary, and supports offline/forensic import of .evtx files,
CSV exports (Sysmon etc.) and JSON exports.

A normalized event has a stable shape:

    id, ts (ISO UTC), ts_epoch, channel, event_id, provider, computer,
    level, source_ip, target_user, subject_user, process, commandline,
    data (raw fields), message, imported ("live"|"evtx"|"csv"|"json"),
    hash (sha256 evidence fingerprint)
"""
import csv
import hashlib
import io
import json
import os
import re
import subprocess
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

MESSAGE_TEMPLATES = {
    4624: "Successful logon for {TargetUserName} via logon type {LogonType} on {LogonProcessName} from {IpAddress}.",
    4625: "FAILED logon for {TargetUserName} (logon type {LogonType}) from {IpAddress}; status {Status}.",
    4634: "Logoff by {TargetUserName} (logon id {TargetLogonId}).",
    4648: "Explicit credentials used by {SubjectUserName} to logon as {TargetUserName} on {TargetServerName}.",
    4672: "Special privileges (admin rights) assigned to new logon by {SubjectUserName}.",
    4720: "NEW account created: {SamAccountName} by {SubjectUserName}.",
    4722: "Account {TargetUserName} was ENABLED by {SubjectUserName}.",
    4724: "Password reset attempted for {TargetUserName} by {SubjectUserName}.",
    4726: "Account {TargetUserName} was DELETED by {SubjectUserName}.",
    4728: "User {MemberName} added to SECURITY-GLOBAL group {TargetUserName} by {SubjectUserName}.",
    4732: "User {MemberName} added to LOCAL group {TargetUserName} by {SubjectUserName}.",
    4756: "User {MemberName} added to UNIVERSAL group {TargetUserName} by {SubjectUserName}.",
    4740: "Account {TargetUserName} was LOCKED OUT (source {CallerComputerName}).",
    4769: "Kerberos service ticket requested for {TargetUserName} -> {ServiceName}.",
    4776: "Credential validation for {TargetUserName} against {PackageName}; result {Status}.",
    1102: "SECURITY LOG WAS CLEARED by {SubjectUserName}. Defense-evasion indicator.",
    104: "Event Log was CLEARED (channel {Channel}).",
    7036: "Service {param1} entered state {param2}.",
    7040: "Service start type changed: {param1}.",
    7045: "NEW SERVICE installed: {param1} (binary {param2}).",
    4698: "SCHEDULED TASK created: {TaskName} by {SubjectUserName}.",
    4699: "SCHEDULED TASK deleted: {TaskName} by {SubjectUserName}.",
    4702: "SCHEDULED TASK updated: {TaskName} by {SubjectUserName}.",
    106: "SCHEDULED TASK registered (Task Scheduler).",
    4688: "Process created: {NewProcessName} by {SubjectUserName} (command: {CommandLine}).",
    4697: "New service installed: {ServiceName} (image {ImagePath}).",
    4104: "PowerShell ScriptBlock executed.",
    4103: "PowerShell module logging: {ModuleName}.",
    400: "PowerShell Engine started.",
    4663: "Object access attempt on {ObjectName} by {SubjectUserName}.",
    4656: "Handle to object requested: {ObjectName} by {SubjectUserName}.",
    4670: "Object permission changed: {ObjectName} by {SubjectUserName}.",
    4725: "Account {TargetUserName} DISABLED by {SubjectUserName}.",
    5136: "Directory object modified: {ObjectDN} by {SubjectUserName}.",
    5140: "SMB share object accessed: {ShareName} by {SubjectUserName} (IP {IpAddress}).",
    5145: "SMB share path accessed: {RelativeTargetName} by {SubjectUserName}.",
    5156: "WFP connection allowed: {Application} -> {DestAddress}:{DestPort}.",
    5157: "WFP connection BLOCKED: {Application} -> {DestAddress}:{DestPort}.",
    4657: "Registry value modified: {ObjectName} by {SubjectUserName}.",
    5137: "Directory object created: {ObjectDN}.",
}

_USER_KEYS = ["TargetUserName", "UserName", "AccountName"]
_SUBJECT_KEYS = ["SubjectUserName", "CallerUserName"]
_IP_KEYS = ["IpAddress", "SourceIp", "RemoteAddress", "ClientAddress",
            "IpAddress_E138E3E0-616C-460E-9A6A-9314F45EB3C6"]
_PROCESS_KEYS = ["NewProcessName", "ProcessName", "Image", "Process"]
_CMD_KEYS = ["CommandLine", "ProcessCommandLine"]


def sha256_of(obj):
    """Deterministic canonical fingerprint of a JSON-serializable object."""
    canonical = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _pick(d, keys, default=""):
    for key in keys:
        lk = str(key).strip().lower()
        for ek, ev in d.items():
            if str(ek).strip().lower() == lk and ev not in (None, ""):
                return str(ev)
        if key in d and d[key] not in (None, ""):
            return str(d[key])
    return default


def _strip_ns(tag):
    return tag.rsplit("}", 1)[-1] if tag.startswith("{") else tag


def _to_iso(value, fallback=None):
    if not value:
        return fallback or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    v = str(value).strip()
    try:
        dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    except ValueError:
        return fallback or v


def _epoch_of(iso_ts):
    try:
        return datetime.fromisoformat(str(iso_ts).replace("Z", "+00:00")).astimezone(timezone.utc).timestamp()
    except Exception:
        return 0.0


def _render(event_id, data):
    tmpl = MESSAGE_TEMPLATES.get(int(event_id))
    if not tmpl:
        return "Event ID %s; fields: %s" % (event_id, ", ".join(list(data.keys())[:8]))
    out = tmpl
    for key, val in data.items():
        out = out.replace("{%s}" % key, str(val)).replace("{%s}" % key.lower(), str(val))
    return out


def _make_event(system, event_data, imported):
    try:
        event_id = int(system.get("EventID", 0))
    except (ValueError, TypeError):
        event_id = 0
    data = {}
    for d in event_data:
        name = d.get("Name") or ""
        val = d.get("Value") or ""
        if name:
            data[name] = val
        elif val != "":
            data.setdefault("param%d" % (len(data) + 1), val)
    ts = _to_iso(system.get("TimeCreated"))
    ev = {
        "id": str(uuid.uuid4()),
        "ts": ts,
        "ts_epoch": _epoch_of(ts),
        "channel": (system.get("Channel") or "unknown").strip().lower(),
        "event_id": event_id,
        "provider": system.get("Provider") or system.get("ProviderName") or "",
        "computer": system.get("Computer") or "",
        "level": system.get("Level") or 0,
        "source_ip": _pick(data, _IP_KEYS),
        "target_user": _pick(data, _USER_KEYS),
        "subject_user": _pick(data, _SUBJECT_KEYS),
        "process": _pick(data, _PROCESS_KEYS),
        "commandline": _pick(data, _CMD_KEYS),
        "data": data,
        "message": _render(event_id, data),
        "imported": imported,
    }
    ev["hash"] = sha256_of({"system": system, "data": data})
    return ev


def parse_wevtutil_xml(xml_text, imported="live"):
    """Parse concatenated <Event> elements produced by `wevtutil qe ... /f:XML`."""
    if not xml_text or not xml_text.strip():
        return []
    text = xml_text.strip()
    if not text.startswith("<"):
        return import_csv(io.StringIO(text))
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        cleaned = re.sub(r"<\?xml[^>]*\?>", "", text)
        if not cleaned.strip().startswith("<"):
            return import_csv(io.StringIO(text))
        cleaned = "<Events>" + cleaned + "</Events>"
        try:
            root = ET.fromstring(cleaned)
        except ET.ParseError:
            return import_csv(io.StringIO(text))
    events = []
    for el in root.iter():
        if _strip_ns(el.tag) != "Event":
            continue
        system, event_data = {}, []
        for child in el:
            tag = _strip_ns(child.tag)
            if tag == "System":
                for sub in child:
                    st = _strip_ns(sub.tag)
                    if st == "TimeCreated":
                        system["TimeCreated"] = sub.get("SystemTime") or sub.text or ""
                    elif st == "Provider":
                        system["Provider"] = sub.get("Name") or sub.text or ""
                    else:
                        system[st] = sub.text or ""
            elif tag == "EventData":
                for sub in child:
                    st = _strip_ns(sub.tag)
                    if st == "Data":
                        event_data.append({"Name": sub.get("Name") or "", "Value": sub.text or ""})
                    elif st == "Binary":
                        event_data.append({"Name": "Binary", "Value": sub.text or ""})
        events.append(_make_event(system, event_data, imported))
    return events
def _run_wevtutil(args, timeout=120):
    flags = 0
    if os.name == "nt":
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        proc = subprocess.run(
            ["wevtutil.exe"] + args,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout,
            creationflags=flags,
        )
        return (proc.returncode,
                proc.stdout.decode("utf-8", "replace"),
                proc.stderr.decode("utf-8", "replace"))
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        return 1, "", str(exc)


def _fmt_filter(since_iso=None, event_ids=None):
    if since_iso:
        return "*[System[TimeCreated[@SystemTime>='%s']]]" % str(since_iso).replace("Z", ".000Z")
    if event_ids:
        ids = ",".join(str(i) for i in event_ids)
        return "*[System[(EventID=%s)]]" % ids
    return "*"


DEFAULT_CHANNELS = ["Security", "System", "Application",
                    "Microsoft-Windows-PowerShell/Operational"]


def collect_live(channels=None, max_per_channel=500, since_iso=None, event_ids=None):
    """Query live Event Log channels via wevtutil. Returns (events, report)."""
    channels = channels or DEFAULT_CHANNELS
    events, report = [], {"channels": {}, "errors": []}
    for ch in channels:
        filt = _fmt_filter(since_iso, event_ids)
        args = ["qe", ch, "/f:XML", "/c:%d" % int(max_per_channel), "/rd:true", "/q:" + filt]
        rc, out, err = _run_wevtutil(args)
        if rc != 0:
            report["errors"].append({"channel": ch, "error": err.strip() or "exit %d" % rc})
            report["channels"][ch] = 0
            continue
        parsed = parse_wevtutil_xml(out, imported="live")
        report["channels"][ch] = len(parsed)
        events.extend(parsed)
    report["total"] = len(events)
    return events, report


def import_evtx(path):
    """Query a forensic .evtx snapshot via `wevtutil qe <path> /lf:true`."""
    rc, out, err = _run_wevtutil(['qe', '"%s"' % path, "/lf:true", "/f:XML"], timeout=240)
    if rc != 0 or not out.strip().startswith("<"):
        return [], [(err.strip() or "no data exported")]
    return parse_wevtutil_xml(out, imported="evtx"), []
_CSV_ALIAS = {
    "timestamp": ["timestamp", "timecreated", "timecreatedsystemtime", "datetime",
                  "dateandtime", "time", "utc", "ts", "observedtime"],
    "event_id": ["eventid", "id", "event_id", "eid", "evt_id"],
    "provider": ["provider", "providername", "source", "sourcemodule"],
    "channel": ["channel", "log", "logname", "eventlog", "logname"],
    "computer": ["computer", "host", "hostname", "machine", "computername"],
    "level": ["level", "severity", "severitylevel"],
    "source_ip": ["sourceip", "ipaddress", "remoteip", "clientaddress", "sourceaddress"],
    "target_user": ["targetusername", "username", "accountname", "targetuser"],
    "subject_user": ["subjectusername", "callerusername", "subjectuser"],
    "process": ["newprocessname", "processname", "image", "imagestring", "process"],
    "commandline": ["commandline", "processcommandline", "cmdline"],
    "message": ["message", "description", "eventmessage", "renderedmessage"],
}


def _find_col(headers, aliases):
    lowered = {h.strip().lower(): i for i, h in enumerate(headers)}
    for a in aliases:
        if a in lowered:
            return lowered[a]
    return None


def import_csv(fileobj, imported="csv"):
    """Import tabular data; `fileobj` may be a path, text stream or bytes."""
    if isinstance(fileobj, str):
        with open(fileobj, "r", encoding="utf-8", errors="replace") as fh:
            return _csv_rows(fh, imported)
    text = fileobj.read() if hasattr(fileobj, "read") else str(fileobj)
    if isinstance(text, bytes):
        text = text.decode("utf-8", "replace")
    return _csv_rows(io.StringIO(text), imported)


def _csv_rows(fh, imported):
    reader = csv.DictReader(fh)
    events = []
    for row in reader:
        ev = _row_to_event(dict(row), imported)
        if ev:
            events.append(ev)
    events.sort(key=lambda e: e["ts_epoch"])
    return events


def _row_to_event(row, imported):
    headers = [h for h in row.keys()]
    col = {k: _find_col(headers, aliases) for k, aliases in _CSV_ALIAS.items()}

    def g(key, default=""):
        i = col.get(key)
        if i is None:
            return default
        return (row.get(headers[i]) or default).strip()

    try:
        event_id = int(float(g("event_id"))) if g("event_id") else 0
    except ValueError:
        event_id = 0
    ts = _to_iso(g("timestamp"))
    data = {k: v for k, v in row.items() if v not in (None, "")}
    ev = {
        "id": str(uuid.uuid4()),
        "ts": ts,
        "ts_epoch": _epoch_of(ts),
        "channel": g("channel").lower() or "unknown",
        "event_id": event_id,
        "provider": g("provider"),
        "computer": g("computer"),
        "level": g("level") or 0,
        "source_ip": g("source_ip"),
        "target_user": g("target_user"),
        "subject_user": g("subject_user"),
        "process": g("process"),
        "commandline": g("commandline"),
        "data": data,
        "message": g("message") or "Imported CSV row (event %s)" % event_id,
        "imported": imported,
    }
    ev["hash"] = sha256_of(data)
    return ev


def import_json(obj=None, imported="json", raw=None):
    """Import a JSON event list, bundle ({"events":[...]}) or raw JSON text."""
    if raw is not None:
        obj = json.loads(raw)
    if isinstance(obj, dict) and "events" in obj:
        obj = obj["events"]
    if not isinstance(obj, (list, tuple)):
        return []
    out = []
    for rec in obj:
        if not isinstance(rec, dict):
            continue
        if rec.get("id") and "channel" in rec and "data" in rec:
            rec["imported"] = imported
            try:
                rec["event_id"] = int(rec.get("event_id", 0))
            except (ValueError, TypeError):
                rec["event_id"] = 0
            rec["hash"] = rec.get("hash") or sha256_of(rec.get("data", {}))
            out.append(rec)
        else:
            row = {str(k): str(v) for k, v in rec.items()}
            ev = _row_to_event(row, imported)
            if ev["event_id"] or row.get("timestamp"):
                out.append(ev)
    out.sort(key=lambda e: e.get("ts_epoch", 0))
    return out