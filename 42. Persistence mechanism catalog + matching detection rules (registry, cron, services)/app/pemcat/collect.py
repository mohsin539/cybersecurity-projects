import glob
import hashlib
import os
import subprocess
import sys

REGISTRY_KEYS = [
    (r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU"),
    (r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM"),
    (r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU"),
    (r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM"),
    (r"Software\Microsoft\Windows\CurrentVersion\RunServices", "HKCU"),
    (r"Software\Microsoft\Windows\CurrentVersion\RunServices", "HKLM"),
    (r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", "HKLM"),
    (r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", "HKLM"),
    (r"Software\Microsoft\Windows NT\CurrentVersion\Windows", "HKLM"),
    (r"Software\Microsoft\Active Setup\Installed Components", "HKLM"),
    (r"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", "HKLM"),
]

BASE_ROOTS = {
    "HKCU": 0x80000001,
    "HKLM": 0x80000002,
}


def _hidden_popen(cmd, timeout=30):
    flags = 0
    if os.name == "nt":
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    return subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL,
        creationflags=flags,
    )


def _run(cmd, timeout=30):
    try:
        proc = _hidden_popen(cmd, timeout=timeout)
        out, err = proc.communicate(timeout=timeout)
        return out.decode("utf-8", errors="replace"), err.decode("utf-8", errors="replace")
    except Exception:
        return "", ""


def _file_sha256(path):
    try:
        with open(path, "rb") as fh:
            return hashlib.sha256(fh.read(4 * 1024 * 1024)).hexdigest()
    except OSError:
        return None


def _winreg_subkeys(root_key, subpath):
    import winreg

    results = []
    try:
        base = BASE_ROOTS.get(root_key)
        if base is None:
            return results
        key = winreg.OpenKey(base, subpath)
        index = 0
        while True:
            try:
                sub = winreg.EnumKey(key, index)
                results.append(sub)
                index += 1
            except OSError:
                break
        winreg.CloseKey(key)
    except OSError:
        pass
    return results


def _winreg_values(root_key, subpath):
    import winreg

    results = []
    try:
        base = BASE_ROOTS.get(root_key)
        if base is None:
            return results
        key = winreg.OpenKey(base, subpath)
        index = 0
        while True:
            try:
                name, value, value_type = winreg.EnumValue(key, index)
                results.append((name, value, value_type))
                index += 1
            except OSError:
                break
        winreg.CloseKey(key)
    except OSError:
        pass
    return results


def enumerate_registry():
    records = []
    if os.name != "nt":
        return records
    try:
        import winreg  # noqa: F401
    except ImportError:
        return records

    for subpath, root in REGISTRY_KEYS:
        full = f"{root}\\{subpath}"
        values = _winreg_values(root, subpath)
        for name, value, _vtype in values:
            value = str(value)
            if not value:
                continue
            payload = {"root": root, "key": subpath, "value_name": name, "value_type": _vtype}
            if "Winlogon" in full:
                if name.lower() not in ("userinit", "shell"):
                    continue
                for part in value.split(","):
                    part = part.strip()
                    if part:
                        records.append({
                            "artifact_type": "registry",
                            "mechanism": f"Winlogon\\{name}: {part}",
                            "image_path": part,
                            "command_line": part,
                            "payload": {**payload, "winlogon_param": name},
                        })
            elif "Active Setup" in full:
                cmd = value
                records.append({
                    "artifact_type": "registry",
                    "mechanism": f"ActiveSetup\\{name}",
                    "image_path": cmd,
                    "command_line": cmd,
                    "payload": {**payload, "active_setup": True},
                })
            elif "AppInit" in full or "Windows NT\\CurrentVersion\\Windows" in full:
                records.append({
                    "artifact_type": "registry",
                    "mechanism": f"AppInit\\{name}",
                    "image_path": value,
                    "command_line": value,
                    "payload": {**payload, "appinit": True},
                })
            elif "Image File Execution Options" in full:
                if name.lower() in ("debugger", "globalflag"):
                    records.append({
                        "artifact_type": "registry",
                        "mechanism": f"IFEO\\{subpath_leaf(full)}\\{name}",
                        "image_path": value,
                        "command_line": value,
                        "payload": {**payload, "ifeo": name},
                    })
            else:
                records.append({
                    "artifact_type": "registry",
                    "mechanism": full,
                    "image_path": value,
                    "command_line": value,
                    "payload": payload,
                })
    return records


def subpath_leaf(full):
    return full.rsplit("\\", 1)[-1]


def enumerate_services():
    records = []
    if os.name != "nt":
        return records
    subkeys = _winreg_subkeys("HKLM", r"SYSTEM\CurrentControlSet\Services")
    for service in subkeys:
        base = rf"SYSTEM\CurrentControlSet\Services\{service}"
        values = _winreg_values("HKLM", base)
        data = {}
        for name, value, _vt in values:
            data[name] = value
        image_path = data.get("ImagePath")
        display = data.get("DisplayName") or service
        start = data.get("Start")
        svc_type = data.get("Type")
        if not image_path:
            continue
        image = str(image_path)
        if image.lower().startswith("\\systemroot\\") and os.environ.get("SystemRoot"):
            image = os.path.join(
                os.environ["SystemRoot"], image[len("\\systemroot\\"):]
            )
        records.append({
            "artifact_type": "service",
            "mechanism": f"service:{service} ({display})",
            "image_path": image,
            "command_line": image,
            "payload": {
                "service": service,
                "display_name": display,
                "start": int(start) if isinstance(start, int) else str(start),
                "type": int(svc_type) if isinstance(svc_type, int) else str(svc_type),
                "object_name": str(data.get("ObjectName") or ""),
            },
        })
    return records


def _parse_list_blocks(text):
    blocks = []
    current = {}
    for line in text.splitlines():
        line = line.rstrip()
        if ":" in line and not line.startswith(" "):
            key, _, value = line.partition(":")
            key = key.strip()
            value = value.strip()
            if key:
                if current:
                    blocks.append(current)
                current = {key: value}
        elif ":" in line and current:
            key, _, value = line.partition(":")
            current[key.strip()] = value.strip()
    if current:
        blocks.append(current)
    return blocks


def enumerate_scheduled_tasks():
    records = []
    if os.name == "nt":
        out, _ = _run(["schtasks", "/query", "/fo", "LIST", "/v"])
        for block in _parse_list_blocks(out):
            task = block.get("TaskName") or block.get("Task To Run") or ""
            cmd = block.get("Task To Run") or ""
            if not cmd:
                continue
            sched = block.get("Schedule Type", "")
            run_as = block.get("Run As User", "")
            rec = {
                "artifact_type": "scheduled_task",
                "mechanism": f"task:{task}",
                "image_path": cmd,
                "command_line": cmd,
                "payload": {
                    "task": task,
                    "schedule_type": sched,
                    "run_as": run_as,
                    "status": block.get("Status"),
                    "last_result": block.get("Last Result"),
                },
            }
            records.append(rec)
    return records


def enumerate_cron():
    records = []
    if os.name == "nt":
        return records
    paths = ["/etc/crontab", "/etc/anacrontab"]
    paths += sorted(glob.glob("/etc/cron.d/*"))
    for user_path in ["/var/spool/cron/crontabs", "/var/spool/cron"]:
        if os.path.isdir(user_path):
            for name in os.listdir(user_path):
                paths.append(os.path.join(user_path, name))
    for path in paths:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                for lineno, line in enumerate(fh, 1):
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    fields = line.split()
                    if len(fields) < 6:
                        continue
                    schedule = " ".join(fields[:5])
                    cmdline = " ".join(fields[5:])
                    records.append({
                        "artifact_type": "cron",
                        "mechanism": f"cron:{path}:{lineno}",
                        "image_path": cmdline.split()[0] if cmdline.split() else cmdline,
                        "command_line": cmdline,
                        "payload": {"cron_file": path, "schedule": schedule, "line": lineno},
                    })
        except OSError:
            continue
    return records


def enumerate_startup_folders():
    records = []
    appdata = os.environ.get("APPDATA")
    programdata = os.environ.get("PROGRAMDATA")
    folders = []
    if appdata:
        folders.append(os.path.join(appdata, r"Microsoft\Windows\Start Menu\Programs\StartUp"))
    if programdata:
        folders.append(os.path.join(programdata, r"Microsoft\Windows\Start Menu\Programs\StartUp"))
    folders.append("/etc/profile.d")
    folders.append(os.path.expanduser("~/.config/autostart"))
    executables = (".exe", ".lnk", ".com", ".bat", ".cmd", ".vbs", ".ps1", ".scr", ".desktop")
    for folder in folders:
        if not folder or not os.path.isdir(folder):
            continue
        for entry in sorted(os.scandir(folder), key=lambda e: e.name.lower()):
            if not entry.is_file():
                continue
            ext = os.path.splitext(entry.name)[1].lower()
            if ext not in executables:
                continue
            file_hash = _file_sha256(entry.path)
            records.append({
                "artifact_type": "startup",
                "mechanism": f"startup:{entry.path}",
                "image_path": entry.path,
                "command_line": entry.path,
                "payload": {"filename": entry.name, "folder": folder, "file_sha256": file_hash},
            })
    return records


def enumerate_wmi():
    records = []
    if os.name != "nt":
        return records
    consumer_script = (
        "Get-CimInstance -Namespace root/subscription -ClassName __EventConsumer "
        "| Select-Object @{N='Class';E={$_.CimSystemProperties.ClassName}},name,"
        "CommandLineTemplate,ScriptText,CommandLine | ConvertTo-Json -Compress"
    )
    cons_out, _ = _run(
        ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
         "-Command", consumer_script],
        timeout=25,
    )
    for consumer in _json_items(cons_out):
        name = consumer.get("name") or ""
        cmd = consumer.get("CommandLineTemplate") or consumer.get("CommandLine") or ""
        script = consumer.get("ScriptText") or ""
        if not cmd and not script:
            continue
        cls = consumer.get("Class") or "__EventConsumer"
        mechanism = "wmi:{0} ({1})".format(name, cls)
        command_line = cmd if cmd else script
        records.append({
            "artifact_type": "wmi",
            "mechanism": mechanism,
            "image_path": command_line,
            "command_line": command_line,
            "payload": {
                "consumer": name,
                "class": cls,
                "wmi_command_consumer": bool(cmd),
                "wmi_script_consumer": bool(script and not cmd),
            },
        })
    return records


def _json_items(text):
    text = (text or "").strip()
    if not text or text == "[]" or text == "null":
        return []
    try:
        import json as _json

        items = _json.loads(text)
    except Exception:
        return []
    if isinstance(items, dict):
        return [items]
    return items if isinstance(items, list) else []


def enumerate_all():
    collectors = [
        ("registry", enumerate_registry),
        ("service", enumerate_services),
        ("scheduled_task", enumerate_scheduled_tasks),
        ("cron", enumerate_cron),
        ("startup", enumerate_startup_folders),
        ("wmi", enumerate_wmi),
    ]
    results = []
    for name, fn in collectors:
        try:
            found = fn()
            results.extend(found)
            last = (name, len(found))
        except Exception:
            last = (name, 0)
    return results, last


def host_id():
    if os.name == "nt":
        try:
            import winreg

            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName")
            value, _ = winreg.QueryValueEx(key, "ComputerName")
            winreg.CloseKey(key)
            return value
        except OSError:
            pass
    return socket_hostname()


def socket_hostname():
    import socket

    try:
        return socket.gethostname()
    except OSError:
        return "localhost"