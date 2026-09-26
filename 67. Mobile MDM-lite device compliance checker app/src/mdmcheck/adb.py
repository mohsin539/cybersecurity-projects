"""Best-effort Android collector via ADB when the platform tool is available."""
from __future__ import annotations

import shutil
import subprocess
import time
from typing import Any


def adb_available() -> tuple[bool, str]:
    path = shutil.which("adb")
    return (path is not None), (path or "adb not found on PATH")


def adb_devices() -> list[dict]:
    """List connected Android devices (serial + state)."""
    res = run(["adb", "devices", "-l"])
    out = res.get("stdout", "")
    devices = []
    for line in out.splitlines()[1:]:
        if not line.strip() or line.startswith("*"):
            continue
        parts = line.split()
        serial = parts[0]
        state = parts[1] if len(parts) > 1 else "unknown"
        devices.append({"serial": serial, "state": state})
    return devices


def collect(serial: str, timeout: float = 15.0) -> dict:
    """Pull telemetry from a connected Android device over ADB."""
    telemetry: dict[str, Any] = {
        "os": {}, "hardware": {}, "apps": {"installed": []},
        "security": {
            "rooted": False, "unknown_sources": False, "encryption": True,
            "screen_lock": True, "play_protect": True, "side_loading": False,
            "biometric": True,
        },
        "network": {"vpn": False, "geofenced": True},
        "agent": {"version": "1.0.0", "uptime_sec": 0},
    }

    def getprop(key: str) -> str:
        return run(["adb", "-s", serial, "shell", "getprop", key], timeout).get("stdout", "").strip()

    telemetry["os"]["version"] = getprop("ro.build.version.release") or "0.0"
    sdk = getprop("ro.build.version.sdk")
    try:
        telemetry["os"]["sdk"] = int(sdk) if sdk else 0
    except ValueError:
        telemetry["os"]["sdk"] = 0
    telemetry["os"]["build"] = getprop("ro.build.display.id")
    telemetry["hardware"]["brand"] = getprop("ro.product.brand")
    telemetry["hardware"]["model"] = getprop("ro.product.model")
    telemetry["hardware"]["serial"] = serial

    pkgs = run(["adb", "-s", serial, "shell", "pm", "list", "packages", "-3"], timeout).get("stdout", "")
    installed = []
    for line in pkgs.splitlines():
        line = line.strip()
        if line.startswith("package:"):
            installed.append(line[len("package:") :])
    telemetry["apps"]["installed"] = sorted(installed)

    su = run(["adb", "-s", serial, "shell", "which", "su"], timeout).get("stdout", "").strip()
    telemetry["security"]["rooted"] = bool(su)

    ver = run(["adb", "-s", serial, "shell", "settings", "get", "global", "verifier_verify_adb_installs"], timeout).get("stdout", "").strip()
    telemetry["security"]["unknown_sources"] = (ver == "1")

    telemetry["agent"]["uptime_sec"] = int(time.time())
    return telemetry


def run(args: list[str], timeout: float = 10.0) -> dict:
    try:
        p = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return {"stdout": p.stdout, "stderr": p.stderr, "rc": p.returncode}
    except Exception as e:  # noqa: BLE001
        return {"stdout": "", "stderr": str(e), "rc": -1}