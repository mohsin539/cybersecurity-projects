"""Alert emitter: normalized HIDS findings -> severity + local log + hooks.

Hooks: local JSONL, Wazuh/OSSEC-compatible syslog message, and a SIEM webhook
that emits the Project-11 CES Event schema. Keep emitter non-fatal.
"""
from __future__ import annotations

import json
import sys
import time
import urllib.request
from pathlib import Path

FINDING_SEVERITY = {
    "file_changed": "high",
    "file_new": "medium",
    "file_deleted": "high",
    "proc_new": {"unknown_binary": "high", "": "medium"},
}

_hooks: list = []


def register_hook(hook) -> None:
    _hooks.append(hook)


def severity_for(finding: dict) -> str:
    t = finding.get("type")
    if t == "proc_new":
        return "high" if finding.get("binary") == "unknown_binary" else "medium"
    return FINDING_SEVERITY.get(t, "medium")


def emit(finding: dict) -> None:
    finding = {**finding, "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
               "severity": severity_for(finding), "source": "hids-agent"}
    for h in list(_hooks):
        try:
            h(finding)
        except Exception as exc:  # noqa: BLE001
            sys.stderr.write(f"[hook {h!r} failed] {exc}\n")


class JsonlHook:
    def __init__(self, path: Path):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = path.open("a", encoding="utf-8")

    def __call__(self, finding: dict) -> None:
        self._fh.write(json.dumps(finding) + "\n")
        self._fh.flush()

    def close(self) -> None:
        self._fh.close()


class SyslogHook:
    """Emits RFC3164-style message usable by Wazuh/OSSEC or any syslog."""

    def __init__(self, path: Path):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = path.open("a", encoding="utf-8")

    def __call__(self, finding: dict) -> None:
        msg = (f"hids-agent[0]: {finding['severity']} {finding['type']} "
               f"{json.dumps({k:v for k,v in finding.items() if k in ('path','pid','exe','cmdline','reason','binary')})}")
        self._fh.write(msg + "\n")
        self._fh.flush()

    def close(self) -> None:
        self._fh.close()


class SiemWebhookHook:
    """Publishes a finding in Project 11 CES Event shape (action=exec/create)."""

    def __init__(self, url: str, token: str = "", timeout: float = 5.0):
        self.url, self.token, self.timeout = url, token, timeout
        self.cache: dict = {}

    def __call__(self, finding: dict) -> None:
        ev = {
            "ts": finding["ts"], "source": "hids-agent",
            "action": "create" if finding["type"].startswith("file") else "exec",
            "category": "file" if finding["type"].startswith("file") else "process",
            "severity": finding["severity"],
            "message": json.dumps(finding),
        }
        try:
            req = urllib.request.Request(
                self.url, data=json.dumps(ev).encode("utf-8"),
                method="POST",
                headers={"Content-Type": "application/json",
                         **({"Authorization": f"Bearer {self.token}"} if self.token else {})},
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                resp.read()
        except Exception as exc:  # noqa: BLE001
            sys.stderr.write(f"[siem-webhook] {exc}\n")