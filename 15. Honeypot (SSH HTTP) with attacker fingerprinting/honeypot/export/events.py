"""Export layer: event JSON + blocklist feed push (Project 16 hook).

Event schema mirrors Project 11 CES (source/action/category/severity).
Push-to-blocklist is a sink: honeypot emits, aggregator consumes.
"""
from __future__ import annotations

import json
import sys
import time
import urllib.request
from pathlib import Path
from typing import Callable, List

from ..engine.fingerprint import attribute
from ..engine.sessions import Session

CRITICAL_SIGNATURE_THRESHOLD = 0.7


class EventExporter:
    def __init__(self, out_dir: Path):
        out_dir = Path(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        self._fh = (out_dir / "sessions.jsonl").open("a", encoding="utf-8")
        self.blocklist_hook: Callable[[dict], None] | None = None

    def set_blocklist_hook(self, hook: Callable[[dict], None]) -> None:
        self.blocklist_hook = hook

    def _envelope(self, session: Session, attr: dict, severity: str) -> dict:
        return {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "source": "honeypot",
            "action": "connect" if session.protocol == "ssh" and not attr["payload"]["has_commands"] else "pwn",
            "category": "deception",
            "severity": severity,
            "session": session.to_dict(),
            "attribution": attr,
        }

    def export(self, session: Session) -> None:
        attr = attribute(session)
        top_conf = attr["tool_scores"][0]["confidence"] if attr["tool_scores"] else 0.0
        sev = "high" if top_conf >= CRITICAL_SIGNATURE_THRESHOLD or session.protocol == "http" else "medium"
        if session.protocol == "ssh" and attr["payload"]["has_commands"] and top_conf >= 0.8:
            sev = "critical"
        self._fh.write(json.dumps(self._envelope(session, attr, sev)) + "\n")
        self._fh.flush()
        # Push to blocklist (Project 16) on critical signals
        if sev == "critical" and self.blocklist_hook:
            self.blocklist_hook({
                "source": "honeypot", "ioc_type": "ipv4", "value": session.peer_ip,
                "confidence": top_conf, "tags": ["attacker"], "feed_id": "honeypot-internal",
            })

    def close(self) -> None:
        self._fh.close()


class WebhookPusher:
    """Send critical IOC to Project 16 aggregator (or any HTTPS sink)."""

    def __init__(self, url: str, token: str = "", timeout: float = 5.0):
        self.url, self.token, self.timeout = url, token, timeout

    def __call__(self, ioc: dict) -> None:
        try:
            req = urllib.request.Request(
                self.url, data=json.dumps(ioc).encode("utf-8"),
                method="POST",
                headers={"Content-Type": "application/json",
                         **({"Authorization": f"Bearer {self.token}"} if self.token else {})},
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                resp.read()
        except Exception as exc:  # noqa: BLE001 - export must never block the door
            sys.stderr.write(f"[blocklist-push] {exc}\n")