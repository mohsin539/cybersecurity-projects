"""Fingerprinting engine: net/io + payload + corpus attribution (architecture §2.3).

Attackers classified into tools by signal heuristics. Attribution is a
weighted score, never a certainty.
"""
from __future__ import annotations

import json
import time
from collections import Counter
from typing import List

from .sessions import Session

HTTP_SUSPICIOUS_PATHS = ["/.env", "/.git", "/admin", "/actuator", "/wp-content",
                         "/login", "/config.php", "/.git/config"]


def net_fingerprint(peer_port: int, duration: float) -> dict:
    """IO signals: source port ephemeral range + session duration shape."""
    brief = duration < 2.0
    return {
        "ephemeral_src_port": 32768 <= peer_port <= 61000,
        "brief_connection": brief,
    }


def payload_fingerprint(session: Session) -> dict:
    cmds = [str(s["value"]) for s in session.signals if s["kind"] == "cmd"]
    if not cmds:
        return {"has_commands": False, "cmd_tokens": []}
    tokens: Counter = Counter()
    for c in cmds:
        body = c.replace(";", " ").replace("&&", " ").split()
        tokens.update(body)
    return {"has_commands": True, "cmd_tokens": dict(tokens.most_common(8))}


def http_fingerprint(session: Session) -> dict:
    paths = []
    for s in session.signals:
        if s["kind"] != "request":
            continue
        try:
            d = json.loads(str(s["value"]))
            paths.append(d.get("path", ""))
        except json.JSONDecodeError:
            continue
    hits = [p for p in paths if any(h in p for h in HTTP_SUSPICIOUS_PATHS)]
    return {"paths": paths, "suspicious_hits": hits}


def attribute(session: Session) -> dict:
    """Attribution score -> tool/game/campaign labels (best-effort)."""
    net = net_fingerprint(session.peer_port, session.ended - session.started)
    pay = payload_fingerprint(session)
    http = http_fingerprint(session)

    scores = {}
    if session.protocol == "ssh":
        auths = [str(s["value"]) for s in session.signals if s["kind"] == "auth-attempt"]
        if len(auths) >= 3 and net["brief_connection"]:
            scores["hydra/medusa"] = 0.7
        if any(a in ("root", "admin", "postgres") for a in auths):
            scores["common-username-prober"] = scores.get("common-username-prober", 0) + 0.4
        if pay.get("has_commands"):
            toks = " ".join(pay["cmd_tokens"])
            cmdstrs = [str(s["value"]) for s in session.signals if s["kind"] == "cmd"]
            if any("cat /etc/passwd" in c for c in cmdstrs):
                scores["interactive-attacker"] = 0.8
            if any(t in toks for t in ("wget", "curl", "mkfifo")):
                scores["toolkit-downloader"] = 0.6
    else:
        if http["suspicious_hits"]:
            scores["vuln-scanner"] = 0.5 + 0.1 * min(len(http["suspicious_hits"]), 4)
        if "/.env" in http["paths"]:
            scores["env-leak-scan"] = 0.6

    # Campaign grouping by identical payload signature
    sig = "|".join(http["paths"] + list(pay["cmd_tokens"]))[:80]
    return {
        "tool_scores": [{"tool": k, "confidence": round(v, 2)} for k, v in
                        sorted(scores.items(), key=lambda kv: -kv[1])[:3]],
        "os_guess": "linux64" if session.peer_port else "unknown",
        "campaign_sig": sig or "none",
        "net": net, "payload": pay, "http": http,
    }