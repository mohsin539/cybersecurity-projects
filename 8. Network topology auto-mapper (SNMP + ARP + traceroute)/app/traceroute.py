from __future__ import annotations

"""Traceroute evidence via Windows `tracert -d` (no DNS lookups).

Runs only against in-scope targets. Output parsed into hop IP lists; adjacent
hop pairs become L3 edge candidates (confidence 0.5) downstream.
"""

import re
import subprocess
from concurrent.futures import ThreadPoolExecutor

from .scope import scope_check

_HOP = re.compile(r"^\s*(\d{1,2})\s+(?:[\d<*]+\s+ms\s+){2,}[\d<*]*\s*([0-9a-f:\.]+)\s*$", re.I)
_HOP_ALT = re.compile(r"^\s*(\d{1,2})\s+[^\d].*?\((\d+\.\d+\.\d+\.\d+)\)\s*$")


def tracert(target: str, max_hops: int = 20, wait: int = 300) -> list[str]:
    scope_check(target)
    proc = subprocess.run(
        ["tracert", "-d", "-h", str(max_hops), "-w", str(wait), target],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=300,
    )
    return parse_tracert(proc.stdout)


def parse_tracert(text: str) -> list[str]:
    hops: list[str] = []
    for line in text.splitlines():
        m = _HOP.match(line) or _HOP_ALT.match(line)
        if m:
            ip = m.group(2)
            hops.append(ip)
    return hops


def collect(targets: list[str], max_hops: int = 20, workers: int = 4) -> list[dict]:
    paths: list[list[str]] = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(tracert, t, max_hops): t for t in targets}
        for f in futs:
            try:
                hops = f.result()
                if len(hops) >= 2:
                    paths.append(hops)
            except Exception:  # noqa: BLE001
                continue
    obs = []
    for path in paths:
        for a, b in zip(path, path[1:]):
            if a == b:
                continue
            obs.append({
                "kind": "hop_pair",
                "source": "traceroute",
                "payload": {"a": a, "b": b},
            })
    return obs