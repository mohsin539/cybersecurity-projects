from __future__ import annotations

"""ARP evidence collection.

Primary source on Windows is the live ARP cache (`arp -a`) — real MAC/IP
bindings observed by the host itself. Optional ICMP sweep (rate-limited, in
scope only) wakes neighbours so more entries appear. No raw sockets needed.
"""

import re
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor

from .scope import scope_check
from .util import in_scope, now_ts

_IP_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
_MAC_RE = re.compile(r"^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$")
_ARP_LINE = re.compile(
    r"^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f\-]{17})\s+(\w+)\s*$", re.I)


def parse_arp_output(text: str) -> list[dict]:
    """Parse `arp -a` output text -> list of {ip, mac, type}."""
    rows = []
    for line in text.splitlines():
        m = _ARP_LINE.match(line)
        if m:
            ip, mac, t = m.group(1), m.group(2).replace("-", ":"), m.group(3)
            rows.append({"ip": ip, "mac": mac, "type": t, "ts": now_ts()})
    return rows


def arp_cache() -> list[dict]:
    proc = subprocess.run(["arp", "-a"], capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=15)
    return parse_arp_output(proc.stdout)


def _ping_one(ip: str) -> str | None:
    try:
        r = subprocess.run(
            ["ping", "-n", "1", "-w", "300", ip],
            capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=2,
        )
        if "TTL=" in r.stdout.upper() or "TTL=" in r.stderr.upper():
            return ip
    except (subprocess.TimeoutExpired, OSError):
        pass
    return None


def ping_sweep(ips: list[str], rate_pps: int = 4, hosts=64) -> list[str]:
    """Rate-limited parallel sweep of in-scope IPs. Returns active IPs."""
    import time
    active: list[str] = []
    batch: list[str] = []
    with ThreadPoolExecutor(max_workers=max(4, rate_pps)) as ex:
        for i, ip in enumerate(ips):
            batch.append(ip)
            if len(batch) >= hosts:
                for res in ex.map(_ping_one, batch):
                    if res:
                        active.append(res)
                batch = []
                time.sleep(0.05 * (64 // max(1, hosts)))
    if batch:
        for res in ex.map(_ping_one, batch):
            if res:
                active.append(res)
    return active


def collect(net=None, sweep: bool = False, sweep_rate: int = 4) -> dict:
    """Collect ARP evidence.

    net: resolved scope network (ipaddress.Network) or None to skip sweep.
    Returns observations:
      arp_binding per MAC (deduped), plus arp_scope metadata.
    """
    rows = arp_cache()
    bindings: dict[str, dict] = {}
    for r in rows:
        ip = r["ip"]
        mac = r["mac"]
        if mac == "00:00:00:00:00:00":
            continue
        if net is not None and not in_scope(ip, net):
            continue
        bindings.setdefault(mac, {"ip": ip, "mac": mac, "type": r["type"],
                                  "ts": r["ts"], "bindings": []})
        if ip not in bindings[mac]["bindings"]:
            bindings[mac]["bindings"].append(ip)

    sweep_hits: list[str] = []
    if sweep and net is not None:
        hosts = [str(h) for h in net.hosts()]
        sweep_hits = ping_sweep(hosts, swap_pps(sweep_rate))
        for ip in sweep_hits:
            if ip in {b["ip"] for b in bindings.values()}:
                continue
            bindings.setdefault(f"sweep:{ip}", {"ip": ip, "mac": "", "type": "sweep",
                                                "ts": now_ts(), "bindings": []})

    obs = []
    for b in bindings.values():
        obs.append({
            "kind": "arp_binding",
            "source": "arp-cache" if not b["ip"].startswith("sweep:") else "ping-sweep",
            "payload": {"ip": b["ip"], "mac": b["mac"], "type": b["type"]},
        })
    return {
        "observations": obs,
        "meta": {"bindings": len(bindings), "sweep_active": len(sweep_hits)},
    }


def swap_pps(n: int) -> int:
    return n