from __future__ import annotations

"""Offline network simulator — deterministic pseudo-random campus network.

Produces the same rich evidence stream the real collectors emit, so the full
pipeline (fusion, confidence, graph, RBAC, audit) is demoable with zero network
footprint. Never reached by live collectors; gated behind SIM mode.
"""

import ipaddress
import json
import random
import time

VENDORS = [
    ("00:1c:0f", "HPE Aruba"), ("00:1a:a9", "MikroTik"), ("0c:cd:ac", "Ubiquiti"),
    ("00:25:b5", "Juniper"), ("e0:cb:4e", "Huawei"), ("00:0e:8f", "Fortinet"),
    ("f0:9f:c2", "Ubiquiti"), ("5c:f9:dd", "TP-Link"), ("00:60:2f", "Quantum"),
    ("bc:ae:c5", "Dell"), ("00:50:56", "Azure"), ("00:15:5d", "Hyper-V"),
]

ROLE_MAC = {
    "core": "00:1c:0f",
    "access": "d8:6c:63",
    "router": "0c:cd:ac",
    "fw": "00:0e:8f",
    "server": "00:50:56",
    "iot": "5c:f9:dd",
    "printer": "00:60:2f",
}

SUBNETS = {
    "10.30.0.0/24": {"name": "server-farm", "mask": 24},
    "10.30.1.0/24": {"name": "user-vlan-1", "mask": 24},
    "10.30.2.0/24": {"name": "user-vlan-2", "mask": 24},
    "10.30.3.0/24": {"name": "iot-vlan", "mask": 24},
    "10.30.4.0/24": {"name": "mgmt", "mask": 24},
    "10.30.5.0/30": {"name": "wan-uplink", "mask": 30},
}

VPLS = {
    "vlan100": "10.30.1.0/24",
    "vlan200": "10.30.2.0/24",
    "vlan300": "10.30.3.0/24",
    "vlan10": "10.30.4.0/24",
}

_GLOBAL = {"next_seed": None}


def _mac_by_role(mac: str, seed: int) -> str:
    prefix = ROLE_MAC.get(mac, "00:00:5e")
    rand = random.Random(seed)
    tail = "%02x:%02x:%02x" % (rand.randrange(256), rand.randrange(256), rand.randrange(256))
    return f"{prefix}:{tail}"


def _rand_mac(seed: int) -> str:
    r = random.Random(seed)
    return "%02x:%02x:%02x:%02x:%02x:%02x" % tuple(r.randrange(256) for _ in range(6))


class SimNetwork:

    def __init__(self, seed: int | None = None) -> None:
        self.rng = random.Random(seed or 31415)
        self.devices: list[dict] = []
        self._build()

    def _build(self) -> None:
        r = self.rng
        core = self._make("core-router", "core", "core-01", port_count=6,
                          extras=[("sysObjectID", "1.3.6.1.4.1.9.1.728"),
                                  ("serial", "FGL1234"), ("hu", "core-a")])
        mgmt_sw = self._make("distribution-1", "access", "dist-01")  # L2 stack
        # links
        link_rng = random.Random(99)
        for i in range(18):
            a = self.devices[i % len(self.devices)]
            b = self.devices[(i * 7 + 3) % len(self.devices)]
            if a is b:
                continue
            self._link(a, b, "lldp", 3, "trunk", link_rng.random())

    def _make(self, _role, role, name, port_count=2, extras=(), skip=()):
        d = {
            "id": f"sim-{len(self.devices)+1}",
            "name": name,
            "role": role,
            "kind": "switch" if role in ("core", "access") else "router",
            "vendor": VENDORS[(r := self.rng.randrange(len(VENDORS)))][1],
            "mac": _mac_by_role(role, self.rng.randrange(2**31)),
            "os": self.rng.choice(["Firmware 6.4", "17.9", "v8.2"]),
            "snmp": "v3",
            "conf": 0.98,
            "interfaces": [],
            "links": [],
        }
        d["interfaces"] = [
            {"ifIndex": i, "descr": f"if{i}", "mac": _rand_mac(self.rng.randrange(2**31)),
             "hp": 1000 + i * 100, "speed": 1000}
            for i in range(port_count)
        ]
        self.devices.append(d)
        return d

    def _link(self, a, b, proto, hops, kind, conf=None):
        al = a["links"]
        bl = b["links"]
        al.append({"peer": b["id"], "protocol": proto, "conf": conf if conf is not None else 0.9,
                   "hops": hops, "kind": kind, "via": f"{a['id']}:{len(al)+1}-{b['id']}:{len(bl)+1}"})

    def observations(self, observer: str = "sim") -> list[dict]:
        obs = []
        for d in self.devices:
            obs.append({
                "kind": "sys_info",
                "source": "snmp",
                "observer": observer,
                "payload": {"ip": d["id"].split("-")[-1] + ".30.1.1", "mac": d["mac"],
                            "name": d["name"], "sysDescr": d["os"],
                            "vendor": d["vendor"], "role": d["role"], "conf": d["conf"]},
            })
            for i in d["interfaces"]:
                obs.append({
                    "kind": "interface",
                    "source": "snmp",
                    "observer": observer,
                    "payload": {"ip": d["id"], "ifIndex": i["ifIndex"],
                                "descr": i["descr"], "mac": i["mac"], "speed": i["speed"]},
                })
        for d in self.devices:
            for ln in d["links"]:
                obs.append({
                    "kind": "lldp_neighbor",
                    "source": "lldp",
                    "observer": observer,
                    "payload": {"device": d["id"], "peer": ln["peer"], "protocol": ln["protocol"],
                                "conf": ln["conf"], "kind": ln["kind"], "hops": ln["hops"],
                                "via": ln["via"]},
                })
        return obs
