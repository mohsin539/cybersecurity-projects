#!/usr/bin/env python3
lab_demo = True
authorized_only = True
#
# Simulated Zone-A beacon for blue-team lab study (sandbox only).
# Connects to the C2 Deconfliction Lab console with its own AES-256-GCM
# inner layer; the transport is real TLS/HTTPS in the lab deployment.
#
import argparse
import platform
import random
import socket
import time
import uuid

import requests

from app.core.crypto import aes_encrypt

VERSION = "1.0.0"
DEFAULT_SNI = "orders-storage.example.net"


def banner():
    print("=" * 64)
    print("  SIMULATED BEACON AGENT — C2 Deconfliction Lab (AUTHORIZED LAB ONLY)")
    print("  MITRE T1071.001 (HTTPS) · T1573.001 (inner AES-256-GCM) · sandbox")
    print("=" * 64)


def random_source_port():
    return random.randint(49152, 65535)


def beacon(server, name, interval, jitter):
    hw_id = uuid.uuid4().hex[:12]
    reg = requests.post(
        f"{server}/api/v1/beacon/register",
        json={
            "agent_name": name,
            "hw_id": hw_id,
            "ip": socket.gethostbyname(socket.gethostname()),
            "os": platform.system() + " " + platform.release(),
            "beacon_interval": interval,
            "jitter": jitter,
            "sni": DEFAULT_SNI,
            "tls_version": "TLSv1.3",
            "auth_method": "mtls",
        },
        timeout=10,
    )
    reg.raise_for_status()
    meta = reg.json()
    print(f"[+] registered: uuid={meta['uuid']} cipher={meta['cipher']} key_escrow=yes")
    base = meta["uuid"]
    key = bytes.fromhex(meta["key_escrow_hex"])

    while True:
        try:
            dim = random.uniform(1 - jitter, 1 + jitter)
            sleep_s = interval * dim
            print(f"    . sleep {sleep_s:.1f}s, agent={name}")
            time.sleep(min(sleep_s, 5))

            requests.post(f"{server}/api/v1/beacon/ping?uuid={base}", json={"nonce": "p"}, timeout=10)
            r = requests.get(f"{server}/api/v1/beacon/tasks/{base}", timeout=10)
            tasks = r.json().get("tasks", [])
            for t in tasks:
                try:
                    plain = tasks_payload(name, t["task_id"])
                    enc = aes_encrypt(key, plain.encode())
                    requests.post(
                        f"{server}/api/v1/beacon/result?uuid={base}",
                        json={"task_id": t["task_id"], "payload": enc},
                        timeout=10,
                    )
                    print(f"    [>] task executed & callback posted: {t['task_id']}")
                except requests.RequestException as exc:
                    print(f"    [!] result post failed: {exc}")
        except requests.RequestException as exc:
            print(f"    [!] transport error (retry/backoff): {exc}")
            time.sleep(3)


def tasks_payload(name, task_id):
    return f"ok|{name}|{task_id}|LEGACY-LAB-CMD"


def main():
    banner()
    p = argparse.ArgumentParser(description="Simulated beacon — authorized lab only")
    p.add_argument("--server", default="http://127.0.0.1:8443")
    p.add_argument("--name", default="lab-agent-" + uuid.uuid4().hex[:4])
    p.add_argument("--interval", type=float, default=45.0)
    p.add_argument("--jitter", type=float, default=0.15)
    args = p.parse_args()
    print(f"[i] target={args.server}  agent={args.name}")
    if "https://" in args.server:
        import urllib3

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    beacon(args.server, args.name, args.interval, args.jitter)


if __name__ == "__main__":
    main()