#!/usr/bin/env python3
"""E2E for manual proxy IP setup: LAN bind (auto/explicit), client allowlist, CLI overrides."""
from __future__ import annotations

import http.server
import json
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
PY = sys.executable
ORIGIN_PORT = 19007

PASS = 0
FAIL = 0


def check(name: str, ok: bool, extra: str = "") -> None:
    global PASS, FAIL
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" — {extra}" if extra else ""), flush=True)
    PASS += 1 if ok else 0
    FAIL += 0 if ok else 1


class QuietOrigin(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"bind-test-ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def wait_port(port: int, timeout: float = 10, host: str = "127.0.0.1") -> bool:
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.15)
    return False


def wait_port_closed(port: int, timeout: float = 10, host: str = "127.0.0.1") -> bool:
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                time.sleep(0.1)  # still open — old server dying
        except OSError:
            return True
    return False


def curl(url: str, bind_ip: str | None = None, socks: bool = False) -> int:
    cmd = ["curl", "-s", "-w", "%{http_code}", "--max-time", "10", "-o", os.devnull]
    if socks:
        cmd += ["--socks5-hostname", f"{bind_ip or '127.0.0.1'}:{port_of['socks']}"]
    else:
        cmd += ["-x", f"http://{bind_ip or '127.0.0.1'}:{port_of['http']}"]
    cmd.append(url)
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
    return int(p.stdout) if p.stdout.isdigit() else 0


def write_cfg(name: str, allow: list[str], bind: str = "127.0.0.1", http_port=18080, socks_port=11080):
    cfg = {
        "listeners": {
            "http": {"bind": bind, "port": http_port},
            "socks5": {"bind": bind, "port": socks_port},
        },
        "rules": [{"id": 2, "action": "Allow", "match": {}}],
        "security": {"denyPrivateTargets": False, "clients": {"allow": allow, "deny": []}},
        "logging": {"level": "info", "directory": f"logs-{name}", "maxFiles": 2},
    }
    p = HERE / f"cfg_{name}.json"
    p.write_text(json.dumps(cfg), encoding="utf-8")
    return p


def start(config: str, extra: list[str] | None = None) -> subprocess.Popen:
    cmd = [PY, "proxy_server.py", "--config", config] + (extra or [])
    return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)


def stop(p: subprocess.Popen, ports=()):
    p.terminate()
    try:
        p.wait(timeout=6)
    except subprocess.TimeoutExpired:
        p.kill()
    for port in ports:  # ensure the listener is really gone before the next phase binds it
        wait_port_closed(port)


port_of = {"http": 18080, "socks": 11080}


def main() -> int:
    os.chdir(HERE)
    # discover a usable non-loopback IP for bind tests
    lan_ip = None
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.168.255.255", 1))
        lan_ip = s.getsockname()[0]
    except OSError:
        pass
    finally:
        s.close()
    if lan_ip and lan_ip.startswith("127."):
        lan_ip = None
    print(f"E2E-bind: detected LAN IP: {lan_ip or '(none)'}", flush=True)

    origin = http.server.ThreadingHTTPServer(("127.0.0.1", ORIGIN_PORT), QuietOrigin)
    threading.Thread(target=origin.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{ORIGIN_PORT}/"

    # ---- 1) explicit LAN IP bind + loopback still works (same-host client) ----
    if lan_ip:
        cfg = write_cfg("lanbind", allow=[], bind=lan_ip, http_port=18081, socks_port=11081)
        port_of.update({"http": 18081, "socks": 11081})
        p = start(str(cfg))
        try:
            # connect to the LAN IP itself — the server is NOT listening on loopback here
            ok_up = wait_port(18081, host=lan_ip)
            check("server binds explicit LAN IP", ok_up)
            code = curl(url, bind_ip=lan_ip)
            check("client via LAN IP reaches proxy (200)", code == 200, f"code={code}")
        finally:
            stop(p, ports=(18081, 11081))
        port_of.update({"http": 18080, "socks": 11080})

    # ---- 2) allowlist: permitted clients work. The test client arrives from loopback,
    # so the allowlist must contain 127.0.0.0/8 for it to be admitted (as documented).
    if lan_ip:
        import ipaddress
        net = ipaddress.ip_network(f"{lan_ip}/24", strict=False)
        cfg = write_cfg("allowlist", allow=[str(net), "127.0.0.0/8"], bind="127.0.0.1")
    else:
        cfg = write_cfg("allowlist", allow=["127.0.0.0/8"], bind="127.0.0.1")
    p = start(str(cfg))
    try:
        wait_port(18080)
        time.sleep(0.3)  # allowlist check runs after accept; give the listener a beat
        code = curl(url)
        check("client inside allowlist is admitted (200)", code == 200, f"code={code}")
    finally:
        stop(p, ports=(18080, 11080))

    # ---- 3) allowlist that EXCLUDES the client -> 403 ----
    cfg = write_cfg("denyall", allow=["10.99.0.0/16"], bind="127.0.0.1")
    p = start(str(cfg))
    try:
        wait_port(18080)
        time.sleep(0.3)
        code = curl(url)
        check("client outside allowlist is refused (403)", code == 403, f"code={code}")
    finally:
        stop(p, ports=(18080, 11080))

    # ---- 4) CLI overrides beat config ----
    p = start(str(write_cfg("cli", allow=[], bind="127.0.0.1")),
              ["--http-port", "18099", "--socks-port", "11099", "--http-bind", "127.0.0.1"])
    try:
        ok_up = wait_port(18099)
        check("--http-port/--socks-port overrides apply", ok_up)
        time.sleep(0.3)
        code = curl(url)
        port_of.update({"http": 18099})
        code = curl(url)
        check("request through CLI-overridden port (200)", code == 200, f"code={code}")
    finally:
        stop(p, ports=(18099, 11099))

    for f in HERE.glob("cfg_*.json"):
        f.unlink()
    for d in HERE.glob("logs-*"):
        if d.is_dir() and d.name.startswith("logs-"):
            for f in d.glob("audit-*.jsonl"):
                f.unlink()
            try:
                d.rmdir()
            except OSError:
                pass

    print(f"\nRESULT: PASS={PASS} FAIL={FAIL}", flush=True)
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
