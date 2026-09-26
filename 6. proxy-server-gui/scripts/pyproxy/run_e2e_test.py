#!/usr/bin/env python3
"""E2E verification for the Python proxy server (offline: uses a local origin server).

Phase A (denyPrivateTargets=false): positive flows
  1. Plain HTTP forward proxy        -> 200, body from local origin
  2. CONNECT tunnel                  -> 200 relay through local origin
  3. SOCKS5 CONNECT                  -> 200
  4. Deny rule (denied.example)      -> 403

Phase B (denyPrivateTargets=true): SSRF guard
  5. Loopback target                 -> 403

Phase C: audit log hash chain
"""
from __future__ import annotations

import http.server
import os
import subprocess
import sys
import socket
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
PY = sys.executable
HTTP_PORT, SOCKS_PORT, ORIGIN_PORT = 18080, 11080, 19007

PASS = 0
FAIL = 0


def check(name: str, ok: bool, extra: str = "") -> None:
    global PASS, FAIL
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" — {extra}" if extra else ""), flush=True)
    global PASS, FAIL
    PASS += 1 if ok else 0
    FAIL += 0 if ok else 1


class QuietOrigin(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = (HERE / "testdata" / "index.html").read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):  # silence
        pass


def wait_port(port: int, timeout: float = 10) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.15)
    return False


def curl(args: list[str]) -> tuple[int, str]:
    cmd = ["curl", "-s", "-o", "-", "-w", "%{http_code}", "--max-time", "20"] + args
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    out = p.stdout
    code = out[-3:] if out[-3:].isdigit() else "000"
    return int(code), out[:-3]


def start_proxy(config: str) -> subprocess.Popen:
    return subprocess.Popen(
        [PY, "proxy_server.py", "--config", config],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)


def stop_proxy(proxy: subprocess.Popen) -> None:
    proxy.terminate()
    try:
        proxy.wait(timeout=8)
    except subprocess.TimeoutExpired:
        proxy.kill()


def main() -> int:
    os.chdir(HERE)
    print("E2E: starting origin server...", flush=True)
    origin = http.server.ThreadingHTTPServer(("127.0.0.1", ORIGIN_PORT), QuietOrigin)
    threading.Thread(target=origin.serve_forever, daemon=True).start()

    url = f"http://127.0.0.1:{ORIGIN_PORT}/testdata/index.html"

    # ---------------- Phase A: positive flows ----------------
    print("E2E: phase A (allow-private config)", flush=True)
    proxy = start_proxy("test_config.json")
    try:
        if not (wait_port(HTTP_PORT) and wait_port(SOCKS_PORT)):
            print("E2E: proxy ports did not open", flush=True)
            return 1

        code, body = curl(["-x", f"http://127.0.0.1:{HTTP_PORT}", url])
        check("plain HTTP via proxy returns 200 + origin body",
              code == 200 and "PyProxy E2E Origin OK" in body, f"code={code}")

        code, _ = curl(["--proxytunnel", "-x", f"http://127.0.0.1:{HTTP_PORT}", url])
        check("CONNECT tunnel via proxy returns 200", code == 200, f"code={code}")

        code, body = curl(["--socks5-hostname", f"127.0.0.1:{SOCKS_PORT}", url])
        check("SOCKS5 via proxy returns 200 + origin body",
              code == 200 and "PyProxy E2E Origin OK" in body, f"code={code}")

        code, _ = curl(["-x", f"http://127.0.0.1:{HTTP_PORT}", "http://denied.example/"])
        check("deny rule returns 403 for denied.example", code == 403, f"code={code}")
    finally:
        stop_proxy(proxy)

    # ---------------- Phase B: SSRF guard ----------------
    print("E2E: phase B (deny-private config)", flush=True)
    proxy = start_proxy("test_config_private.json")
    try:
        if not wait_port(HTTP_PORT):
            print("E2E: proxy port did not open (phase B)", flush=True)
            return 1
        code, _ = curl(["-x", f"http://127.0.0.1:{HTTP_PORT}", url])
        check("SSRF guard blocks loopback target (403)", code == 403, f"code={code}")
    finally:
        stop_proxy(proxy)

    # ------- Phase C: audit chain (per directory; each server run owns one chain) -------
    import json
    all_chained = True
    seen_any = False
    for d in ("logs-test", "logs-test-private"):
        prev = None
        seen = False
        for f in sorted((HERE / d).glob("audit-*.jsonl")):
            for line in f.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                ev = json.loads(line)
                ok = (ev.get("prev") == "GENESIS") if not seen else (ev.get("prev") == prev)
                all_chained = all_chained and ok
                seen = True
                prev = ev.get("hash")
        seen_any = seen_any or seen
    check("audit log is hash-chained (GENESIS → prev links)", all_chained and seen_any)

    print(f"\nRESULT: PASS={PASS} FAIL={FAIL}", flush=True)
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
