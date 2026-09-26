"""
VulnLab deliberately vulnerable service (LAB ONLY).

Line-oriented TCP service on port 1337 exposing six teaching sinks:
  auth      - weak default credentials (admin/admin)
  inject    - command injection via ECHO header (X-Cmd)
  sql       - SQLi in WHERE clause
  overflow  - oversized length field semantics (NO real memory corruption)
  trace     - verbose debug disclosure
  ssrf      - blind server-side fetch of an arbitrary URL

Every request is mirrored as JSON to stdout/log for evidence correlation.
It MUST only be run inside an isolated lab network or localhost.
"""
import ipaddress
import json
import socketserver
import subprocess
import sys
import urllib.request

HOST = "0.0.0.0"
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 1337
WEAK_CREDS = {"admin": "admin", "lab": "lab123"}
ALLOW_SSRF_RANGES = ("127.0.0.1", "10.10.10.")


def log(kind, detail):
    row = {"sink": kind, "detail": detail}
    print(json.dumps(row), flush=True)


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        peer = self.client_address[0]
        self.wfile.write(b"VulnLab/1.0 (debug)\r\n")
        self.wfile.flush()
        while True:
            data = self.rfile.readline()
            if not data:
                break
            line = data.decode(errors="replace").strip()
            cmd, _, args = line.partition(" ")
            log(f"raw:{cmd.lower()}", args)

            if cmd.lower() == "auth":
                user, _, pwd = args.partition(" ")
                if WEAK_CREDS.get(user) == pwd:
                    log("auth", "default credentials accepted")
                    self.wfile.write(b"OK weak-auth permitted\r\n")
                else:
                    self.wfile.write(b"DENIED\r\n")

            elif cmd.lower() == "echo":
                # Command-injection sink: opaquely safe on the lab host.
                if ";id" in args or (args.startswith("&") and "id" in args) or "&& id" in args:
                    log("inject", f"command injection fired: {args}")
                    self.wfile.write(b"uid=0(root) gid=0(root)\r\n")
                else:
                    self.wfile.write(b"ECHO target dump: safe\r\n")

            elif cmd.lower() == "sql":
                if "' OR 1=1" in args.upper() or "1=1" in args:
                    log("sql", "boolean-based SQLi")
                    self.wfile.write(b"3 records returned (flag_rows)\r\n")
                else:
                    self.wfile.write(b"0 records\r\n")

            elif cmd.lower() == "size":
                try:
                    n = int(args.split()[0])
                except ValueError:
                    n = 0
                log("overflow", f"length field {n}")
                if n > 8192:
                    self.wfile.write(b"SIZE_FLAG oversized length accepted (lab semantics)\r\n")
                else:
                    self.wfile.write(b"OK\r\n")

            elif cmd.lower() == "trace":
                if "?debug=1" in args or "verbose" in args:
                    log("trace", "verbose debug enabled")
                    self.wfile.write(b"DEBUG python-3.12 framework=Flask traceback dump\r\n")
                else:
                    self.wfile.write(b"OK\r\n")

            elif cmd.lower() == "fetch":
                target = args.strip()
                # Lab-only SSRF: refuse the internet, allow loopback/lab only.
                host = target.split("/")[2] if target.startswith("http") else target
                if not (target.startswith("http://") or target.startswith("https://")):
                    self.wfile.write(b"FETCH_ERR bad url\r\n")
                    continue
                if not host.startswith(ALLOW_SSRF_RANGES):
                    log("ssrf", f"blocked fetch to {target}")
                    self.wfile.write(b"FETCH_ERR outside lab range\r\n")
                    continue
                log("ssrf", f"fetch accepted: {target}")
                try:
                    with urllib.request.urlopen(target, timeout=3) as r:
                        self.wfile.write(b"FETCH_OK " + r.read(128) + b"\r\n")
                except Exception:
                    self.wfile.write(b"FETCH_ERR unreachable\r\n")

            elif cmd.lower() in ("quit", "exit"):
                break

            else:
                self.wfile.write(b"ERR unknown command\r\n")
            self.wfile.flush()


class Threaded(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True


if __name__ == "__main__":
    print(f"[*] VulnLab vulnerable service listening on {HOST}:{PORT} (LAB ONLY)", flush=True)
    try:
        Threaded((HOST, PORT), Handler).serve_forever()
    except KeyboardInterrupt:
        print("\n[*] VulnLab service stopped", flush=True)