"""HTTP door emulation: fake admin panel + request trace capture."""
from __future__ import annotations

import http.server
import json
import threading
import urllib.parse
from typing import List

from ..engine.sessions import Session

PAGES = {
    "/": b"""<html><body><h1>Admin Portal</h1>
    <form action="/login" method=post><input name=user><input type=password name=passwd>
    <input type=submit></form></body></html>""",
    "/login": b"login_failed",
    "/admin": b"{secret: 'none-this-is-decoys'}",
    "/.env": b"DB_HOST=10.0.0.9\nDB_PASS=hunny",  # decorative decoy
}


class _Handler(http.server.BaseHTTPRequestHandler):
    door: "HttpDoor" = None

    def log_message(self, *a):  # silence default logging noise
        pass

    def do_GET(self):
        self._route()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        self.door._record(self, self.path, body, "POST")
        self._route()

    def _route(self):
        self.door._record(self, self.path, None, self.command)
        page = PAGES.get(self.path, b"<html>404 not found: maybe the real starting point</html>")
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(page)


class HttpDoor:
    def __init__(self, bind_port: int, session_id_fn=None):
        self.port = bind_port
        self.session_id_fn = session_id_fn or (lambda peer: f"http-{peer[0]}")
        self.sessions: List[Session] = []

    def start(self):
        _Handler.door = self
        self._srv = http.server.ThreadingHTTPServer(("0.0.0.0", self.port), _Handler)
        t = threading.Thread(target=self._srv.serve_forever, daemon=True)
        t.start()
        return t

    def _record(self, handler, path: str, body, method: str):
        session = Session(sid=self.session_id_fn(handler.client_address),
                          peer_ip=handler.client_address[0],
                          peer_port=handler.client_address[1],
                          protocol="http")
        session.add_signal("request",
                           json.dumps({
                               "method": method, "path": path,
                               "ua": handler.headers.get("User-Agent", ""),
                               "body": (body or b"").decode("utf-8", errors="replace")[:256],
                           }))
        session.close()
        self.sessions.append(session)

    def stop(self):
        self._srv.shutdown()


class HttpSimulator:
    """Minimal client for tests (like sqlmap/nmap crawler)."""
    def __init__(self, host: str, port: int):
        self.host, self.port = host, port

    def probe(self, paths):
        import http.client
        out = []
        for p in paths:
            conn = http.client.HTTPConnection(self.host, self.port, timeout=8)
            conn.request("GET", p)
            resp = conn.getresponse()
            body = resp.read(200)
            out.append((p, resp.status, body[:40]))
            conn.close()
        return out
