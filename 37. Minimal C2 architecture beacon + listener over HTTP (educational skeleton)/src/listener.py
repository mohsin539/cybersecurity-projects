"""HTTP listener (C2 communication hub).

Implementation notes (education focus):
- Uses stdlib `http.server.ThreadingHTTPServer` so the request/response
  mechanics are fully visible - no framework magic.
- All protected endpoints require a Bearer token (beacon or console).
- All payloads are Fernet-encrypted at the application layer.
- Input validation + size limits + rate limiting (OWASP A01/A02/A05/A07).
"""
import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional

from .authn import AuthService
from .c2logging import AuditLog
from .config import (
    AUTH_HEADER,
    MAX_BODY_BYTES,
    CONSOLE_TOKEN,
    BEACON_TOKEN,
)
from .crypto import PayloadCrypto
from .registry import BeaconRegistry

__all__ = ["C2Listener", "C2RequestHandler"]


class C2Listener:
    """Owns the registry, security services and HTTP server lifecycle."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8080,
        beacon_token: Optional[str] = None,
        console_token: Optional[str] = None,
        key_b64: Optional[str] = None,
        audit: Optional[AuditLog] = None,
        logger=None,
    ):
        self.host = host
        self.port = port
        self.crypto = PayloadCrypto(key_b64)
        self.registry = BeaconRegistry()
        self.logger = logger
        self.audit = audit or AuditLog("logs/audit.jsonl")

        self.auth = AuthService(
            beacon_token or BEACON_TOKEN,
            console_token or CONSOLE_TOKEN,
            audit=self.audit,
        )
        self._server: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    # ---- lifecycle --------------------------------------------------------
    def start(self) -> bool:
        if self._server:
            return False

        self._server = ThreadingHTTPServer((self.host, self.port), C2RequestHandler)
        self._server.listener = self  # type: ignore[attr-defined]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        if self.logger:
            self.logger.info("Listener UP on http://%s:%s", self.host, self.port)
        self.audit.record("listener.started", "console", f"{self.host}:{self.port}")
        return True

    def stop(self):
        if self._server:
            server = self._server
            self._server = None
            server.shutdown()
            server.server_close()
            self.audit.record("listener.stopped", "console", f"{self.host}:{self.port}")
            if self.logger:
                self.logger.info("Listener DOWN")

    @property
    def running(self) -> bool:
        return self._server is not None

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"

    # ---- domain ops called by the handler ----------------------------------
    def handle_checkin(self, principal_ip: str, decoded: dict) -> dict:
        bid = decoded.get("beacon_id")
        meta = decoded.get("meta") or {}
        if not bid:
            raise ValueError("missing beacon_id")
        self.registry.register(bid, meta, principal_ip)
        self.audit.record("beacon.checkin", bid, "/api/v1/checkin",
                          detail={"ip": principal_ip, "os": meta.get("platform")})
        tasks = self.registry.dequeue_pending(bid)
        return {"beacon_id": bid, "tasks": tasks}

    def handle_result(self, decoded: dict) -> dict:
        bid = decoded.get("beacon_id")
        task_id = decoded.get("task_id")
        ok = bool(decoded.get("ok"))
        output = decoded.get("output") or {}
        if not bid or not task_id:
            raise ValueError("missing beacon_id/task_id")
        found = self.registry.mark_complete(bid, task_id, ok, output)
        self.audit.record("task.result" if found else "task.result.unknown",
                          bid, f"/task/{task_id}", severity="info" if found else "warn",
                          detail={"ok": ok})
        return {"accepted": found}

    def handle_new_task(self, decoded: dict) -> dict:
        bid = decoded.get("beacon_id")
        task = decoded.get("task") or {}
        if not bid or not task.get("name"):
            raise ValueError("task requires beacon_id + task.name")
        task = self.registry.enqueue(bid, task)
        self.audit.record("task.enqueue", "console", bid,
                          detail={"task": task.get("name"), "task_id": task.get("task_id")})
        return {"task_id": task["task_id"], "status": task["status"]}


class C2RequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "C2StudyLab/1.0"

    def _listener(self) -> C2Listener:
        return self.server.listener  # type: ignore[attr-defined]

    # ---- plumbing -----------------------------------------------------------
    def log_message(self, fmt, *args):
        pass  # structured logging handled elsewhere

    def _send(self, code: int, payload: dict):
        body = json.dumps(payload, default=str).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict | None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return None
        if length <= 0 or length > MAX_BODY_BYTES:
            return None
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None

    def _auth_json(self, principal: str, ip: str):
        """Extract + decrypt the user-supplied JSON body iff auth passes."""
        if not self._listener().auth.rate_allowed(ip):
            self._send(429, {"status": "rate_limited"})
            self._listener().auth.failure(ip, self.path, reason="rate limited")
            return None
        header = self.headers.get(AUTH_HEADER)
        if not self._listener().auth.verify(header, principal):
            self._send(401, {"status": "unauthorized"})
            self._listener().auth.failure(ip, self.path)
            return None
        body = self._read_json()
        if body is None or "payload" not in body:
            self._send(400, {"status": "bad_request"})
            return None
        try:
            plain = self._listener().crypto.decrypt(body["payload"])
            return json.loads(plain)
        except (ValueError, json.JSONDecodeError):
            self._send(400, {"status": "decrypt_failed"})
            return None

    def _client_ip(self) -> str:
        try:
            return self.client_address[0]
        except (IndexError, TypeError):
            return "unknown"

    # ---- routes -----------------------------------------------------------
    def do_GET(self):
        ip = self._client_ip()
        ln = self._listener()
        if self.path == "/" or self.path == "/api/v1/health":
            self._send(200, {"status": "ok", "app": "C2StudyLab",
                             "beacons": len(ln.registry.snapshot()),
                             "tasks": ln.registry.counts()["tasks"]})
            return
        if self.path == "/api/v1/beacons":
            decoded = self._auth_json("console", ip)
            if decoded is None:
                return
            self._send(200, {"status": "ok", "beacons": ln.registry.snapshot()})
            return
        if self.path == "/api/v1/events":
            decoded = self._auth_json("console", ip)
            if decoded is None:
                return
            self._send(200, {"status": "ok", "events": ln.audit.read_all()})
            return
        self._send(404, {"status": "not_found"})

    def do_POST(self):
        ip = self._client_ip()
        ln = self._listener()
        decoded = self._auth_json("beacon", ip) if self.path != "/api/v1/task" else self._auth_json("console", ip)
        if decoded is None:
            return
        try:
            if self.path == "/api/v1/checkin":
                self._send(200, {"status": "ok", "result": ln.handle_checkin(ip, decoded)})
            elif self.path == "/api/v1/result":
                self._send(200, {"status": "ok", "result": ln.handle_result(decoded)})
            elif self.path == "/api/v1/task":
                self._send(200, {"status": "ok", "result": ln.handle_new_task(decoded)})
            else:
                self._send(404, {"status": "not_found"})
        except ValueError as exc:
            self._send(400, {"status": "bad_request", "error": str(exc)})

    do_PUT = do_POST  # tolerate bots/proxies


def probe_port(host: str, port: int) -> bool:
    """True if something is already listening on the port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.3)
        return s.connect_ex((host, port)) == 0