"""Self-hosted loopback web server: REST API + SSE console stream + static SPA.

Deliberately stdlib-only so the portable .exe has zero runtime dependencies.
Binds exclusively to 127.0.0.1; every /api request is validated against the
per-session bearer token (injected into the served page).
"""
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from data.db import Database
from backend.secure_config import SecureConfig
from integration.orchestrator import LabGateError, Orchestrator
from reporting import report_engine


class Handler(BaseHTTPRequestHandler):
    server_version = "VulnLabSentinel/1.0"

    @property
    def cfg(self) -> SecureConfig:
        return self.server.cfg

    @property
    def orch(self) -> Orchestrator:
        return self.server.orch

    # ---- helpers ----------------------------------------------------------
    def _send_json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length == 0:
            return {}
        return json.loads(self.rfile.read(length))

    def _authorized(self) -> bool:
        if self.path.startswith("/index.html") or self.path == "/":
            return True
        query = parse_qs(urlparse(self.path).query)
        qtoken = (query.get("token") or [""])[0]
        return (self.headers.get("X-Auth-Token", "") == self.cfg.rpc_token
                or qtoken == self.cfg.rpc_token)

    def log_message(self, fmt, *args):  # quiet console, audit via db
        pass

    # ---- routing ----------------------------------------------------------
    def do_GET(self):
        if not self._authorized():
            return self._send_json({"error": "unauthorized"}, 401)
        path = urlparse(self.path).path
        if path in ("/", "/index.html"):
            html = (self.cfg.web_dir / "index.html").read_text(encoding="utf-8")
            html = html.replace(
                "__VULNLAB_TOKEN__",
                f'<meta name="vulnlab-token" content="{self.cfg.rpc_token}">',
            )
            return self._send_bytes(html.encode(), "text/html; charset=utf-8")
        if path == "/api/state":
            return self._send_json(self._state())
        if path == "/api/targets":
            return self._send_json([_t(t) for t in self.orch.db.targets()])
        if path == "/api/findings":
            return self._send_json(self.orch.findings())
        if path == "/api/compliance":
            return self._send_json(self.orch.compliance_matrix())
        if path == "/api/audit":
            rows = self.orch.db._conn.execute(
                "SELECT ts,actor,action,detail FROM audit_log "
                "ORDER BY id DESC LIMIT 60").fetchall()
            return self._send_json(
                [{"ts": r[0], "actor": r[1], "action": r[2], "detail": r[3]}
                 for r in rows])
        if path == "/api/transport":
            return self._send_json({
                "kind": self.orch.transport_kind(),
                "summary": self.cfg.transport_summary(),
                "frameworks": {
                    "OWASP": "Top Ten 2021",
                    "NIST": "CSF v2.0 / SP 800-115 / SP 800-53",
                    "ISO": "IEC 27001:2022 Annex A",
                },
            })
        if path.startswith("/api/report/"):
            fmt = path.rsplit("/", 1)[1].split(".")[0]
            return self._serve_report(fmt)
        if path == "/api/events":
            return self._stream_events()
        return self._send_json({"error": "not found"}, 404)

    def do_POST(self):
        if not self._authorized():
            return self._send_json({"error": "unauthorized"}, 401)
        path = urlparse(self.path).path
        body = self._body()
        try:
            if path == "/api/consent":
                self.orch.attest_consent(body.get("operator", ""))
                return self._send_json({"ok": True})
            if path == "/api/targets":
                tid = self.orch.add_target(
                    body.get("host", ""), body.get("port", 1337),
                    body.get("label", ""), body.get("cidr"))
                return self._send_json({"ok": True, "id": tid})
            if path == "/api/run":
                res = self.orch.run_module(
                    int(body.get("target_id", 0)),
                    body.get("module", "exploit/lab/vulnlab_cmd"),
                    body.get("options", {}))
                return self._send_json(res)
            if path == "/api/run/stop":
                self.orch.stop_run()
                return self._send_json({"ok": True})
            if path == "/api/seed":
                return self._send_json(self._seed_demo(body))
        except LabGateError as exc:
            return self._send_json({"error": str(exc)}, 400)
        except Exception as exc:
            return self._send_json({"error": str(exc)}, 400)
        return self._send_json({"error": "not found"}, 404)

    # ---- payload handlers -------------------------------------------------
    def _state(self):
        st = self.orch.db.stats()
        return {
            "stats": st,
            "consent": bool(self.orch.db.get_cfg("consent")),
            "transport": self.orch.transport_kind(),
            "scan_status": "RUNNING" if self.orch.active_run else "IDLE",
            "no_payload_default": self.cfg.no_payload_default,
            "app": self.cfg.transport_summary(),
        }

    def _send_bytes(self, data, ctype):
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _serve_report(self, fmt):
        try:
            generators = {
                "xlsx": report_engine.generate_xlsx,
                "csv": report_engine.generate_csv,
                "html": report_engine.generate_html,
            }
            path = generators[fmt](self.orch, self.cfg)
        except KeyError:
            return self._send_json({"error": "unsupported format"}, 400)
        ctype = {"xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                 "csv": "text/csv; charset=utf-8",
                 "html": "text/html; charset=utf-8"}[fmt]
        data = path.read_bytes()
        self.orch.db.audit("operator", "REPORT_EXPORT", f"{fmt} {path.name}")
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header(
            "Content-Disposition",
            f'attachment; filename="{path.name}"')
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _stream_events(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        seen = set()
        try:
            while True:
                rows = self.orch.db._conn.execute(
                    "SELECT id, console_log FROM runs "
                    "WHERE status='running' OR end_ts IS NOT NULL "
                    "ORDER BY id DESC LIMIT 3").fetchall()
                for rid, log in rows:
                    lines = (log or "").splitlines()
                    for idx, line in enumerate(lines):
                        key = (rid, idx)
                        if key not in seen:
                            seen.add(key)
                            payload = json.dumps(
                                {"run": rid, "kind": _guess_kind(line),
                                 "line": line})
                            self.wfile.write(f"event: log\ndata: {payload}\n\n".encode())
                            self.wfile.flush()
                if self.orch.active_run is None and len(seen) > 0:
                    self.wfile.write(
                        b'event: state\ndata: {"scan_status":"IDLE"}\n\n')
                    self.wfile.flush()
                time.sleep(0.5)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass

    def _seed_demo(self, body):
        """During CI/smoke testing we simulate module output without a lab."""
        from integration.msgrpc_client import CHECK_FLOW
        rid = self.orch.db.add_run(
            int(body.get("target_id", 1)), "exploit/lab/vulnlab_cmd",
            {"command": "check", "mode": "inject"})
        self.orch.db.audit("smoke", "SEED_DEMO", f"run {rid}")
        for kind, text in CHECK_FLOW:
            self.orch.db.append_run_log(rid, text.format(
                host="sim.lab", port="1337", mode="inject", mid=99))
        self.orch.db.end_run(rid, "complete")
        return {"run_id": rid}


def _t(row):
    return {"id": row[0], "host": row[1], "port": row[2], "label": row[3],
            "scope_cidr": row[4], "created_at": row[6]}


def _guess_kind(line: str) -> str:
    if line.startswith("[+]"):
        return "ok"
    if line.startswith("[-]") or "failed" in line:
        return "err"
    if line.startswith("[!]"):
        return "warn"
    if line.lstrip().startswith("msf6") or "=>" in line:
        return "target"
    return "neutral"


def serve(cfg: SecureConfig, orch: Orchestrator):
    server = ThreadingHTTPServer((cfg.host, cfg.port), Handler)
    server.cfg = cfg
    server.orch = orch
    token = cfg.rpc_token
    print(f"[*] VulnLab Sentinel bound to {cfg.host}:{cfg.port} "
          f"(token={token[:6]}...)")
    return server