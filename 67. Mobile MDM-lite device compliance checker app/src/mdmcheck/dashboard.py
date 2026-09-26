"""Local HTTP server: hosts the colorful dashboard UI + JSON API."""
from __future__ import annotations

import json
import os
import re
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable

from . import __version__
from .adb import adb_available, adb_devices, collect as adb_collect
from .demo import demo_telemetry
from .engine import evaluate
from .model import now_iso
from .report import generate_html_report, generate_json_report
from .store import StateStore

UI_DIR = Path(__file__).parent / "ui"


def _resource_path(rel: str) -> Path:
    """Resolve resource path for both source and PyInstaller onefile runs."""
    if getattr(sys, "frozen", False):
        base = Path(getattr(sys, "_MEIPASS", "."))
        return base / "mdmcheck" / rel
    return Path(__file__).parent / rel


class AppContext:
    def __init__(self, store: StateStore, on_shutdown: Callable[[], None] | None = None):
        self.store = store
        self.on_shutdown = on_shutdown or (lambda: os._exit(0))

    # ------------------------------------------------------------- business ops
    def scan_device(self, device_id: str, mode: str = "demo", serial: str = "") -> dict:
        dev = self.store.device(device_id)
        if not dev:
            return {"error": "device not found", "id": device_id}

        telemetry: dict
        used_mode = mode
        if mode == "adb":
            ok, msg = adb_available()
            if not ok:
                return {"error": "ADB unavailable: " + msg}
            target_serial = serial or device_id
            try:
                telemetry = adb_collect(target_serial)
                used_mode = "adb"
            except Exception as e:  # noqa: BLE001
                return {"error": f"ADB collect failed: {e}"}
        elif mode == "telemetry":
            telemetry = dev.telemetry
            if not telemetry:
                telemetry = demo_telemetry(dev.id, dev.platform)
            used_mode = "manual"
            if dev.telemetry:
                used_mode = "agent"
        else:
            telemetry = demo_telemetry(dev.id, dev.platform)
            used_mode = "demo"

        if not telemetry:
            telemetry = demo_telemetry(dev.id, dev.platform)

        result = evaluate(self.store.policy(), dev.id, dev.platform, telemetry)
        updated = self.store.apply_scan(dev.id, telemetry, result, used_mode)
        return {"ok": True, "device": updated.to_dict() if updated else None}

    def scan_all(self, mode: str = "demo") -> dict:
        out = []
        for d in self.store.devices():
            r = self.scan_device(d["id"], mode="adb" if mode == "adb" else "demo")
            out.append({"id": d["id"], "ok": r.get("ok"), "status": (r.get("device") or {}).get("status"), "error": r.get("error")})
        return {"ok": True, "scanned": len(out), "results": out}


def make_handler(ctx: AppContext):
    class Handler(BaseHTTPRequestHandler):
        server_version = f"MDMLite/{__version__}"

        def log_message(self, fmt, *args):  # quiet stdout
            pass

        # -------------------------------------------------------------- helpers
        def _send(self, code: int, body: bytes, ctype: str = "application/json; charset=utf-8", extra: dict | None = None):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            if extra:
                for k, v in extra.items():
                    self.send_header(k, v)
            self.end_headers()
            try:
                self.wfile.write(body)
            except BrokenPipeError:
                pass

        def _json(self, data: Any, code: int = 200):
            self._send(code, json.dumps(data, default=str).encode("utf-8"))

        def _error(self, msg: str, code: int = 400):
            self._json({"error": msg}, code)

        def _body(self) -> dict:
            try:
                length = int(self.headers.get("Content-Length", 0) or 0)
            except ValueError:
                length = 0
            if length <= 0:
                return {}
            raw = self.rfile.read(length)
            try:
                data = json.loads(raw.decode("utf-8"))
                return data if isinstance(data, dict) else {}
            except Exception:  # noqa: BLE001
                return {}

        def _serve_static(self, rel: str, ctype: str):
            p = _resource_path(rel)
            if p.is_file():
                self._send(200, p.read_bytes(), ctype)
            else:
                self._error("not found", 404)

        # -------------------------------------------------------------- routes
        def do_GET(self):  # noqa: N802
            path, query = self._split()
            try:
                if path == "/":
                    self._serve_static("ui/index.html", "text/html; charset=utf-8")
                elif path == "/favicon.ico":
                    self._send(204, b"", "image/x-icon")
                elif path == "/api/health":
                    self._json({"ok": True, "version": __version__, "at": now_iso(), "frozen": bool(getattr(sys, "frozen", False))})
                elif path == "/api/state":
                    st = ctx.store.snapshot()
                    self._json({
                        "meta": st["meta"],
                        "policy": st["policy"],
                        "devices": st["devices"],
                        "logs": list(reversed(st["securityLog"][-40:])),
                        "settings": st.get("settings", {}),
                        "counts": _counts(st),
                    })
                elif path == "/api/devices":
                    self._json({"devices": ctx.store.devices()})
                elif path.startswith("/api/devices/"):
                    d = ctx.store.device(path.split("/", 3)[3])
                    self._json(d.to_dict() if d else {"error": "not found"}, 200 if d else 404)
                elif path == "/api/policy":
                    self._json(ctx.store.policy())
                elif path == "/api/securitylog":
                    self._json({"log": ctx.store.logs(200)})
                elif path == "/api/adb/status":
                    ok, msg = adb_available()
                    self._json({"available": ok, "message": msg, "devices": adb_devices() if ok else []})
                elif path == "/api/report/html":
                    st = ctx.store.export_report()
                    html = generate_html_report(st, query.get("device", ""))
                    self._send(200, html.encode("utf-8"), "text/html; charset=utf-8")
                elif path == "/api/report/json":
                    st = ctx.store.export_report()
                    self._json(generate_json_report(st, query.get("device", "")))
                elif path == "/api/summary":
                    st = ctx.store.snapshot()
                    self._json(_counts(st))
                else:
                    self._error("not found", 404)
            except Exception as e:  # noqa: BLE001
                self._error(f"server error: {e}", 500)

        def do_POST(self):  # noqa: N802
            path, _ = self._split()
            body = self._body()
            try:
                if path == "/api/devices":
                    if not body.get("name"):
                        return self._error("device name is required")
                    dev = ctx.store.add_device(body)
                    if body.get("telemetry"):
                        # agent push: store real telemetry and evaluate on-device data
                        d = ctx.store.set_telemetry(dev.id, body["telemetry"])
                        if d:
                            r = ctx.scan_device(dev.id, mode="telemetry")
                            if not r.get("ok"):
                                ctx.store.log("warn", "agent_scan_failed", r.get("error", ""), device_id=dev.id)
                            dev = ctx.store.device(dev.id)
                    elif body.get("scanOnEnroll"):
                        ctx.scan_device(dev.id, mode=body.get("mode", "demo"))
                        dev = ctx.store.device(dev.id)
                    self._json({"ok": True, "device": dev.to_dict() if dev else None})
                elif path == "/api/scan":
                    mode = body.get("mode", "demo")
                    self._json(ctx.scan_all(mode))
                elif path == "/api/policy":
                    try:
                        pol = ctx.store.set_policy(body.get("policy", body))
                    except ValueError as e:
                        return self._error(str(e))
                    self._json({"ok": True, "policy": pol})
                elif path == "/api/policy/reset":
                    self._json({"ok": True, "policy": ctx.store.reset_policy()})
                elif path == "/api/securitylog/clear":
                    ctx.store.clear_logs()
                    self._json({"ok": True})
                elif path == "/api/shutdown":
                    self._json({"ok": True, "message": "shutting down"})
                    threading.Thread(target=ctx.on_shutdown, daemon=True).start()
                elif path.startswith("/api/devices/") and path.endswith("/scan"):
                    device_id = path.split("/")[3]
                    r = ctx.scan_device(device_id, mode=body.get("mode", "demo"), serial=body.get("serial", ""))
                    self._json(r, 400 if r.get("error") else 200)
                elif path.startswith("/api/devices/") and path.endswith("/telemetry"):
                    device_id = path.split("/")[3]
                    tel = body.get("telemetry", {})
                    d = ctx.store.set_telemetry(device_id, tel)
                    if not d:
                        return self._error("device not found", 404)
                    self._json({"ok": True, "device": d.to_dict()})
                else:
                    self._error("not found", 404)
            except Exception as e:  # noqa: BLE001
                self._error(f"server error: {e}", 500)

        def do_DELETE(self):  # noqa: N802
            path, _ = self._split()
            if path.startswith("/api/devices/"):
                device_id = path.split("/", 3)[3]
                ok = ctx.store.remove_device(device_id)
                self._json({"ok": ok}, 200 if ok else 404)
            else:
                self._error("not found", 404)

        def _split(self):
            parts = self.path.split("?", 1)
            path = parts[0]
            q: dict[str, str] = {}
            if len(parts) == 2:
                for kv in parts[1].split("&"):
                    if "=" in kv:
                        k, v = kv.split("=", 1)
                        q[_urldecode(k)] = _urldecode(v)
            return path, q

    return Handler


def _urldecode(s: str) -> str:
    from urllib.parse import unquote

    return unquote(s)


def _counts(st: dict) -> dict:
    devices = st.get("devices", [])
    c = {
        "total": len(devices),
        "compliant": 0,
        "nonCompliant": 0,
        "pending": 0,
        "scoreSum": 0.0,
        "scoreCount": 0,
        "android": 0,
        "ios": 0,
        "totalScans": st.get("meta", {}).get("totalScans", 0),
    }
    for d in devices:
        c["android" if d.get("platform") == "android" else "ios"] += 1
        s = d.get("scan")
        if s is None:
            c["pending"] += 1
        elif s["status"] == "COMPLIANT":
            c["compliant"] += 1
        else:
            c["nonCompliant"] += 1
        if s:
            c["scoreSum"] += s.get("score", 0)
            c["scoreCount"] += 1
    c["avgScore"] = round(c["scoreSum"] / c["scoreCount"], 1) if c["scoreCount"] else 0
    return c


def pick_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def serve(store: StateStore, port: int = 0, host: str = "127.0.0.1", on_shutdown: Callable[[], None] | None = None) -> tuple[ThreadingHTTPServer, str]:
    ctx = AppContext(store, on_shutdown)
    handler = make_handler(ctx)
    if not port:
        port = pick_port()
    httpd = ThreadingHTTPServer((host, port), handler)
    httpd.daemon_threads = True
    url = f"http://{host}:{port}"
    return httpd, url