"""Hardened localhost REST/static server (OWASP-Top-10 aligned).

Binds only to 127.0.0.1 on an OS-assigned random port and requires a
single-use session token in the URL path, so the portable tool surface
is not exposed to the network. Every request is audited.
"""
import json
import mimetypes
import os
import re
import secrets
import socket
import threading
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import __version__
from .audit import AuditTrail
from .compliance import coverage_matrix, tool_framework_compliance
from .correlate import analyze as run_analysis
from .events import (import_csv, import_evtx, import_json, collect_live,
                     sha256_of)
from .rules import load_rules
from . import report as report_mod

ALLOWED_IMPORT_EXT = {".evtx", ".csv", ".json", ".txt"}
MAX_UPLOAD = 100 * 1024 * 1024  # 100 MB cap (OWASP A04-size control)

_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Content-Security-Policy": ("default-src 'self'; script-src 'self'; "
                                "style-src 'self' 'unsafe-inline'; "
                                "img-src 'self' data:; connect-src 'self'; "
                                "frame-ancestors 'none'; base-uri 'self'"),
    "Cache-Control": "no-store",
}


def _json_bytes(obj):
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _filename_ok(name):
    name = os.path.basename(str(name or ""))
    ext = os.path.splitext(name)[1].lower()
    return name and ext in ALLOWED_IMPORT_EXT, ext


class Case:
    """Mutable investigation state shared by API handlers."""

    def __init__(self, work_dir, audit):
        self.case_id = "C-" + secrets.token_hex(4).upper()
        self.events = []
        self.analysis = None
        self.source_report = {}
        self.framework = tool_framework_compliance()
        self.window_start = self.window_end = None
        self.generated_at = None
        self.integrity = {}
        self.audit = audit

    def reset(self):
        self.__init__(self.audit.directory, self.audit)

    def set_events(self, events):
        self.events = events
        if events:
            times = [e.get("ts_epoch", 0) for e in events]
            self.window_start = min(t for t in times if t)
            self.window_end = max(t for t in times if t)

    def build_case_dict(self):
        from datetime import datetime, timezone
        return {
            "tool": __version__,
            "case_id": self.case_id,
            "generated_at": (self.generated_at or
                             datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")),
            "source": self.source_report,
            "window_start": self.window_start,
            "window_end": self.window_end,
            "events": self.events,
            "analysis": self.analysis or {"summary": {"events": len(self.events), "incidents": 0,
                                                       "risk_score": 0, "risk_label": "none",
                                                       "phase_count": 0, "phases_covered": [],
                                                       "campaigns": 0, "spikes": 0,
                                                       "max_severity": 0},
                                           "incidents": [], "phases": [], "campaigns": [],
                                           "spikes": [], "mitre": {}, "mitigation": [],
                                           "generated_at": None},
            "framework": self.framework,
            "coverage": coverage_matrix(load_rules()),
            "audit": self.audit.entries(),
            "integrity": self.integrity,
        }


class Handler(BaseHTTPRequestHandler):
    server_version = "WEL-Intrusion-Suite/%s" % __version__
    protocol_version = "HTTP/1.1"

    @property
    def app(self):
        return self.server.app

    # -- helpers ----------------------------------------------------------
    def _send(self, code, body=b"", ctype="application/json; charset=utf-8", headers=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Server", "WEL-Intrusion-Suite/%s" % __version__)
        for k, v in _SECURITY_HEADERS.items():
            self.send_header(k, v)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code, obj):
        self._send(code, _json_bytes(obj))

    def _file(self, data, name, ctype, disposition="attachment"):
        self._send(200, data, ctype, {
            "Content-Disposition": "%s; filename=\"%s\"" % (disposition, name),
            "X-Download-Options": "noopen",
        })

    def log_message(self, fmt, *args):
        app = getattr(self.server, "app", None)
        try:
            if app:
                app.last_request = __import__("time").time()
        except Exception:
            pass

    # -- routing -----------------------------------------------------------
    def do_GET(self):
        self._route("GET")

    def do_POST(self):
        self._route("POST")

    def do_HEAD(self):
        self._route("HEAD")

    def do_OPTIONS(self):
        self._route("OPTIONS")

    def _route(self, method):
        app = self.app
        try:
            parsed = urlparse(self.path)
            path = parsed.path
            # token gate
            token = app.token
            if not path.startswith("/tk-" + token):
                self.app.audit.append("user", "denied request", "no/invalid token", "warn")
                self._send(403, b'{"error":"forbidden"}')
                return
            if method not in ("GET", "POST", "HEAD"):
                self._send(405, b'{"error":"method not allowed"}')
                return
            rest = path[len("/tk-" + token):]
            if rest.startswith("/api/"):
                self._api(rest, parsed.query)
            else:
                self._static(rest)
        except BrokenPipeError:
            pass
        except Exception as exc:
            self.app.audit.append("system", "server error", str(exc)[:200], "error")
            try:
                self._send(500, _json_bytes({"error": str(exc)}))
            except Exception:
                pass

    # -- API ----------------------------------------------------------------
    def _api(self, route, query):
        parts = route.split("/")
        app = self.app
        if route == "/api/status":
            stats = app.audit.stats()
            self._json(200, {"version": __version__, "case_id": app.case.case_id,
                             "events": len(app.case.events),
                             "rules": len(app.rules),
                             "analyzed": app.case.analysis is not None,
                             "audit_entries": stats["entries"],
                             "audit_valid": stats["valid"],
                             "uptime_s": app.uptime()})
            return
        if route == "/api/events":
            qs = parse_qs(query)
            start = int(qs.get("start", ["0"])[0])
            limit = int(qs.get("limit", ["200"])[0])
            evs = app.case.events[start: start + limit]
            self._json(200, {"total": len(app.case.events), "events": evs})
            return
        if route == "/api/audit":
            self._json(200, {"entries": app.case.audit.entries(),
                             "stats": app.case.audit.stats()})
            return
        if route == "/api/framework":
            self._json(200, {"coverage": coverage_matrix(app.rules),
                             "tool": app.case.framework})
            return
        if route == "/api/report":
            qs = parse_qs(query)
            rtype = qs.get("type", ["html"])[0]
            self._download_report(rtype)
            return
        if route == "/api/analyze":
            self._api_analyze()
            return
        if route == "/api/import":
            self._api_import()
            return
        if route == "/api/collect":
            self._api_collect()
            return
        if route == "/api/case/reset":
            app.case.reset()
            app.last_request = __import__("time").time()
            self._json(200, {"ok": True, "case_id": app.case.case_id})
            return
        if route == "/api/shutdown":
            threading.Thread(target=app.shutdown, daemon=True).start()
            self._json(200, {"ok": True, "message": "shutting down"})
            return
        self._send(404, b'{"error":"endpoint not found"}')
# -- API handlers ---------------------------------------------------------
    def _read_json(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length > max(65536, MAX_UPLOAD):
            raise ValueError("payload too large")
        raw = self.rfile.read(length) if length else b"{}"
        return json.loads(raw.decode("utf-8", "replace") if raw else "{}")

    def _api_analyze(self):
        app = self.app
        if not app.case.events:
            self._json(400, {"error": "no events loaded"})
            return
        app.case.analysis = run_analysis(app.case.events, app.rules,
                                         {"cluster_window": 300})
        app.case.generated_at = app.case.analysis["generated_at"]
        app.audit.append("user", "analysis", "correlation over %d events" % len(app.case.events))
        s = app.case.analysis["summary"]
        self._json(200, {"ok": True, "summary": s, "analysis": app.case.analysis,
                         "incidents": len(app.case.analysis["incidents"]),
                         "phases": app.case.analysis["phases"]})

    def _api_collect(self):
        app = self.app
        try:
            body = self._read_json()
        except Exception:
            body = {}
        channels = [str(c) for c in body.get("channels", [])] or None
        max_per = int(body.get("max_per_channel", 300))
        if not (1 <= max_per <= 50000):
            max_per = 300
        since = body.get("since")
        evs, report = collect_live(channels=channels, max_per_channel=max_per,
                                   since_iso=since)
        app.case.set_events(evs)
        app.case.window_start = app.case.window_end = None
        app.audit.append("user", "collect", "queried %s channels (%d events)" % (
            ", ".join(report["channels"].keys()), report["total"]))
        self._json(200, {"ok": True, "report": report, "events": len(evs)})

    def _api_import(self):
        app = self.app
        ctype = self.headers.get("Content-Type", "")
        ok_name, ext = False, ""
        events, errors = [], []
        if "multipart/form-data" in ctype:
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_UPLOAD:
                self._json(413, {"error": "upload too large"})
                return
            import email
            import mimetypes
            body_bytes = self.rfile.read(length)
            import re
            m = re.search(r'name="file"; filename="([^"]+)"', body_bytes.decode("utf-8", "replace"),
                          re.IGNORECASE)
            fname = m.group(1) if m else "upload"
            ok_name, ext = _filename_ok(fname)
            if not ok_name:
                app.audit.append("user", "import rejected", "bad extension: %s" % fname, "warn")
                self._json(415, {"error": "unsupported file type"})
                return
            try:
                msg = email.message_from_bytes(body_bytes)
                for part in msg.walk():
                    if part.get_content_type() == "text/plain" and part.get_filename():
                        payload = part.get_payload(decode=True)
                        break
                else:
                    payload = b""
            except Exception:
                payload = body_bytes
            evs, errs, ext = self._dispatch_import_bytes(payload, ext)
            events, errors = evs, errs
        else:
            if "application/json" in ctype:
                try:
                    payload = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                    events = import_json(raw=payload.decode("utf-8", "replace"))
                    ext = ".json"
                except Exception as exc:
                    errors = ["invalid JSON: %s" % exc]
            else:
                errors = ["unsupported content type"]
        app.case.reset()
        app.case.set_events(events)
        app.case.source_report = {"import_mock": True, "source": "import",
                                  "ext": ext, "count": len(events),
                                  "errors": errors}
        app.audit.append("user", "import", "%s file, %d events (%s)" % (
            ext or "?", len(events), "; ".join(errors or ["ok"])))
        self._json(200, {"ok": True, "imported": len(events), "errors": errors,
                         "source": app.case.source_report})

    def _dispatch_import_bytes(self, payload, ext):
        if ext == ".evtx":
            path = self.app._write_temp(payload, ".evtx")
            try:
                evs, errs = import_evtx(path)
                return evs, errs, ext
            finally:
                self.app._del_temp(path)
        if ext == ".json":
            try:
                return import_json(raw=payload.decode("utf-8", "replace")), [], ext
            except Exception as exc:
                return [], ["invalid JSON payload: %s" % exc], ext
        return import_csv(payload.decode("utf-8", "replace")), [], ext

    def _download_report(self, rtype):
        app = self.app
        if not app.case.events:
            self._json(400, {"error": "no data"})
            return
        case = app.case.build_case_dict()
        if rtype == "html":
            stats = app.case.audit.stats()
            data = report_mod.html_report(case, stats).encode("utf-8")
            case["integrity"]["hash"] = sha256_of({"artifact": "html",
                                                   "bytes": data.decode("utf-8", "replace")})
            sid = app._write_report_sidecar(data, "report.html")
            app.audit.append("user", "report", "downloaded HTML (sha256 %s...)" % sid[:12])
            self._file(data, "intrusion_report_%s.html" % app.case.case_id,
                       "text/html; charset=utf-8")
            return
        if rtype == "csv":
            data = report_mod.csv_events(case)
            sid = app._write_report_sidecar(data, "events.csv")
            app.audit.append("user", "report", "downloaded CSV events (sha256 %s...)" % sid[:12])
            self._file(data, "events_%s.csv" % app.case.case_id, "text/csv; charset=utf-8")
            return
        if rtype == "timeline.csv":
            data = report_mod.csv_timeline(case)
            hm = sha256_of({"d": data.decode("utf-8", "replace")})[:12]
            app.audit.append("user", "report", "downloaded timeline CSV (sha256 %s...)" % hm)
            self._file(data, "timeline_%s.csv" % app.case.case_id, "text/csv; charset=utf-8")
            return
        data = report_mod.json_case(case)
        case["integrity"]["hash"] = sha256_of({"artifact": "json",
                                               "bytes": data.decode("utf-8")})
        app._write_report_sidecar(data, "case.json")
        app.audit.append("user", "report", "exported JSON case")
        self._file(data, "case_%s.json" % app.case.case_id, "application/json; charset=utf-8")

    # -- static ---------------------------------------------------------------
    def _static(self, rel):
        rel = rel.lstrip("/") or "index.html"
        if not rel or ".." in rel or rel.startswith("\\") or ":" in rel:
            self._send(400, b'{"error":"bad path"}')
            return
        base = os.path.join(self.app.web_dir, rel)
        if not os.path.isfile(base):
            self._send(404, b'{"error":"not found"}')
            return
        ctype = mimetypes.guess_type(rel)[0] or "application/octet-stream"
        with open(base, "rb") as fh:
            data = fh.read()
        self._send(200, data, ctype, {"Cache-Control": "no-store"})


class AppServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, web_dir, work_dir):
        self.web_dir = web_dir
        self.work_dir = work_dir
        self.audit = AuditTrail(os.path.join(work_dir, "audit"))
        self.case = Case(work_dir, self.audit)
        self.rules = load_rules()
        port = int(os.environ.get("WELICS_PORT", "0"))
        token = os.environ.get("WELICS_TOKEN") or secrets.token_hex(16)
        self.token = token if re.fullmatch(r"[0-9a-f]{8,64}", token) else secrets.token_hex(16)
        self.app = self
        self._start_time = __import__("time").time()
        self.last_request = self._start_time
        self._temp_files = []
        super().__init__(("127.0.0.1", port or 0), Handler)
        self.port = self.server_address[1]
        self._temp_dir = os.path.join(work_dir, "tmp")
        os.makedirs(self._temp_dir, exist_ok=True)

    def setup_sanitized(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.shutdown()

    def uptime(self):
        import time
        return int(time.time() - self._start_time)

    def url(self):
        return "http://127.0.0.1:%d/tk-%s/index.html" % (self.port, self.token)

    def safe_shutdown(self):
        try:
            self.shutdown()
        except Exception:
            pass

    def _write_temp(self, data, ext):
        import tempfile
        fd, path = tempfile.mkstemp(prefix="upl_", suffix=ext, dir=self._temp_dir)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        self._temp_files.append(path)
        return path

    def _del_temp(self, path):
        try:
            os.unlink(path)
        except OSError:
            pass

    def _write_report_sidecar(self, data, name):
        import hashlib
        from datetime import datetime, timezone
        checksum = hashlib.sha256(data).hexdigest()
        out_dir = os.path.join(self.work_dir, "exports")
        os.makedirs(out_dir, exist_ok=True)
        base = os.path.join(out_dir, name)
        with open(base, "wb") as fh:
            fh.write(data)
        with open(base + ".sha256", "w", encoding="utf-8") as fh:
            fh.write(checksum + "\n")
        with open(os.path.join(out_dir, "CASE_%s.txt" % self.case.case_id), "a", encoding="utf-8") as fh:
            fh.write("%s %s %s\n" % (datetime.now(timezone.utc).isoformat(),
                                     os.path.basename(base), checksum))
        return checksum
# __CHUNK_SRV2__