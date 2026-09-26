"""Headless smoke test of the XSS tester core against a temporary local vulnerable lab app."""
import http.server
import threading
import urllib.parse


class VulnHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(parsed.query)
        p = q.get("q", [""])[0]
        path = parsed.path
        if path == "/":
            body = (
                b"<html>"
                b'<a href="/xss?q=x">1</a>'
                b'<a href="/attr?q=x">2</a>'
                b'<a href="/script?q=x">3</a>'
                b'<a href="/href?q=x">4</a>'
                b'<a href="/encoded?q=x">5</a>'
                b'<a href="/noreflect?q=x">6</a>'
                b'<form method="post" action="/msg"><input name="msg" value=""></form>'
                b"</html>"
            )
            self.send_response(200)
            self.end_headers()
            self.wfile.write(body)
            return
        if path == "/xss":
            body = ("<html>Hello <b>" + p + "</b> world</html>").encode()
            self._ok(body)
            return
        if path == "/attr":
            body = ('<html><input id="probe" value="' + p + '"></html>').encode()
            self._ok(body)
            return
        if path == "/href":
            body = ('<html><a href="' + p + '">link</a></html>').encode()
            self._ok(body)
            return
        if path == "/script":
            body = ("<html><script>var s = '" + p + "';</script></html>").encode()
            self._ok(body)
            return
        if path == "/encoded":
            import html as _html

            body = ("<html>Escaped: " + _html.escape(p, quote=True) + "</html>").encode()
            self._ok(body)
            return
        if path == "/noreflect":
            self._ok(b"<html>static, no reflection</html>")
            return
        self.send_response(404)
        self.end_headers()
        self.wfile.write(b"not found")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        data = self.rfile.read(length).decode()
        parsed = urllib.parse.parse_qs(data)
        msg = parsed.get("msg", [""])[0]
        path = urllib.parse.urlparse(self.path).path
        if path == "/msg":
            body = ("<html>Message: <b>" + msg + "</b></html>").encode()
            self._ok(body)
            return
        self.send_response(404)
        self.end_headers()
        self.wfile.write(b"not found")

    def _ok(self, body: bytes, headers: dict = None):
        self.send_response(200)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)


def main():
    srv = http.server.HTTPServer(("127.0.0.1", 0), VulnHandler)
    port = srv.server_address[1]
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()

    from app.core.engine import Engine, ScanConfig
    from app.core.models import Finding

    findings: list[Finding] = []
    cfg = ScanConfig(
        url=f"http://127.0.0.1:{port}/",
        modules=["basic", "event_handler", "breakout", "scheme", "dom", "iframe"],
        max_pages=20,
        max_payloads=60,
        max_requests=2000,
        concurrency=3,
        delay_ms=0,
        verify_tls=True,
    )
    engine = Engine(cfg, on_finding=findings.append, on_log=print)
    found = engine.run()
    print(f"\nRESULT: {engine.requests} requests, {len(found)} findings")
    for f in found:
        print("  ", f.traceability_line())

    assert len(found) >= 4, "expected multiple XSS detections on the vulnerable lab app"
    assert found[0].owasp == "A05 Injection"
    assert "CWE-79" in found[0].cwes, "expected CWE-79 mapping"

    bad = {f.url for f in found if "/encoded" in f.url or "/noreflect" in f.url}
    assert not bad, f"safe endpoints must not produce findings: {bad}"

    by_module = {f.module for f in found}
    print("categories found:", sorted(by_module))
    assert "basic" in by_module, "expected basic category detections"
    assert "breakout" in by_module, "expected breakout category detections"

    verdicts = {f.verdict for f in found}
    assert "EXECUTED" in verdicts, "expected at least one EXECUTED verdict on raw reflection"

    post_findings = [f for f in found if "/msg" in f.url]
    assert post_findings, "expected POST form parameter to be scanned"


if __name__ == "__main__":
    main()
    print("SMOKE TEST OK")