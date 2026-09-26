"""Headless smoke test of the fuzzer core against a temporary local vulnerable app."""
import http.server
import json
import threading
import urllib.parse


class VulnHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(parsed.query)
        p = q.get("id", [""])[0]
        if parsed.path in ("/trav",):
            p = q.get("file", [""])[0]
        elif parsed.path in ("/err",):
            p = q.get("p", [""])[0]
        elif parsed.path in ("/xss",):
            p = q.get("name", [""])[0]
        if parsed.path == "/":
            body = b'<html><a href="/?id=1">a</a><a href="/sqli?id=2">b</a><a href="/xss?name=x">c</a><a href="/trav?file=note.txt">d</a><a href="/err?p=1">e</a><form method="post" action="/login"><input name="user"></form></html>'
            self.send_response(200)
            self.end_headers()
            self.wfile.write(body)
            return
        if parsed.path == "/sqli":
            if "CONVERT" in p or p == "'":
                body = b"<html>SQLSTATE[42000]: Syntax error near ' in query</html>"
            elif "SLEEP" in p:
                import time
                time.sleep(2.2)
                body = b"<html>ok</html>"
            else:
                body = b"<html>ok</html>"
            self.send_response(200 if p else 400)
            self.end_headers()
            self.wfile.write(body)
            return
        if parsed.path == "/xss":
            body = ("<html>Hello " + p + "</html>").encode()
            self.send_response(200)
            self.end_headers()
            self.wfile.write(body)
            return
        if parsed.path == "/trav":
            if "etc/passwd" in p:
                body = b"<pre>root:x:0:0:root:/root:/bin/bash</pre>"
            else:
                body = b"<pre>no file</pre>"
            self.send_response(200)
            self.end_headers()
            self.wfile.write(body)
            return
        if parsed.path == "/err":
            if p == "1":
                body = b"<html>ok</html>"
                self.send_response(200)
            else:
                body = b"<html>Traceback (most recent call last):\nFile main.py line 9\nTypeError</html>"
                self.send_response(500)
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.end_headers()
        self.wfile.write(b"not found")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        data = self.rfile.read(length).decode()
        parsed = urllib.parse.parse_qs(data)
        user = parsed.get("user", [""])[0]
        if "/login" in self.path:
            body = ("<html>Login " + user + "</html>").encode()
            self.send_response(200)
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.end_headers()
        self.wfile.write(b"not found")


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
        modules=["xss", "sqli", "traversal", "errors", "boundary"],
        max_pages=10,
        max_requests=600,
        concurrency=3,
        delay_ms=0,
        verify_tls=True,
    )
    engine = Engine(cfg, on_finding=findings.append, on_log=print)
    found = engine.run()
    print(f"\nRESULT: {engine.requests} requests, {len(found)} findings")
    for f in found:
        print("  ", f.traceability_line())
    assert len(found) >= 3, "expected at least SQLi, XSS and traversal detections"
    assert found[0].owasp == "A05 Injection"
    by_module = {f.module for f in found}
    assert "traversal" in by_module and "errors" in by_module and "sqli" in by_module and "xss" in by_module


if __name__ == "__main__":
    main()
    print("SMOKE TEST OK")