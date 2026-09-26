"""HTTP-layer smoke test: live AppServer + REST API + report downloads."""
import json
import os
import sys
import tempfile
import threading
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from app.server import AppServer  # noqa: E402

CHECKS = []


def check(name, cond, extra=""):
    CHECKS.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name + (("  [" + extra + "]") if extra else ""))


def http(url, method="GET", data=None, headers=None):
    req = urllib.request.Request(url, data=data, method=method)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    with urllib.request.urlopen(req, timeout=30) as resp:
        body = resp.read()
        return resp.status, resp.headers, body


def main():
    tmp = tempfile.mkdtemp(prefix="welics_")
    web = os.path.join(ROOT, "app", "web")
    server = AppServer(web_dir=web, work_dir=tmp)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    base = "http://127.0.0.1:%d/tk-%s" % (server.port, server.token)

    try:
        st, hd, bd = http(base + "/api/status")
        check("status 200", st == 200)
        check("loopback+token gate", hd.get("Content-Security-Policy") is not None and
              b'"case_id"' in bd)  # JSON C-XXXX status body
        check("CSP present", "default-src 'self'" in hd.get("Content-Security-Policy", ""))
        check("nosniff", hd.get("X-Content-Type-Options") == "nosniff")

        # forbidden without token
        bad_url = "http://127.0.0.1:%d/api/status" % server.port
        bad = None
        try:
            http(bad_url)
        except urllib.error.HTTPError as e:
            bad = e.code
        check("no-token rejected 403", bad == 403)

        # static index
        st, hd, bd = http(base + "/index.html")
        check("index.html served", st == 200 and b"WEL INTRUSION" in bd)
        st, _, bd = http(base + "/style.css")
        check("style.css served", b"--bg:#0b1220" in bd[:4000])
        st, _, bd = http(base + "/app.js")
        check("app.js served", b"renderDashboard" in bd[:6000])
        trav = 0
        try:
            http(base + "/../server.py")
        except urllib.error.HTTPError as e:
            trav = e.code
        check("path traversal blocked", trav != 200, str(trav))

        # import case JSON
        case_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "case_guest.json")
        with open(case_path, "rb") as fh:
            payload = fh.read()
        st, _, bd = http(base + "/api/import", method="POST", data=payload,
                         headers={"Content-Type": "application/json"})
        imp = json.loads(bd)
        check("import 37 events", imp.get("imported") == 37, str(imp.get("imported")))
        check("import audited", server.audit.entries()[-1]["action"] == "import")

        # analyze
        st, _, bd = http(base + "/api/analyze", method="POST", data=b"{}",
                         headers={"Content-Type": "application/json"})
        an = json.loads(bd)
        check("analyze returns incidents", an.get("incidents", 0) >= 12, str(an.get("incidents")))
        check("phases populated", len(an.get("phases", [])) >= 6)
        check("risk score", an["summary"]["risk_score"] > 30)

        # events endpoint
        st, _, bd = http(base + "/api/events?start=0&limit=10")
        evs = json.loads(bd)
        check("events paged", evs["total"] == 37 and len(evs["events"]) == 10)

        # reports
        for tag, ttype, marker in [("html", "html", b"SHA-256"), ("csv", "csv", b"timestamp"),
                                   ("timeline.csv", "timeline.csv", b"stage"),
                                   ("json", "json", b'"events"')]:
            st, hd, bd = http(base + "/api/report?type=" + ttype)
            check(tag + " report download", st == 200 and marker in bd[:40000])
            check(tag + " disposition", "attachment" in hd.get("Content-Disposition", ""))

        # framework + audit
        st, _, bd = http(base + "/api/framework")
        fw = json.loads(bd)
        check("framework endpoint", fw.get("coverage") and fw.get("tool"))
        st, _, bd = http(base + "/api/audit")
        au = json.loads(bd)
        check("audit stream", au["stats"]["valid"] is True and len(au["entries"]) >= 4,
              "%d entries" % len(au["entries"]))

        # report integrity sidecar saved
        exp = os.path.join(tmp, "exports")
        check("sidecar artefacts on disk", os.path.isdir(exp) and
              len(os.listdir(exp)) >= 6, str(os.listdir(exp))[:80])

        # shutdown
        st, _, bd = http(base + "/api/shutdown", method="POST", data=b"{}")
        check("shutdown accepted", st == 200)
        time.sleep(0.8)
        shut = 0
        try:
            http(base + "/api/status")
        except urllib.error.HTTPError as e:
            shut = e.code
        except Exception:
            shut = -1
        check("server terminated", shut != 200, repr(shut))
    finally:
        try:
            server.shutdown()
        except Exception:
            pass
        server.server_close()

    failed = [n for n, p in CHECKS if not p]
    print("\n%d/%d passed" % (len(CHECKS) - len(failed), len(CHECKS)))
    if failed:
        print("FAILED: %s" % ", ".join(failed))
        sys.exit(1)
    print("SERVER TESTS: ALL GREEN")


if __name__ == "__main__":
    main()