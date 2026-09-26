"""In-process smoke test: starts the server, exercises the full API flow."""
import json
import threading
import time
import urllib.request
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from backend.app import serve
from backend.secure_config import SecureConfig
from data.db import Database
from integration.orchestrator import Orchestrator

cfg = SecureConfig(ROOT / "data", ROOT)
cfg.port = 5891
db = Database(cfg.data_dir)
orch = Orchestrator(db, cfg)
srv = serve(cfg, orch)
threading.Thread(target=srv.serve_forever, daemon=True).start()
time.sleep(0.4)

BASE = f"http://{cfg.host}:{cfg.port}"
TOKEN = cfg.rpc_token


def call(path, method="GET", body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        BASE + path, data=data, method=method,
        headers={"X-Auth-Token": TOKEN, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=5) as r:
        return r.status, (r.read())


ok = True


def check(name, cond):
    global ok
    print(("PASS " if cond else "FAIL ") + name)
    ok = ok and cond


status, body = call("/api/state")
check("GET /api/state", status == 200 and b"scan_status" in body)

status, _ = call("/api/consent", "POST", {"operator": "lead-tester"})
check("POST /api/consent", status == 200)

try:
    call("/api/targets", "POST", {"host": "8.8.8.8", "port": 1337, "label": "public"})
    check("scope gate blocks public host", False)
except urllib.error.HTTPError as e:
    check("scope gate blocks public host", e.code == 400)

status, _ = call("/api/targets", "POST",
                 {"host": "10.10.10.5", "port": 1337, "label": "vulnlab service"})
check("POST /api/targets (lab host)", status == 200)

status, body = call("/api/targets")
targets = json.loads(body)
check("GET /api/targets", len(targets) == 1 and targets[0]["host"] == "10.10.10.5")

status, body = call("/api/run", "POST",
                    {"target_id": targets[0]["id"], "module": "exploit/lab/vulnlab_cmd",
                     "options": {"command": "check", "mode": "inject"}})
check("POST /api/run (check)", status == 200 and b"run_id" in body)
time.sleep(1.5)

status, body = call("/api/findings")
findings = json.loads(body)
check("findings ingested", len(findings) >= 1 and findings[0]["owasp"] == "A03")

for fmt in ("csv", "xlsx", "html"):
    status, body = call(f"/api/report/{fmt}")
    check(f"GET /api/report/{fmt}", status == 200 and len(body) > 100)

status, body = call("/api/audit")
check("GET /api/audit", status == 200 and b"CONSENT_ACCEPTED" in body)

srv.shutdown()
print("\nRESULT:", "ALL PASS" if ok else "FAILURES PRESENT")
sys.exit(0 if ok else 1)