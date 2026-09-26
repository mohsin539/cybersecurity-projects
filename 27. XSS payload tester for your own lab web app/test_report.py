import http.server
import json
import threading
from pathlib import Path
from tempfile import TemporaryDirectory

from smoke_test import VulnHandler
from app.core.engine import Engine, ScanConfig
from app.core.reporter import export_html, export_json

srv = http.server.HTTPServer(("127.0.0.1", 0), VulnHandler)
threading.Thread(target=srv.serve_forever, daemon=True).start()
url = f"http://127.0.0.1:{srv.server_address[1]}/"

with TemporaryDirectory() as tmp:
    audit = str(Path(tmp) / "audit")
    cfg = ScanConfig(
        url=url,
        modules=["basic", "event_handler", "breakout", "scheme"],
        max_pages=20,
        max_payloads=40,
        max_requests=1000,
        concurrency=2,
        delay_ms=0,
    )
    found = []
    eng = Engine(cfg, on_finding=found.append, audit_dir=audit)
    found = eng.run()
    print("findings:", len(found))
    meta = {"target": url, "modules": "basic,event_handler,breakout,scheme", "requests": eng.requests, "findings": len(found)}
    h = export_html(found, meta, str(Path(tmp) / "r.html"))
    j = export_json(found, meta, str(Path(tmp) / "r.json"))
    size_h = Path(h).stat().st_size
    size_j = Path(j).stat().st_size
    print("HTML bytes:", size_h, "JSON bytes:", size_j)
    head = Path(h).read_text(encoding="utf-8")[:200]
    assert "XssTester" in head
    audit_file = Path(audit) / "audit.jsonl"
    lines = audit_file.read_text(encoding="utf-8").splitlines()
    assert len(lines) > 10, "audit trail expected"
    print("audit lines:", len(lines))
    ev = json.loads(lines[1])
    assert "run" in ev and "event" in ev

print("REPORT/AUDIT TEST OK")