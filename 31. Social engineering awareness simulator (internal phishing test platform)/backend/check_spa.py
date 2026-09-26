import os, sys
sys.path.insert(0, os.getcwd())
from fastapi.testclient import TestClient
from app.main import app, DIST_DIR

c = TestClient(app, raise_server_exceptions=False)
idx = os.path.join(DIST_DIR, "index.html")
ok = True

print("dist is file:", os.path.isfile(idx))
r = c.get("/")
ok &= r.status_code == 200
ok &= 'id="root"' in r.text
print("root 200 + SPA root mount:", ok, "| ct:", r.headers.get("content-type"))

r2 = c.get("/campaigns/deep/duck/link")
ok &= r2.status_code == 200 and 'id="root"' in r2.text
print("SPA deep-link fallback 200:", r2.status_code == 200 and 'id="root"' in r2.text)
print("COLORFUL SPA CHECK:", "PASS" if ok else "FAIL")