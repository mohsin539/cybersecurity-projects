import os, sys
from fastapi.testclient import TestClient
from app.main import app, DIST_DIR
from app.seed import init_db

init_db()
c = TestClient(app, raise_server_exceptions=False)

ok = True
def mark(name, cond):
    global ok
    ok = ok and cond
    print(("PASS " if cond else "FAIL ") + name)

r = c.get("/")
mark("SPA index asset present", bool(os.path.isfile(os.path.join(DIST_DIR, "index.html"))))
mark("root serves SPA (200 HTML)", r.status_code == 200 and r.headers["content-type"] in ("text/html", "text/html; charset=utf-8"))
mark("root contains color console mount", 'id="root"' in r.text)
r = c.get("/some/deep/spa/link")
mark("SPA history fallback", r.status_code == 200 and 'id="root"' in r.text)

print("SEA Check:", "OK" if ok else "FAILED")
