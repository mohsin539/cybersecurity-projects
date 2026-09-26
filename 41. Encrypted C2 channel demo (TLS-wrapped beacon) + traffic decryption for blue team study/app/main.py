from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.api import admin, beacon, blue, panel, reports
from app.config import EVIDENCE_DIR, STATIC_DIR
from app.core import security as sec
from app.db import init_db
from app.services.detection import seed_rules

init_db()
seed_rules()

app = FastAPI(title="C2 Deconfliction Lab", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

ADMIN_TOKEN = sec.ensure_admin_token()

PROTECTED_PREFIXES = (
    "/api/panel",
    "/api/blue",
    "/api/reports/list",
    "/api/reports/generate",
    "/api/admin/audit",
    "/api/admin/keys",
    "/api/admin/keys/rotate",
    "/api/admin/tls",
    "/api/admin/compliance",
)


@app.middleware("http")
async def authz(request: Request, call_next):
    if request.url.path.startswith(PROTECTED_PREFIXES):
        token = request.headers.get("x-lab-token", "")
        if token != ADMIN_TOKEN:
            from fastapi.responses import JSONResponse

            return JSONResponse({"detail": "unauthorized"}, status_code=401)
    return await call_next(request)


app.include_router(beacon.router)
app.include_router(panel.router)
app.include_router(blue.router)
app.include_router(reports.router)
app.include_router(admin.router)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/")
def index():
    return FileResponse(str(STATIC_DIR / "index.html"))


@app.get("/api/health")
def health():
    return {"status": "ok", "app": "C2 Deconfliction Lab", "mode": "lab"}