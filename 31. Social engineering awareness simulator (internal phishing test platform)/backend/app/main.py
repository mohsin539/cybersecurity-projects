import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from .config import get_settings
from .db import SessionLocal
from .routers import audit, auth, campaigns, reports, targets, templates, tracking, training
from .seed import init_db

settings = get_settings()

DIST_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "frontend", "dist")


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title=settings.app_name,
    version="1.0.0",
    description=(
        "Internal phishing-test platform engineered for Bangladeshi banking. "
        "OWASP Top 10 hardened, NIST CSF 2.0 & ISO 27001 Annex-A aligned. "
        "Report exports: XLSX, CSV, HTML."
    ),
    lifespan=lifespan,
)

origins = [o.strip() for o in settings.cors_origins.split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["Content-Disposition"],
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Phish-Security"] = "true"
    return response


app.include_router(auth.router)
app.include_router(campaigns.router)
app.include_router(targets.router)
app.include_router(templates.router)
app.include_router(tracking.router)
app.include_router(reports.router)
app.include_router(training.router)
app.include_router(audit.router)


@app.get("/", response_class=HTMLResponse, response_model=None, include_in_schema=False)
def root() -> FileResponse | HTMLResponse:
    index = os.path.join(DIST_DIR, "index.html")
    if os.path.isfile(index):
        return FileResponse(index)
    return HTMLResponse(
        "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>"
        "<title>%s</title></head>"
        "<body style='font-family:Segoe UI,Roboto,Arial,sans-serif;background:#0b1f3a;color:#e2ecf9;'>"
        "<div style='max-width:640px;margin:60px auto;padding:0 20px;'>"
        "<h1 style='margin:0 0 8px;'>%s</h1>"
        "<p>Serving the API-only build. Frontend console bundle not found — run "
        "<code>npm run build</code> in <b>frontend/</b>, then reload this page.</p>"
        "<p>API reference: <a href='/docs' style='color:#7dd3fc;'>/docs</a> &middot; "
        "Health: <a style='color:#7dd3fc;' href='/health'>/health</a></p>"
        "</div></body></html>"
        % (settings.app_name, settings.app_name),
    )


@app.get("/health", tags=["ops"])
def health() -> dict:
    return {"status": "ok", "service": settings.app_name}


assets_dir = os.path.join(DIST_DIR, "assets")
if os.path.isdir(assets_dir):
    app.mount("/assets", StaticFiles(directory=assets_dir), name="assets")


@app.get("/favicon.ico", include_in_schema=False)
def no_favicon() -> RedirectResponse:
    return RedirectResponse(url="/docs")