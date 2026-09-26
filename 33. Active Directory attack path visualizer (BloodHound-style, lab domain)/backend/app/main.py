"""SentinelGraph — AD Attack Path Visualizer (FastAPI entrypoint)."""
from __future__ import annotations

import logging
import sys
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware  # noqa: F401


def _static_root() -> Path:
    """Locate the bundled SPA in dev and PyInstaller-frozen modes.

    Onefile exes extract data files to sys._MEIPASS; CWD-relative paths
    would break when launched from an arbitrary working directory.
    """
    if getattr(sys, "frozen", False):
        base = Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent))
        return base / "static"
    return Path(__file__).resolve().parent.parent / "static"

from app.api import routes_auth, routes_core
from app.core import audit
from app.core.config import settings
from app.core.errors import ApiError, api_error_handler, \
    unhandled_error_handler
from app.core.headers import SecurityHeadersMiddleware

logging.basicConfig(level=settings.log_level,
                    format="%(asctime)s %(levelname)s %(name)s %(message)s")

app = FastAPI(
    title=settings.app_name,
    version=settings.version,
    docs_url="/api/docs" if settings.environment == "lab" else None,
    redoc_url=None,
    openapi_url="/api/openapi.json" if settings.environment == "lab" else None,
)

# ---- Security middleware ---------------------------------------------------
app.add_middleware(SecurityHeadersMiddleware)

# Lab-only CORS for the Vite dev server; production serves the built SPA
# from this same origin, so no CORS needed there.
if settings.environment == "lab":
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

app.add_exception_handler(ApiError, api_error_handler)
app.add_exception_handler(Exception, unhandled_error_handler)

app.include_router(routes_auth.router, prefix=settings.api_prefix)
app.include_router(routes_core.router, prefix=settings.api_prefix)


# ---- UI (single-origin; packaged/portable mode) ----------------------------
_static = _static_root()
if (_static / "index.html").is_file():
    app.mount("/assets", StaticFiles(directory=str(_static / "assets")),
              name="assets")

    @app.get("/", include_in_schema=False)
    def index() -> FileResponse:
        return FileResponse(_static / "index.html")

    @app.get("/{path:path}", include_in_schema=False)
    def spa(path: str) -> FileResponse:
        return FileResponse(_static / "index.html")
else:
    # static/ not built yet — API-only mode (development).
    @app.get("/", include_in_schema=False)
    def api_root() -> dict:
        return {"app": settings.app_name,
                "docs": "/api/docs" if app.docs_url else None}


@app.on_event("startup")
def startup() -> None:
    audit.record("app.start", version=settings.version,
                 environment=settings.environment,
                 neo4j=settings.neo4j_enabled)
    if not settings.neo4j_enabled:
        from app.graph import lab_seed
        from app.analysis import tiers
        from app.graph.store import STORE
        lab_seed.seed_lab_domain()
        tiers.classify_tiers(STORE)
    # Optional scheduled re-scan with baseline diffing (SG_RESCAN_INTERVAL_MIN).
    try:
        from app.analysis import rescan
        rescan.start_scheduler(settings.rescan_interval_minutes)
    except Exception:  # never block startup on the scheduler
        audit.record("rescan.scheduler_failed", severity="warn")


@app.on_event("shutdown")
def shutdown() -> None:
    from app.analysis import rescan
    rescan.stop_scheduler()
    audit.record("app.stop")
