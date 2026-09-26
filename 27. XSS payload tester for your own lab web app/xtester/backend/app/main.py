"""FastAPI application entrypoint.

Serves the hardened API and the zero-dependency dashboard SPA. Wires up:
  - security headers middleware
  - audit-aware exception handling
  - bootstrap admin provisioning (first run)
  - static SPA at /
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.api import routes_admin, routes_auth, routes_collector, routes_scans
from app.config import settings
from app.db.session import SessionLocal, init_db
from app.security.audit import audit
from app.security.headers import SecurityHeadersMiddleware

logging.basicConfig(level=settings.log_level)
logger = logging.getLogger("xtester")

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"
STATIC_DIR = FRONTEND_DIR / "static"


def bootstrap_admin() -> None:
    from app.db.models import Role, User
    from app.security.passwords import hash_password

    db = SessionLocal()
    try:
        if db.query(User).count() == 0:
            admin = User(
                username=settings.bootstrap_admin_username.lower(),
                password_hash=hash_password(settings.bootstrap_admin_password),
                role=Role.admin,
                must_change_password=True,
            )
            db.add(admin)
            db.commit()
            audit.record("admin.bootstrap", actor=admin.username, outcome="success",
                         resource=admin.username, details={"note": "first-run admin provisioned"})
            logger.warning("bootstrapped first admin user %r (change the password now)", admin.username)
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    if settings.app_env == "production" and not settings.public_base_url.startswith("https://"):
        logger.warning("PUBLIC_BASE_URL is not https in production; HSTS/beacon may be misconfigured")
    init_db()

    def _persist_audit(entry: dict) -> None:
        from app.db.models import AuditLog

        db = SessionLocal()
        try:
            import json as _json

            db.add(
                AuditLog(
                    actor=entry.get("actor"),
                    actor_type=entry.get("actor_type", "user"),
                    action=entry.get("action"),
                    outcome=entry.get("outcome", "success"),
                    resource=entry.get("resource"),
                    ip=entry.get("ip"),
                    details=_json.dumps(entry.get("details") or {}, ensure_ascii=False),
                    prev_hash=entry.get("prev_hash"),
                    entry_hash=entry.get("entry_hash"),
                )
            )
            db.commit()
        except Exception:  # noqa: BLE001
            db.rollback()
        finally:
            db.close()

    audit.set_persister(_persist_audit)
    bootstrap_admin()
    yield


app = FastAPI(
    title=f"{settings.app_name} - XSS Payload Tester for your lab",
    version="1.0.0",
    description=(
        "Authorized-use lab scanner. It only scans hosts listed in "
        "ALLOWED_TARGET_HOSTS and requires the operator's own consent/DB context. "
        "See ARCHITECTURE.md and SECURITY.md for the security model."
    ),
    docs_url="/docs" if settings.app_env != "production" else None,
    redoc_url=None if settings.app_env != "production" else None,
    lifespan=lifespan,
)

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[] if settings.app_env == "production" else ["*"],  # same-origin only in prod
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(routes_auth.router)
app.include_router(routes_scans.router)
app.include_router(routes_admin.router)
app.include_router(routes_collector.router)


@app.exception_handler(Exception)
async def unhandled_exc_handler(request: Request, exc: Exception):
    from fastapi.responses import JSONResponse

    logger.exception("unhandled error on %s", request.url.path)
    audit.record(
        "api.error",
        actor="system",
        outcome="failure",
        resource=request.url.path,
        details={"type": type(exc).__name__},
        severity="warning",
    )
    return JSONResponse(status_code=500, content={"detail": "internal error"})


@app.get("/health")
def health():
    return {"status": "ok", "app": settings.app_name, "env": settings.app_env}


async def _spa():
    return FileResponse(FRONTEND_DIR / "index.html")


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
app.add_api_route("/", _spa, methods=["GET"], include_in_schema=False)