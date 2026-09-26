"""SOAR-Lite FastAPI application.

Production considerations:
  - Run behind a TLS-terminating reverse proxy/gateway (see docker-compose).
  - Secret key must come from the environment (never the default dev value).
  - The embedded worker should be disabled when a standalone worker runs.
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.config import settings
from app.core.http_middleware import SecurityHeadersMiddleware
from app.core.logging_setup import setup_logging

log = logging.getLogger("soarlite")


@asynccontextmanager
async def lifespan(app: FastAPI):
    from app.db.base import init_db
    from app.seed import seed
    from app.worker import start_embedded

    setup_logging()
    init_db()
    seed()
    if settings.enable_embedded_worker:
        start_embedded()
        log.info("embedded worker enabled")
    yield
    if settings.enable_embedded_worker:
        from app.worker import stop

        stop()


def create_app() -> FastAPI:
    app = FastAPI(
        title="SOAR-Lite Incident Response Playbook Runner",
        version="1.0.0",
        description=(
            "Automated Incident Response Playbook Runner (SOAR-Lite). "
            "Built with OWASP Top 10, NIST SP 800-61/800-53 and ISO 27001 alignment."
        ),
        docs_url="/docs" if not settings.is_production else "/api-docs",
        redoc_url=None,
        openapi_url="/openapi.json" if not settings.is_production else None,
        lifespan=lifespan,
    )

    app.add_middleware(SecurityHeadersMiddleware)

    from app.routers import api, auth, web

    app.include_router(auth.router)
    app.include_router(api.router)
    app.include_router(web.router)

    # static assets (CSS/JS), served same-origin to satisfy CSP 'self'
    import os
    from pathlib import Path

    static_dir = Path(__file__).resolve().parent.parent / "static"
    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    return app


app = create_app()