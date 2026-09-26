"""FastAPI application factory and lifespan.

Startup order matters: database, then service, then seed, then hub, then the
simulator. The hub binds to the running event loop before the simulator starts so
no frame is published into the void.
"""

from __future__ import annotations

import contextlib
import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .api import admin, ingest, public
from .config import WEB_DIR, Settings, get_settings
from .database import get_db, init_db
from .realtime import StreamHub
from .seed import seed_all
from .service import ServiceError, ScoreboardService, init_service
from .simulator import Simulator

log = logging.getLogger("scoreboard")

DESCRIPTION = """
Event-sourced 3D CTF leaderboard.

* **Deterministic scoring** - the same event log always projects the same board.
* **Append-only history** - `event_log` and `audit_log` reject `UPDATE`/`DELETE`
  at the storage layer and are hash chained.
* **Two-person control** - a referee cannot change a score alone.
* **Verifiable** - every invariant is an endpoint, not a claim.
""".strip()


def create_app(settings: Settings | None = None, *, database_path=None, seed: bool | None = None) -> FastAPI:
    settings = settings or get_settings()
    app = FastAPI(
        title=settings.app_name,
        version=settings.version,
        description=DESCRIPTION,
        docs_url="/docs",
        redoc_url=None,
    )
    app.state.settings = settings

    @contextlib.asynccontextmanager
    async def lifespan(app: FastAPI):
        db = init_db(database_path or settings.database_path)
        service: ScoreboardService = init_service(db, settings)
        app.state.db = db
        app.state.service = service

        should_seed = settings.seed_on_startup if seed is None else seed
        if should_seed and db.is_empty():
            summary = seed_all(service, teams=settings.seed_teams, challenges=settings.seed_challenges)
            log.info("seeded demo event: %s", summary)

        hub = StreamHub(service, replay_size=settings.sse_replay_buffer, heartbeat=settings.sse_heartbeat_seconds)
        hub.bind_loop(__import__("asyncio").get_running_loop())
        service._hub = hub
        app.state.hub = hub

        simulator = Simulator(service, rate_per_second=settings.seed_solve_rate_per_second)
        if settings.simulator_enabled:
            simulator.start()
        app.state.simulator = simulator
        log.info("%s %s ready (event data in %s)", settings.app_name, settings.version, settings.database_path)
        try:
            yield
        finally:
            await simulator.stop()
            db.close()

    app.router.lifespan_context = lifespan

    app.include_router(public.router)
    app.include_router(admin.router)
    app.include_router(ingest.router)

    @app.exception_handler(ServiceError)
    async def service_error_handler(request: Request, exc: ServiceError) -> JSONResponse:
        return JSONResponse(status_code=exc.status, content=exc.to_dict())

    @app.get("/", include_in_schema=False)
    async def index() -> FileResponse:
        return FileResponse(WEB_DIR / "index.html")

    @app.get("/favicon.svg", include_in_schema=False)
    async def favicon() -> FileResponse:
        return FileResponse(WEB_DIR / "favicon.svg", media_type="image/svg+xml")

    if WEB_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(WEB_DIR)), name="static")

    return app


app = create_app()
