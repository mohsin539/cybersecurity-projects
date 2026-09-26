from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Optional

import uvicorn
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

from .engine import Simulator
from .security import SecurityManager
from .state_store import PersistentStore

GUI_DIR = Path(__file__).resolve().parent / "gui"

ALLOWED_POLICIES = {"ROUND_ROBIN", "WEIGHTED_ROUND_ROBIN", "LEAST_CONNECTIONS",
                    "LEAST_RESPONSE_TIME", "POWER_OF_TWO_CHOICES", "RANDOM",
                    "IP_HASH", "CONSISTENT_HASH"}
ALLOWED_ARRIVAL = {"POISSON", "CONSTANT", "MMPP"}
ALLOWED_FAILURE = {"NONE", "CRASH", "LAG", "SLOW_CPU", "PROBE_NO_TOKEN", "FLAP"}
ALLOWED_LATENCY = {"FIXED", "EXP", "NORMAL", "PARETO"}


class RunStart(BaseModel):
    seed: Optional[int] = Field(default=None, ge=0)
    rps: Optional[float] = Field(default=None, ge=0)
    speed: Optional[float] = Field(default=None, ge=0.1, le=2000)
    policy: Optional[str] = None
    arrival_model: Optional[str] = None
    backends: Optional[list] = None

    @field_validator("policy")
    @classmethod
    def _policy(cls, v):
        if v is not None and v not in ALLOWED_POLICIES:
            raise ValueError(f"unsupported policy {v}")
        return v

    @field_validator("arrival_model")
    @classmethod
    def _arrival(cls, v):
        if v is not None and v not in ALLOWED_ARRIVAL:
            raise ValueError(f"unsupported arrival_model {v}")
        return v


class RunUpdate(BaseModel):
    rps: Optional[float] = Field(default=None, ge=0)
    speed: Optional[float] = Field(default=None, ge=0.1, le=2000)
    policy: Optional[str] = None
    arrival_model: Optional[str] = None

    @field_validator("policy")
    @classmethod
    def _policy(cls, v):
        if v is not None and v not in ALLOWED_POLICIES:
            raise ValueError(f"unsupported policy {v}")
        return v

    @field_validator("arrival_model")
    @classmethod
    def _arrival(cls, v):
        if v is not None and v not in ALLOWED_ARRIVAL:
            raise ValueError(f"unsupported arrival_model {v}")
        return v


class BackendCreate(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    weight: int = Field(default=100, ge=1, le=10000)
    capacity: int = Field(default=1000, ge=1, le=100000)
    latency_base_ms: int = Field(default=40, ge=1, le=60000)
    latency_model: str = "EXP"
    severity_error_p: float = Field(default=0.005, ge=0, le=1)

    @field_validator("latency_model")
    @classmethod
    def _lat(cls, v):
        if v not in ALLOWED_LATENCY:
            raise ValueError(f"unsupported latency_model {v}")
        return v

    @field_validator("name")
    @classmethod
    def _name(cls, v):
        for ch in v:
            if not (ch.isalnum() or ch in "-_"):
                raise ValueError("name must be alphanumeric, '-' or '_'")
        return v


class FailureIn(BaseModel):
    profile: str
    until: Optional[float] = Field(default=None, ge=0)

    @field_validator("profile")
    @classmethod
    def _prof(cls, v):
        if v not in ALLOWED_FAILURE:
            raise ValueError(f"unsupported failure_profile {v}")
        return v


class NotesIn(BaseModel):
    text: str = Field(max_length=4000)


def build_app(sim: Optional[Simulator] = None) -> FastAPI:
    store_root = os.environ.get("AEGIS_STORE_ROOT", str(Path(__file__).resolve().parent.parent))
    if sim is None:
        sim = Simulator(store_root=store_root)
    store = sim._store
    if store is None:
        store = PersistentStore(store_root)
        sim._store = store

    mgr = SecurityManager(emit=lambda etype, payload, sev: sim._emit(etype, payload, sev))
    store.attach_security_manager(mgr)

    app = FastAPI(
        title="AegisLB Load Balancer Simulator",
        version="1.0.0",
        docs_url=None,
        redoc_url=None,
        openapi_url="/api/v1/openapi.json",
    )

    async def rate_guard(request: Request):
        client = request.client.host if request.client else "unknown"
        if not mgr.rate_allow(client):
            raise HTTPException(status_code=429, detail="rate_limited")
        return client

    def require_role(role: str):
        async def dep(x_aegis_key: Optional[str] = Header(default=None), request: Request = None):
            ok, reason = mgr.authorize(x_aegis_key, role, request.method, request.url.path)
            if not ok:
                raise HTTPException(status_code=403, detail=reason)
            return role
        return dep

    @app.get("/")
    async def index():
        return FileResponse(GUI_DIR / "index.html")

    app.mount("/static", StaticFiles(directory=str(GUI_DIR)), name="static")

    @app.get("/healthz")
    async def healthz():
        return {"status": "ok"}

    @app.get("/readyz")
    async def readyz():
        ready = sim.running or sim.started
        return {"ok": ready, "running": sim.running}

    @app.get("/api/v1/snapshot", dependencies=[Depends(rate_guard)])
    async def snapshot():
        return sim.snapshot()

    @app.get("/api/v1/metrics", dependencies=[Depends(rate_guard)])
    async def metrics():
        snap = sim.snapshot()
        return {"metrics": snap["metrics"], "run": snap["run"]}

    @app.get("/api/v1/manifest", dependencies=[Depends(rate_guard)])
    async def manifest():
        snap = sim.snapshot()
        return {"manifest": snap["manifest"], "run": snap["run"]}

    @app.get("/api/v1/events", dependencies=[Depends(rate_guard)])
    async def events(cursor: int = 0):
        evs, tail = sim.events_after(cursor)
        return {"events": evs[-500:], "tail": tail}

    @app.get("/api/v1/events/stream", dependencies=[Depends(rate_guard)])
    async def event_stream(cursor: int = 0, request: Request = None):
        async def gen():
            cur = cursor
            while True:
                if await request.is_disconnected():
                    break
                evs, _ = sim.events_after(cur)
                for ev in evs:
                    yield f"data: {json.dumps(ev)}\n\n"
                    cur = ev["id"]
                if not evs:
                    yield ": keepalive\n\n"
                await asyncio.sleep(0.2)
        return StreamingResponse(gen(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache",
                                          "X-Accel-Buffering": "no"})

    @app.post("/api/v1/runs/start", dependencies=[Depends(require_role("config"))])
    async def run_start(body: RunStart):
        manifest = {}
        if body.seed is not None:
            manifest["seed"] = body.seed
        if body.rps is not None:
            manifest["rps"] = body.rps
        if body.speed is not None:
            manifest["speed"] = body.speed
        if body.policy is not None:
            manifest["policy"] = body.policy
        if body.arrival_model is not None:
            manifest["arrival_model"] = body.arrival_model
        if body.backends is not None:
            manifest["backends"] = body.backends
        res = sim.start(manifest)
        if not res.get("ok"):
            raise HTTPException(status_code=409, detail=res.get("error"))
        return res

    @app.post("/api/v1/runs/stop", dependencies=[Depends(require_role("config"))])
    async def run_stop():
        return sim.stop()

    @app.post("/api/v1/runs/pause", dependencies=[Depends(require_role("config"))])
    async def run_pause(body: dict):
        paused = bool(body.get("paused", True))
        return sim.set_paused(paused)

    @app.patch("/api/v1/run", dependencies=[Depends(require_role("config"))])
    async def run_update(body: RunUpdate):
        res = sim.set_run(rps=body.rps, speed=body.speed, policy=body.policy,
                          arrival_model=body.arrival_model)
        return res

    @app.post("/api/v1/backends", dependencies=[Depends(require_role("config"))])
    async def backend_create(body: BackendCreate):
        return sim.add_backend(name=body.name, weight=body.weight, capacity=body.capacity,
                               latency_base_ms=body.latency_base_ms,
                               latency_model=body.latency_model,
                               severity_error_p=body.severity_error_p)

    @app.delete("/api/v1/backends/{backend_id}", dependencies=[Depends(require_role("ops"))])
    async def backend_remove(backend_id: str):
        res = sim.remove_backend(backend_id)
        if not res.get("ok"):
            raise HTTPException(status_code=404, detail=res.get("error"))
        return res

    @app.post("/api/v1/backends/{backend_id}/failures", dependencies=[Depends(require_role("config"))])
    async def backend_failure(backend_id: str, body: FailureIn):
        res = sim.set_failure(backend_id, body.profile, body.until)
        if not res.get("ok"):
            raise HTTPException(status_code=404, detail=res.get("error"))
        return res

    @app.post("/api/v1/backends/{backend_id}/drain", dependencies=[Depends(require_role("ops"))])
    async def backend_drain(backend_id: str):
        res = sim.drain(backend_id)
        if not res.get("ok"):
            raise HTTPException(status_code=404, detail=res.get("error"))
        return res

    @app.post("/api/v1/backends/{backend_id}/cancel-drain", dependencies=[Depends(require_role("ops"))])
    async def backend_cancel_drain(backend_id: str):
        res = sim.cancel_drain(backend_id)
        if not res.get("ok"):
            raise HTTPException(status_code=404, detail=res.get("error"))
        return res

    @app.post("/api/v1/backends/{backend_id}/rearm", dependencies=[Depends(require_role("ops"))])
    async def backend_rearm(backend_id: str):
        res = sim.rearm(backend_id)
        if not res.get("ok"):
            raise HTTPException(status_code=404, detail=res.get("error"))
        return res

    @app.get("/api/v1/audit", dependencies=[Depends(require_role("auditor"))])
    async def audit(limit: int = 50):
        limit = max(1, min(limit, 500))
        return {"audit": mgr.audit_tail(limit), "chain_tail": mgr._chain_tail,
                "count": len(mgr.audit)}

    @app.get("/api/v1/security/status", dependencies=[Depends(rate_guard)])
    async def security_status():
        return mgr.status()

    @app.post("/api/v1/memory/notes", dependencies=[Depends(require_role("config"))])
    async def set_notes(body: NotesIn):
        store.set_notes(body.text)
        sim._emit("NOTE_SAVED", {"actor": "config", "len": len(body.text)}, "info")
        return {"ok": True}

    @app.get("/api/v1/memory/notes", dependencies=[Depends(rate_guard)])
    async def get_notes():
        return {"notes": store.notes}

    @app.exception_handler(HTTPException)
    async def _http_exc_handler(request: Request, exc: HTTPException):
        return JSONResponse(status_code=exc.status_code,
                            content={"error": exc.detail, "schema": "aegis-err-v1"})

    app.state.sim = sim
    app.state.mgr = mgr
    return app


def run_server(sim: Optional[Simulator] = None, host: str = "127.0.0.1",
               port: int = 8000, autostart: bool = True) -> None:
    if sim is not None and autostart and not sim.running and not sim.started:
        sim.start({})
    app = build_app(sim)
    if host not in ("127.0.0.1", "localhost", "::1"):
        print("[!] WARNING: binding to a non-loopback interface exposes the admin API. "
              "Requires X-Aegis-Key on every write and is intended for hardened lab use only.")
    uvicorn.run(app, host=host, port=port, log_level="info")