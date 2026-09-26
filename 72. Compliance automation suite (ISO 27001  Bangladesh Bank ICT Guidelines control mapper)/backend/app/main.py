"""Compliance Automation Suite — FastAPI application entrypoint."""
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from .database import Base, engine
from .routers import assets, assessments, audit, auth, controls, dashboard, evidence, reports, risk


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    from .seed import seed
    seed(force=False)
    yield


app = FastAPI(
    title="Compliance Automation Suite",
    version="1.0.0",
    description="ISO 27001 • Bangladesh Bank ICT Guidelines • NIST CSF • OWASP Top 10 control mapper & GRC reporting platform",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

for r in (auth, dashboard, controls, assets, assessments, evidence, risk, reports, audit):
    app.include_router(r.router)


@app.get("/health")
def health():
    return {"status": "ok", "service": "compliance-automation-suite", "version": "1.0.0"}


STATIC_DIR = Path(__file__).resolve().parent / "static"
app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")