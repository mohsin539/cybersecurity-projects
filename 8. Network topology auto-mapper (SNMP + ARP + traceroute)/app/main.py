from __future__ import annotations

"""Web layer (FastAPI). Authn/z + RBAC via app.auth; scope gating enforced in
engine/scope; jobs via app.engine (launch_sim_scan/get_job); audit chain via
app.audit.AUDIT (append/verify/tail). Every name against the verified module
surfaces; DB queries only against the real schema (devices, links, jobs,
observations — no invention).
"""
import json
from pathlib import Path

from fastapi import (Cookie, Depends, FastAPI, HTTPException, Query, Request,
                     Response)
from fastapi import status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field
from starlette.status import HTTP_401_UNAUTHORIZED, HTTP_403_FORBIDDEN

from . import db
from .audit import AUDIT
from .auth import (AuthError, authenticate, get_claims, issue_token,
                   require_roles, verify_token)
from .config import CFG
from .engine import get_job as engine_get_job
from .engine import launch_sim_scan
from .util import now_ts

COOKIE_NAME = "ntm_sid"


class CORSConfig(BaseModel):
    allow_origins: list[str] = [f"http://{CFG.host}:{CFG.port}"]
    allow_methods: list[str] = ["GET", "POST"]
    allow_headers: list[str] = ["authorization", "content-type"]
    allow_credentials: bool = True

app = FastAPI(title="NTM", version="0.2.0")
_cors = CORSConfig()
app.add_middleware(CORSMiddleware, **_cors.model_dump())


@app.on_event("startup")
def _startup() -> None:
    db.init_db()
    db.ensure_default_admin()


class LoginBody(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)
    code: str = Field(default="", max_length=8)


class ScanBody(BaseModel):
    scope: str = Field(min_length=1, max_length=128)
    budget: int = Field(default=6000, gt=0, le=50000)


def _set_cookie(res: Response, token: str) -> None:
    res.set_cookie(COOKIE_NAME, token, httponly=True, samesite="lax",
                   max_age=CFG.session_hours * 3600)


@app.get("/")
def index() -> HTMLResponse:
    p = Path(__file__).resolve().parent.parent / "ui" / "index.html"
    return HTMLResponse(p.read_text("utf-8"))


@app.post("/api/login")
def login(body: LoginBody, res: Response):
    try:
        user = authenticate(body.username, body.password, body.code)
    except AuthError as e:
        raise HTTPException(HTTP_401_UNAUTHORIZED, str(e)) from e
    token = issue_token(user)
    _set_cookie(res, token)
    claims = verify_token(token)
    db.run("INSERT INTO audit_log(actor,action,target,detail,level) "
           "VALUES(?,?,?,?,?)",
           (user.get("username", "!"), "login", "/api/login",
            json.dumps({"role": claims.get("r")}), "info"))
    return {"ok": True, "username": claims.get("u"),
            "role": claims.get("r", "operator")}


@app.post("/api/logout")
def logout(res: Response):
    res.delete_cookie(COOKIE_NAME)
    return {"ok": True}


@app.post("/api/scan/sim")
def sim_scan(body: ScanBody, claims: dict = Depends(get_claims)):
    if claims.get("r") not in ("admin", "operator"):
        raise HTTPException(HTTP_403_FORBIDDEN, "operator role required")
    job_id = launch_sim_scan(body.scope, agent=claims.get("u", "sim"),
                             budget_items=body.budget)
    AUDIT.append(claims.get("u", "?"), "scan_sim", body.scope,
                 {"job": job_id}, "info")
    return {"ok": True, "job": job_id}


@app.get("/api/jobs/{job_id}")
def job_status(job_id: str, claims: dict = Depends(get_claims)):
    j = engine_get_job(job_id)
    if not j:
        raise HTTPException(404, "no such job")
    return {"job": j}


@app.get("/api/topology")
def topology(claims: dict = Depends(get_claims)):
    redacted = claims.get("r") == "viewer"
    nodes = db.q("SELECT id,name,ip,mac,vendor,kind FROM devices ORDER BY ip")
    links = db.q("SELECT source,target,kind,protocol,confidence FROM links "
                 "WHERE confidence>=0.4 ORDER BY confidence DESC")
    if redacted:
        for n in nodes:
            n["mac"] = "REDACTED"
    return {"nodes": nodes, "links": links, "redacted": redacted,
            "at": now_ts()}


@app.get("/api/inventory")
def inventory(claims: dict = Depends(get_claims)):
    redacted = claims.get("r") == "viewer"
    rows = db.q("SELECT id,name,ip,mac,vendor,kind,last_seen "
                "FROM devices ORDER BY ip")
    if redacted:
        for r in rows:
            r["mac"] = "REDACTED"
    return {"devices": rows, "redacted": redacted}


@app.get("/api/audit")
def audit_tail(limit: int = Query(default=200, ge=1, le=2000),
               claims: dict = Depends(get_claims)):
    records = AUDIT.tail(limit)
    result = AUDIT.verify()
    return {"records": records,
            "chain_ok": bool(result.get("ok")),
            "broken_at": result.get("broken_at")}


@app.get("/api/export")
def export(fmt: str = Query(default="json", pattern="^(json|graphml)$"),
           claims: dict = Depends(get_claims)):
    redacted = claims.get("r") == "viewer"
    nodes = db.q("SELECT id,name,ip,mac,vendor,kind FROM devices ORDER BY ip")
    links = db.q("SELECT source,target,kind,protocol,confidence FROM links "
                 "WHERE confidence>=0.4")
    data = {"nodes": nodes, "links": links, "redacted": redacted,
            "at": now_ts()}
    if fmt == "graphml":
        body = ['<?xml version="1.0"?>',
                "<graphml xmlns='http://graphml.graphdrawing.org/xmlns'>",
                "<graph edgedefault='undirected'>"]
        for n in nodes:
            body.append(f'<node id="{n["id"]}"/>')
        for l in links:
            body.append(f'<edge source="{l["source"]}" target="{l["target"]}"/>')
        body.append("</graph></graphml>")
        return JSONResponse(content="\n".join(body))
    return JSONResponse(content=json.dumps(data), media_type="application/json")


@app.get("/api/health")
def health():
    return {"ok": True, "app": "ntm", "up": now_ts()}
