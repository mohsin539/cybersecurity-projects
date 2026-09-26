from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from app.core import security as sec
from app.core.security import client_ip
from app.db import query_all, query_one
from app.services import decryption
from app.services.detection import compute_risk, list_alerts, list_rules, set_alert_status, stats, toggle_rule

router = APIRouter(prefix="/api/blue", tags=["blue"])


class RuleToggle(BaseModel):
    rule_id: str
    enabled: bool


class AlertAction(BaseModel):
    alert_id: int
    status: str


@router.get("/stats")
def get_stats():
    return stats()


@router.get("/traffic")
def traffic():
    rows = query_all(
        "SELECT t.*, s.agent_name FROM traffic t LEFT JOIN sessions s ON t.session_uuid=s.uuid ORDER BY t.id DESC LIMIT 500"
    )
    return rows


@router.post("/decrypt/session")
def decrypt_session(session_uuid: str, request: Request):
    if not query_one("SELECT 1 AS ok FROM sessions WHERE uuid=?", (session_uuid,)):
        raise HTTPException(404, "session not found")
    res = decryption.decrypt_session(session_uuid)
    sec.audit("BLUE", "decrypt_session", "D", f"{session_uuid} -> {res['decrypted']} ok", client_ip(request))
    return res


@router.post("/decrypt/record")
def decrypt_one(record_id: int, request: Request):
    res = decryption.decrypt_record(record_id)
    sec.audit("BLUE", "decrypt_record", "D", f"record {record_id} -> {res.get('ok')}", client_ip(request))
    return res


@router.get("/rules")
def rules():
    return list_rules()


@router.post("/rules")
def set_rule(body: RuleToggle, request: Request):
    toggle_rule(body.rule_id, body.enabled)
    sec.audit("BLUE", f"rule:{'on' if body.enabled else 'off'}", "D", body.rule_id, client_ip(request))
    return {"ok": True}


@router.get("/alerts")
def alerts():
    return list_alerts()


@router.post("/alerts/action")
def alert_action(body: AlertAction, request: Request):
    set_alert_status(body.alert_id, body.status)
    sec.audit("BLUE", f"alert:{body.status}", "D", f"alert {body.alert_id}", client_ip(request))
    return {"ok": True}


@router.get("/keys")
def keys():
    return query_all("SELECT * FROM keys ORDER BY id DESC")

def _risk(uuid: str):
    return compute_risk(uuid)