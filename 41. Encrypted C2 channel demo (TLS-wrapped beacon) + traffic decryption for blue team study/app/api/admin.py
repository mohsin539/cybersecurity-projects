from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from app.core import security as sec
from app.core.security import client_ip, ensure_lab_certs, tls_policy
from app.db import query_all
from app.services import decryption
from app.services.detection import stats
from app.services.reporting import COMPLIANCE_MATRIX

router = APIRouter(prefix="/api/admin", tags=["admin"])


class RotateIn(BaseModel):
    session_uuid: str


@router.get("/hello")
def hello(request: Request):
    return {
        "app": "C2 Deconfliction Lab",
        "version": "1.0.0",
        "lab_mode": True,
        "token": sec.ensure_admin_token(),
        "host": "authorized-lab-only",
    }


@router.get("/audit")
def audit():
    return query_all("SELECT * FROM audit_log ORDER BY id DESC LIMIT 300")


@router.get("/keys")
def keys():
    return query_all("SELECT * FROM keys ORDER BY id DESC LIMIT 200")


@router.post("/keys/rotate")
def rotate(body: RotateIn, request: Request):
    if not query_one0(body.session_uuid):
        raise HTTPException(404, "session not found")
    sec.rotate_session_keys(body.session_uuid)
    sec.audit("ADMIN", "rotate_keys", "C", body.session_uuid, client_ip(request))
    return {"ok": True}


@router.get("/tls")
def tls():
    cert, key = ensure_lab_certs()
    return {"policy": tls_policy(), "cert": str(cert), "key": str(key)}


@router.get("/compliance")
def compliance():
    return {"matrix": COMPLIANCE_MATRIX, "stats": stats()}


def query_one0(uuid: str):
    from app.db import query_one
    return query_one("SELECT 1 AS ok FROM sessions WHERE uuid=?", (uuid,))