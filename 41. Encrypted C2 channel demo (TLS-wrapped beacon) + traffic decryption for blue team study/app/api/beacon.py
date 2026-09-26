import random
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from app.config import TLS_CIPHER
from app.core import security as sec
from app.core.crypto import new_aes_key, random_hex
from app.core.security import client_ip, derive_tls_identity, new_uuid
from app.db import execute, now_iso, query_one
from app.services import tasking
from app.services.capture import record_traffic
from app.services.decryption import active_key, escrow_key
from app.services.detection import run_rules

router = APIRouter(prefix="/api/v1/beacon", tags=["beacon"])


class RegisterIn(BaseModel):
    agent_name: str = "lab-agent"
    hw_id: str = ""
    ip: str = "10.0.0.1"
    os: str = "unknown"
    beacon_interval: float = 45.0
    jitter: float = 0.15
    sni: str = "orders-storage.example.net"
    tls_version: str = "TLSv1.3"
    auth_method: str = "mtls"


class PingIn(BaseModel):
    nonce: str = ""


class ResultIn(BaseModel):
    task_id: str
    payload: str


class RegisterOut(BaseModel):
    uuid: str
    status: str
    beacon_interval: float
    jitter: float
    server_nonce: str
    cipher: str
    key_escrow_hex: str


@router.post("/register", response_model=RegisterOut)
def register(body: RegisterIn, request: Request):
    existing = query_one(
        "SELECT * FROM sessions WHERE agent_name=? AND status NOT IN ('dead','flagged')",
        (body.agent_name,),
    )
    if existing:
        k = active_key(existing["uuid"])
        return RegisterOut(
            uuid=existing["uuid"],
            status="resumed",
            beacon_interval=existing["beacon_interval"],
            jitter=existing["jitter"],
            server_nonce="resumed",
            cipher=existing["cipher"],
            key_escrow_hex=k["key_value"] if k else "",
        )

    uuid = new_uuid()
    session_key_hex = new_aes_key().hex()
    ident = derive_tls_identity(uuid)
    execute(
        "INSERT INTO sessions (uuid, agent_name, hw_id, ip, os, status, first_seen, last_seen, "
        "beacon_interval, jitter, ja3, ja3s, sni, tls_version, cipher, auth_method, risk_score, kill_switch, notes) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0,0,?)",
        (
            uuid, body.agent_name, body.hw_id, body.ip, body.os, "active", now_iso(), now_iso(),
            body.beacon_interval, body.jitter, ident["ja3"], ident["ja3s"], body.sni,
            body.tls_version, TLS_CIPHER, body.auth_method, "escrow-backed mTLS demo session",
        ),
    )
    escrow_key(uuid, "session_aes", "AES-256-GCM inner-layer escrow", session_key_hex)
    escrow_key(uuid, "sslkeylog", "simulated TLS (pre)-master capture", random_hex(32))
    record_traffic(
        uuid, "client_hello", src_ip=body.ip, dst_ip="10.0.30.10", dst_port=443,
        record_len=_rl(), meta={"ja3": ident["ja3"], "sni": body.sni, "tls_version": body.tls_version},
    )
    record_traffic(
        uuid, "server_hello", src_ip="10.0.30.10", dst_ip=body.ip, src_port=443, dst_port=0,
        record_len=_rl(), meta={"ja3s": ident["ja3s"], "cipher": TLS_CIPHER},
    )
    record_traffic(uuid, "register", src_ip=body.ip, dst_ip="10.0.30.10", dst_port=443, record_len=_rl(), meta={"tls_version": body.tls_version})
    sec.audit("BEACON", "register", "A", f"{body.agent_name} registered via {body.auth_method}", client_ip(request))
    return RegisterOut(
        uuid=uuid, status="active", beacon_interval=body.beacon_interval, jitter=body.jitter,
        server_nonce="N-" + uuid[:8], cipher=TLS_CIPHER, key_escrow_hex=session_key_hex,
    )


@router.post("/ping")
def ping(uuid: str, request: Request):
    if not query_one("SELECT 1 AS ok FROM sessions WHERE uuid=?", (uuid,)):
        raise HTTPException(404, "session not found")
    execute("UPDATE sessions SET last_seen=? WHERE uuid=?", (now_iso(), uuid))
    record_traffic(uuid, "ping", dst_port=443, record_len=_rl(), meta={"nonce": "p"})
    return {"pong": True, "server_time": _st()}


@router.get("/tasks/{uuid}")
def tasks(uuid: str, request: Request):
    k = _need(uuid)
    key = bytes.fromhex(k["key_value"])
    out = tasking.pending_for(uuid, key)
    record_traffic(uuid, "task", dst_port=443, record_len=_rl(), meta={"tasks": len(out)})
    return {"tasks": out, "server_time": _st()}


@router.post("/result")
def result(uuid: str, body: ResultIn, request: Request):
    k = _need(uuid)
    key = bytes.fromhex(k["key_value"])
    ack = tasking.accept_result(body.task_id, uuid, key, body.payload)
    record_traffic(
        uuid, "result", dst_port=443, record_len=len(body.payload) if body.payload else 0,
        ciphertext=body.payload, plaintext=ack["result"],
    )
    run_rules(uuid)
    return {"ack": True, "task": ack["task_id"], "server_time": _st()}


def _need(uuid: str):
    s = query_one("SELECT * FROM sessions WHERE uuid=?", (uuid,))
    if not s:
        raise HTTPException(404, "session not found")
    if s["kill_switch"]:
        raise HTTPException(403, "kill switch engaged")
    k = active_key(uuid)
    if not k:
        raise HTTPException(410, "no escrowed key")
    return k


def _rl():
    return random.randint(64, 512)


def _st():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")