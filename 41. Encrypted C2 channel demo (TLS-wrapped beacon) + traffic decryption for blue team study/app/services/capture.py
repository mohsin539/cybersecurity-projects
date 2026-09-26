import json

from app.core.security import dumps
from app.db import execute, now_iso


def record_traffic(
    session_uuid: str,
    event: str,
    src_ip: str = "10.0.0.1",
    dst_ip: str = "10.0.30.10",
    src_port: int = 0,
    dst_port: int = 443,
    record_len: int = 0,
    meta: dict = None,
    ciphertext: str = None,
    plaintext: str = None,
    ts: str = None,
):
    execute(
        "INSERT INTO traffic (session_uuid, ts, event, src_ip, dst_ip, src_port, dst_port, record_len, meta, ciphertext, plaintext, decrypted) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            session_uuid,
            ts or now_iso(),
            event,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            int(record_len),
            dumps(meta or {}),
            ciphertext,
            plaintext,
            1 if plaintext is not None else 0,
        ),
    )