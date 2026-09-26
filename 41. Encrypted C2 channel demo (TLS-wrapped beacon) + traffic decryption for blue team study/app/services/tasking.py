import secrets

from app.core.crypto import aes_decrypt, aes_encrypt
from app.db import execute, now_iso, query_all, query_one


def create_task(session_uuid: str, command: str) -> dict:
    task_id = "T-" + secrets.token_hex(4).upper()
    execute(
        "INSERT INTO tasks (task_id, session_uuid, command, status, created_at) VALUES (?,?,?,?,?)",
        (task_id, session_uuid, command, "queued", now_iso()),
    )
    return {"task_id": task_id, "command": command, "status": "queued"}


def list_tasks(session_uuid: str = None) -> list:
    if session_uuid:
        return query_all(
            "SELECT * FROM tasks WHERE session_uuid=? ORDER BY id DESC", (session_uuid,)
        )
    return query_all("SELECT * FROM tasks ORDER BY id DESC")


def pending_for(session_uuid: str, key: bytes) -> list:
    rows = query_all(
        "SELECT task_id, command FROM tasks WHERE session_uuid=? AND status='queued'",
        (session_uuid,),
    )
    out = []
    for r in rows:
        token = aes_encrypt(key, r["command"].encode())
        out.append({"task_id": r["task_id"], "payload": token})
        execute(
            "UPDATE tasks SET status='sent', issued_at=? WHERE task_id=?",
            (now_iso(), r["task_id"]),
        )
    return out


def accept_result(task_id: str, session_uuid: str, key: bytes, ciphertext: str) -> dict:
    try:
        raw = aes_decrypt(key, ciphertext)
        plaintext = raw.decode(errors="replace")
    except Exception:
        plaintext = "<decryption failed: key mismatch>"
    execute(
        """
        UPDATE tasks SET status='executed', result_at=?, result_data=?, result_size=?
        WHERE task_id=? AND session_uuid=?
        """,
        (now_iso(), plaintext, len(raw), task_id, session_uuid),
    )
    return {"task_id": task_id, "status": "executed", "result": plaintext, "size": len(raw)}


def task_by_id(task_id: str) -> dict:
    return query_one("SELECT * FROM tasks WHERE task_id = ?", (task_id,))