from app.core.crypto import aes_decrypt
from app.db import execute, query_all, query_one


def escrow_key(session_uuid: str, key_type: str, label: str, key_value: str) -> int:
    from app.db import now_iso

    return execute(
        "INSERT INTO keys (session_uuid, key_type, label, key_value, created_at, status) VALUES (?,?,?,?,?,?)",
        (session_uuid, key_type, label, key_value, now_iso(), "escrow"),
    )


def active_key(session_uuid: str, key_type: str = "session_aes"):
    return query_one(
        "SELECT * FROM keys WHERE session_uuid=? AND key_type=? AND status='escrow' "
        "ORDER BY id DESC LIMIT 1",
        (session_uuid, key_type),
    )


def list_keys(session_uuid: str = None) -> list:
    if session_uuid:
        return query_all("SELECT * FROM keys WHERE session_uuid=? ORDER BY id", (session_uuid,))
    return query_all("SELECT * FROM keys ORDER BY id DESC")


def decrypt_record(record_id: int) -> dict:
    rec = query_one("SELECT * FROM traffic WHERE id=?", (record_id,))
    if not rec or rec["ciphertext"] is None:
        return {"ok": False, "reason": "no ciphertext on record"}
    key_row = active_key(rec["session_uuid"])
    if not key_row:
        return {"ok": False, "reason": "no escrowed key available"}
    try:
        plain = aes_decrypt(bytes.fromhex(key_row["key_value"]), rec["ciphertext"]).decode(
            errors="replace"
        )
    except Exception as exc:
        return {"ok": False, "reason": f"decrypt failed: {exc}"}
    execute(
        "UPDATE traffic SET plaintext=?, decrypted=1 WHERE id=?",
        (plain, record_id),
    )
    return {"ok": True, "plaintext": plain}


def decrypt_session(session_uuid: str) -> dict:
    recs = query_all("SELECT id FROM traffic WHERE session_uuid=? AND ciphertext IS NOT NULL", (session_uuid,))
    ok = fail = 0
    for r in recs:
        res = decrypt_record(r["id"])
        if res["ok"]:
            ok += 1
        else:
            fail += 1
    return {"session_uuid": session_uuid, "decrypted": ok, "failed": fail, "total": ok + fail}


def mark_decrypted(session_uuid: str, plaintext: str, ciphertext: str, key_id: str):
    execute(
        "UPDATE traffic SET plaintext=?, decrypted=1, key_id=? WHERE session_uuid=? AND ciphertext=? AND rowid=(SELECT MAX(rowid) FROM traffic WHERE session_uuid=? AND ciphertext=?)",
        (plaintext, key_id, session_uuid, ciphertext, session_uuid, ciphertext),
    )