"""Immutable (WORM-style) audit trail with SHA-256 hash chaining.

Every state change emits an event. Events are append-only; the API exposes
no update/delete path. `hash` of each row = SHA256(prev_hash + canonical payload),
so any tampering breaks the chain and is detectable by the verifier.

Maps ISO 27001 A.8.15/A.8.16, NIST AU-2..AU-12, OWASP A09.
"""

import hashlib
import hmac
import json
import time

from .db import get_db

ACTIONS = (
    "LOGIN", "LOGOUT", "LOGIN_FAILED", "BOOTSTRAP",
    "CASE_CREATE", "CASE_UPDATE", "CASE_DELETE", "CASE_CLOSE",
    "EVIDENCE_CREATE", "EVIDENCE_UPDATE", "EVIDENCE_DELETE",
    "CUSTODY_EVENT", "ARTIFACT_CREATE", "ARTIFACT_UPDATE", "ARTIFACT_DELETE",
    "REPORT_ORDERED", "REPORT_DOWNLOADED", "AUDIT_EXPORT", "COMPLIANCE_VIEW",
    "USER_CREATE", "USER_UPDATE", "SETTINGS_UPDATE",
)

def _canonical(obj):
    """Deterministic canonical JSON for hashing."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _chain_hash(prev_hash, canonical_payload: str, secret: bytes) -> str:
    digest = hashlib.sha256()
    digest.update(prev_hash.encode())
    digest.update(b"|")
    digest.update(canonical_payload.encode())
    digest.update(b"|")
    digest.update(secret)
    return digest.hexdigest()


def init_audit(app):
    # Per-install random secret persisted in settings so the chain survives restarts.
    from .db import get_db
    with app.app_context():
        db = get_db()
        row = db.execute("SELECT value FROM settings WHERE key='audit_secret'").fetchone()
        if not row:
            secret = hmac.new(b"mfl", hashlib.sha256(str(app.secret_key).encode()).hexdigest().encode(),
                              hashlib.sha256).hexdigest()
            db.execute("INSERT OR IGNORE INTO settings(key,value) VALUES('audit_secret',?)", (secret,))
            db.commit()


def get_secret(app):
    db = get_db()
    row = db.execute("SELECT value FROM settings WHERE key='audit_secret'").fetchone()
    return (row["value"] if row else "seed").encode()


def audit(app, actor_id, actor_role, action, subject_type, subject_id, context, severity="info"):
    if action not in ACTIONS:
        raise ValueError("unregistered audit action")
    db = get_db()
    prev = db.execute(
        "SELECT hash FROM audit_events ORDER BY id DESC LIMIT 1"
    ).fetchone()
    prev_hash = prev["hash"] if prev else "0" * 64

    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    payload = _canonical({
        "ts": ts,
        "actor_id": actor_id,
        "actor_role": actor_role,
        "action": action,
        "subject_type": subject_type,
        "subject_id": subject_id,
        "context": context or {},
        "severity": severity,
    })
    chain = _chain_hash(prev_hash, payload, get_secret(app))
    db.execute(
        "INSERT INTO audit_events(ts,actor_id,actor_role,action,subject_type,subject_id,context,severity,prev_hash,hash)"
        " VALUES(?,?,?,?,?,?,?,?,?,?)",
        (ts, str(actor_id), actor_role, action, subject_type, str(subject_id) if subject_id is not None else None,
         payload, severity, prev_hash, chain),
    )
    db.commit()


def verify_chain(app):
    """Recompute the hash chain and report any broken link (AU-10 verification).

    `context` stores the canonical payload used at insert time, so each row can
    be recomputed exactly. Any mismatch (tamper, silent corruption) is reported.
    """
    db = get_db()
    rows = db.execute(
        "SELECT id, prev_hash, hash, context FROM audit_events ORDER BY id ASC"
    ).fetchall()
    secret = get_secret(app)
    prev = "0" * 64
    broken = []
    checked = 0
    for r in rows:
        if r["prev_hash"] != prev:
            broken.append({"id": r["id"], "reason": "prev-mismatch"})
            break
        recomputed = _chain_hash(prev, r["context"], secret)
        if recomputed != r["hash"]:
            broken.append({"id": r["id"], "reason": "hash-tamper"})
            break
        prev = recomputed
        checked += 1
    return {"checked": checked, "total": len(rows), "intact": not broken, "issues": broken}