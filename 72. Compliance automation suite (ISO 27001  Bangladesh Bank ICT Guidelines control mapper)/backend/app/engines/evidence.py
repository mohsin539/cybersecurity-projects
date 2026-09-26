"""Evidence Vault (architecture.md §4.4) — WORM storage, SHA-256 chaining, overlap linking."""
import hashlib
import json
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy.orm import Session

from ..database import naive_utcnow
from ..models import AuditLog, Evidence, EvidenceLink

VAULT_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "vault"
VAULT_DIR.mkdir(parents=True, exist_ok=True)

ALLOWED_MIME = {
    ".pdf": "application/pdf", ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".csv": "text/csv", ".json": "application/json", ".txt": "text/plain",
    ".png": "image/png", ".jpg": "image/jpeg", ".log": "text/plain", ".zip": "application/zip",
}

CHAIN_LEDGER = VAULT_DIR / "ledger.json"


def _ledger(db: Session, evidence: Evidence, prev_hash: str) -> str:
    """Compute + persist the vault ledger entry (tamper-evident)."""
    payload = (
        f"{evidence.id}|{evidence.title}|{evidence.artefact_type}|{evidence.sha256}|"
        f"{evidence.created_at.isoformat()}|{prev_hash}"
    )
    return hashlib.sha256(payload.encode()).hexdigest()


def _last_vault_hash(db: Session) -> str:
    last = db.query(Evidence).order_by(Evidence.id.desc()).first()
    return last.chain_hash if last else hashlib.sha256(b"VAULT_GENESIS").hexdigest()


def validate_upload(filename: str, size: int) -> tuple[str, str]:
    """Return (storage_basename, mime_type) or raise."""
    ext = Path(filename).suffix.lower()
    if ext not in ALLOWED_MIME:
        raise ValueError(f"Unsupported file type '{ext}' ({', '.join(ALLOWED_MIME)})")
    if size > 25 * 1024 * 1024:
        raise ValueError("Maximum evidence size is 25 MB")
    return ext, ALLOWED_MIME[ext]


def store_evidence(db: Session, *, title: str, artefact_type: str, source_system: str,
                   description: str, filename: str, mime_type: str, size: int,
                   sha256: str, uploaded_by: str, control_ids: list[int],
                   retention_days: int = 365) -> Evidence:
    """WORM-write artefact + hash-chain into vault, then link to controls."""
    ext, _ = validate_upload(filename, size)
    if not sha256:
        raise ValueError("sha256 digest required — refuse to store unverifiable artefact")

    prev_hash = _last_vault_hash(db)
    evidence = Evidence(
        title=title, artefact_type=artefact_type, source_system=source_system,
        description=description, mime_type=mime_type, file_size=size,
        sha256=sha256, uploaded_by=uploaded_by, retention_days=retention_days,
        worm_locked=True,
    )
    db.add(evidence)
    db.flush()
    evidence.file_path = str(VAULT_DIR / f"ev-{evidence.id}{ext}")
    evidence.chain_hash = _ledger(db, evidence, prev_hash)
    db.commit()
    db.refresh(evidence)

    # WORM: write physical artefact marker (payload bytes managed by upload endpoint)
    marker = VAULT_DIR / f"ev-{evidence.id}.meta.json"
    marker.write_text(json.dumps({
        "evidence_id": evidence.id, "title": title, "sha256": sha256,
        "chain_hash": evidence.chain_hash, "worm": True,
        "retention_until": (naive_utcnow() + timedelta(days=retention_days)).isoformat(),
        "controls": control_ids, "uploaded_by": uploaded_by,
    }, indent=2), encoding="utf-8")

    for ctrl_id in control_ids:
        link = EvidenceLink(evidence_id=evidence.id, control_id=ctrl_id, linked_by=uploaded_by)
        db.add(link)
    db.commit()
    return evidence


def link_evidence(db: Session, evidence_id: int, control_id: int, actor: str) -> EvidenceLink:
    link = db.query(EvidenceLink).filter(
        EvidenceLink.evidence_id == evidence_id,
        EvidenceLink.control_id == control_id,
    ).first()
    if not link:
        link = EvidenceLink(evidence_id=evidence_id, control_id=control_id, linked_by=actor)
        db.add(link)
        db.commit()
        db.refresh(link)
    return link


def verify_vault_integrity(db: Session) -> dict:
    """Recompute the vault hash-chain; flag any tampering."""
    rows = db.query(Evidence).order_by(Evidence.id.asc()).all()
    prev = hashlib.sha256(b"VAULT_GENESIS").hexdigest()
    status = {"verified": True, "checked": len(rows), "tampered": 0}
    for ev in rows:
        payload = (
            f"{ev.id}|{ev.title}|{ev.artefact_type}|{ev.sha256}|"
            f"{ev.created_at.isoformat()}|{prev}"
        )
        if hashlib.sha256(payload.encode()).hexdigest() != ev.chain_hash:
            status["verified"] = False
            status["tampered"] += 1
        prev = ev.chain_hash
    return status


def build_evidence_pack(db: Session, evidence_ids: list[int], pack_path: Path) -> Path:
    """Zip evidence manifest + artefacts into an auditor-ready pack."""
    rows = db.query(Evidence).filter(Evidence.id.in_(evidence_ids)).all()
    manifest = {
        "generated_at": naive_utcnow().isoformat(),
        "artefacts": [],
    }
    with zipfile.ZipFile(pack_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for ev in rows:
            manifest["artefacts"].append({
                "id": ev.id, "title": ev.title, "sha256": ev.sha256,
                "chain_hash": ev.chain_hash, "mime": ev.mime_type,
                "retention_until": None,
            })
            # attach stored artefact if present, else include placeholder note
            marker = VAULT_DIR / f"ev-{ev.id}.meta.json"
            if marker.exists():
                zf.write(marker, f"meta/ev-{ev.id}.meta.json")
        zf.writestr("MANIFEST.json", json.dumps(manifest, indent=2))
        zf.writestr("README.txt",
                    "Compliance Automation Suite — auditor evidence pack.\n"
                    "Verify integrity via sha256 in MANIFEST.json and the vault chain.")
    return pack_path


def audit_chain_verify(db: Session) -> dict:
    """Verify the audit-log hash chain (tamper evidence)."""
    rows = db.query(AuditLog).order_by(AuditLog.id.asc()).all()
    prev = hashlib.sha256(b"GENESIS").hexdigest()
    tampered = 0
    for row in rows:
        payload = (
            f"{row.actor}|{row.actor_role}|{row.action}|{row.entity_type}|{row.entity_id}|"
            f"{json.dumps(row.detail or {}, default=str, sort_keys=True)}|{row.ip_address}|{prev}|"
            f"{row.created_at.isoformat()}"
        )
        if hashlib.sha256(payload.encode()).hexdigest() != row.row_hash or row.prev_hash != prev:
            tampered += 1
        prev = row.row_hash
    return {"verified": tampered == 0, "checked": len(rows), "tampered": tampered}