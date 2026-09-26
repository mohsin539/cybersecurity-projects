"""Evidence Vault endpoints — upload (WORM), link, integrity verify, pack download."""
from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from sqlalchemy.orm import Session

from ..database import get_db
from ..engines.evidence import (
    audit_chain_verify, build_evidence_pack, store_evidence, verify_vault_integrity,
    validate_upload,
)
from ..reports.generator import build_evidence_pack_zip
from ..models import Evidence, EvidenceLink, User
from ..security import audit, client_ip, require, sha256_file

router = APIRouter(prefix="/evidence", tags=["evidence"])


@router.get("")
def list_evidence(db: Session = Depends(get_db), _: User = Depends(require("evidence:read"))):
    out = []
    for ev in db.query(Evidence).order_by(Evidence.id.desc()).all():
        links = db.query(EvidenceLink).filter(EvidenceLink.evidence_id == ev.id).all()
        controls = []
        for link in links:
            controls.append({"control_id": link.control_id, "code": link.control.code,
                             "framework": link.control.framework.code if link.control.framework else ""})
        out.append({
            "id": ev.id, "title": ev.title, "artefact_type": ev.artefact_type,
            "source_system": ev.source_system, "description": ev.description,
            "mime_type": ev.mime_type, "file_size": ev.file_size, "sha256": ev.sha256,
            "chain_hash": ev.chain_hash, "worm_locked": ev.worm_locked,
            "uploaded_by": ev.uploaded_by, "created_at": ev.created_at.isoformat(),
            "controls": controls,
        })
    return out


@router.post("/upload")
async def upload_evidence(
    request: Request,
    title: str = Form(...),
    artefact_type: str = Form("AUDIT"),
    source_system: str = Form("MANUAL"),
    description: str = Form(""),
    control_ids: str = Form("[]"),
    retention_days: int = Form(365),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: User = Depends(require("evidence:write")),
):
    data = await file.read()
    size = len(data)
    filename = file.filename or "artefact.bin"
    ext, mime = validate_upload(filename, size)

    import hashlib
    sha = hashlib.sha256(data).hexdigest()

    ctrl_ids = []
    try:
        import json
        ctrl_ids = json.loads(control_ids)
        ctrl_ids = [int(c) for c in ctrl_ids]
    except Exception:
        raise HTTPException(status_code=422, detail="control_ids must be a JSON int array")

    evidence = store_evidence(
        db, title=title, artefact_type=artefact_type, source_system=source_system,
        description=description, filename=filename, mime_type=mime,
        size=size, sha256=sha, uploaded_by=user.username,
        control_ids=ctrl_ids, retention_days=retention_days,
    )
    # persist raw artefact bytes into WORM vault
    from ..engines.evidence import VAULT_DIR
    (VAULT_DIR / f"ev-{evidence.id}{ext}").write_bytes(data)

    audit(db, user.username, user.role, "EVIDENCE_UPLOAD", "EVIDENCE", evidence.id,
          {"title": evidence.title, "sha256": evidence.sha256,
           "chain_hash": evidence.chain_hash, "size": size}, client_ip(request))
    return {"id": evidence.id, "sha256": evidence.sha256, "chain_hash": evidence.chain_hash}


@router.post("/{evidence_id}/link")
def link(evidence_id: int, payload: dict, request: Request, db: Session = Depends(get_db),
         user: User = Depends(require("evidence:write"))):
    from ..engines.evidence import link_evidence as link_fn
    lk = link_fn(db, evidence_id, payload["control_id"], user.username)
    audit(db, user.username, user.role, "EVIDENCE_LINK", "EVIDENCE", evidence_id,
          {"control_id": payload["control_id"]}, client_ip(request))
    return {"linked": True, "id": lk.id}


@router.get("/integrity")
def integrity(db: Session = Depends(get_db), _: User = Depends(require("audit:read"))):
    return {"vault": verify_vault_integrity(db), "audit_chain": audit_chain_verify(db)}


@router.get("/pack")
def pack(evidence_ids: str = "", db: Session = Depends(get_db),
         _: User = Depends(require("report:read"))):
    ids = [int(x) for x in evidence_ids.split(",") if x.strip().isdigit()]
    if not ids:
        ids = [ev.id for ev in db.query(Evidence).limit(20).all()]
    return build_evidence_pack_zip(db, ids)