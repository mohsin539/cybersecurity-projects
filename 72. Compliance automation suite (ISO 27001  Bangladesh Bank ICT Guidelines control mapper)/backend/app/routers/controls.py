"""Control mapper endpoints — catalog, suggest, map, overlaps, gaps."""
from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from ..database import get_db
from ..engines.mapper import (
    compliance_matrix, dedupe_overlaps, gap_analysis, map_control, suggest_mappings,
)
from ..models import Asset, Control, Evidence, EvidenceLink, Framework, ControlMapping, ScanResult, User
from ..security import audit, client_ip, require

router = APIRouter(prefix="/controls", tags=["controls"])


@router.get("")
def list_controls(framework: str = None, category: str = None, db: Session = Depends(get_db),
                  _: User = Depends(require("dashboard:read"))):
    q = db.query(Control)
    if framework:
        fw = db.query(Framework).filter(Framework.code == framework).first()
        if fw:
            q = q.filter(Control.framework_id == fw.id)
    if category:
        q = q.filter(Control.category == category)
    q = q.order_by(Control.framework_id, Control.code)
    result = []
    for c in q.all():
        fw = db.query(Framework).filter(Framework.id == c.framework_id).first()
        ev = db.query(EvidenceLink).filter(EvidenceLink.control_id == c.id).count()
        result.append({
            "id": c.id, "framework": fw.code if fw else "", "code": c.code,
            "title": c.title, "category": c.category, "intent": c.intent,
            "status": c.implementation_status, "owner": c.owner, "weight": c.weight,
            "evidence_count": ev,
        })
    return result


@router.get("/frameworks")
def frameworks(db: Session = Depends(get_db), _: User = Depends(require("dashboard:read"))):
    return [{ "id": f.id, "code": f.code, "name": f.name, "version": f.version,
        "publisher": f.publisher, "cadence": f.cadence } for f in
        db.query(Framework).filter(Framework.is_active.is_(True)).all()]


@router.get("/mapping/suggest/{control_id}")
def suggest(control_id: int, db: Session = Depends(get_db),
            _: User = Depends(require("map:write"))):
    control = db.query(Control).filter(Control.id == control_id).first()
    if not control:
        return {"suggestions": []}
    return {"control": {"id": control.id, "code": control.code, "category": control.category},
            "suggestions": suggest_mappings(db, control)}


@router.post("/mapping")
def map_targets(payload: dict, request: Request, db: Session = Depends(get_db),
                user: User = Depends(require("map:write"))):
    created = []
    for item in payload.get("mappings", []):
        m = map_control(db, item["source_id"], item["target_id"],
                        item.get("map_type", "EQUIVALENT"), item.get("rationale", ""),
                        user.username)
        created.append({"id": m.id, "source_id": m.source_id, "target_id": m.target_id})
    audit(db, user.username, user.role, "CONTROL_MAPPED", "CONTROL",
          payload.get("mappings", [{}])[0].get("source_id"),
          {"count": len(created), "map_type": payload.get("map_type")}, client_ip(request))
    return {"created": created}


@router.get("/mapping/list")
def mapping_graph(db: Session = Depends(get_db), _: User = Depends(require("dashboard:read"))):
    edges = []
    node_map = {}

    def node_for(ctrl):
        fw = db.query(Framework).filter(Framework.id == ctrl.framework_id).first()
        node_map.setdefault(ctrl.id, {"id": ctrl.id, "code": ctrl.code,
                                      "framework": fw.code if fw else "?"})

    for m in db.query(ControlMapping).all():
        src, tgt = m.source, m.target
        node_for(src)
        node_for(tgt)
        edges.append({"from": {"id": src.id}, "to": {"id": tgt.id}, "type": m.map_type})
    return {"nodes": list(node_map.values()), "edges": edges}


@router.get("/overlaps")
def overlaps(db: Session = Depends(get_db), _: User = Depends(require("dashboard:read"))):
    report = dedupe_overlaps(db)
    # per-evidence multi-framework breakdown
    breakdown = []
    links = db.query(EvidenceLink).all()
    by_ev = {}
    for link in links:
        by_ev.setdefault(link.evidence_id, []).append(link)
    for ev_id, ev_links in by_ev.items():
        ev = db.query(Evidence).filter(Evidence.id == ev_id).first()
        fw_codes = []
        for link in ev_links:
            ctrl = db.query(Control).filter(Control.id == link.control_id).first()
            if ctrl:
                fw = db.query(Framework).filter(Framework.id == ctrl.framework_id).first()
                if fw and fw.code not in fw_codes:
                    fw_codes.append(fw.code)
        breakdown.append({"evidence_id": ev_id, "title": ev.title if ev else "",
                          "frameworks": fw_codes, "count": len(fw_codes)})
    breakdown.sort(key=lambda x: x["count"], reverse=True)
    return {**report, "breakdown": breakdown[:20]}


@router.get("/gaps")
def gaps(framework: str = None, db: Session = Depends(get_db),
         _: User = Depends(require("dashboard:read"))):
    return gap_analysis(db, framework)


@router.get("/matrix")
def matrix(framework: str = None, db: Session = Depends(get_db),
           _: User = Depends(require("dashboard:read"))):
    return compliance_matrix(db, framework)