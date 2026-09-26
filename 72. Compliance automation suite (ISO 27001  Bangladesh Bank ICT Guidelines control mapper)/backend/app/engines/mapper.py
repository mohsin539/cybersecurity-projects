"""Control Mapper Engine (architecture.md §5) — canonical mapping & gap analysis."""
from sqlalchemy.orm import Session

from ..models import (
    Assessment, AssessmentDecision, Control, ControlMapping, EvidenceLink,
    Framework,
)


CATEGORY_THESAURUS = {
    "DATA_PROTECTION": ("A.8.24", "CH-14", "PR.DS-1", "A02"),
    "ACCESS_CONTROL": ("A.8.2", "CH-16", "PR.AC-1", "A01"),
    "LOG_AND_MONITOR": ("A.8.15", "CH-14", "DE.CM-1", "A09"),
    "VULNERABILITY": ("A.8.8", "CH-12", "RA-5", "A06"),
    "CRYPTOGRAPHY": ("A.8.24", "CH-14", "SC-13", "A02"),
    "SECURE_CODING": ("A.8.28", "CH-12", "PR.DS-6", "A03"),
    "IDENTITY": ("A.8.5", "CH-16", "PR.AA-1", "A07"),
    "TRAINING": ("A.6.3", "CH-17", "PR.AT-1", "NONE"),
    "BCM": ("A.5.30", "CH-18", "RC.RP-1", "NONE"),
    "INCIDENT": ("A.5.24", "CH-27", "RS.RP-1", "NONE"),
    "NETWORK": ("A.8.20", "CH-12", "PR.PT-4", "NONE"),
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
DECISION_ORDER = {"COMPLIANT": 0, "PARTIAL": 1, "NON_COMPLIANT": 2, "NOT_ASSESSED": 3, "NOT_APPLICABLE": 4}


def framework_by_code(db: Session, code: str) -> Framework | None:
    return db.query(Framework).filter(Framework.code == code).first()


def auto_hint(framework_code: str, category: str) -> str | None:
    """Heuristic hint at the mapping target code for a category (rule-based)."""
    hints = CATEGORY_THESAURUS.get(category, ())
    code_by_fw = {"ISO27001": 0, "BBICT2015": 1, "NISTCSF": 2, "OWASP2021": 3}
    idx = code_by_fw.get(framework_code)
    return None if idx is None or idx >= len(hints) or hints[idx] == "NONE" else hints[idx]


def suggest_mappings(db: Session, control: Control) -> list[dict]:
    """Given a canonical control, propose equivalent controls in other frameworks."""
    suggestions = []
    for fw in db.query(Framework).filter(Framework.is_active.is_(True)).all():
        if fw.id == control.framework_id:
            continue
        hint = auto_hint(fw.code, control.category)
        if hint:
            target = (
                db.query(Control)
                .join(Framework)
                .filter(Framework.code == fw.code, Control.code == hint)
                .first()
            )
            if target:
                existing = (
                    db.query(ControlMapping)
                    .filter(
                        ControlMapping.source_id == control.id,
                        ControlMapping.target_id == target.id,
                    )
                    .first()
                )
                suggestions.append({"target_id": target.id, "code": target.code,
                                    "framework": fw.code, "title": target.title,
                                    "mapped": existing is not None})
    return suggestions


def map_control(db: Session, source_id: int, target_id: int, map_type: str, rationale: str, actor: str) -> ControlMapping:
    mapping = (
        db.query(ControlMapping)
        .filter(ControlMapping.source_id == source_id, ControlMapping.target_id == target_id)
        .first()
    )
    if not mapping:
        mapping = ControlMapping(source_id=source_id, target_id=target_id)
    mapping.map_type = map_type
    mapping.rationale = rationale
    db.add(mapping)
    db.commit()
    db.refresh(mapping)
    return mapping


def dedupe_overlaps(db: Session) -> dict:
    """Count multi-framework coverage enabled by each evidence artefact."""
    stats = {"evidence_artefacts": 0, "evidence_links": 0, "overlap_savings": 0,
             "max_frameworks_per_evidence": 0}
    links = db.query(EvidenceLink).all()
    by_evidence = {}
    for link in links:
        by_evidence.setdefault(link.evidence_id, []).append(link)
    stats["evidence_artefacts"] = len(by_evidence)
    stats["evidence_links"] = len(links)
    fw_counts = []
    for ev_id, ev_links in by_evidence.items():
        distinct_fw = set()
        for link in ev_links:
            ctrl = db.query(Control).filter(Control.id == link.control_id).first()
            if ctrl:
                fw = db.query(Framework).filter(Framework.id == ctrl.framework_id).first()
                if fw:
                    distinct_fw.add(fw.code)
        fw_counts.append(len(distinct_fw))
    if fw_counts:
        stats["max_frameworks_per_evidence"] = max(fw_counts)
        stats["overlap_savings"] = sum(c - 1 for c in fw_counts if c > 1)
    return stats


def compliance_matrix(db: Session, framework_code: str = None) -> dict:
    """Status distribution per framework — powers the compliance heatmaps."""
    fws = db.query(Framework).filter(Framework.is_active.is_(True)).all()
    if framework_code:
        fws = [f for f in fws if f.code == framework_code]
    matrix = {"frameworks": [], "overall": 0.0}
    totals = {"COMPLIANT": 0, "PARTIAL": 0, "NON_COMPLIANT": 0, "NOT_ASSESSED": 0, "NOT_APPLICABLE": 0}
    for fw in fws:
        row = {"code": fw.code, "name": fw.name, "total": 0, "status": {}, "compliance_score": 0.0}
        controls = db.query(Control).filter(Control.framework_id == fw.id).all()
        row["total"] = len(controls)
        latest = (
            db.query(Assessment)
            .filter(Assessment.framework_code == fw.code, Assessment.status.in_(["COMPLETED", "REVIEWED"]))
            .order_by(Assessment.completed_at.desc())
            .first()
        )
        status_map = {}
        if latest:
            decisions = db.query(AssessmentDecision).filter(
                AssessmentDecision.assessment_id == latest.id).all()
            control_ids = {c.id: c for c in controls}
            for d in decisions:
                if d.control_id in control_ids:
                    status_map[d.control_id] = d.status
        for c in controls:
            st = status_map.get(c.id, c.implementation_status if c.implementation_status in DECISION_ORDER else "NOT_ASSESSED")
            row["status"].setdefault(st, 0)
            row["status"][st] += 1
            totals[st if st in totals else "NOT_ASSESSED"] += 1
        assessed = [k for k in ("COMPLIANT", "PARTIAL", "NON_COMPLIANT") if k in row["status"]]
        n_assessed = sum(row["status"].get(k, 0) for k in assessed)
        if n_assessed:
            weight = {"COMPLIANT": 1.0, "PARTIAL": 0.5, "NON_COMPLIANT": 0.0}
            row["compliance_score"] = round(
                100 * sum(weight[k] * row["status"].get(k, 0) for k in assessed) / n_assessed, 1)
        matrix["frameworks"].append(row)

    assessed_total = sum(totals[k] for k in ("COMPLIANT", "PARTIAL", "NON_COMPLIANT"))
    if assessed_total:
        matrix["overall"] = round(
            100 * (1.0 * totals["COMPLIANT"] + 0.5 * totals["PARTIAL"]) / assessed_total, 1)
    return matrix


def gap_analysis(db: Session, framework_code: str = None) -> list[dict]:
    """Non-compliant / unassessed controls grouped — drives remediation."""
    rows = []
    fws = db.query(Framework).filter(Framework.is_active.is_(True)).all()
    if framework_code:
        fws = [f for f in fws if f.code == framework_code]
    for fw in fws:
        latest = (
            db.query(Assessment)
            .filter(Assessment.framework_code == fw.code, Assessment.status.in_(["COMPLETED", "REVIEWED"]))
            .order_by(Assessment.completed_at.desc())
            .first()
        )
        status_map = {}
        if latest:
            for d in db.query(AssessmentDecision).filter(AssessmentDecision.assessment_id == latest.id).all():
                status_map[d.control_id] = d.status
        for ctrl in db.query(Control).filter(Control.framework_id == fw.id).all():
            st = status_map.get(ctrl.id, ctrl.implementation_status if ctrl.implementation_status in DECISION_ORDER else "NOT_ASSESSED")
            if st in ("NON_COMPLIANT", "PARTIAL", "NOT_ASSESSED"):
                rows.append({
                    "control_id": ctrl.id, "code": ctrl.code, "title": ctrl.title,
                    "framework": fw.code, "category": ctrl.category, "status": st, "owner": ctrl.owner,
                })
    return rows


def evidence_coverage(db: Session, control_id: int) -> int:
    return db.query(EvidenceLink).filter(EvidenceLink.control_id == control_id).count()