"""Risk Engine (architecture.md §4.3) — CVSS-weighted scoring & risk register."""
import math
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from ..database import naive_utcnow

from ..models import RiskPoint, RemediationTicket


def cvss_to_tier(cvss: float) -> str:
    if cvss <= 0.0:
        return "LOW"
    if cvss < 4.0:
        return "LOW"
    if cvss < 7.0:
        return "MEDIUM"
    if cvss < 9.0:
        return "HIGH"
    return "CRITICAL"


def risk_tier(likelihood: float, impact: float) -> str:
    score = likelihood * impact
    if score >= 20:
        return "CRITICAL"
    if score >= 12:
        return "HIGH"
    if score >= 6:
        return "MEDIUM"
    return "LOW"


def raw_score(likelihood: float, impact: float, cvss: float) -> float:
    """Blend qualitative 1-5 grid with quantitative CVSS (0-10)."""
    return round(((likelihood * impact) / 25) * 0.6 + (cvss / 10) * 0.4, 3)


def score_risk(db: Session, risk_id: int, likelihood: float, impact: float, cvss: float) -> RiskPoint:
    risk = db.query(RiskPoint).filter(RiskPoint.id == risk_id).first()
    if not risk:
        raise ValueError("Risk not found")
    risk.likelihood = max(1.0, min(5.0, float(likelihood)))
    risk.impact = max(1.0, min(5.0, float(impact)))
    risk.cvss = max(0.0, min(10.0, float(cvss)))
    risk.tier = risk_tier(risk.likelihood, risk.impact)
    risk.raw_score = raw_score(risk.likelihood, risk.impact, risk.cvss)
    risk.residual_score = round(risk.raw_score * (1.0 - 0.2), 3)  # simulated mitigation overlay
    db.commit()
    db.refresh(risk)
    return risk


def auto_escalate(db: Session) -> list[int]:
    """Escalate risks whose tier is CRITICAL/HIGH into remediation tickets."""
    created = []
    risks = db.query(RiskPoint).filter(
        RiskPoint.tier.in_(["CRITICAL", "HIGH"]),
        RiskPoint.status == "OPEN",
    ).all()
    for r in risks:
        exists = db.query(RemediationTicket).filter(
            RemediationTicket.risk_id == r.id,
            RemediationTicket.status.in_(["OPEN", "IN_PROGRESS", "IN_REVIEW"]),
        ).first()
        if exists:
            continue
        sla = {"CRITICAL": 24, "HIGH": 72, "MEDIUM": 168}.get(r.tier, 720)
        ticket = RemediationTicket(
            risk_id=r.id,
            control_id=r.control_id,
            title=f"Remediate: {r.title}",
            description=f"Auto-escalated from risk tier '{r.tier}' (raw {r.raw_score}).",
            priority=r.tier,
            sla_hours=sla,
            due_at=naive_utcnow() + timedelta(hours=sla),
            external_ticket=None,
        )
        db.add(ticket)
        created.append(ticket.id)
    db.commit()
    return created


def sla_metrics(db: Session) -> dict:
    tickets = db.query(RemediationTicket).all()
    result = {"open": 0, "in_review": 0, "resolved": 0, "overdue": 0, "avg_resolution_hours": 0.0, "sla_breaches": 0}
    resolved_hours = []
    now = naive_utcnow()
    for t in tickets:
        if t.status == "OPEN":
            result["open"] += 1
            if t.due_at and t.due_at < now:
                result["overdue"] += 1
        elif t.status == "IN_PROGRESS":
            if t.due_at and t.due_at < now:
                result["overdue"] += 1
        elif t.status == "IN_REVIEW":
            result["in_review"] += 1
        elif t.status == "RESOLVED":
            result["resolved"] += 1
            if t.resolved_at and t.created_at:
                diff = t.resolved_at - t.created_at
                if t.sla_hours and diff > timedelta(hours=t.sla_hours):
                    result["sla_breaches"] += 1
                resolved_hours.append(diff.total_seconds() / 3600)
    if resolved_hours:
        result["avg_resolution_hours"] = round(sum(resolved_hours) / len(resolved_hours), 1)
    return result


def risk_register_summary(db: Session) -> dict:
    risks = db.query(RiskPoint).all()
    by_tier = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    by_status = {}
    top = []
    for r in risks:
        tier = r.tier or risk_tier(r.likelihood, r.impact)
        by_tier[tier] = by_tier.get(tier, 0) + 1
        by_status[r.status] = by_status.get(r.status, 0) + 1
        top.append({"id": r.id, "title": r.title, "tier": tier,
                    "raw": r.raw_score, "cvss": r.cvss, "status": r.status})
    top.sort(key=lambda x: (x["raw"] or 0) or (x["cvss"] or 0), reverse=True)
    return {"by_tier": by_tier, "by_status": by_status, "top": top[:10], "total": len(risks)}