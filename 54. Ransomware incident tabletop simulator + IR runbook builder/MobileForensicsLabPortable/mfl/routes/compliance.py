"""Compliance dashboard routes."""

from flask import Blueprint, current_app, render_template

from ..security import login_required
from ..compliance import posture, evidence_counts, FRAMEWORK_LABELS
from ..audit import verify_chain
from ..db import query

bp = Blueprint("compliance", __name__, url_prefix="/compliance")


@bp.route("/")
@login_required
def index():
    pos = posture(current_app)
    counts = evidence_counts(current_app)
    chain = verify_chain(current_app)

    by_fw = {}
    for r in pos["rows"]:
        by_fw.setdefault(r["framework"], {"evidenced": 0, "total": 0, "refs": []})
        by_fw[r["framework"]]["total"] += 1
        by_fw[r["framework"]]["refs"].append(r)
        if r["evidence"]:
            by_fw[r["framework"]]["evidenced"] += 1
    latest = query("SELECT ts,action,actor_id FROM audit_events ORDER BY id DESC LIMIT 5")
    return render_template("compliance.html", posture=pos, counts=counts,
                           by_fw=by_fw, colors=FRAMEWORK_LABELS, chain=chain, latest=latest)