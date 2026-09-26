"""Case management routes."""

from flask import (
    Blueprint, abort, current_app, flash, redirect, render_template, request, url_for
)

from ..db import execute, get_db, query, query_one
from ..security import login_required, role_required, g_user_id, g_user_role
from ..audit import audit

bp = Blueprint("cases", __name__, url_prefix="/cases")


def _valid_status(s):
    return s in ("open", "active", "closed", "shelved")


@bp.route("/")
@login_required
def index():
    status = request.args.get("status") or ""
    if status:
        rows = query("SELECT * FROM cases WHERE status=? ORDER BY updated_at DESC", (status,))
    else:
        rows = query("SELECT * FROM cases ORDER BY updated_at DESC")
    counts = {}
    for s in ("open", "active", "closed", "shelved"):
        counts[s] = query("SELECT COUNT(*) n FROM cases WHERE status=?", (s,))[0]["n"]
    return render_template("cases_index.html", cases=rows, counts=counts, active=status)


@bp.route("/new", methods=["GET", "POST"])
@login_required
@role_required("examiner", "admin")
def create():
    if request.method == "POST":
        ref = (request.form.get("case_ref") or "").strip().upper()
        title = (request.form.get("title") or "").strip()
        severity = request.form.get("severity") or "medium"
        lead = (request.form.get("lead_examiner") or "").strip()
        description = (request.form.get("description") or "").strip()
        if not ref or not title:
            flash("Case ref and title are required.", "danger")
        elif query_one("SELECT 1 FROM cases WHERE case_ref=?", (ref,)):
            flash("Case ref already exists — case_ref must be unique.", "danger")
        else:
            cid = execute(
                "INSERT INTO cases(case_ref,title,description,status,severity,lead_examiner,created_by)"
                " VALUES(?,?,?,?,?,?,?)",
                (ref, title, description, "open", severity, lead, g_user_id()))
            audit(current_app, g_user_id(), g_user_role(), "CASE_CREATE", "case", cid,
                  {"case_ref": ref, "severity": severity}, "info")
            flash(f"Case {ref} created.", "success")
            return redirect(url_for("cases.detail", cid=cid))
    return render_template("case_form.html", case=None)


@bp.route("/<int:cid>")
@login_required
def detail(cid):
    case = query_one("SELECT * FROM cases WHERE id=?", (cid,))
    if not case:
        abort(404)
    evidence = query("SELECT * FROM evidence WHERE case_id=? ORDER BY id DESC", (cid,))
    artifacts = query(
        "SELECT a.*, e.device_model FROM artifacts a JOIN evidence e ON a.evidence_id=e.id "
        "WHERE e.case_id=? ORDER BY a.id DESC", (cid,))
    custody = query(
        "SELECT cu.*, e.device_model FROM custody_events cu "
        "JOIN evidence e ON cu.evidence_id=e.id WHERE e.case_id=? ORDER BY cu.occurred_at DESC", (cid,))
    return render_template("case_detail.html", case=case, evidence=evidence,
                           artifacts=artifacts, custody=custody)


@bp.route("/<int:cid>/edit", methods=["GET", "POST"])
@login_required
@role_required("examiner", "admin")
def update(cid):
    case = query_one("SELECT * FROM cases WHERE id=?", (cid,))
    if not case:
        abort(404)
    if request.method == "POST":
        title = (request.form.get("title") or "").strip()
        severity = request.form.get("severity") or case["severity"]
        status = request.form.get("status") or case["status"]
        lead = (request.form.get("lead_examiner") or "").strip()
        description = (request.form.get("description") or "").strip()
        if not title:
            flash("Title is required.", "danger")
        else:
            closed_at = None
            if status == "closed" and case["status"] != "closed":
                closed_at = "datetime('now')"
            get_db().execute(
                "UPDATE cases SET title=?,description=?,status=?,severity=?,lead_examiner=?,"
                "updated_at=datetime('now'),closed_at=COALESCE(?,closed_at) WHERE id=?",
                (title, description, status, severity, lead, closed_at, cid))
            get_db().commit()
            audit(current_app, g_user_id(), g_user_role(), "CASE_UPDATE", "case", cid,
                  {"status": status, "severity": severity}, "info" if status != "closed" else "medium")
            flash("Case updated.", "success")
            return redirect(url_for("cases.detail", cid=cid))
    return render_template("case_form.html", case=case)


@bp.route("/<int:cid>/close", methods=["POST"])
@login_required
@role_required("examiner", "admin")
def close(cid):
    case = query_one("SELECT * FROM cases WHERE id=?", (cid,))
    if case:
        get_db().execute("UPDATE cases SET status='closed',closed_at=datetime('now'),updated_at=datetime('now') WHERE id=?", (cid,))
        get_db().commit()
        audit(current_app, g_user_id(), g_user_role(), "CASE_CLOSE", "case", cid, {"case_ref": case["case_ref"]}, "high")
        flash("Case closed.", "success")
    return redirect(url_for("cases.detail", cid=cid))