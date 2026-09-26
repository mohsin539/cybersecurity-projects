"""Artifact analysis routes."""

import hashlib

from flask import (
    Blueprint, abort, current_app, flash, redirect, render_template, request, url_for
)

from ..db import execute, get_db, query, query_one
from ..security import login_required, role_required, g_user_id, g_user_role
from ..audit import audit

bp = Blueprint("analysis", __name__, url_prefix="/analysis")

CATEGORIES = ("call_log", "sms", "contact", "geo", "app", "media", "browser", "account", "crypto", "other")
SEVERITIES = ("blocker", "critical", "high", "medium", "low", "info")


@bp.route("/")
@login_required
def index():
    sev = request.args.get("severity") or ""
    if sev in SEVERITIES:
        rows = query("SELECT a.*, e.device_model, c.case_ref FROM artifacts a "
                     "JOIN evidence e ON a.evidence_id=e.id JOIN cases c ON e.case_id=c.id "
                     "WHERE a.severity=? ORDER BY a.created_at DESC", (sev,))
    else:
        rows = query("SELECT a.*, e.device_model, c.case_ref FROM artifacts a "
                     "JOIN evidence e ON a.evidence_id=e.id JOIN cases c ON e.case_id=c.id "
                     "ORDER BY a.created_at DESC")
    return render_template("analysis_index.html", artifacts=rows,
                           categories=CATEGORIES, severities=SEVERITIES, active=sev)


@bp.route("/evidence/<int:eid>/add", methods=["GET", "POST"])
@login_required
def create(eid):
    item = query_one("SELECT * FROM evidence WHERE id=?", (eid,))
    if not item:
        abort(404)
    if request.method == "POST":
        category = request.form.get("category") or "other"
        if category not in CATEGORIES:
            category = "other"
        name = (request.form.get("name") or "").strip()
        if not name:
            flash("Artifact name is required.", "danger")
        else:
            value = (request.form.get("value") or "").strip()
            detail = (request.form.get("detail") or "").strip()
            severity = request.form.get("severity") or "info"
            if severity not in SEVERITIES:
                severity = "info"
            ts = (request.form.get("timestamp") or "").strip() or None
            source = (request.form.get("source_path") or "").strip()
            ah = (request.form.get("artifact_hash") or "").strip().lower()
            cid = execute(
                "INSERT INTO artifacts(evidence_id,category,name,detail,value,timestamp,severity,"
                "source_path,artifact_hash,created_by) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (eid, category, name, detail, value, ts, severity, source, ah, g_user_id()))
            audit(current_app, g_user_id(), g_user_role(), "ARTIFACT_CREATE", "artifact", cid,
                  {"evidence_id": eid, "category": category, "name": name, "severity": severity}, "info")
            if severity in ("blocker", "critical", "high"):
                flash("High-severity finding recorded.", "warning")
            else:
                flash("Artifact recorded.", "success")
            return redirect(url_for("evidence.detail", eid=eid))
    return render_template("artifact_form.html", item=item, categories=CATEGORIES,
                           severities=SEVERITIES, artifact=None, action="Add")


@bp.route("/<int:aid>/edit", methods=["GET", "POST"])
@login_required
def update(aid):
    artifact = query_one("SELECT * FROM artifacts WHERE id=?", (aid,))
    if not artifact:
        abort(404)
    if request.method == "POST":
        name = (request.form.get("name") or artifact["name"]).strip()
        category = request.form.get("category") or artifact["category"]
        if category not in CATEGORIES:
            category = artifact["category"]
        severity = request.form.get("severity") or artifact["severity"]
        if severity not in SEVERITIES:
            severity = artifact["severity"]
        get_db().execute(
            "UPDATE artifacts SET category=?,name=?,detail=?,value=?,timestamp=?,severity=?,"
            "source_path=?,artifact_hash=? WHERE id=?",
            (category, name, (request.form.get("detail") or "").strip(),
             (request.form.get("value") or "").strip(), (request.form.get("timestamp") or "").strip() or None,
             severity, (request.form.get("source_path") or "").strip(),
             (request.form.get("artifact_hash") or "").strip().lower(), aid))
        get_db().commit()
        audit(current_app, g_user_id(), g_user_role(), "ARTIFACT_UPDATE", "artifact", aid,
              {"category": category, "severity": severity}, "info")
        flash("Artifact updated.", "success")
        return redirect(url_for("evidence.detail", eid=artifact["evidence_id"]))
    return render_template("artifact_form.html", item=query_one("SELECT * FROM evidence WHERE id=?", (artifact["evidence_id"],)),
                           categories=CATEGORIES, severities=SEVERITIES, artifact=artifact, action="Edit")


@bp.route("/<int:aid>/delete", methods=["POST"])
@login_required
@role_required("admin", "examiner")
def delete(aid):
    artifact = query_one("SELECT * FROM artifacts WHERE id=?", (aid,))
    if artifact:
        audit(current_app, g_user_id(), g_user_role(), "ARTIFACT_DELETE", "artifact", aid,
              {"name": artifact["name"]}, "warning")
        execute("DELETE FROM artifacts WHERE id=?", (aid,))
        flash("Artifact deleted (audit retained).", "warning")
    return redirect(url_for("evidence.detail", eid=artifact["evidence_id"] if artifact else 0))