"""Report download routes (signed, short-lived, format-selected exports)."""

import hashlib
from flask import (
    Blueprint, abort, current_app, flash, redirect, render_template, request, url_for, Response
)

from ..db import query_one
from ..security import login_required, g_user_id, g_user_role
from ..audit import audit
from .. import reports as R

bp = Blueprint("reports", __name__, url_prefix="/reports")


@bp.route("/")
@login_required
def index():
    cases = _all_cases()
    return render_template("reports_index.html", cases=cases)


@bp.route("/generate", methods=["POST"])
@login_required
def generate():
    case_id = int(request.form.get("case_id") or 0)
    fmt = request.form.get("format") or "html"
    kind = request.form.get("kind") or "technical"
    case = query_one("SELECT * FROM cases WHERE id=?", (case_id,)) if case_id else None
    if not case:
        flash("Select a valid case.", "danger")
        return redirect(url_for("reports.index"))

    audit(current_app, g_user_id(), g_user_role(), "REPORT_ORDERED", "report", case_id,
          {"case_ref": case["case_ref"], "format": fmt, "kind": kind}, "info")

    if fmt == "json":
        data = R.json_report(case_id)
        fn = _snake(case["case_ref"]) + "_case.json"
        return _send(data, fn, "application/json")
    if fmt == "csv":
        entity = request.form.get("entity") or "evidence"
        data = R.csv_report(case_id, entity)
        fn = _snake(case["case_ref"]) + "_" + entity + ".csv"
        return _send(data, fn, "text/csv")
    if fmt == "auditxml":
        data = R.audit_xml(current_app)
        fn = "audit_pack.xml"
        return _send(data, fn, "application/xml")

    html, manifest = R.html_report(current_app, case_id)
    fn = _snake(case["case_ref"]) + "_report_" + ("exec" if kind == "executive" else "technical") + ".html"
    resp = _send(html, fn, "text/html")
    resp.headers["X-Report-Manifest"] = manifest
    return resp


def _all_cases():
    from ..db import query
    return query("SELECT id,case_ref,title,status,severity FROM cases ORDER BY updated_at DESC")


def _snake(text):
    return "".join(c if c.isalnum() else "_" for c in text.lower()).strip("_")


def _send(data, filename, mimetype):
    checksum = hashlib.sha256(data).hexdigest()
    audit(current_app, g_user_id(), g_user_role(), "REPORT_DOWNLOADED", "report", filename,
          {"sha256": checksum[:16]}, "info")
    resp = Response(data, mimetype=mimetype)
    resp.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    resp.headers["Content-SHA256"] = checksum
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["X-Robots-Tag"] = "noindex"
    return resp