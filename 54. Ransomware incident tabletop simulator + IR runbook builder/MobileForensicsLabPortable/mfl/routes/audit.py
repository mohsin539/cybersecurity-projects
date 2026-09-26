"""Audit trail viewing & export routes (auditor/admin restricted, AU-2..AU-11)."""

from flask import (
    Blueprint, current_app, flash, redirect, render_template, request, url_for, Response
)

from ..db import query
from ..security import login_required, role_required, g_user_id, g_user_role
from ..audit import audit
from ..compliance import evidence_counts
from ..reports import audit_xml

bp = Blueprint("audit", __name__, url_prefix="/audit")


@bp.route("/")
@login_required
@role_required("admin", "auditor")
def index():
    page = max(1, int(request.args.get("page") or 1))
    per = 50
    action = request.args.get("action") or ""
    total = query("SELECT COUNT(*) n FROM audit_events")[0]["n"]
    if action:
        rows = query("SELECT * FROM audit_events WHERE action=?"
                     " ORDER BY id DESC LIMIT ? OFFSET ?", (action, per, (page - 1) * per))
    else:
        rows = query("SELECT * FROM audit_events ORDER BY id DESC LIMIT ? OFFSET ?",
                     (per, (page - 1) * per))
    actions = [r["action"] for r in query("SELECT DISTINCT action FROM audit_events ORDER BY action")]
    return render_template("audit_index.html", events=rows, total=total, page=page,
                           per=per, actions=actions, active=action)


@bp.route("/export/<fmt>")
@login_required
@role_required("admin", "auditor")
def export(fmt):
    audit(current_app, g_user_id(), g_user_role(), "AUDIT_EXPORT", "audit", "all",
          {"format": fmt}, "high")
    if fmt == "xml":
        data = audit_xml(current_app)
        return _csv_or_xml_resp(data, "audit_pack.xml", "application/xml")
    if fmt == "json":
        rows = [dict(r) for r in query("SELECT * FROM audit_events ORDER BY id ASC")]
        import json
        data = json.dumps(rows, indent=2).encode("utf-8")
        return _csv_or_xml_resp(data, "audit_export.json", "application/json")
    rows = query("SELECT * FROM audit_events ORDER BY id ASC")
    import io, csv
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=[k for k in rows[0].keys()] if rows else [])
    if rows:
        w.writeheader()
        for r in rows:
            w.writerow(dict(r))
    data = buf.getvalue().encode("utf-8")
    return _csv_or_xml_resp(data, "audit_export.csv", "text/csv")


def _csv_or_xml_resp(data, filename, mimetype):
    import hashlib
    checksum = hashlib.sha256(data).hexdigest()
    resp = Response(data, mimetype=mimetype)
    resp.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    resp.headers["Content-SHA256"] = checksum
    resp.headers["Cache-Control"] = "no-store"
    return resp


@bp.route("/stats")
@login_required
@role_required("admin", "auditor")
def stats():
    counts = evidence_counts(current_app)
    by_action = [{"action": k, "count": v} for k, v in sorted(counts.items(), key=lambda x: -x[1])]
    return render_template("audit_stats.html", by_action=by_action)