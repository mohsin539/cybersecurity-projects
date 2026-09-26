"""Chain-of-custody routes (tamper-evident evidence handling)."""

from flask import (
    Blueprint, abort, current_app, flash, redirect, render_template, request, url_for
)

from ..db import execute, get_db, query, query_one
from ..security import login_required, g_user_id, g_user_role
from ..audit import audit

bp = Blueprint("custody", __name__, url_prefix="/custody")

EVENT_TYPES = ("INTAKE", "CHECKOUT", "TRANSFER", "CHECKIN", "SEAL", "DESTRUCTION")


@bp.route("/")
@login_required
def index():
    events = query(
        "SELECT cu.*, e.device_model, c.case_ref FROM custody_events cu "
        "JOIN evidence e ON cu.evidence_id=e.id "
        "JOIN cases c ON e.case_id=c.id ORDER BY cu.occurred_at DESC LIMIT 100")
    return render_template("custody_index.html", events=events, event_types=EVENT_TYPES)


@bp.route("/evidence/<int:eid>/add", methods=["GET", "POST"])
@login_required
def add(eid):
    item = query_one("SELECT * FROM evidence WHERE id=?", (eid,))
    if not item:
        abort(404)
    if request.method == "POST":
        evtype = request.form.get("event_type") or "TRANSFER"
        if evtype not in EVENT_TYPES:
            evtype = "TRANSFER"
        from_user = (request.form.get("from_user") or "").strip()
        to_user = (request.form.get("to_user") or "").strip()
        from_loc = (request.form.get("from_location") or "").strip()
        to_loc = (request.form.get("to_location") or "").strip()
        notes = (request.form.get("notes") or "").strip()
        cid = execute(
            "INSERT INTO custody_events(evidence_id,event_type,from_user,to_user,from_location,"
            "to_location,notes,occurred_at) VALUES(?,?,?,?,?,?,?,datetime('now'))",
            (eid, evtype, from_user, to_user, from_loc, to_loc, notes))
        audit(current_app, g_user_id(), g_user_role(), "CUSTODY_EVENT", "custody", cid,
              {"evidence_id": eid, "event_type": evtype, "from_loc": from_loc, "to_loc": to_loc,
               "to_user": to_user}, "info")
        flash(f"Custody event {evtype} recorded.", "success")
        return redirect(url_for("custody.detail", cuid=cid))
    return render_template("custody_form.html", item=item, event_types=EVENT_TYPES, event=None)


@bp.route("/<int:cuid>")
@login_required
def detail(cuid):
    event = query_one(
        "SELECT cu.*, e.device_model, c.case_ref FROM custody_events cu "
        "JOIN evidence e ON cu.evidence_id=e.id JOIN cases c ON e.case_id=c.id WHERE cu.id=?",
        (cuid,))
    if not event:
        abort(404)
    return render_template("custody_detail.html", event=event)


@bp.route("/evidence/<int:eid>/timeline")
@login_required
def timeline(eid):
    item = query_one("SELECT * FROM evidence WHERE id=?", (eid,))
    if not item:
        abort(404)
    events = get_db().execute(
        "SELECT * FROM custody_events WHERE evidence_id=? ORDER BY occurred_at ASC", (eid,)).fetchall()
    return render_template("custody_timeline.html", item=item, events=events)