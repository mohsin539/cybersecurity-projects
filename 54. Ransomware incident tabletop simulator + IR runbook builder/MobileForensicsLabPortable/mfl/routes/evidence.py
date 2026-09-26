"""Evidence intake routes (OWASP A01: examiner+ roles only)."""

import hashlib

from flask import (
    Blueprint, abort, current_app, flash, redirect, render_template, request, url_for
)

from ..db import execute, get_db, query, query_one
from ..security import login_required, role_required, g_user_id, g_user_role
from ..audit import audit

bp = Blueprint("evidence", __name__, url_prefix="/evidence")

ACQ_METHODS = ("logical", "physical", "chip-off", "cloud", "manual")
STATUSES = ("intake", "acquired", "analyzed", "sealed", "disposed")


def _norm_hash(value):
    v = ((value or "").strip() or "").lower()
    if v and len(v) == 64 and all(c in "0123456789abcdef" for c in v):
        return v
    return ""


@bp.route("/case/<int:cid>/new", methods=["GET", "POST"])
@login_required
def create(cid):
    case = query_one("SELECT * FROM cases WHERE id=?", (cid,))
    if not case:
        abort(404)
    if request.method == "POST":
        model = (request.form.get("device_model") or "").strip()
        if not model:
            flash("Device model is required.", "danger")
        else:
            serial = (request.form.get("device_serial") or "").strip()
            sha256 = _norm_hash(request.form.get("sha256"))
            storage_hash = _norm_hash(request.form.get("storage_hash")) or sha256
            acq = request.form.get("acquisition_method") or "logical"
            if acq not in ACQ_METHODS:
                acq = "logical"
            eid = execute(
                "INSERT INTO evidence(case_id,device_serial,device_model,manufacturer,os_type,imei,"
                "phone_number,carrier,acquisition_method,acquired_by,acquired_at,location,"
                "storage_hash,sha1,sha256,status,custodian,notes)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,datetime('now'),?,?,?,?,?,?,?)",
                (cid, serial, model, (request.form.get("manufacturer") or "").strip(),
                 (request.form.get("os_type") or "").strip(), (request.form.get("imei") or "").strip(),
                 (request.form.get("phone_number") or "").strip(), (request.form.get("carrier") or "").strip(),
                 acq, (request.form.get("acquired_by") or "").strip(),
                 (request.form.get("location") or "").strip(), storage_hash,
                 _norm_hash(request.form.get("sha1")), sha256, "intake",
                 (request.form.get("custodian") or "").strip(),
                 (request.form.get("notes") or "").strip()))
            audit(current_app, g_user_id(), g_user_role(), "EVIDENCE_CREATE", "evidence", eid,
                  {"case_id": cid, "model": model, "acq": acq, "sha256_head": sha256[:12] if sha256 else "-"}, "info")
            flash("Evidence recorded. Keep the device sealed until analysis.", "success")
            return redirect(url_for("evidence.detail", eid=eid))
    return render_template("evidence_form.html", case=case, item=None,
                           acq_methods=ACQ_METHODS, statuses=STATUSES, action="Add")


@bp.route("/<int:eid>")
@login_required
def detail(eid):
    item = query_one("SELECT * FROM evidence WHERE id=?", (eid,))
    if not item:
        abort(404)
    case = query_one("SELECT * FROM cases WHERE id=?", (item["case_id"],))
    custody = query("SELECT * FROM custody_events WHERE evidence_id=? ORDER BY occurred_at DESC", (eid,))
    artifacts = query("SELECT * FROM artifacts WHERE evidence_id=? ORDER BY id DESC", (eid,))
    return render_template("evidence_detail.html", item=item, case=case,
                           custody=custody, artifacts=artifacts)


@bp.route("/<int:eid>/edit", methods=["GET", "POST"])
@login_required
def update(eid):
    item = query_one("SELECT * FROM evidence WHERE id=?", (eid,))
    if not item:
        abort(404)
    case = query_one("SELECT * FROM cases WHERE id=?", (item["case_id"],))
    if request.method == "POST":
        status = request.form.get("status") or item["status"]
        if status not in STATUSES:
            status = item["status"]
        sha256 = _norm_hash(request.form.get("sha256"))
        get_db().execute(
            "UPDATE evidence SET device_serial=?,manufacturer=?,os_type=?,imei=?,phone_number=?,"
            "carrier=?,acquisition_method=?,acquired_by=?,location=?,storage_hash=?,sha1=?,sha256=?,"
            "status=?,custodian=?,notes=?,updated_at=datetime('now') WHERE id=?",
            ((request.form.get("device_serial") or "").strip(), (request.form.get("manufacturer") or "").strip(),
             (request.form.get("os_type") or "").strip(), (request.form.get("imei") or "").strip(),
             (request.form.get("phone_number") or "").strip(), (request.form.get("carrier") or "").strip(),
             request.form.get("acquisition_method") or item["acquisition_method"],
             (request.form.get("acquired_by") or "").strip(), (request.form.get("location") or "").strip(),
             _norm_hash(request.form.get("storage_hash")) or sha256, _norm_hash(request.form.get("sha1")),
             sha256, status, (request.form.get("custodian") or "").strip(),
             (request.form.get("notes") or "").strip(), eid))
        get_db().commit()
        audit(current_app, g_user_id(), g_user_role(), "EVIDENCE_UPDATE", "evidence", eid,
              {"status": status, "sha256_head": sha256[:12] if sha256 else "-"}, "info" if status != "sealed" else "medium")
        flash("Evidence updated.", "success")
        return redirect(url_for("evidence.detail", eid=eid))
    return render_template("evidence_form.html", case=case, item=item,
                           acq_methods=ACQ_METHODS, statuses=STATUSES, action="Edit")


@bp.route("/<int:eid>/delete", methods=["POST"])
@login_required
@role_required("admin")
def delete(eid):
    item = query_one("SELECT * FROM evidence WHERE id=?", (eid,))
    if item:
        audit(current_app, g_user_id(), g_user_role(), "EVIDENCE_DELETE", "evidence", eid,
              {"model": item["device_model"]}, "critical")
        execute("DELETE FROM evidence WHERE id=?", (eid,))
        flash("Evidence entry deleted (audit retained).", "warning")
    return redirect(url_for("cases.detail", cid=item["case_id"] if item else 0))