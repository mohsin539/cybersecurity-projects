"""Main routes: login/logout, dashboard, account & admin user management."""

from flask import (
    Blueprint, flash, redirect, render_template, request, session, url_for, current_app
)
from werkzeug.security import generate_password_hash

from ..db import get_db, query, query_one
from ..security import attempt_login, login_required, role_required, g_user_id, g_user_role
from ..audit import audit
from ..compliance import posture, evidence_counts

bp = Blueprint("main", __name__)


@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        user, err = attempt_login(username, password)
        if user:
            return redirect(url_for("main.dashboard"))
        flash(err or "Login failed", "danger")
    return render_template("login.html")


@bp.route("/logout")
def logout():
    if "uid" in session:
        u = query_one("SELECT id,role FROM users WHERE id=?", (session["uid"],))
        if u:
            audit(current_app, u["id"], u["role"], "LOGOUT", "auth", u["id"], {}, "info")
    session.clear()
    return redirect(url_for("main.login"))


@bp.route("/")
@login_required
def dashboard():
    db = get_db()
    total_cases = db.execute("SELECT COUNT(*) n FROM cases").fetchone()["n"]
    open_cases = db.execute("SELECT COUNT(*) n FROM cases WHERE status != 'closed'").fetchone()["n"]
    evidence = db.execute("SELECT COUNT(*) n FROM evidence").fetchone()["n"]
    artifacts = db.execute("SELECT COUNT(*) n FROM artifacts").fetchone()["n"]
    audits = db.execute("SELECT COUNT(*) n FROM audit_events").fetchone()["n"]
    recent_cases = query(
        "SELECT * FROM cases ORDER BY updated_at DESC LIMIT 6")
    recent_audits = query(
        "SELECT * FROM audit_events ORDER BY id DESC LIMIT 8")
    pos = posture(current_app)
    counts = evidence_counts(current_app)
    by_fw = {}
    for r in pos["rows"]:
        by_fw.setdefault(r["framework"], [0, 0])
        by_fw[r["framework"]][1] += 1
        if r["evidence"]:
            by_fw[r["framework"]][0] += 1
    return render_template(
        "dashboard.html", total_cases=total_cases, open_cases=open_cases,
        evidence=evidence, artifacts=artifacts, audits=audits,
        recent_cases=recent_cases, recent_audits=recent_audits,
        posture=pos, counts=counts, by_fw=by_fw)


@bp.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    if request.method == "POST":
        org = (request.form.get("org_name") or "").strip()
        if org:
            db = get_db()
            db.execute("INSERT INTO settings(key,value) VALUES('org_name',?) "
                       "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (org,))
            db.commit()
            audit(current_app, g_user_id(), g_user_role(), "SETTINGS_UPDATE",
                  "settings", "org_name", {"org_name": org}, "info")
            flash("Settings updated.", "success")
        return redirect(url_for("main.settings"))
    org_row = query_one("SELECT value FROM settings WHERE key='org_name'")
    return render_template("settings.html", org_name=org_row["value"] if org_row else "")


@bp.route("/users", methods=["GET", "POST"])
@login_required
@role_required("admin")
def users():
    db = get_db()
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        display = (request.form.get("display_name") or username).strip()
        role = request.form.get("role")
        password = request.form.get("password") or ""
        if role not in ("admin", "examiner", "auditor"):
            flash("Invalid role.", "danger")
        elif len(password) < 8:
            flash("Password must be at least 8 characters.", "danger")
        else:
            try:
                db.execute("INSERT INTO users(username,password_hash,display_name,role) VALUES(?,?,?,?)",
                           (username, generate_password_hash(password), display, role))
                db.commit()
                audit(current_app, g_user_id(), g_user_role(), "USER_CREATE", "user", username,
                      {"role": role}, "info")
                flash(f"Created user {username}.", "success")
            except Exception:
                flash("Username already exists.", "danger")
        return redirect(url_for("main.users"))
    return render_template("users.html", users=query("SELECT id,username,display_name,role,active,last_login,created_at FROM users ORDER BY id"))


@bp.route("/users/<int:uid>/toggle", methods=["POST"])
@login_required
@role_required("admin")
def toggle_user(uid):
    u = query_one("SELECT * FROM users WHERE id=?", (uid,))
    if u and u["id"] != session["uid"]:
        db = get_db()
        db.execute("UPDATE users SET active=? WHERE id=?", (0 if u["active"] else 1, uid))
        db.commit()
        audit(current_app, g_user_id(), g_user_role(), "USER_UPDATE", "user", u["username"],
              {"active": 0 if u["active"] else 1}, "info")
        flash(f"Updated {u['username']}.", "success")
    return redirect(url_for("main.users"))


@bp.route("/chain/verify")
@login_required
@role_required("auditor", "admin")
def verify_chain():
    from ..audit import verify_chain
    result = verify_chain(current_app)
    audit(current_app, g_user_id(), g_user_role(), "COMPLIANCE_VIEW", "audit", "chain",
          {"result": result}, "info" if result["intact"] else "critical")
    return render_template("chain.html", result=result)