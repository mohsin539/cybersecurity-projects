import io

from flask import Flask, abort, jsonify, render_template, request, send_file, url_for

from exports import build_csv, build_html, build_xlsx, sign
from models import (AuditLog, BlueDetection, Case, Control, Evidence, MitreTechnique,
                    RedAttack, audit, db)
from seed_db import seed_if_empty

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///purple.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db.init_app(app)


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    resp.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'"
    resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return resp


@app.route("/")
def dashboard():
    cases = Case.query.order_by(Case.created_at.desc()).all()
    techniques = MitreTechnique.query.all()
    missed_tactics = {}
    for case in cases:
        for a in case.attacks:
            det = BlueDetection.query.filter_by(red_attack_id=a.id).first()
            if det is None or det.status == "missed":
                missed_tactics.setdefault(a.technique.tactic, 0)
                missed_tactics[a.technique.tactic] += 1
    stats = {
        "cases": len(cases),
        "attacks": RedAttack.query.count(),
        "detections": BlueDetection.query.count(),
        "avg_align": (round(sum(c.alignment_score for c in cases) / len(cases), 1)
                      if cases else 0),
        "controls_ok": Control.query.filter_by(status="implemented").count(),
        "controls": Control.query.count(),
        "missed_tactics": missed_tactics,
    }
    return render_template("dashboard.html", cases=cases, techniques=techniques,
                           stats=stats, active="dashboard")


@app.route("/cases")
def cases():
    return render_template("cases.html", cases=Case.query.order_by(Case.created_at.desc()).all(),
                           active="cases")


@app.route("/case/<int:case_id>")
def case_view(case_id):
    case = Case.query.get_or_404(case_id)
    techniques = MitreTechnique.query.order_by(MitreTechnique.name).all()
    return render_template("case_view.html", case=case, techniques=techniques,
                           active="cases")


@app.post("/case/<int:case_id>/attack")
def add_attack(case_id):
    case = Case.query.get_or_404(case_id)
    tid = request.form.get("technique_id")
    if not tid or not MitreTechnique.query.get(tid):
        abort(400)
    title = request.form.get("title") or MitreTechnique.query.get(tid).name
    a = RedAttack(case_id=case.id, technique_id=tid, title=title,
                  payload=request.form.get("payload"),
                  status=request.form.get("status", "running"))
    db.session.add(a)
    db.session.flush()
    db.session.add(Evidence(attack_id=a.id, kind="log",
                            description="execution kickoff", file_ref="-"))
    case.recompute_align()
    db.session.commit()
    audit("red-ops", "launched attack", "%s | %s" % (case.title, tid))
    return redirect_case(case.id)


@app.post("/case/<int:case_id>/detect")
def add_detection(case_id):
    case = Case.query.get_or_404(case_id)
    tid = request.form.get("technique_id")
    attack_id = request.form.get("attack_id") or None
    if not tid or not MitreTechnique.query.get(tid):
        abort(400)
    db.session.add(BlueDetection(case_id=case.id, red_attack_id=attack_id,
                                 technique_id=tid,
                                 status=request.form.get("status", "missed"),
                                 rule_ref=request.form.get("rule_ref"),
                                 analyst=request.form.get("analyst", "blue-soc")))
    case.recompute_align()
    db.session.commit()
    audit("blue-soc", "recorded detection", "%s | %s" % (case.title, tid))
    return redirect_case(case.id)


def redirect_case(cid):
    return render_template("case_view.html", case=Case.query.get(cid),
                           techniques=MitreTechnique.query.order_by(MitreTechnique.name).all(),
                           active="cases",
                           msg="Saved and audit-logged.")


@app.route("/reports")
def reports():
    cases = Case.query.all()
    return render_template("reports.html", cases=cases, controls=Control.query.all(),
                           active="reports")


@app.route("/export/xlsx")
def export_xlsx():
    cid = request.args.get("case_id", type=int)
    blob = build_xlsx(cid)
    audit("red-ops", "exported XLSX", "case=%s" % cid)
    return send_file(blob, as_attachment=True, download_name="purple-team-report.xlsx",
                     mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")


@app.route("/export/csv")
def export_csv():
    kind = request.args.get("kind", "mapping")
    cid = request.args.get("case_id", type=int)
    blob = build_csv(kind, cid)
    audit("blue-soc", "exported CSV", "kind=%s case=%s" % (kind, cid))
    return send_file(blob, as_attachment=True, download_name="purple-team-%s.csv" % kind,
                     mimetype="text/csv")


@app.route("/export/html")
def export_html():
    cid = request.args.get("case_id", type=int)
    blob = io.BytesIO(build_html(cid))
    audit("auditor", "exported HTML" , "case=%s" % cid)
    return send_file(blob, as_attachment=True,
                     download_name="purple-team-case-%s.html" % cid,
                     mimetype="text/html")


@app.route("/api/stats")
def api_stats():
    cases = Case.query.all()
    return jsonify({
        "cases": len(cases),
        "attacks": RedAttack.query.count(),
        "detections": BlueDetection.query.count(),
        "avg_align": (round(sum(c.alignment_score for c in cases) / len(cases), 1)
                      if cases else 0),
    })


@app.route("/api/audit")
def api_audit():
    logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(20).all()
    return jsonify([{"actor": l.actor, "action": l.action, "target": l.target,
                     "at": l.created_at.isoformat()} for l in logs])


with app.app_context():
    db.create_all()
    seed_if_empty()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True, use_reloader=False)