import argparse
import os
import random
import secrets
import time

from flask import Flask, abort, redirect, render_template, request, send_file, session, url_for

from lamdex import DEFAULT_PIN
from lamdex.engine import TECHNIQUES, technique_map, run_technique, seed as engine_seed
from lamdex.metrics import compute, coverage_matrix
from lamdex.report import data_meta, write_bundle
from lamdex.rules import BUILTIN_RULES, evaluate_run, rule_stats
from lamdex.store import Storage

ROOT = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("LAMDEX_DATA_DIR", os.path.join(ROOT, "out"))
DB_PATH = os.path.join(DATA_DIR, "lamdex.db")
OUT_DIR = os.path.join(DATA_DIR, "reports")

PEL = {"critical": 4, "high": 3, "medium": 2, "low": 1}
SEV_BADGE = {"critical": "crit", "high": "high", "medium": "med", "low": "low"}

storage = Storage(DB_PATH)
app = Flask(__name__)
app.secret_key = os.environ.get("LAMDEX_SECRET") or secrets.token_hex(32)
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self'; img-src 'self' data:; "
        "script-src 'self'; connect-src 'self'; frame-ancestors 'none'")
    return resp


def logged_in():
    return session.get("auth") is True


@app.before_request
def gate():
    if request.endpoint in ("login", "static") or request.endpoint is None:
        return None
    if not logged_in():
        return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        pin = request.form.get("pin", "")
        tries = int(session.get("pin_tries", 0))
        if pin == (os.environ.get("LAMDEX_PIN") or DEFAULT_PIN):
            session.clear()
            session["auth"] = True
            session["actor"] = "analyst"
            session["ts"] = time.time()
            storage.audit("analyst", "auth.login", "success")
            return redirect(url_for("dashboard"))
        session["pin_tries"] = tries + 1
        storage.audit("analyst", "auth.login", "denied (attempt %d)" % (tries + 1))
        if tries + 1 >= 5:
            storage.audit("analyst", "auth.lockout", "5 failed attempts")
            return render_template("login.html", error="Temporary lockout. Wait and restart the service.", locked=True), 429
        return render_template("login.html", error="Invalid PIN.", locked=False), 401
    return render_template("login.html", error=None, locked=False)


@app.route("/logout")
def logout():
    storage.audit(session.get("actor", "analyst"), "auth.logout", "session ended")
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
def dashboard():
    runs = storage.list_runs()
    detections = storage.list_detections()
    metrics = compute(runs, detections)
    cov = coverage_matrix(detections)
    recent = detections[:10]
    lab_up = storage.get_lab_state("lab_up") == "1"
    return render_template("dashboard.html",
                           metrics=metrics["totals"], per_tech=metrics["per_technique"],
                           coverage=cov, recent=recent, runs=runs,
                           lab_up=lab_up, actor=session.get("actor", "analyst"),
                           engine=engine_seed(), rules=rule_stats(), reports=storage.list_reports(),
                           detections_count=storage.detection_count())


@app.route("/techniques")
def techniques():
    runs = storage.list_runs()
    ran_ids = {r["technique_id"] for r in runs}
    run_map = {}
    for r in runs:
        run_map.setdefault(r["technique_id"], []).append(r)
    cov_by_id = {c["technique_id"]: c for c in coverage_matrix(storage.list_detections())}
    return render_template("techniques.html", techniques=TECHNIQUES, ran_ids=ran_ids,
                           run_map=run_map, cov_by_id=cov_by_id,
                           lab_up=storage.get_lab_state("lab_up") == "1")


@app.route("/techniques/run", methods=["POST"])
def run_route():
    if not logged_in():
        return redirect(url_for("login"))
    tid = request.form.get("technique_id")
    tech = technique_map().get(tid)
    if not tech:
        abort(404)
    seed_val = time.time_ns()
    rng = random.Random(seed_val)
    run = run_technique(tech, rng)
    detections = evaluate_run(run, rng)
    storage.add_run(run)
    storage.add_detections(detections)
    storage.set_lab_state("last_run", run["run_id"])
    detail = "%s from %s -> %s: %d records, %d detections" % (
        tid, run["source"], run["target"], run["record_count"], len(detections))
    storage.audit(session.get("actor", "analyst"), "technique.run", detail)
    return redirect(url_for("dashboard") + "?runid=" + run["run_id"])


@app.route("/lab/provision", methods=["POST"])
def provision():
    storage.set_lab_state("lab_up", "1")
    storage.audit(session.get("actor", "analyst"), "lab.provision", "isolated AD lab brought up")
    return redirect(url_for("techniques"))


@app.route("/lab/teardown", methods=["POST"])
def teardown():
    storage.set_lab_state("lab_up", "0")
    storage.audit(session.get("actor", "analyst"), "lab.teardown", "isolated AD lab destroyed")
    return redirect(url_for("techniques"))


@app.route("/detections")
def detections():
    technique = request.args.get("technique", "")
    level = request.args.get("level", "")
    dets = storage.list_detections(technique or None, level or None)
    runs = storage.list_runs()
    technique_opts = sorted({r["technique_id"] for r in runs})
    return render_template("detections.html", detections=dets,
                           technique_opts=technique_opts, selected_tech=technique, selected_level=level,
                           actor=session.get("actor", "analyst"))


@app.route("/coverage")
def coverage():
    detections = storage.list_detections()
    runs = storage.list_runs()
    metrics = compute(runs, detections)
    cov = coverage_matrix(detections)
    return render_template("coverage.html", metrics=metrics, coverage=cov, rules=BUILTIN_RULES)


@app.route("/reports")
def reports():
    return render_template("reports.html",
                           reports=storage.list_reports(),
                           data_meta=data_meta(),
                           audit=storage.list_audit(20),
                           engine=engine_seed(),
                           out_dir=OUT_DIR)


@app.route("/reports/generate", methods=["POST"])
def generate():
    if not logged_in():
        return redirect(url_for("login"))
    if storage.run_count() == 0:
        return redirect(url_for("reports") + "?msg=empty")
    os.makedirs(OUT_DIR, exist_ok=True)
    written = write_bundle(storage, OUT_DIR)
    return redirect(url_for("reports") + "?msg=ok&count=%d" % len(written))


@app.route("/reports/download/<report_id>")
def download(report_id):
    rep = storage.get_report(report_id)
    if not rep or not os.path.isfile(rep["path"]):
        abort(404)
    storage.audit(session.get("actor", "analyst"), "report.download", report_id + " (" + rep["format"] + ")")
    resp = send_file(rep["path"], as_attachment=True,
                     download_name=os.path.basename(rep["path"]))
    resp.headers["X-Checksum-Sha256"] = rep["sha256"]
    return resp


@app.route("/audit")
def audit():
    return render_template("audit.html", audit=storage.list_audit(200),
                           engine=engine_seed())


@app.cli.command("demo")
def demo():
    storage.audit("analyst", "demo.start", "running full simulation")
    for tech in TECHNIQUES:
        rng = random.Random(time.time_ns())
        run = run_technique(tech, rng)
        dets = evaluate_run(run, rng)
        storage.add_run(run)
        storage.add_detections(dets)
    storage.set_lab_state("lab_up", "1")
    os.makedirs(OUT_DIR, exist_ok=True)
    written = write_bundle(storage, OUT_DIR)
    print("demo complete: %d runs, %d detects, %d report artifacts" %
          (storage.run_count(), storage.detection_count(), len(written)))


def main():
    ap = argparse.ArgumentParser(description="LAMDEX web console")
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--demo", action="store_true", help="run full simulation before serving")
    ap.add_argument("--run-demo-only", action="store_true", help="simulate + export, then exit")
    args = ap.parse_args()
    if args.demo or args.run_demo_only:
        for tech in TECHNIQUES:
            rng = random.Random(time.time_ns())
            run = run_technique(tech, rng)
            dets = evaluate_run(run, rng)
            storage.add_run(run)
            storage.add_detections(dets)
        storage.set_lab_state("lab_up", "1")
        if args.run_demo_only:
            os.makedirs(OUT_DIR, exist_ok=True)
            written = write_bundle(storage, OUT_DIR)
            print("SIMULATION: %d runs, %d detections" % (storage.run_count(), storage.detection_count()))
            metrics = compute(storage.list_runs(), storage.list_detections())["totals"]
            print("METRICS: precision=%s recall=%s f1=%s (tp=%d fp=%d fn=%d)" %
                  (metrics["precision"], metrics["recall"], metrics["f1"],
                   metrics["tp"], metrics["fp"], metrics["fn"]))
            for w in written:
                print("REPORT: %s (%s bytes) sha256=%s" % (w["kind"], w["size"], w["sha256"]))
            return
    print("LAMDEX web console on http://%s:%d  (PIN: %s)" %
          (args.host, args.port, os.environ.get("LAMDEX_PIN") or DEFAULT_PIN))
    app.run(host=args.host, port=args.port, threaded=True)


if __name__ == "__main__":
    main()