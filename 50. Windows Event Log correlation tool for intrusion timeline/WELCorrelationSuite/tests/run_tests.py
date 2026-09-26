"""End-to-end engine tests on the synthetic guest scenario.

Validates collection->import->correlation->timeline->compliance->
reporting->audit without the HTTP layer (pure engine), then optionally
smoke-tests the HTTP server + UI assets.
"""
import os
import shutil
import sys
import traceback

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from app import events as evmod                       # noqa: E402
from app import report as rpt                         # noqa: E402
from app.audit import AuditTrail                      # noqa: E402
from app.compliance import coverage_matrix            # noqa: E402
from app.correlate import analyze                     # noqa: E402
from app.rules import load_rules                      # noqa: E402

CHECKS = []


def check(name, cond, extra=""):
    CHECKS.append((name, bool(cond), extra))
    print(("PASS " if cond else "FAIL ") + name + ("  [" + extra + "]" if extra else ""))


def main():
    data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
    case_path = os.path.join(data_dir, "case_guest.json")
    if not os.path.exists(case_path):
        from tests import make_dataset
        import importlib
        importlib.reload(make_dataset)
        make_dataset.main()

    with open(case_path, "r", encoding="utf-8") as fh:
        raw = fh.read()
    events = evmod.import_json(raw=raw)
    check("dataset imported", len(events) > 30, "%d events" % len(events))

    rules = load_rules()
    check("rules loaded", len(rules) == 40, "%d rules" % len(rules))

    analysis = analyze(events, rules)
    s = analysis["summary"]
    ids = {i["rule_id"] for i in analysis["incidents"]}
    check("log-clearing detected (R-008)", "R-008" in ids)
    check("brute-force detected (R-005)", "R-005" in ids)
    check("account created (R-001)", "R-001" in ids)
    check("priv group add (R-003)", "R-003" in ids)
    check("RDP logon (R-006)", "R-006" in ids)
    check("service installed (R-009)", "R-009" in ids)
    check("scheduled task (R-010)", "R-010" in ids)
    check("powershell exec (R-011)", "R-011" in ids)
    check("lsass dump (R-013)", "R-013" in ids)
    check("defender detection (R-019)", "R-019" in ids)
    check("lockout burst (R-004)", "R-004" in ids)
    check("audit-policy change (R-040)", "R-040" in ids)
    check("kill-chain phases detected", s["phase_count"] >= 6, str(s["phase_count"]))
    check("risk score computed", s["risk_score"] > 30, str(s["risk_score"]))
    check("campaigns clustered", s["campaigns"] >= 1, str(s["campaigns"]))
    check("mitre mapping populated", len(analysis["mitre"]) >= 5,
          "%d tactics" % len(analysis["mitre"]))
    check("surges detected", s["spikes"] >= 1, str(s["spikes"]))
    check("top users identified", len(s["top_users"]) >= 3)

    cov = coverage_matrix(rules)
    check("ISO controls mapped", len(cov["iso_27001"]) >= 10, "%d" % len(cov["iso_27001"]))
    check("NIST categories mapped", len(cov["nist_csf"]) >= 5, "%d" % len(cov["nist_csf"]))

    case = {
        "tool": "app", "case_id": "C-TEST", "generated_at": "2026-09-15T10:00:00Z",
        "source": {"source": "synthetic"}, "window_start": None, "window_end": None,
        "events": events, "analysis": analysis, "framework": {},
        "coverage": cov, "audit": [], "integrity": {},
        "filler": "x" * 500,
    }
    html = rpt.html_report(case).encode("utf-8")
    check("HTML report generated", len(html) > 30000, "%d bytes" % len(html))
    check("HTML report has risk section", b"Overall Risk" in html or b"risk" in html.lower())
    check("HTML report embeds integrity block", b"SHA-256" in html)

    csv_e = rpt.csv_events(case).decode("utf-8-sig")
    check("CSV event export", csv_e.count("\n") >= len(events) and "timestamp" in csv_e.lower())
    csv_t = rpt.csv_timeline(case).decode("utf-8-sig")
    check("CSV timeline export", "stage" in csv_t.lower())

    j = rpt.json_case(case).decode("utf-8")
    check("JSON case export", '"events"' in j and '"incidents"' in j)

    work = os.path.join(data_dir, "_audit_test")
    shutil.rmtree(work, ignore_errors=True)
    trail = AuditTrail(work)
    trail.append("tester", "test", "engine suite")
    trail.append("user", "report", "downloaded HTML")
    ok, broken = trail.verify()
    check("audit chain valid", ok, "" if ok else repr(broken))
    check("audit entries persisted", len(trail.entries()) >= 2)

    failed = [n for n, p, _ in CHECKS if not p]
    print("\n%d/%d passed" % (len(CHECKS) - len(failed), len(CHECKS)))
    if failed:
        print("FAILED: %s" % ", ".join(failed))
        sys.exit(1)
    print("ENGINE TESTS: ALL GREEN")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        traceback.print_exc()
        sys.exit(2)