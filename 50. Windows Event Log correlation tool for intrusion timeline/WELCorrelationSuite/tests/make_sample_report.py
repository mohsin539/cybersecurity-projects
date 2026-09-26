"""Generate a sample executive HTML report into samples/ for visual QA."""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from app import report as rpt
from app import events as evmod
from app.audit import AuditTrail
from app.compliance import coverage_matrix
from app.correlate import analyze
from app.rules import load_rules


def main():
    data = os.path.join(ROOT, "tests", "data", "case_guest.json")
    with open(data, "r", encoding="utf-8") as fh:
        events = evmod.import_json(raw=fh.read())
    rules = load_rules()
    analysis = analyze(events, rules)
    trail = AuditTrail(os.path.join(ROOT, "workspace", "audit"))
    trail.append("user", "sample report", "generated for QA")
    case = {
        "tool": "WEL", "case_id": "C-QA-SAMPLE", "generated_at": analysis["generated_at"],
        "source": {"source": "tests/data/case_guest.json"}, "window_start": None,
        "window_end": None, "events": events, "analysis": analysis,
        "framework": __import__("app.compliance", fromlist=["tool_framework_compliance"]).tool_framework_compliance(),
        "coverage": coverage_matrix(rules), "audit": trail.entries(), "integrity": {},
    }
    html = rpt.html_report(case, trail.stats()).encode("utf-8")
    os.makedirs(os.path.join(ROOT, "samples"), exist_ok=True)
    out = os.path.join(ROOT, "samples", "intrusion_report_sample.html")
    with open(out, "wb") as fh:
        fh.write(html)
    print("wrote", out, len(html), "bytes")


if __name__ == "__main__":
    main()