"""smoke_test.py - headless end-to-end verification of the full pipeline."""

from __future__ import annotations

import os
import sys
import tempfile

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
os.environ.setdefault("PCAFLESS_DATA_DIR", tempfile.mkdtemp(prefix="pcapless_test_"))

from app.core import audit, pcap_engine, reports, state, story_engine
from scripts.make_sample_capture import build as build_sample


def main() -> int:
    tmp = tempfile.mkdtemp(prefix="pcapless_smoke_")
    pcap_path = os.path.join(tmp, "sample_triage.pcap")
    build_sample(pcap_path)
    print(f"[1] sample capture written: {pcap_path}")

    db = state.StateDB(os.path.join(tmp, "smoke.db"))
    ab = audit.AuditBus(db, "smoke")

    print("[2] parsing + session reassembly…")
    res = pcap_engine.load_capture(pcap_path)
    print(f"    frames={res['total_frames']} skip={res['decode_errors']} sessions={len(res['sessions'])}")

    cap_id = db.add_capture("DEFAULT", os.path.basename(pcap_path), res["capture_sha256"],
                            os.path.getsize(pcap_path), res["total_frames"])
    for r in res["sessions"]:
        story_engine.build_story(r)
        assert r["story"]["nodes"], f"session {r['session_id']} produced no story nodes"
        assert len(r["story"]["narrative"]) > 0, "narrative empty"
        db.add_session(cap_id, r)
    ab.log("INGEST_SMOKE", os.path.basename(pcap_path), evidence_hash=res["capture_sha256"])

    print("[3] story graphs:")
    for r in res["sessions"]:
        s = r["story"]
        print(f"    {r['flow_key']:42s} l7={r['l7']:7s} risk={s['severity']:8s} ttp={s['ttp']}")

    print("[4] exporting every report format…")
    out = os.path.join(tmp, "reports")
    os.makedirs(out, exist_ok=True)
    for fmt in ("pdf", "html", "json", "csv", "md", "stix", "zip"):
        rid = reports.generate_report(res["sessions"][0], fmt, out, case_id="DEFAULT",
                                      analyst="smoke", clearance=2, report_version=1)
        assert os.path.exists(rid["path"]) and rid["size"] > 0, f"{fmt} produced empty output"
        db.add_report("DEFAULT", res["sessions"][0]["session_id"], fmt, rid["filename"], rid["sha256"], rid["size"])
        print(f"    [OK] {fmt:5s} -> {os.path.basename(rid['path'])} ({rid['size']} B)")

    print("[5] audit chain integrity…")
    ok, bad = ab.verify()
    assert ok and not bad, f"audit chain tampered: {bad}"
    print(f"    [OK] chain intact ({db.audit_count()} events)")

    print("[6] masking at clearance 1 / 0...")
    from app.core.security import mask_ip
    assert mask_ip("10.10.0.55", 1) == "10.10.0.x"
    assert mask_ip("10.10.0.55", 0) == "*.*.*.*"
    print("    [OK] masking works")

    print("\nALL CHECKS PASSED")
    for f in os.listdir(out):
        print("   ", f)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())