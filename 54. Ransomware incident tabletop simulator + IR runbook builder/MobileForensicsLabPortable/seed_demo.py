"""Optional demo seed: creates a representative case with evidence, custody
events and artifacts so dashboards and compliance posture are populated.

Usage:
    python seed_demo.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mfl import create_app
from mfl.db import get_db
from mfl.audit import audit, ACTIONS

app = create_app()


def main():
    with app.app_context():
        db = get_db()
        if db.execute("SELECT 1 FROM cases WHERE case_ref='DEMO-2026-001'").fetchone():
            print("Demo case already exists — skipping.")
            return

        cid = db.execute(
            "INSERT INTO cases(case_ref,title,description,status,severity,lead_examiner,created_by)"
            " VALUES('DEMO-2026-001','Suspicious exfiltration on corporate device',"
            "'Imaged a Samsung Galaxy S22 following a data-exfiltration alert from HR.','active',"
            "'high','A. Reyes',1)").lastrowid
        eid = db.execute(
            "INSERT INTO evidence(case_id,device_serial,device_model,manufacturer,os_type,imei,"
            "phone_number,carrier,acquisition_method,acquired_by,location,sha256,status,custodian,notes)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (cid, "SM-S901B-XYZ9", "Galaxy S22 5G", "Samsung", "Android 13 (One UI 5.1)",
             "359147065412549", "+1-555-0148", "MALCO", "logical", "A. Reyes", "Evidence Room 2 · Locker B",
             "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", "analyzed",
             "P. Okafor", "Acquired with mobile forensics workstation MFL-01.")).lastrowid
        db.execute(
            "INSERT INTO custody_events(evidence_id,event_type,from_user,to_user,from_location,"
            "to_location,notes,occurred_at) VALUES(?,?,?,?,?,?,?,datetime('now','-6 hours'))",
            (eid, "TRANSFER", "A. Reyes", "P. Okafor", "Evidence Room 2 · Locker B",
             "Analysis Bay 3", "Transferred for analysis."))
        for rec in [
            ("call_log", "Outgoing call to known C2?", "+15551234567", "calls at 03:12–03:14 UTC", "high"),
            ("sms", "Exfil drop message", "SMS with Mega.nz link & password", "Click:\n" "hxxps://mega.nz/#!Exfil", "critical"),
            ("geo", "Location history gap", "Airplane mode 02:00-04:00 UTC", "No cell/network pings in window", "medium"),
            ("app", "Unflagged messaging app", "Signal (unknown account)", "Package com.signal.android (non-corporate)", "low"),
            ("crypto", "Wallet app present", "Coinbase Wallet", "Package com.coinbase.wallet · 0 tx logs", "info"),
        ]:
            db.execute(
                "INSERT INTO artifacts(evidence_id,category,name,detail,value,timestamp,severity,artifact_hash,created_by)"
                " VALUES(?,?,?,?,?,datetime('now','-4 hours'),?,?,1)",
                (eid, rec[0], rec[1], rec[2], rec[3], rec[4],
                 "5d41402abc4b2a76b9719d911017c592" + rec[0]))
        db.commit()

        for action in ("CASE_CREATE", "EVIDENCE_CREATE", "CUSTODY_EVENT",
                       "ARTIFACT_CREATE", "ARTIFACT_CREATE", "ARTIFACT_CREATE",
                       "ARTIFACT_CREATE", "ARTIFACT_CREATE"):
            audit(app, 1, "admin", action, "demo", cid, {"seed": True}, "info")

        print("Seeded DEMO-2026-001 with evidence, custody events and 5 artifacts.")
        print("Log in with the bootstrap credentials and open the dashboard.")


if __name__ == "__main__":
    main()