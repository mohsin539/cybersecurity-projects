from datetime import datetime, timezone

from exports import sign
from mitre_data import CONTROLS, MITRE_TECHNIQUES
from models import (BlueDetection, Case, Control, Evidence, MitreTechnique,
                    RedAttack, User, audit, db)


def seed_if_empty():
    if MitreTechnique.query.count():
        return
    for tid, name, tactic, desc, platforms in MITRE_TECHNIQUES:
        db.session.add(MitreTechnique(id=tid, name=name, tactic=tactic,
                                      description=desc, platforms=platforms))
    for code, title, desc, nist, owasp, status in CONTROLS:
        db.session.add(Control(code=code, title=title, description=desc,
                               nist_ref=nist, owasp_ref=owasp, iso_ref=code,
                               status=status))
    db.session.add_all([
        User(username="red-ops", role="red", full_name="Red Operations"),
        User(username="blue-soc", role="blue", full_name="Blue SOC Analyst"),
    ])

    c = Case(title="Operation Phantom Basilisk", status="running", owner="red-ops",
             scope="Sandboxed Windows lab (single AD forest; no production assets).",
             rules_of_engagement="No DNS changes, no cloud blowback, stop clock on 4h.",
             lessons="")
    db.session.add(c)
    db.session.flush()

    chain = [
        ("T1566", True, "detected", "SIGMA-Phish-Adversary"),
        ("T1190", True, "detected", "WAF-SQLi-Burst"),
        ("T1059", True, "detected", "AMSI-PS-Runspace"),
        ("T1547", True, "partial",  "Sysmon-13-Autostart"),
        ("T1562", True, "partial",  "EDR-Heartbeat"),
        ("T1003", True, "detected", "LSASS-Sensitive-Read"),
        ("T1021", True, "missed",   None),
    ]
    now = datetime.now(timezone.utc)
    for i, (tid, ok, det, rule) in enumerate(chain, start=1):
        t = MitreTechnique.query.get(tid)
        a = RedAttack(case_id=c.id, technique_id=tid,
                      title="Step %d: %s" % (i, t.name),
                      payload="demo-payload-%s.bin --silent" % tid.lower(),
                      status="success" if ok else "failed",
                      finished_at=now,
                      telemetry_ref="telemetry/%s/events.json" % tid)
        db.session.add(a)
        db.session.flush()
        if i % 2:
            ev = Evidence(attack_id=a.id, kind="pcap", description="Capture for %s" % tid,
                          file_ref="evidence/%s.pcap" % tid, sha256=sign(b"pcap"))
        else:
            ev = Evidence(attack_id=a.id, kind="screenshot", description="Screen grab for %s" % tid,
                          file_ref="evidence/%s.png" % tid, sha256=sign(b"png"))
        db.session.add(ev)
        db.session.add(BlueDetection(case_id=c.id, red_attack_id=a.id, technique_id=tid,
                                     status=det, rule_ref=rule, analyst="blue-soc",
                                     detected_at=now))
    c.recompute_align()
    db.session.commit()
    audit("system", "seed database", c.title)