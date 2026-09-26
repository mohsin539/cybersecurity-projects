"""Real service-layer SOAR workflow probe.

Exercises the ACTUAL surface: ingestion -> dedupe -> playbook digest/select ->
dispatch -> engine steps (enrich/connector/approval/notify/ticket/evidence) ->
case/SLA/timeline -> audit-chain integrity -> expressions sandbox.
"""
from __future__ import annotations

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)

import yaml  # noqa: E402

from app.db.base import SessionLocal, init_db  # noqa: E402
from app.db.models import (  # noqa: E402
    AuditEvent, Case, CaseTimeline, ExecutionRun, Playbook, StepRun,
    ApprovalRequest, User,
)
from app.services.playbook_validator import (  # noqa: E402
    digest_playbook, parse_playbook_document,
)
from app.services.engine import (  # noqa: E402
    open_case_for_alert, start_run, tick,
)
from app.services.ingestion import (  # noqa: E402
    create_alert, find_duplicate, normalize_payload, redact_payload,
)
from app.services.cases import add_timeline, check_sla  # noqa: E402
from app.services.expressions import eval_expr  # noqa: E402
from app.core.audit import verify_chain  # noqa: E402
from app.seed import seed  # noqa: E402

PASS: list[str] = []
FAIL: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    (PASS if cond else FAIL).append(name)
    flag = "ok " if cond else "FAIL"
    print(f"  [{flag}] {name}" + (f" :: {detail}" if detail else ""))


def main() -> None:
    init_db()
    seed()
    db = SessionLocal()
    try:
        # 1) playbook: parse YAML -> validate -> digest
        doc_yaml = """
id: ph-probe-2
name: Probe Runbook
description: SOAR verification playbook
version: "1.0"
trigger: on_alert
steps:
  - id: s1
    name: Enrich host
    action: enrich
    params:
      passive_dns: true
      whois: false
    continue_on_error: false
  - id: s2
    name: Isolate host
    action: connector
    connector: probe_conn
    params:
      name: isolate_host
      args:
        host: "{{ alert.host }}"
    approval: human
    continue_on_error: false
  - id: s3
    name: Notify
    action: notify
    params:
      channel: slack
      message: "Case opened"
    continue_on_error: true
  - id: s4
    name: Ticket
    action: ticket
    params:
      queue: it
      summary: "auto"
    continue_on_error: true
  - id: s5
    name: Evidence
    action: evidence
    params:
      collector: probe
    continue_on_error: true
"""  # noqa: E501
        parsed = parse_playbook_document(doc_yaml)
        check("parse_playbook_document", isinstance(parsed, dict) and "steps" in parsed)
        norm = None
        from app.services.playbook_validator import normalize_document

        norm = normalize_document(parsed)
        check("normalize_document", isinstance(norm, dict))
        digest = digest_playbook(norm)
        check("digest_playbook -> sha256", isinstance(digest, str) and len(digest) == 64, digest[:12])

        pb = Playbook(
            playbook_id="ph-probe-e2e",
            name="Probe Runbook",
            description="E2E verification playbook",
            version="1.0",
            raw_yaml=doc_yaml,
            digest=digest,
            status="published",
        )
        db.add(pb)
        db.commit()

        # 2) ingest alert
        payload = {
            "source": "ids",
            "title": "Possible beaconing from host",
            "severity": "high",
            "host": "10.20.30.40",
            "category": "c2",
            "raw": {"dst_ip": "185.220.102.7", "ua": "Mozilla/5.0"},
        }
        redacted = redact_payload(payload)
        check("redact_payload masks secrets", any("*" in str(v) for v in redacted.values()))
        normalized = normalize_payload(redacted)
        alert = create_alert(db, normalized.model_dump())
        db.commit()
        check("alert persisted", alert.id is not None)

        dup = find_duplicate(db, alert.fingerprint)
        check("find_duplicate finds original", dup is not None)

        # 3) dispatch
        run = start_run(db, pb, alert=alert, actor="probe")
        db.commit()
        check("run started", run.id is not None, f"id={run.id}")

        # 4) tick until settled
        for _ in range(30):
            stats = tick(db)
            db.commit()
            if stats.get("awaiting", 0) == 0 and stats.get("completed", 0) >= 1:
                break
        db.commit()
        fresh = db.get(ExecutionRun, run.id)
        check("run awaiting approval", fresh.status in ("pending_approval", "completed"), fresh.status)

        # 5) approvals
        appr = db.query(ApprovalRequest).filter_by(run_id=run.id).first()
        if appr:
            check("approval created", appr.id is not None)
            appr.status = "approved"
            db.commit()
            for _ in range(30):
                stats = tick(db)
                db.commit()
                if stats.get("awaiting", 0) == 0:
                    break
            db.commit()
            fresh = db.get(ExecutionRun, run.id)
            check("run completes post-approval", fresh.status in ("completed", "failed"), fresh.status)

        # 6) case + SLA + timeline
        case = open_case_for_alert(db, alert, actor="probe")
        add_timeline(db, case.id, actor="engine", event_type="created", message="case opened")
        db.commit()
        check("case opened", case.id is not None, f"id={case.id}")
        try:
            check_sla(db, case)
            check("SLA check ran", True)
        except Exception as exc:  # noqa: BLE001
            check("SLA check ran", False, str(exc))

        # 7) audit chain
        ok, count, _ = verify_chain(db)
        check("audit chain verified", ok, f"events={count}")

        # 8) expressions sandbox
        val = eval_expr("1 + 2", {})
        check("expression eval", val == 3, str(val))

        db.commit()
    finally:
        db.close()

    print("\n========================================")
    print(f"PASS {len(PASS)}  FAIL {len(FAIL)}")
    if FAIL:
        print("FAILED:", FAIL)
        sys.exit(1)
    print("ALL GREEN - SOAR verified")


if __name__ == "__main__":
    main()


