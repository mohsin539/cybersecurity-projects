"""End-to-end integration — full scan, IOC escalation, verify, seal, CLI."""
import json

import pytest

from sap.app import SAPController, ScanConfig
from sap.security.policy import PolicyViolation

from helpers import build_minimal_pe


def test_scan_pipeline_end_to_end(tmp_path, minimal_pe):
    case = str(tmp_path / "case")
    ctl = SAPController(case, ScanConfig(analyst="tester"))
    card = ctl.scan_sample(minimal_pe)

    assert card["schema"] == "sap.triage_card.v1"
    assert card["scan"]["status"] == "complete"
    assert card["sample"]["original_name"] == "sample.exe"
    assert len(card["digests"]["sha256"]) == 64
    assert card["strings_summary"]["ascii_count"] >= 1
    assert card["pe_summary"]["machine"] == "I386"
    assert card["pe_summary"]["bitness"] == "PE32"
    assert card["pe_summary"]["overlay_size"] > 0
    assert card["risk"]["score"] >= 0
    assert card["audit"]["ledger_events"] >= 6
    assert card["scan"]["engines"] == {"strings": "ok", "pe": "ok", "intel": "ok"}

    reports = card["_reports"]
    for fname in (f"{card['_scan_id']}.json", f"{card['_scan_id']}.csv",
                  f"{card['_scan_id']}.html", f"{card['_scan_id']}.stix.json"):
        assert (tmp_path / "case" / "reports" / fname).exists()
    json.loads((tmp_path / "case" / "reports" / f"{card['_scan_id']}.json").read_text("utf-8"))


def test_ioc_bloom_and_malicious_floor(tmp_path, minimal_pe):
    case = str(tmp_path / "case")
    ctl = SAPController(case, ScanConfig(analyst="tester"))
    ctl.scan_sample(minimal_pe)
    sha = ctl.store.get_last_scan()["sha256"]

    ctl.add_ioc(sha, "malicious", reference="test-vault")
    ctl2 = SAPController(case, ScanConfig(analyst="tester"))
    card = ctl2.scan_sample(minimal_pe)
    assert card["intel"]["highest_verdict"] == "malicious"
    assert card["risk"]["score"] == 80
    assert card["risk"]["band"] == "high"
    assert any(f["rule_id"] == "SAP-I-MAL" for f in card["findings"])

    # bloom + facts persisted
    from sap.data.sandbox import CaseDir
    case_dir = CaseDir(case)
    assert case_dir.get_bloom().contains_hex(sha)
    facts = json.loads(case_dir.facts_path.read_text("utf-8"))
    assert facts[sha]["verdict"] == "malicious"


def test_verify_ok_after_scan(tmp_path, minimal_pe):
    case = str(tmp_path / "case")
    ctl = SAPController(case, ScanConfig(analyst="tester"))
    ctl.scan_sample(minimal_pe)
    report = ctl.verify(rehash_path=minimal_pe)
    assert report["ok"] is True
    assert report["audit"]["ok"] and report["custody"]["ok"]
    assert report["rehash"]["ok"] is True


def test_seal_writes_package(tmp_path, minimal_pe):
    case = str(tmp_path / "case")
    ctl = SAPController(case, ScanConfig(analyst="tester"))
    ctl.scan_sample(minimal_pe)
    out = ctl.seal(password="hunter2")
    pkg = out["package"]
    assert pkg.endswith(".sapcase")
    assert (tmp_path / "case.sapcase").exists()
    assert out["seals"]["audit"]["signature_hex"]
    assert out["seals"]["custody"]["signature_hex"]


def test_size_gate_fails_closed(tmp_path, minimal_pe):
    case = str(tmp_path / "case")
    ctl = SAPController(case, ScanConfig(analyst="tester", max_bytes=1))
    with pytest.raises(PolicyViolation):
        ctl.scan_sample(minimal_pe)


def test_missing_sample_raises(tmp_path):
    ctl = SAPController(str(tmp_path / "case"))
    with pytest.raises(PolicyViolation):
        ctl.scan_sample(tmp_path / "missing.exe")


def test_non_pe_is_isolated_not_fatal(tmp_path):
    case = str(tmp_path / "case")
    ctl = SAPController(case, ScanConfig(analyst="tester"))
    txt = tmp_path / "script.txt"
    txt.write_text("This is just a plain text script, not a PE at all.\n", "utf-8")
    card = ctl.scan_sample(txt)
    assert card["pe_summary"]["status"] == "not-pe"
    assert card["scan"]["status"] == "complete"
    assert card["_scan_id"]


def test_add_ioc_rejects_bad_verdict(tmp_path):
    ctl = SAPController(str(tmp_path / "case"))
    with pytest.raises(PolicyViolation):
        ctl.add_ioc("ab" * 32, "super-malicious")


def test_cli_scan_subcommand(tmp_path, minimal_pe, capsys):
    from sap.cli import main

    case = str(tmp_path / "cli_case")
    rc = main(["scan", str(minimal_pe), "--case-dir", case, "--no-reports"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "SAP TRIAGE CARD" in out
    assert "risk" in out
    assert (tmp_path / "cli_case" / "audit" / "ledger.jsonl").exists()


def test_cli_info_and_doctor(tmp_path):
    from sap.cli import main

    rc = main(["info"])
    assert rc == 0
    rc = main(["doctor"])
    assert rc == 0


def test_second_scan_same_sample_consistent(tmp_path, minimal_pe):
    case = str(tmp_path / "case")
    ctl1 = SAPController(case, ScanConfig(analyst="a"))
    c1 = ctl1.scan_sample(minimal_pe)
    ctl2 = SAPController(case, ScanConfig(analyst="b"))
    c2 = ctl2.scan_sample(minimal_pe)
    assert c1["digests"]["sha256"] == c2["digests"]["sha256"]
    assert c1["sample"]["size_bytes"] == c2["sample"]["size_bytes"]
    assert c1["risk"]["band"] == c2["risk"]["band"]