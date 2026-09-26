import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from app.persistence.audit import AuditLog
from app.persistence.store import StateStore


def test_audit_chain_verifies(tmp_path):
    log = AuditLog(tmp_path / "audit.log")
    log.append("a", "u", "s", "t", "OK", "d1")
    log.append("b", "u", "s", "t", "OK", "d2")
    log.append("c", "u", "s", "t", "ERR", "d3")
    ok, broken = log.verify()
    assert ok and broken == []
    events = log.read_all()
    assert events[1]["prev_hash"] == events[0]["event_hash"]
    assert events[2]["prev_hash"] == events[1]["event_hash"]


def test_audit_chain_detects_tamper(tmp_path):
    log = AuditLog(tmp_path / "audit.log")
    log.append("a", "u", "s", "t", "OK", "original")
    log.append("b", "u", "s", "t", "OK", "original")
    # tamper with the first event's detail
    events = log.read_all()
    events[0]["detail"] = "CHANGED"
    with open(log.path, "w", encoding="utf-8") as fh:
        import json
        fh.writelines(json.dumps(ev) + "\n" for ev in events)
    ok, broken = log.verify()
    assert not ok
    assert len(broken) >= 1


def test_audit_redaction_never_reaches_file(tmp_path):
    from app.security.redactor import scrub_payload
    log = AuditLog(tmp_path / "audit.log")
    event = log.append("tunnel.build", "operator", "web-ui", "wg0", "OK",
                       scrub_payload({"private_key": "S3CR3T"})["private_key"])
    raw = (tmp_path / "audit.log").read_text(encoding="utf-8")
    assert "S3CR3T" not in raw
    assert "REDACTED" in raw


def test_store_atomic_and_separates_secrets(tmp_path):
    store = StateStore(tmp_path / "data")
    state = store.load_state()
    state["tunnels"] = [{"name": "x", "interface": "wg0"}]
    store.save_state(state)
    store.save_secrets({"private_keys": {"k1": "TOP-SECRET"}})
    assert "TOP-SECRET" not in store.state_path.read_text(encoding="utf-8")
    assert store.load_state()["tunnels"][0]["interface"] == "wg0"
    assert store.load_secrets()["private_keys"]["k1"] == "TOP-SECRET"


def test_settings_schema_strict():
    from app.core.config import validate_settings
    cleaned, errors = validate_settings({"default_listen_port": 51821,
                                         "unknown_key": 1})
    assert errors and "unknown" in errors[0]
    cleaned2, errors2 = validate_settings({"default_listen_port": "51999"})
    assert not errors2
    assert cleaned2["default_listen_port"] == 51999