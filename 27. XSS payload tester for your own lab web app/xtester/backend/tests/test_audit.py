import json
import tempfile
from pathlib import Path

from app.security.audit import AuditLogger


def _fresh_logger() -> tuple[AuditLogger, Path]:
    tmp = Path(tempfile.mkdtemp(prefix="xtest-audit-"))
    logger = AuditLogger(log_dir=str(tmp), secret="audit-secret")
    return logger, tmp


def test_records_with_chain():
    logger, _ = _fresh_logger()
    e1 = logger.record("auth.login", actor="admin", outcome="success", resource="user")
    e2 = logger.record("scan.create", actor="alice", ip="10.0.0.1")
    assert e1["entry_hash"] and e2["prev_hash"] == e1["entry_hash"]
    assert e1["entry_hash"] != e2["entry_hash"]


def test_chain_verifies_after_clean_writes():
    logger, tmp = _fresh_logger()
    for i in range(5):
        logger.record("test.write", actor="t", details={"i": i})
    ok, detail = logger.verify_chain()
    assert ok, detail


def test_tamper_is_detected():
    logger, tmp = _fresh_logger()
    logger.record("auth.login", actor="admin", outcome="success")
    logger.record("auth.login", actor="bob", outcome="failure", details={"reason": "x"})
    logfile = tmp / "audit.jsonl"
    lines = logfile.read_text(encoding="utf-8").splitlines()
    # tamper with the first record's actor
    altered = json.loads(lines[0])
    altered["actor"] = "attacker"
    lines[0] = json.dumps(altered, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    logfile.write_text("\n".join(lines) + "\n", encoding="utf-8")
    ok, detail = logger.verify_chain()
    assert not ok
    assert "tampered" in detail


def test_two_loggers_agree_on_verification():
    logger, tmp = _fresh_logger()
    logger.record("test", actor="u", details={"secret": "s3cr3t"})
    ok, _ = logger.verify_chain()
    assert ok
    # a fresh logger with the same dir + secret recreates the same chain
    logger2 = AuditLogger(log_dir=str(tmp), secret="audit-secret")
    ok2, detail2 = logger2.verify_chain()
    assert ok2, detail2


def test_secrets_redacted():
    logger, _ = _fresh_logger()
    entry = logger.record("admin.apikey.create", actor="admin", details={"password": "hunter2", "path": "/x"})
    assert "password" in entry["details"]
    assert entry["details"]["password"] == "[REDACTED]"
    assert entry["details"]["path"] == "/x"