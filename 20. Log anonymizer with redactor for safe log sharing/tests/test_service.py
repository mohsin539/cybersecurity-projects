"""End-to-end tests for the anonymizer service and API."""

import pytest

from anonymizer.services import AnonymizationRequest, AnonymizerService, LoadedPolicy


@pytest.fixture
def service(tmp_path):
    from anonymizer.security import AuditTrail

    return AnonymizerService(audit_trail=AuditTrail(output_dir=tmp_path / "audit"))


def test_end_to_end_redaction(service):
    lines = [
        "user john.smith@example.com login failed ssn 123-45-6789",
        "payment card 4539665131016828 processed by ip 10.0.0.5",
    ]
    result = service.anonymize(AnonymizationRequest(lines=lines))
    assert len(result.redacted_lines) == 2
    joined = "\n".join(result.redacted_lines)
    assert "123-45-6789" not in joined
    assert "john.smith@example.com" not in joined
    assert "4539665131016828" not in joined
    assert result.audit_events >= 4


def test_policy_downgrades_security(service):
    service.policies.register(
        LoadedPolicy(
            id="full-lockdown",
            description="No PII at all",
            allowed_data_classes=["SAFE"],
            rules=[],
        )
    )
    result = service.anonymize(
        AnonymizationRequest(
            lines=["call a@b.co error code 500"],
            policy_id="full-lockdown",
        )
    )
    assert "a@b.co" not in result.redacted_lines[0]


def test_default_policy_allows_operational_data(service):
    result = service.anonymize(
        AnonymizationRequest(
            lines=["request completed status=200 duration=45ms"],
        )
    )
    out = result.redacted_lines[0]
    assert "200" in out and "45ms" in out  # operational data preserved


def test_date_shift_applies(service):
    result = service.anonymize(
        AnonymizationRequest(
            lines=["event at 2024-03-15 occurred in service"],
            date_shift_days=7,
        )
    )
    assert "2024-03-22" in result.redacted_lines[0]


def test_audit_ticket_exists(service):
    service.anonymize(AnonymizationRequest(lines=["ssn 555-66-7777 found"]))
    ticket = service.audit.verification_ticket()
    assert ticket["record_count"] >= 1
    assert len(ticket["root"]) == 64


def test_empty_batch_rejected(service):
    from anonymizer.security.input_validation import ValidationError

    with pytest.raises(ValidationError):
        service.anonymize(AnonymizationRequest(lines=[]))


# ---------- API tests ----------


@pytest.fixture
def api_app(tmp_path):
    """Isolated app: each test gets its own audit store (single-writer)."""
    from anonymizer.api.main import create_app
    from anonymizer.security import AuditTrail
    from anonymizer.services import AnonymizerService

    svc = AnonymizerService(audit_trail=AuditTrail(output_dir=tmp_path / "audit"))
    return create_app(svc)


def test_api_ingest_endpoint(api_app):
    from fastapi.testclient import TestClient

    client = TestClient(api_app)
    resp = client.post(
        "/api/v1/ingest",
        json={
            "lines": ["ssn 111-22-3333 in record"],
            "policy_id": "default",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["entity_stats"].get("SSN") == 1
    assert "111-22-3333" not in data["lines"][0]


def test_api_rejects_null_bytes(api_app):
    from fastapi.testclient import TestClient

    client = TestClient(api_app)
    resp = client.post(
        "/api/v1/ingest",
        json={
            "lines": ["bad \x00 input"],
        },
    )
    assert resp.status_code == 400 or resp.status_code == 422


def test_api_healthz(api_app):
    from fastapi.testclient import TestClient

    client = TestClient(api_app)
    assert client.get("/healthz").json()["status"] == "ok"


def test_api_audit_verify(api_app):
    from fastapi.testclient import TestClient

    client = TestClient(api_app)
    client.post("/api/v1/ingest", json={"lines": ["ssn 111-22-3333"]})
    data = client.get("/api/v1/audit/verify").json()
    assert data["verified"] is True


def test_api_policies_list(api_app):
    from fastapi.testclient import TestClient

    client = TestClient(api_app)
    data = client.get("/api/v1/policies").json()
    assert "default" in data["policies"]
