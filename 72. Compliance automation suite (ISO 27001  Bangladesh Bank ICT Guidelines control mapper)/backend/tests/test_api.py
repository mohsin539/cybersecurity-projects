"""Integration tests for the Compliance Automation Suite API."""
import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="module")
def ciso_headers(client):
    r = client.post("/auth/login", json={"username": "ciso", "password": "Ciso@12345"})
    assert r.status_code == 200
    return {"Authorization": f"Bearer {r.json()['token']}"}


@pytest.fixture(scope="module")
def regulator_headers(client):
    r = client.post("/auth/login", json={"username": "regulator", "password": "Regul@12345"})
    assert r.status_code == 200
    return {"Authorization": f"Bearer {r.json()['token']}"}


def test_health(client):
    assert client.get("/health").json()["status"] == "ok"


def test_login_bad_password(client):
    assert client.post("/auth/login", json={"username": "ciso", "password": "wrong"}).status_code == 401


def test_dashboard_summary(client, ciso_headers):
    r = client.get("/dashboard/summary", headers=ciso_headers)
    assert r.status_code == 200
    body = r.json()
    assert "overall" in body["matrix"]
    assert body["kpis"]["frameworks"] == 4
    assert 0 <= body["kpis"]["overall_compliance"] <= 100


def test_controls_catalogue(client, ciso_headers):
    r = client.get("/controls", headers=ciso_headers)
    assert r.status_code == 200
    assert len(r.json()) > 50  # 56 canonical controls seeded
    fws = client.get("/controls/frameworks", headers=ciso_headers).json()
    assert {f["code"] for f in fws} == {"ISO27001", "BBICT2015", "NISTCSF", "OWASP2021"}


def test_mapping_graph_and_overlap_dedupe(client, ciso_headers):
    mapping = client.get("/controls/mapping/list", headers=ciso_headers).json()
    assert mapping["edges"], "expected pre-seeded cross-framework mappings"
    overlaps = client.get("/controls/overlaps", headers=ciso_headers).json()
    assert overlaps["overlap_savings"] >= 1


def test_gap_analysis(client, ciso_headers):
    gaps = client.get("/controls/gaps?framework=ISO27001", headers=ciso_headers).json()
    assert isinstance(gaps, list)
    assert all(g["framework"] == "ISO27001" for g in gaps)


def test_run_assessment(client, ciso_headers):
    r = client.post("/assessments", headers=ciso_headers,
                    json={"name": "pytest ISO", "framework_code": "ISO27001",
                          "method": "AUTO", "scope": "RELEASE"})
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "COMPLETED"
    assert 0 <= body["score"] <= 100
    detail = client.get(f"/assessments/{body['id']}", headers=ciso_headers).json()
    assert len(detail["decisions"]) == 20  # ISO control count


def test_suggest_mapping(client, ciso_headers):
    ctrl = client.get("/controls", headers=ciso_headers).json()[0]
    r = client.get(f"/controls/mapping/suggest/{ctrl['id']}", headers=ciso_headers)
    assert r.status_code == 200
    assert isinstance(r.json()["suggestions"], list)


def test_report_formats(client, ciso_headers):
    for fmt, expected in [("pdf", "application/pdf"),
                          ("docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
                          ("xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
                          ("json", "application/json")]:
        r = client.get(f"/reports/download?report=controls&fmt={fmt}", headers=ciso_headers)
        assert r.status_code == 200
        assert r.headers["content-type"].startswith(expected)
        assert len(r.content) > 100


def test_csv_export(client, ciso_headers):
    r = client.get("/reports/csv?report=risk", headers=ciso_headers)
    assert r.status_code == 200
    assert r.text.startswith("risk_id")


def test_bb_fr_return_xlsx(client, ciso_headers):
    import io
    from openpyxl import load_workbook
    r = client.get("/reports/download?report=bb_fr&fmt=xlsx&period=Q3 2026", headers=ciso_headers)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
    wb = load_workbook(io.BytesIO(r.content))
    assert "Cover Letter" in wb.sheetnames and "Control Return" in wb.sheetnames
    ws = wb["Cover Letter"]
    cover = dict(
        (ws.cell(row=i + 1, column=1).value, ws.cell(row=i + 1, column=2).value)
        for i in range(1, ws.max_row + 1))
    assert cover["Reporting Period"] == "Q3 2026"
    ctrl = wb["Control Return"]
    headers = [c.value for c in ctrl[1]]
    assert "bb_chapter" in headers and "iso_overlap" in headers
    assert ctrl.max_row >= 14  # all 14 seeded BB chapters returned


def test_bb_fr_return_csv_and_regulator_download(client, ciso_headers, regulator_headers):
    r = client.get("/reports/csv?report=bb_fr", headers=ciso_headers)
    assert r.status_code == 200
    assert r.text.startswith("seq")
    rr = client.get("/reports/download?report=bb_fr&fmt=pdf", headers=regulator_headers)
    assert rr.status_code == 200
    assert rr.headers["content-type"] == "application/pdf"


def test_evidence_pack_zip(client, ciso_headers):
    r = client.get("/evidence/pack", headers=ciso_headers)
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/zip"
    assert r.content[:2] == b"PK"


def test_integrity_verification(client, ciso_headers):
    integrity = client.get("/evidence/integrity", headers=ciso_headers).json()
    assert integrity["vault"]["verified"] is True
    assert integrity["audit_chain"]["verified"] is True
    audit_verify = client.get("/audit/verify", headers=ciso_headers).json()
    assert audit_verify["verified"] is True


def test_rbac_regulator_denied_write(client, regulator_headers):
    assert client.post("/assessments", headers=regulator_headers,
                       json={"framework_code": "ISO27001"}).status_code == 403
    assert client.get("/dashboard/summary", headers=regulator_headers).status_code == 200


def test_risk_escalation_flow(client, ciso_headers):
    tickets_before = client.get("/risk/tickets", headers=ciso_headers).json()
    r = client.post("/risk/escalate", headers=ciso_headers, json={})
    assert r.status_code == 200
    tickets_after = client.get("/risk/tickets", headers=ciso_headers).json()
    assert len(tickets_after) >= len(tickets_before)
    sla = client.get("/risk/sla", headers=ciso_headers).json()
    assert "open" in sla and "sla_breaches" in sla