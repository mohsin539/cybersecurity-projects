"""API-level integration tests: auth, RBAC, scan lifecycle (mocked scanner,
so no Playwright/browser is required in CI)."""

from __future__ import annotations



from app.config import settings


def test_health(client):
    res = client.get("/health")
    assert res.status_code == 200
    assert res.json()["status"] == "ok"


def test_login_failure_and_ratelimit_not_hit(client):
    res = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "wrong-password-123"},
    )
    assert res.status_code == 401


def test_admin_can_login(client):
    res = client.post(
        "/api/auth/login",
        json={
            "username": settings.bootstrap_admin_username,
            "password": settings.bootstrap_admin_password,
        },
    )
    assert res.status_code == 200
    body = res.json()
    assert body["access_token"]
    assert "xt_refresh" in res.cookies
    assert body["user"]["role"] == "admin"


def test_me(client, admin_headers):
    res = client.get("/api/auth/me", headers=admin_headers)
    assert res.status_code == 200
    assert res.json()["user"]["username"] == settings.bootstrap_admin_username


def test_unauthenticated_scan_list_rejected(client):
    res = client.get("/api/scans")
    assert res.status_code in (401, 403)


def test_scan_creation_flow_with_mocked_pipeline(client, admin_headers, monkeypatch):
    from app.api import routes_scans

    captured = {}

    def fake_process(scan_id):
        captured["scan_id"] = scan_id

    # swap the dispatcher so nothing actually runs (no playwright/redis in CI)
    monkeypatch.setattr(routes_scans, "_dispatch", lambda scan_id: fake_process(scan_id))

    res = client.post(
        "/api/scans",
        headers=admin_headers,
        json={"url": "http://localhost:5001/html?name=x", "context": "auto"},
    )
    assert res.status_code == 201, res.text
    scan = res.json()
    assert scan["status"] == "queued"
    assert scan["url"] == "http://localhost:5001/html?name=x"
    assert captured.get("scan_id") == scan["id"]


def test_scan_creation_refuses_external_target(client, admin_headers):
    res = client.post(
        "/api/scans",
        headers=admin_headers,
        json={"url": "https://google.com/x", "context": "auto"},
    )
    assert res.status_code == 422
    assert "allowlist" in res.json()["detail"].lower()


def test_create_viewer_and_role_enforced(client, admin_headers):
    res = client.post(
        "/api/admin/users",
        headers=admin_headers,
        json={"username": "bob", "password": "Bob_Password_2026!", "role": "viewer"},
    )
    assert res.status_code == 201, res.text
    bob = dict(res.json())
    assert bob["role"] == "viewer"

    login = client.post(
        "/api/auth/login", json={"username": "bob", "password": "Bob_Password_2026!"}
    )
    bob_headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

    # viewer cannot create scans
    res2 = client.post(
        "/api/scans",
        headers=bob_headers,
        json={"url": "http://localhost:5001/html?name=x", "context": "html"},
    )
    assert res2.status_code == 403


def test_audit_trail_written_on_events(client, admin_headers):
    from app.db.models import AuditLog
    from app.db.session import SessionLocal

    client.get("/api/scans", headers=admin_headers)  # trigger any call
    db = SessionLocal()
    try:
        count = db.query(AuditLog).count()
        assert count > 0
    finally:
        db.close()


def test_api_key_auth_flow(client, admin_headers):
    res = client.post(
        "/api/admin/api-keys",
        headers=admin_headers,
        json={"role_binding": "engineer", "expires_days": 30},
    )
    assert res.status_code == 201
    key = res.json()["api_key"]
    assert key.startswith("xt_")

    headers = {"X-API-Key": key}
    res2 = client.get("/api/scans", headers=headers)
    assert res2.status_code == 200


def test_target_admin_flow(client, admin_headers):
    created = client.post(
        "/api/admin/targets",
        headers=admin_headers,
        json={"label": "lab", "base_url": "http://localhost:5001"},
    )
    assert created.status_code == 201, created.text
    tid = created.json()["id"]
    denied = client.post(
        "/api/admin/targets",
        headers=admin_headers,
        json={"label": "evil", "base_url": "https://evil.example.com"},
    )
    assert denied.status_code == 422
    gone = client.delete(f"/api/admin/targets/{tid}", headers=admin_headers)
    assert gone.status_code == 200


def test_headers_hardened(client):
    res = client.get("/health")
    assert res.headers.get("x-content-type-options") == "nosniff"
    assert res.headers.get("x-frame-options") == "DENY"
    assert res.headers.get("referrer-policy") == "no-referrer"