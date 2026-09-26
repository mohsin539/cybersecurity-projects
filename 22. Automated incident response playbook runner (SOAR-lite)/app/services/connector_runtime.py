"""Connector runtime: outbound action execution.

Security controls applied to EVERY outbound action:
  - SSRF/egress validation (app.core.ssrf) — OWASP A10
  - Credentials injected at call time from the encrypted vault, never logged
  - Generic HTTP action supports a bounded contract; timeouts always enforced
  - A `simulator` connector enables safe, deterministic dry-run testing
"""
from __future__ import annotations

import hashlib
import json
import time

import httpx

from app.core import cipher as vault_cipher
from app.core.ssrf import assert_egress_allowed
from app.db.models import Connector, SecretVault


class ConnectorError(Exception):
    pass


class SecretNotFoundError(ConnectorError):
    pass


def get_secret_value(secret_ref: str) -> str:
    if not secret_ref or not secret_ref.startswith("vault:"):
        raise SecretNotFoundError("secret ref must use format vault:<name>")
    name = secret_ref.split(":", 1)[1]
    # resolved by caller with a db session via resolve_secret
    raise SecretNotFoundError("resolve_secret must provide the secret")


def resolve_secret(db, secret_ref: str) -> str:
    if not secret_ref:
        return ""
    if secret_ref.startswith("vault:"):
        name = secret_ref.split(":", 1)[1]
        row = db.query(SecretVault).filter(SecretVault.name == name).first()
        if row is None:
            raise SecretNotFoundError(f"vault secret `{name}` not found")
        value = vault_cipher.decrypt_secret(row.key_id, row.ciphertext)
        row.last_used_at = time_now()
        db.add(row)
        return value
    return secret_ref


def time_now():
    import datetime as dt

    return dt.datetime.utcnow()


def make_idempotency_key(run_id: str, step_id: str, action: str, args: dict) -> str:
    blob = json.dumps({"run": run_id, "step": step_id, "action": action, "args": args}, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _allowed_host(connector: Connector) -> str | None:
    allowed = connector.allowed_hosts or []
    if connector.base_url:
        from urllib.parse import urlparse

        allowed.append(urlparse(connector.base_url).netloc)
    return ",".join(allowed) if allowed else None


def execute_action(db, connector: Connector, action_name: str, args: dict) -> dict:
    """Run a single named action on a connector. Returns canonical result dict."""
    if not connector.enabled:
        raise ConnectorError(f"connector `{connector.name}` is disabled")

    if connector.conn_type == "simulator":
        return _execute_simulator(db, connector, action_name, args)

    if connector.conn_type == "generic_http":
        return _execute_generic_http(db, connector, action_name, args)

    if connector.conn_type in ("slack", "teams"):
        return _execute_messaging(db, connector, action_name, args)

    raise ConnectorError(f"unsupported connector type `{connector.conn_type}`")


def _headers_for(db, connector: Connector) -> dict:
    headers = {"Accept": "application/json", "User-Agent": "SOAR-Lite/1.0"}
    if connector.auth_type == "header_token" and connector.auth_secret_ref:
        token = resolve_secret(db, connector.auth_secret_ref)
        headers["Authorization"] = f"Bearer {token}"
    elif connector.auth_type == "basic" and connector.auth_secret_ref:
        import base64

        raw = resolve_secret(db, connector.auth_secret_ref)
        headers["Authorization"] = "Basic " + base64.b64encode(raw.encode("utf-8")).decode("ascii")
    return headers


def _execute_generic_http(db, connector: Connector, action_name: str, args: dict) -> dict:
    method = str(args.get("method", "POST")).upper()
    if method not in ("GET", "POST", "PUT", "DELETE", "PATCH"):
        raise ConnectorError(f"unsupported method {method}")
    path = str(args.get("path", ""))
    query = args.get("query")
    url = connector.base_url.rstrip("/") + path
    if query:
        from urllib.parse import urlencode

        url += "?" + urlencode(query)

    try:
        assert_egress_allowed(url, connector.allowed_hosts and ",".join(connector.allowed_hosts) or None)
    except ValueError as exc:
        raise ConnectorError(f"egress policy blocked request: {exc}")

    payload = args.get("body")
    timeout = float(args.get("timeout_seconds", 15))
    if timeout > 60:
        timeout = 60

    try:
        with httpx.Client(timeout=timeout, follow_redirects=False) as client:
            response = client.request(method, url, headers=_headers_for(db, connector), json=payload)
    except httpx.HTTPError as exc:
        raise ConnectorError(f"connector request failed: {exc.__class__.__name__}: {exc}")

    body = None
    content_type = response.headers.get("content-type", "")
    if "application/json" in content_type:
        try:
            body = response.json()
        except ValueError:
            body = {"_text": response.text[:4000]}
    elif response.text:
        body = {"_text": response.text[:4000]}

    return {
        "status_code": response.status_code,
        "body": body,
        "ok": 200 <= response.status_code < 300,
    }


def _execute_simulator(db, connector: Connector, action_name: str, args: dict) -> dict:
    """Deterministic canned response used for demos, tests and dry-runs."""
    seed_material = json.dumps({"action": action_name, "args": args}, sort_keys=True, default=str)
    seed = int(hashlib.sha256(seed_material.encode("utf-8")).hexdigest()[:8], 16)
    ok = seed % 5 != 0  # ~20% simulated failure exercises retries/compensation
    time.sleep(0.05)

    if action_name == "enrich_ip":
        body = {
            "ip": (args.get("value") or "8.8.8.8"),
            "asn": "AS15169", "country": "US",
            "reputation": "malicious" if seed % 3 == 0 else "neutral",
            "score": seed % 100,
        }
    elif action_name == "enrich_hash":
        body = {"sha256": (args.get("value") or "sim"), "malicious": seed % 4 == 0, "engine_hits": seed % 20}
    elif action_name in ("block_ip", "block_sender", "quarantine", "disable_user", "isolate"):
        body = {"contained": True, "technique": "simulator", "ref": f"sim-{seed:08x}"}
    elif action_name in ("unblock_ip", "unblock_sender", "restore"):
        body = {"restored": True}
    elif action_name in ("tag_user", "reset_password", "revoke_session"):
        body = {"applied": True, "target": args.get("value")}
    elif action_name == "notify":
        body = {"delivered": True, "channel": args.get("channel", "simulator")}
    elif action_name == "open_ticket":
        body = {"ticket_id": f"SIM-{seed % 100000:05d}", "state": "open"}
    else:
        body = {"done": True, "action": action_name}

    if not ok and action_name.startswith("block"):
        body = {"contained": False, "error": "simulated upstream failure"}

    return {"ok": ok, "body": body, "simulated": True, "seed": seed}


def _execute_messaging(db, connector: Connector, action_name: str, args: dict) -> dict:
    message = str(args.get("message", ""))
    if connector.conn_type == "slack":
        if connector.base_url:
            payload = {"text": message}
            url = connector.base_url.rstrip("/") + "/chat.postMessage"
            try:
                assert_egress_allowed(url, connector.allowed_hosts and ",".join(connector.allowed_hosts) or None)
            except ValueError as exc:
                raise ConnectorError(f"egress policy blocked request: {exc}")
            with httpx.Client(timeout=15) as client:
                try:
                    response = client.post(url, headers=_headers_for(db, connector), json=payload)
                    return {"ok": 200 <= response.status_code < 300, "status_code": response.status_code}
                except httpx.HTTPError as exc:
                    raise ConnectorError(f"slack call failed: {exc}")
        return {"ok": True, "body": {"delivered": True, "message": message[:200]}}
    return {"ok": True, "body": {"delivered": True, "channel": args.get("channel", "teams")}}