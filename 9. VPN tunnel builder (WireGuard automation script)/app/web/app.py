"""Flask application factory (OWSAP A01/A09; ISO 27001 A.8.28).

Wiring: StateStore -> AuditLog -> SnapshotManager -> backend -> services.
Security: session auth, CSRF synchroniser token, secret redaction, and
per-request CSRF enforcement are wired as request hooks below.
"""

from __future__ import annotations

import logging
import secrets
from pathlib import Path

from flask import (
    Flask,
    Response,
    abort,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)

from ..core.config import DEFAULTS, get_defaults, new_token, validate_settings
from ..core.validate import is_interface_name
from ..persistence.audit import AuditLog
from ..persistence.snapshots import SnapshotManager
from ..persistence.store import StateStore
from ..platform.backend import detect_backend
from ..security import auth
from ..services.base import ServiceContext
from ..services.peer_service import PeerService
from ..services.tunnel_service import TunnelService

log = logging.getLogger("vpntb.web")


def _load_store(data_dir: str | Path):
    return StateStore(data_dir)


def _load_flask_secret(data_dir: str | Path) -> str:
    path = Path(data_dir) / ".flask_secret"
    if path.exists():
        return path.read_text(encoding="utf-8").strip()
    secret = secrets.token_urlsafe(48)
    path.write_text(secret, encoding="utf-8")
    try:
        import os
        if os.name == "posix":
            os.chmod(path, 0o600)
    except OSError:
        pass
    return secret


def create_app(data_dir: str | Path = "data", no_auth: bool = False) -> Flask:
    data_dir = Path(data_dir)
    data_dir.mkdir(parents=True, exist_ok=True)

    store = _load_store(data_dir)
    audit = AuditLog(store.audit_path)
    snapshots = SnapshotManager(store)
    settings = store.load_settings(get_defaults())
    if settings.get("backend") not in ("auto", "local", "simulator", "dry-run"):
        settings["backend"] = "auto"
    backend = detect_backend(store, settings.get("backend", "auto"))
    snapshots.set_retention(int(settings.get("snapshot_retention", 10)))

    ctx = ServiceContext.from_parts(store, audit, snapshots, backend)
    tunnel_service = TunnelService(ctx, lambda: settings)
    peer_service = PeerService(ctx, lambda: settings, tunnel_service)

    bootstrap_token = ""
    if settings.get("auth_enabled") and not settings.get("token_hash"):
        token, salt, token_hash = new_token()
        settings["token_hash"] = token_hash
        settings["token_salt"] = salt
        store.save_settings(settings)
        bootstrap_token = token
        auth_file = data_dir / "initial-auth.txt"
        auth_file.write_text(
            "Initial VPN Tunnel Builder login token (change it from Settings):\n"
            f"{token}\n",
            encoding="utf-8",
        )
        try:
            import os
            if os.name == "posix":
                os.chmod(auth_file, 0o600)
        except OSError:
            pass

    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.secret_key = _load_flask_secret(data_dir)
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        MAX_CONTENT_LENGTH=2 * 1024 * 1024,
        APP_SETTINGS=settings,
        NO_AUTH=no_auth,
        SERVICE_CTX=ctx,
        TUNNEL_SERVICE=tunnel_service,
        PEER_SERVICE=peer_service,
        BOOTSTRAP_TOKEN=bootstrap_token,
        STORE=store,
        AUDIT=audit,
    )

    # -------------------------------------------------------------- security hooks
    @app.before_request
    def _hook_csrf():
        auth.csrf_protect()

    @app.template_global()
    def csrf_token():
        return auth.get_csrf_token()

    @app.template_global()
    def current_user():
        return auth.get_current_user()

    @app.context_processor
    def _inject():
        return {
            "app_settings": settings,
            "backend_is_simulated": backend.is_simulated,
            "backend_name": backend.name,
            "auth_enabled": (not no_auth) and bool(settings.get("auth_enabled")),
            "no_auth_mode": no_auth,
        }

    # --------------------------------------------------------------- error pages
    @app.errorhandler(403)
    def _forbidden(err):
        if request.path.startswith("/api/"):
            return {"ok": False, "error": "forbidden"}, 403
        return render_template("error.html", code=403, message=str(err.description or "Forbidden")), 403

    @app.errorhandler(404)
    def _not_found(err):
        return render_template("error.html", code=404, message="Not found"), 404

    @app.errorhandler(500)
    def _server_error(err):
        log.exception("unhandled error")
        audit.append("app.error", "system", "-", request.path, "ERR",
                     str(err)[:400])
        return render_template("error.html", code=500, message="Internal error (see audit log)"), 500

    _register_routes(app)
    return app


def _register_routes(app: Flask) -> None:
    store: StateStore = app.config["STORE"]
    audit: AuditLog = app.config["AUDIT"]
    tunnel_service: TunnelService = app.config["TUNNEL_SERVICE"]
    peer_service: PeerService = app.config["PEER_SERVICE"]
    settings: dict = app.config["APP_SETTINGS"]

    def _logged_ok(action, target, message):
        return audit.append(action, "operator", "web-ui", target, "OK", message)

    def _flash_result(result: dict, ok_text: str = ""):
        if result.get("ok"):
            flash(result.get("message") or ok_text or "OK", "success")
        else:
            flash("; ".join(result.get("errors") or [result.get("error") or "failed"]), "danger")

    def _guard_interface(interface: str) -> str | None:
        if not is_interface_name(interface):
            abort(404)
        return interface

    # -------------------------------------------------------------- login / auth
    @app.route("/login", methods=["GET", "POST"])
    def login():
        if app.config.get("NO_AUTH") or not settings.get("auth_enabled"):
            return redirect(url_for("dashboard"))
        if request.method == "POST":
            token = request.form.get("token", "")
            if auth.login_check(settings, token):
                auth.set_session("operator", token)
                audit.append("auth.login", "operator", "web-ui", "login", "OK", "")
                return redirect(url_for("dashboard"))
            audit.append("auth.login", "anonymous", "web-ui", "login", "ERR", "bad token")
            flash("Invalid token", "danger")
            return redirect(url_for("login"))
        return render_template(
            "login.html",
            bootstrap_token=app.config.get("BOOTSTRAP_TOKEN", ""),
        )

    @app.route("/logout", methods=["POST"])
    def logout():
        auth.clear_session()
        return redirect(url_for("login"))

    # ----------------------------------------------------------------- dashboard
    @app.route("/")
    @auth.require_auth
    def dashboard():
        tunnels = tunnel_service.list_tunnels()
        state = store.load_state()
        audits = audit.recent(12)
        return render_template(
            "dashboard.html",
            tunnels=tunnels,
            peers_total=len(state.get("peers", [])),
            tunnels_total=len(tunnels),
            running_count=sum(1 for t in tunnels if t.get("status", {}).get("running")),
            audits=audits,
        )

    # ------------------------------------------------------------------ tunnels
    @app.route("/tunnels")
    @auth.require_auth
    def tunnels_page():
        return render_template("tunnels.html", tunnels=tunnel_service.list_tunnels())

    @app.route("/tunnels", methods=["POST"])
    @auth.require_auth
    def tunnels_create():
        data = {
            "name": request.form.get("name", "").strip(),
            "interface": request.form.get("interface", "wg0").strip(),
            "role": request.form.get("role", "server"),
            "listen_port": request.form.get("listen_port", "") or 0,
            "addresses": [a.strip() for a in request.form.get("addresses", "").split(",") if a.strip()],
            "mtu": request.form.get("mtu", "") or None,
            "dns": [d.strip() for d in request.form.get("dns", "").split(",") if d.strip()],
            "start": bool(request.form.get("start")),
        }
        result = tunnel_service.build(data)
        _flash_result(result, "tunnel built")
        _logged_ok("tunnel.build", data["interface"], result.get("message", ""))
        return redirect(url_for("tunnels_page"))

    @app.route("/tunnels/<interface>")
    @auth.require_auth
    def tunnel_detail(interface):
        interface = _guard_interface(interface)
        tunnel = tunnel_service.get(interface)
        if not tunnel:
            abort(404)
        status = tunnel_service.status(interface)
        peers = peer_service.list_for(interface)
        conf_preview = None
        if tunnel:
            from ..platform.configgen import strip_private_key
            conf_preview = strip_private_key(tunnel_service.export_conf(interface) or "")
        snapshots = tunnel_service.list_snapshots()
        return render_template(
            "tunnel_detail.html",
            tunnel=tunnel,
            status=status,
            peers=peers,
            conf_preview=conf_preview,
            snapshots=snapshots,
        )

    @app.route("/tunnels/<interface>/<action>", methods=["POST"])
    @auth.require_auth
    def tunnel_action(interface, action):
        interface = _guard_interface(interface)
        if action == "start":
            result = tunnel_service.start(interface)
        elif action == "stop":
            result = tunnel_service.stop(interface)
        elif action == "validate":
            result = tunnel_service.validate_conf(interface)
            if result.get("ok"):
                flash("Config valid", "success")
            else:
                flash("Config issues: " + "; ".join(result.get("issues", [])), "danger")
            return redirect(url_for("tunnel_detail", interface=interface))
        elif action == "snapshot":
            result = tunnel_service.snapshot(interface)
        elif action == "rollback":
            result = tunnel_service.rollback(interface)
        elif action == "delete":
            result = tunnel_service.remove(interface)
            _logged_ok(action, interface, "tunnel removed")
            flash(result.get("message", "tunnel removed"), "success" if result.get("ok") else "danger")
            return redirect(url_for("tunnels_page"))
        else:
            abort(404)
        _flash_result(result)
        _logged_ok(action, interface, result.get("message", ""))
        return redirect(url_for("tunnel_detail", interface=interface))

    @app.route("/tunnels/<interface>/conf/download")
    @auth.require_auth
    def tunnel_conf_download(interface):
        interface = _guard_interface(interface)
        content = tunnel_service.export_conf(interface)
        if content is None:
            abort(404)
        resp = Response(content, mimetype="text/plain")
        resp.headers["Content-Disposition"] = f'attachment; filename="{interface}.conf"'
        return resp

    @app.route("/api/status/<interface>")
    @auth.require_auth
    def api_status(interface):
        interface = _guard_interface(interface)
        status = tunnel_service.status(interface)
        if "error" in status and status.get("error") == f"tunnel {interface} not found":
            abort(404)
        return status

    # -------------------------------------------------------------------- peers
    @app.route("/peers/add", methods=["POST"])
    @auth.require_auth
    def peers_add():
        interface = _guard_interface(request.form.get("tunnel", ""))
        data = {
            "name": request.form.get("name", "").strip(),
            "public_key": request.form.get("public_key", "").strip(),
            "generate_keypair": bool(request.form.get("generate_keypair") or request.form.get("auto_key", "")),
            "allowed_ips": [a.strip() for a in request.form.get("allowed_ips", "").split(",") if a.strip()],
            "endpoint": request.form.get("endpoint", "").strip(),
            "persistent_keepalive": request.form.get("persistent_keepalive", "") or 0,
            "psk_enabled": not request.form.get("no_psk"),
            "notes": request.form.get("notes", "").strip(),
        }
        result = peer_service.add(interface, data)
        _flash_result(result, "peer added")
        if result.get("ok") and data.get("generate_keypair"):
            flash("Generated client keypair — copy the peer's private key from the conf file", "info")
        return redirect(url_for("tunnel_detail", interface=interface))

    @app.route("/peers/<peer_id>/<action>", methods=["POST"])
    @auth.require_auth
    def peer_action(peer_id, action):
        if action == "delete":
            result = peer_service.delete(peer_id)
        elif action == "rotate-psk":
            result = peer_service.rotate_psk(peer_id)
        elif action == "toggle":
            target = "disable"
            state = store.load_state()
            for p in state.get("peers", []):
                if p.get("id") == peer_id:
                    target = "disable" if p.get("enabled") else "enable"
                    break
            result = peer_service.set_enabled(peer_id, target == "enable")
        elif action == "update":
            return peer_update(peer_id)
        else:
            abort(404)
        _flash_result(result)
        interface = request.referrer or url_for("dashboard")
        return redirect(interface)

    def peer_update(peer_id):
        state = store.load_state()
        iface = next((p.get("tunnel") for p in state.get("peers", []) if p.get("id") == peer_id), None)
        data = {
            "notes": request.form.get("notes"),
            "endpoint": request.form.get("endpoint"),
            "name": request.form.get("name"),
            "keepalive": request.form.get("keepalive"),
        }
        result = peer_service.update(peer_id, data)
        _flash_result(result, "peer updated")
        if not iface:
            return redirect(url_for("dashboard"))
        return redirect(url_for("tunnel_detail", interface=iface))

    # ------------------------------------------------------------------ settings
    @app.route("/settings")
    @auth.require_auth
    def settings_page():
        return render_template("settings.html", settings=store.load_settings(DEFAULTS))

    @app.route("/settings", methods=["POST"])
    @auth.require_auth
    def settings_save():
        raw = {
            "default_subnet": request.form.get("default_subnet", ""),
            "default_listen_port": request.form.get("default_listen_port", 0),
            "default_mtu": request.form.get("default_mtu", 0),
            "default_keepalive": request.form.get("default_keepalive", 0),
            "snapshot_retention": request.form.get("snapshot_retention", 0),
            "audit_retention_days": request.form.get("audit_retention_days", 0),
            "monitor_interval_sec": request.form.get("monitor_interval_sec", 0),
            "psk_enabled": bool(request.form.get("psk_enabled")),
            "auto_assign_ips": bool(request.form.get("auto_assign_ips")),
            "auth_enabled": bool(request.form.get("auth_enabled")),
            "require_localhost_only": bool(request.form.get("require_localhost_only")),
            "redact_secrets_in_logs": bool(request.form.get("redact_secrets_in_logs")),
            "backend": request.form.get("backend", "auto"),
        }
        if request.form.get("reset_token"):
            token, salt, token_hash = new_token()
            raw["token_hash"] = token_hash
            raw["token_salt"] = salt
        cleaned, errors = validate_settings(raw)
        if errors:
            for e in errors:
                flash(e, "danger")
            return redirect(url_for("settings_page"))

        settings.clear()
        settings.update(cleaned)
        store.save_settings(settings)

        # hot-swap backend if requested
        app.config["SERVICE_CTX"].backend = detect_backend(store, settings.get("backend", "auto"))

        audit.append("settings.save", "operator", "web-ui", "settings", "OK", "")
        if request.form.get("reset_token"):
            flash(f"New auth token (shown once): {token}", "warning")
        else:
            flash("Settings saved", "success")
        return redirect(url_for("settings_page"))

    # ----------------------------------------------------------------------- audit
    @app.route("/audit")
    @auth.require_auth
    def audit_page():
        events = audit.recent(500)
        valid, broken = audit.verify()
        return render_template("audit.html", events=events, chain_valid=valid, broken=broken)

    @app.route("/audit/export")
    @auth.require_auth
    def audit_export():
        from io import StringIO
        buf = StringIO()
        for ev in audit.recent(5000):
            buf.write("\t".join(str(ev.get(k, "")) for k in
                                ("ts", "action", "actor", "target", "result", "detail")) + "\n")
        resp = Response(buf.getvalue(), mimetype="text/plain")
        resp.headers["Content-Disposition"] = 'attachment; filename="audit-export.tsv"'
        return resp