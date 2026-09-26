"""Application factory for MobileForensicsLabPortable."""

import os
import secrets

from flask import Flask, session

from .db import init_db
from .security import apply_security_middleware, csrf_protect
from .audit import init_audit

DEFAULT_ADMIN_USER = os.environ.get("MFL_ADMIN_USER", "admin")
DEFAULT_ADMIN_PASS = os.environ.get("MFL_ADMIN_PASS", "admin123!")


def create_app(test_config=None):
    app = Flask(
        __name__,
        instance_relative_config=True,
        template_folder="templates",
        static_folder="static",
    )
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("MFL_SECRET", secrets.token_hex(32)),
        DATABASE=os.path.join(os.environ.get("MFL_DATA_DIR", app.instance_path), "mfl.db"),
        MAX_CONTENT_LENGTH=int(os.environ.get("MFL_MAX_UPLOAD_MB", "25")) * 1024 * 1024,
        PERMANENT_SESSION_LIFETIME=45 * 60,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("MFL_COOKIE_SECURE", "0") == "1",
        CSRF_ENABLED=True,
    )
    if test_config:
        app.config.update(test_config)

    os.makedirs(os.path.dirname(app.config["DATABASE"]), exist_ok=True)

    init_db(app)
    init_audit(app)
    apply_security_middleware(app)
    csrf_protect(app)

    from .routes import main, cases, evidence, analysis, custody, reports, audit, compliance

    for bp in (
        main.bp,
        cases.bp,
        evidence.bp,
        analysis.bp,
        custody.bp,
        reports.bp,
        audit.bp,
        compliance.bp,
    ):
        app.register_blueprint(bp)

    bootstrap(app)
    return app


def bootstrap(app):
    """Idempotent first-run bootstrap: seed roles, user, settings, demo case."""
    from .db import get_db

    with app.app_context():
        db = get_db()
        row = db.execute("SELECT COUNT(*) AS n FROM settings WHERE key='bootstrapped'").fetchone()
        if row and row["n"]:
            return

        db.execute("INSERT OR IGNORE INTO users(username,password_hash,display_name,role) VALUES(?,?,?,?)", (
            DEFAULT_ADMIN_USER,
            _phash(DEFAULT_ADMIN_PASS),
            "Lab Administrator",
            "admin",
        ))
        db.execute("INSERT OR IGNORE INTO settings(key,value) VALUES('bootstrapped','1')")
        db.execute("INSERT OR IGNORE INTO settings(key,value) VALUES('org_name','Mobile Forensics Lab')")
        db.commit()

        from .audit import audit
        audit(app, "SYSTEM", "system", "BOOTSTRAP", "system", None,
              {"message": "First-run bootstrap completed"}, "info")


def _phash(pw):
    from werkzeug.security import generate_password_hash
    return generate_password_hash(pw)