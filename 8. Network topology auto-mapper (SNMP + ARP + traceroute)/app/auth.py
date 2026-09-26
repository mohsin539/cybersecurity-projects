from __future__ import annotations

import hashlib
import json
import time

from fastapi import Depends, HTTPException, Request, status

from . import db
from .audit import AUDIT
from .config import AUTH_ITERATIONS, CFG
from .util import b64d, b64e, pbkdf2, sig_valid, sign

FAIL_REASONS = dict()


class AuthError(Exception):
    pass


def hash_password(pw: str, salt: bytes) -> str:
    return pbkdf2(pw, salt, AUTH_ITERATIONS)


def new_salt() -> str:
    import secrets
    return secrets.token_bytes(16).hex()


def create_user(username: str, password: str, role: str) -> None:
    salt = new_salt()
    db.create_user(username, hash_password(password, bytes.fromhex(salt)), salt, role)


def authenticate(username: str, password: str, code: str = "") -> dict:
    user = db.get_user(username)
    if not user:
        raise AuthError("invalid credentials")
    expect = hash_password(password, bytes.fromhex(user["salt"]))
    if not hashlib.sha256(expect.encode()).hexdigest() == hashlib.sha256(user["pw_hash"].encode()).hexdigest():
        raise AuthError("invalid credentials")
    if user["totp_enabled"]:
        from .util import totp_verify
        if not totp_verify(user["totp_secret"] or "", code):
            raise AuthError("invalid TOTP code")
    db.update_user(username, last_login=__import__("app.util", fromlist=["now_ts"]).now_ts())
    return user


def issue_token(user: dict) -> str:
    payload = json.dumps({
        "u": user["username"],
        "r": user["role"],
        "exp": int(time.time()) + CFG.session_hours * 3600,
    }, separators=(",", ":"))
    return sign(payload, CFG.session_secret)


def verify_token(token: str) -> dict:
    payload = sig_valid(token, CFG.session_secret)
    if not payload:
        raise AuthError("invalid or tampered token")
    try:
        claims = json.loads(payload)
    except ValueError:
        raise AuthError("invalid token payload")
    if int(claims.get("exp", 0)) < int(time.time()):
        raise AuthError("token expired")
    return claims


def get_claims(request: Request) -> dict:
    header = request.headers.get("authorization", "")
    if not header.lower().startswith("bearer "):
        raise AuthError("missing bearer token")
    return verify_token(header[7:])


def require_roles(*roles_needed: str):
    def dep(request: Request) -> dict:
        try:
            claims = get_claims(request)
        except AuthError as e:
            AUDIT.append(claims_actor(request), "auth_failure", "api",
                         {"reason": str(e)}, "warn")
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail=str(e))
        role = claims.get("r", "viewer")
        if roles_needed and role not in roles_needed:
            AUDIT.append(claims.get("u", "?"), "authz_denied", request.url.path,
                         {"role": role, "needed": list(roles_needed)}, "warn")
            raise HTTPException(status.HTTP_403_FORBIDDEN, detail="insufficient role")
        return claims
    return dep


def claims_actor(request: Request) -> str:
    try:
        return get_claims(request).get("u", "anonymous")
    except AuthError:
        return "anonymous"


def set_password(username: str, new_pw: str) -> None:
    if len(new_pw) < 10:
        raise AuthError("password must be at least 10 characters")
    salt = new_salt()
    db.update_user(username, salt=salt, pw_hash=hash_password(new_pw, bytes.fromhex(salt)))
    db.set_setting(f"pwd_forced_{username}", "no")


def enroll_totp(username: str) -> dict:
    from .util import gen_totp_secret
    import base64
    secret = gen_totp_secret()
    db.update_user(username, totp_secret=secret, totp_enabled=0)
    uri = f"otpauth://totp/NTM:{username}?secret={secret}&issuer=NTM&digits=6&period=30"
    return {"secret": secret, "uri": uri}


def confirm_totp(username: str, code: str) -> None:
    from .util import totp_verify
    user = db.get_user(username)
    if not user or not totp_verify(user.get("totp_secret") or "", code):
        raise AuthError("invalid TOTP code")
    db.update_user(username, totp_enabled=1)


class LoginRateLimiter:
    def __init__(self, maxfails: int, window: int) -> None:
        self.maxfails = maxfails
        self.window = window
        self._fails: dict[str, list[float]] = {}

    def blocked(self, ip: str) -> bool:
        now = time.time()
        fails = [t for t in self._fails.get(ip, []) if now - t < self.window]
        self._fails[ip] = fails
        return len(fails) >= self.maxfails

    def record_fail(self, ip: str) -> None:
        fails = self._fails.setdefault(ip, [])
        fails.append(time.time())

    def reset(self, ip: str) -> None:
        self._fails.pop(ip, None)


LOGIN_LIMIT = LoginRateLimiter(CFG.login_lock_attempts, CFG.login_lock_seconds)
