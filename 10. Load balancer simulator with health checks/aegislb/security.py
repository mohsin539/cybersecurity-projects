from __future__ import annotations

import collections
import hashlib
import json
import os
import secrets
import time
from typing import Callable, Dict, List, Optional, Tuple


class SecurityManager:
    ROLES = ("config", "ops", "auditor")

    def __init__(self, emit: Optional[Callable[[str, dict, str], None]] = None) -> None:
        self.emit = emit
        self.hardened = os.environ.get("AEGIS_HARDENED", "1") == "1"
        self.tokens: Dict[str, str] = {}
        self.audit: List[dict] = []
        self._chain_tail = os.environ.get("AEGIS_AUDIT_CHAIN_TAIL", "GENESIS")
        self._rate_buckets: Dict[str, List[float]] = collections.defaultdict(list)
        self._load_tokens()
        self._rate_limit = int(os.environ.get("AEGIS_RATE_LIMIT", "120"))
        self._rate_window = float(os.environ.get("AEGIS_RATE_WINDOW", "60.0"))

    def _load_tokens(self) -> None:
        env_map = {"config": "AEGIS_CONFIG_KEY", "ops": "AEGIS_OPS_KEY", "auditor": "AEGIS_AUDITOR_KEY"}
        for role, env in env_map.items():
            val = os.environ.get(env)
            self.tokens[role] = val if val else secrets.token_urlsafe(24)

    def redacted_tokens(self) -> Dict[str, str]:
        out = {}
        for role, tok in self.tokens.items():
            out[role] = f"{tok[:8]}…{len(tok)}char(s)"
        return out

    def status(self) -> dict:
        return {"hardened": self.hardened, "roles": list(self.ROLES),
                "tokens": self.redacted_tokens(), "audit_entries": len(self.audit),
                "chain_tail": self._chain_tail, "rate_limit_per_min": self._rate_limit}

    def check(self, key: Optional[str], role: str) -> Tuple[bool, str]:
        if role not in self.tokens:
            return False, "unknown_role"
        expected = self.tokens[role]
        if key is None or not secrets.compare_digest(key, expected):
            return False, "invalid_key"
        return True, "ok"

    def authorize(self, key: Optional[str], role: str, action: str, resource: str) -> Tuple[bool, str]:
        ok, reason = self.check(key, role)
        self.audit_entry(role if ok else "anonymous", action, resource, "allow" if ok else "deny", reason)
        if ok:
            self._swallow(self.emit, "AUTHZ_ALLOW",
                          {"principal": role, "action": action, "resource": resource}, "info")
        else:
            self._swallow(self.emit, "AUTHZ_DENIED",
                          {"principal": "anonymous", "action": action, "resource": resource,
                           "reason": reason}, "warn")
        return ok, reason

    def rate_allow(self, client: str) -> bool:
        now = time.monotonic()
        bucket = self._rate_buckets[client]
        bucket[:] = [t for t in bucket if now - t < self._rate_window]
        if len(bucket) >= self._rate_limit:
            return False
        bucket.append(now)
        return True

    def _swallow(self, fn, etype, payload, sev) -> None:
        if fn is None:
            return
        try:
            fn(etype, payload, sev)
        except Exception:
            pass

    def audit_entry(self, principal: str, action: str, resource: str,
                    effect: str, detail: str) -> None:
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        body = json.dumps({"t": now, "p": principal, "a": action, "r": resource,
                           "e": effect, "d": detail}, sort_keys=True)
        chain = hashlib.sha256((self._chain_tail + body).encode("utf-8")).hexdigest()
        self._chain_tail = chain
        self.audit.append({"t": now, "principal": principal, "action": action,
                           "resource": resource, "effect": effect, "detail": detail,
                           "chain": chain})
        if len(self.audit) > 5000:
            del self.audit[:1000]

    def audit_tail(self, limit: int = 50) -> List[dict]:
        return list(self.audit[-limit:])