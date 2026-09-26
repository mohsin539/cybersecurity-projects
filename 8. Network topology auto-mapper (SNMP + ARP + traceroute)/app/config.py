from __future__ import annotations

import os
from pathlib import Path

APP_NAME = "Network Topology Auto-Mapper (NTM)"
APP_VERSION = "0.1.0"
ROLES = ("viewer", "operator", "admin")
DEFAULT_ROLE = "operator"
AUTH_ITERATIONS = 310_000
SCOPE_DENY_CIDRS = (
    "0.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4",
    "255.255.255.255/32",
)


class Config:
    def __init__(self) -> None:
        root = Path(__file__).resolve().parent.parent
        self.root = root
        data_dir = os.environ.get("NTM_DATA_DIR")
        self.data_dir = Path(data_dir) if data_dir else (root / "data")
        self.data_dir.mkdir(parents=True, exist_ok=True)

        self.host = os.environ.get("NTM_HOST", "127.0.0.1")
        self.port = int(os.environ.get("NTM_PORT", "8000"))
        self.session_secret = self._load_secret("session.key")
        self.login_lock_attempts = 5
        self.login_lock_seconds = 300
        self.session_hours = 8
        self.scan_ping_sweep = os.environ.get("NTM_PING_SWEEP", "0") == "1"

    def _load_secret(self, name: str) -> bytes:
        path = self.data_dir / name
        if not path.exists():
            path.write_bytes(os.urandom(32))
        return path.read_bytes()

    @property
    def db_path(self) -> Path:
        return self.data_dir / "ntm.db"

    @property
    def audit_path(self) -> Path:
        return self.data_dir / "audit.jsonl"

    @property
    def audit_key_path(self) -> Path:
        return self.data_dir / "audit.key"


CFG = Config()