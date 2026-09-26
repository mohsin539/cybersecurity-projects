import json
import secrets
from pathlib import Path

APP_NAME = "VulnLab Sentinel"
VERSION = "1.0.0"
HOST = "127.0.0.1"  # forced loopback — never expose the dashboard
DEFAULT_PORT = 5885
LAB_CONSOLE_BANNER = "VulnLab/1.0 (debug)"


class SecureConfig:
    """Hardening-focused configuration. All binds are forced to loopback."""

    def __init__(self, base_dir: Path):
        self.base_dir = base_dir
        self.data_dir = base_dir / "data"
        self.web_dir = base_dir / "web"
        self.modules_dir = base_dir / "modules"
        self.reports_dir = base_dir / "reports"
        self.lab_dir = base_dir / "lab-service"
        for d in (self.data_dir, self.reports_dir):
            d.mkdir(parents=True, exist_ok=True)
        self.host = HOST
        self.port = DEFAULT_PORT
        self.loopback_only = True
        self.scope_cidrs = ["10.10.10.0/24", "192.168.56.0/24", "172.16.0.0/16"]
        self.rpc_token = self._persistent_token()
        self.no_payload_default = True  # exploit locked until explicit unlock

    def _persistent_token(self) -> str:
        tok_file = self.base_dir / "data" / ".session_token"
        if tok_file.exists():
            return tok_file.read_text(encoding="utf-8").strip()
        tok = secrets.token_urlsafe(24)
        tok_file.write_text(tok, encoding="utf-8")
        return tok

    def transport_summary(self) -> dict:
        return {
            "product": APP_NAME,
            "version": VERSION,
            "bind": f"{self.host}:{self.port}",
            "loopback_only": self.loopback_only,
            "scope_cidrs": self.scope_cidrs,
            "msgrpc": "127.0.0.1:55553",
            "no_payload_default": self.no_payload_default,
        }