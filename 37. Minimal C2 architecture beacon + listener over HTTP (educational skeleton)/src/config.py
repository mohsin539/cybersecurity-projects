"""Central configuration for the C2 Study Lab.

In production, secrets are injected via environment variables / a KMS and
rotated regularly (OWASP A02, ISO 27001 A.10). The values below are lab-only
defaults so the skeleton runs out of the box.
"""
import base64
import hashlib
import os
from pathlib import Path

APP_NAME = "C2StudyLab"
APP_VERSION = "1.0.0"
TAGLINE = "Minimal C2 beacon + listener over HTTP (educational skeleton)"

BASE_DIR = Path(__file__).resolve().parent.parent
LOG_DIR = BASE_DIR / "logs"
REPORT_DIR = BASE_DIR / "reports"

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8080

# ---- secrets (override with environment variables) ---------------------
BEACON_TOKEN = os.environ.get("C2_BEACON_TOKEN", "lab-beacon-token-0001")
CONSOLE_TOKEN = os.environ.get("C2_CONSOLE_TOKEN", "lab-console-token-0001")
FERNET_KEY = os.environ.get("C2_FERNET_KEY", "")  # auto-derived when empty

# ---- operational tuning -------------------------------------------------
CHECKIN_INTERVAL_SEC = int(os.environ.get("C2_INTERVAL", "3"))     # lab only
AUTH_HEADER = "Authorization"
RATE_LIMIT_WINDOW_SEC = 60
RATE_LIMIT_MAX_REQUESTS = 120
MAX_BODY_BYTES = 128 * 1024

# Tasks the beacon may execute - strictly whitelisted, pure-Python only.
ALLOWED_TASKS = ("get-sysinfo", "get-timestamp", "get-uptime", "heartbeat-test")


def derive_fernet_key(label: str = "c2-study-lab-key") -> str:
    """Deterministic lab key for payload encryption (Fernet)."""
    digest = hashlib.sha256(label.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii")


def audit_path() -> Path:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    return LOG_DIR / "audit.jsonl"