from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

DATA_DIR = BASE_DIR / "data"
EVIDENCE_DIR = DATA_DIR / "evidence"
CERTS_DIR = DATA_DIR / "certs"
REPORTS_DIR = DATA_DIR / "reports"
LOG_DIR = DATA_DIR / "logs"
STATIC_DIR = BASE_DIR / "app" / "static"
TEMPLATES_DIR = BASE_DIR / "app" / "templates"

for d in (DATA_DIR, EVIDENCE_DIR, CERTS_DIR, REPORTS_DIR, LOG_DIR):
    d.mkdir(parents=True, exist_ok=True)

DATABASE = DATA_DIR / "c2lab.db"
ADMIN_TOKEN_FILE = DATA_DIR / "admin_token.txt"

APP_NAME = "C2 Deconfliction Lab"
APP_VERSION = "1.0.0"
LAB_MODE = True

HOST = "127.0.0.1"
PORT = 8443

TLS_CIPHER = "TLS_AES_256_GCM_SHA384"
TLS_MIN_VERSION = "TLS1.3"
SESSION_KEY_ALGO = "AES-256-GCM"

ENFORCE_AUTH = True