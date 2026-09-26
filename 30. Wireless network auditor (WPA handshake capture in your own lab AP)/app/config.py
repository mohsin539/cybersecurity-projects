APP_NAME = "Wireless Network Auditor"
APP_VERSION = "1.0.0"
APP_TAGLINE = "WPA handshake capture in your own lab AP"
APP_AUTHOR = "Lab Security Team"

import os
import tempfile

PORTABLE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def runtime_dir() -> str:
    root = os.environ.get("WNA_RUNTIME_DIR")
    if root:
        os.makedirs(root, exist_ok=True)
        return root
    base = os.path.join(tempfile.gettempdir(), "wna_auditor")
    os.makedirs(base, exist_ok=True)
    return base

def workspace_dir() -> str:
    wd = os.path.join(const_runtime_base(), "workspace")
    os.makedirs(wd, exist_ok=True)
    return wd

def const_runtime_base() -> str:
    base = os.environ.get("WNA_DATA_DIR")
    if not base:
        base = os.path.join(os.path.dirname(PORTABLE_ROOT), "wna_data")
    os.makedirs(base, exist_ok=True)
    return base

RUNTIME = runtime_dir()
WORKSPACE = workspace_dir()
VAULT_DB = os.path.join(WORKSPACE, "evidence.db")
HASHCHAIN_FILE = os.path.join(WORKSPACE, "evidence.hashchain")
REPORT_DIR = os.path.join(WORKSPACE, "reports")
KEYSTORE = os.path.join(WORKSPACE, ".keystore")

os.makedirs(REPORT_DIR, exist_ok=True)

DEFAULT_CHANNELS = [1, 6, 11]
CAPTURE_INTERVAL_MS = 400
SIM_TICK_MS = 350