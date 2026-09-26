"""Global configuration for the traffic obfuscation demo."""

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_DIR = PROJECT_ROOT / "output"
DATA_DIR = PROJECT_ROOT / "data"

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
DATA_DIR.mkdir(parents=True, exist_ok=True)

# Well-known CDN / fronting-capable networks used by the heuristics.
CDN_NETWORKS = {
    "cloudflare": [
        "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "190.93.240.0/20",
        "162.158.0.0/15",
    ],
    "fastly": ["151.101.0.0/16", "199.232.0.0/16", "146.75.0.0/16"],
    "akamai": ["23.32.0.0/11", "23.192.0.0/11", "184.24.0.0/13", "96.6.0.0/15"],
    "google": ["142.250.0.0/15", "172.217.0.0/16", "216.58.192.0/19", "74.125.0.0/16"],
    "amazon": ["52.84.0.0/15", "54.230.0.0/16", "13.32.0.0/15", "205.251.192.0/19"],
    "microsoft": ["20.36.0.0/14", "13.64.0.0/11", "40.84.0.0/15"],
}

# TLS 1.3 cipher suites used for JA3/JA4-style hashing rules.
TLS_CIPHER_LIST = [
    "1302", "1301", "1303", "c02f", "c02b", "c02c", "c030", "cca9", "cca8",
    "c013", "c014", "009c", "009d", "002f", "0035",
]

# Reference heuristics tuning.
SCORE_THRESHOLD_SUSPICIOUS = 40
SCORE_THRESHOLD_HIGH = 70