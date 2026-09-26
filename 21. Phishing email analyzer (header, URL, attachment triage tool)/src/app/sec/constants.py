"""Central security policy constants - immutable, versioned.

Map: NIST SP 800-53 SI-10 (input validation), SC-28 (PII protection),
ENCRYPTION / AUTHN (IA-5), AUDIT (AU-3), RETENTION (SI-12 / ISO A.8.10).
"""

# --- Hardening ---------------------------------------------------------------
SCHEMA_VERSION = 1

# Input validation limits (SI-10): fail-closed on exceed
MAX_EMAIL_BYTES = 10 * 1024 * 1024        # 10 MB raw EML cap
MAX_ATTACHMENT_BYTES = 25 * 1024 * 1024   # 25 MB per attachment
MAX_HEADER_FIELDS = 200
MAX_HEADER_BYTES = 64 * 1024              # 64 KB header block
MAX_LINE_LENGTH = 16 * 1024
MAX_URLS_EXTRACT = 500
MAX_URL_LENGTH = 2048
MAX_RECEIVED_HOPS = 30
MAX_ATTACHMENTS = 100
TEXT_RENDER_MAX = 500_000                 # GUI body preview cap (chars)

# --- Cryptography (A02 / IA-5 / SC-28 / ISO A.10.1) --------------------------
PBKDF2_ITERATIONS = 600_000               # NIST SP 800-132 PBKDF2 guidance tier
AES_KEY_BYTES = 32                        # AES-256-GCM
AES_NONCE_BYTES = 12
AES_TAG_BYTES = 16
SALT_BYTES = 16
ENCRYPTED_MAGIC = b"PEA1"                 # container magic: version-1
RANDOM = None  # filled on demand to avoid top-level import cost

# --- Identity / access control (AC-2/6, A07, ISO A.9) ------------------------
ROLES = ("admin", "analyst", "auditor")   # least privilege
DEFAULT_ROLE = "analyst"
LOGIN_MAX_ATTEMPTS = 5
LOGIN_LOCKOUT_SECONDS = 900               # 15 min lockout (AC-7 style)
IDLE_LOCK_SECONDS = 15 * 60               # GUI auto-lock
ALLOWED_ROLE_BY_ACTION = {
    "view": {"admin", "analyst", "auditor"},
    "analyze": {"admin", "analyst"},
    "enforce_override": {"admin", "analyst"},
    "delete_case": {"admin"},
    "settings": {"admin"},
    "export_audit": {"admin", "auditor"},
    "audit_view": {"admin", "auditor"},
}
MIN_PASSWORD_LEN = 12

# --- Audit (AU-3/6/11, A09, ISO A.12.4) --------------------------------------
AUDIT_EVENTS = {
    "LOGIN_SUCCESS", "LOGIN_FAIL", "ACCOUNT_LOCKED", "LOGOUT", "LOCK",
    "APP_START", "APP_EXIT", "CASE_ANALYZED", "CASE_VIEWED", "CASE_SAVED",
    "CASE_DELETED", "CASE_EXPORTED", "VERDICT_OVERRIDE", "AUDIT_VERIFY",
    "SETTINGS_CHANGED", "PASSWORD_CHANGED", "USER_CREATED", "RETENTION_PURGE",
    "AUDIT_EXPORT",
}
AUDIT_PURGE_KEEP = 100_000                # cap audit entries before archival
AUDIT_BATCH = 50                          # entries per encrypted batch file

# --- Data minimization / retention (SI-12 / ISO A.8.10) ----------------------
DEFAULT_CASE_RETENTION_DAYS = 90
DEFAULT_RAW_RETENTION_DAYS = 30           # raw EML shred after this
MAX_AUDIT_EXPORT_BYTES = 512 * 1024

# --- Networking (OWASP A10 SSRF / SC-7) --------------------------------------
# URL engine NEVER fetches arbitrary URLs. Optional reputation lookups are
# pinned to an explicit allowlist of API hosts only, TLS-verified.
ALLOWED_REPUTATION_HOSTS = (
    "www.virustotal.com",
    "api.virustotal.com",
    "urlhaus.abuse.ch",
)
DNS_TIMEOUT_SECONDS = 4.0
DNS_LIFETIME_SECONDS = 8.0

# Reserved/private networks that must never be resolved-to or dialed (SSRF).
PRIVATE_NETWORKS = (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
    "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
    "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32",
)
# IPv6: loopback, link-local, ULA, V4-mapped handled in code.

# --- Threat-data (feeds of brand names for impersonation heuristics) ----------
BRAND_WATCHLIST = (
    "microsoft", "apple", "google", "paypal", "amazon", "netflix",
    "facebook", "linkedin", "github", "dropbox", "moneydeposit",
    "chase", "wellsfargo", "bankofamerica", "citibank", "hsbc",
    "adobe", "office", "outlook", "onedrive", "teams", "irs", "tax",
)
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "top", "xyz", "work", "click", "link",
    "bid", "download", "loan", "men", "review", "stream", "racing",
}
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "ow.ly", "goo.gl", "is.gd", "buff.ly",
    "t.co", "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc", "lnkd.in",
}
PHISHING_KEYWORDS = {
    "urgent", "immediately", "verify", "confirm", "password", "credential",
    "account", "suspended", "locked", "unusual", "login", "update",
    "payment", "invoice", "refund", "wallet", "gift card", "win", "prize",
    "claim", "limited time", "click here", "security alert", "expires soon",
    "mfa", "2fa", "otp", "bank details", "w-2", "wire transfer",
}