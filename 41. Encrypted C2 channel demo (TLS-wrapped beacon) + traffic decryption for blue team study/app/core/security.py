import datetime
import json
import secrets
import socket
import uuid

from app.config import BASE_DIR, CERTS_DIR, DATABASE, LAB_MODE
from app.core.crypto import random_hex, short_ja3
from app.db import execute, query_all, query_one


def ensure_admin_token() -> str:
    from app.config import ADMIN_TOKEN_FILE

    if ADMIN_TOKEN_FILE.exists():
        return ADMIN_TOKEN_FILE.read_text().strip()
    token = secrets.token_hex(24)
    ADMIN_TOKEN_FILE.write_text(token)
    return token


def client_ip(request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    try:
        return request.client.host if request.client else "unknown"
    except Exception:
        return "unknown"


def new_uuid() -> str:
    return str(uuid.uuid4())


def audit(actor: str, action: str, zone: str, detail: str, ip: str = "local"):
    from app.db import now_iso

    execute(
        "INSERT INTO audit_log (ts, actor, action, zone, detail, ip) VALUES (?,?,?,?,?,?)",
        (now_iso(), actor, action, zone, detail[:500], ip),
    )


def hostname() -> str:
    return socket.gethostname()


def tls_policy() -> dict:
    from app.config import TLS_CIPHER, TLS_MIN_VERSION

    return {
        "min_version": TLS_MIN_VERSION,
        "cipher": TLS_CIPHER,
        "lab_mode": LAB_MODE,
        "keylog_path": "data/evidence/master_keys.log / captured (pre)-master secrets",
    }


def ensure_lab_certs():
    certfile = CERTS_DIR / "lab_server.crt"
    keyfile = CERTS_DIR / "lab_server.key"
    if certfile.exists() and keyfile.exists():
        return certfile, keyfile
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "lab-c2-observatory.local"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Authorized Lab Only"),
        ]
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    keyfile.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    certfile.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return certfile, keyfile


def cfg_keylog(session_key_hex: str, host: str, port: int, extra: dict) -> dict:
    entry = {
        "client_random": random_hex(32),
        "server_random": random_hex(32),
        "aes_session_key_hex": session_key_hex,
        "host": host,
        "port": port,
    }
    entry.update(extra)
    return entry


def derive_tls_identity(seed: str) -> dict:
    ja3 = short_ja3("cli:" + seed)
    ja3s = short_ja3("srv:" + seed)
    return {"ja3": ja3, "ja3s": ja3s}


def require_uuid(uuid_value: str) -> bool:
    return query_one("SELECT 1 AS ok FROM sessions WHERE uuid = ?", (uuid_value,)) is not None


def rotate_session_keys(session_uuid: str):
    from app.db import now_iso

    execute(
        "UPDATE keys SET status='rotated' WHERE session_uuid=? AND key_type='session_aes'",
        (session_uuid,),
    )
    audit("KYC", "rotate_session_keys", "C", f"keys rotated for {session_uuid}")


def dumps(v) -> str:
    return json.dumps(v)