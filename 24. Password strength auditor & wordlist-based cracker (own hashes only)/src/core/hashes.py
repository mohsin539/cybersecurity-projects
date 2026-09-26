import hashlib
import re

from .ntlm import ntlm_hex

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")

_KNOWN_LENGTHS = {
    "SHA1": 40,
    "SHA224": 56,
    "SHA256": 64,
    "SHA384": 96,
    "SHA512": 128,
}

_AMBI = ("MD5", "NTLM")

_MODULAR = (
    ("bcrypt", "$2a$"),
    ("bcrypt", "$2b$"),
    ("bcrypt", "$2y$"),
    ("argon2", "$argon2"),
    ("sha512crypt", "$6$"),
    ("sha256crypt", "$5$"),
    ("md5crypt", "$1$"),
    ("sha1crypt", "$sha1$"),
    ("sha256_", "$sha256$"),
    ("sha512_", "$sha512$"),
)


def is_hex(s):
    return bool(_HEX_RE.match(s))


def identify_token(token):
    raw = token.strip().strip('"').strip("'")
    if not raw:
        return None
    if raw.startswith("$"):
        lower = raw.lower()
        for name, prefix in _MODULAR:
            if lower.startswith(prefix):
                return [name]
        return ["modular-crypt"]
    salt = None
    h = raw
    if ":" in raw:
        left, right = raw.split(":", 1)
        if is_hex(left):
            h = left
            salt = right
    if not is_hex(h) or len(h) % 2 != 0:
        return None
    if len(h) == 32:
        return list(_AMBI)
    for name, ln in _KNOWN_LENGTHS.items():
        if len(h) == ln:
            return [name]
    return None


def identify_line(line, force32=None):
    token = line.strip()
    if not token:
        return None
    salt = None
    h = token
    if ":" in token:
        left, right = token.split(":", 1)
        if is_hex(left):
            h = left
            salt = right
        else:
            return None
        token = left
    algos = identify_token(token)
    if not algos:
        return None
    if len(h) == 32 and force32:
        algos = [force32]
    target = {"token": token, "algos": algos, "salt": salt}
    return target


def compute(algo, password, salt=None, order="pass_salt"):
    if algo == "NTLM":
        return ntlm_hex(password)
    pw_bytes = password.encode("utf-8", "surrogatepass")
    if salt is not None:
        salt_bytes = salt.encode("utf-8", "surrogatepass")
        if order == "salt_pass":
            pw_bytes = salt_bytes + pw_bytes
        else:
            pw_bytes = pw_bytes + salt_bytes
    if algo == "MD5":
        return hashlib.md5(pw_bytes).hexdigest()
    if algo == "SHA1":
        return hashlib.sha1(pw_bytes).hexdigest()
    return getattr(hashlib, algo.lower())(pw_bytes).hexdigest()


def normalize(h):
    return h.strip().lower()


def description(algos):
    return "/".join(algos)