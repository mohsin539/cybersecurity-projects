"""Secret redaction — secrets must never reach logs, audit output, or UI
(ISO 27001 A.8.12 / A.8.9; OWASP A02). A canonical scrubber works on dicts
and strings; add new secret-like attribute names here."""

SECRET_KEYS = {
    "private_key",
    "preshared_key",
    "psk",
    "secret",
    "token",
    "token_hash",
    "token_salt",
    "password",
    "passphrase",
    "api_key",
    "private-keys",
}

REDACTED = "[REDACTED]"


def scrub(text: str, secrets: list[str] | None = None) -> str:
    """Replace known secret strings inside free text."""
    result = text if text else ""
    for secret in secrets or []:
        if secret and len(secret) >= 8:
            result = result.replace(secret, REDACTED)
    return result


def scrub_mapping(mapping: dict, name: str) -> str:
    """Return a log-safe rendering of a mapping with secret keys replaced."""
    if not isinstance(mapping, dict):
        return str(mapping)

    def safe_value(v):
        if isinstance(v, dict):
            return scrub_mapping(v, "")[-400:]
        if isinstance(v, (list, tuple)):
            return [safe_value(i) for i in v][:20]
        return v

    out = {}
    for key, value in mapping.items():
        if isinstance(key, str) and key.lower() in SECRET_KEYS:
            out[key] = REDACTED
        else:
            out[key] = safe_value(value)
    return repr(out)[:600]


def scrub_payload(payload: dict) -> dict:
    """Deep-copy a dict, replacing any secret-keyed value with [REDACTED]."""
    if isinstance(payload, dict):
        return {
            k: (REDACTED if (isinstance(k, str) and k.lower() in SECRET_KEYS)
                else scrub_payload(v))
            for k, v in payload.items()
        }
    if isinstance(payload, list):
        return [scrub_payload(i) for i in payload]
    return payload