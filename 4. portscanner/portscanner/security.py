"""Security helpers implementing controls from security.md.

- Authorization gate   (ISO 27001 A.8.8 / NIST CM-7 / OWASP A05)
- Audit logging        (ISO 27001 A.8.15 / NIST AU-2, AU-3)
- Output sanitization  (terminal escape injection; OWASP A03)
- Resource caps        (OWASP A04)
- Credential redaction (ISO A.5.17 / NIST AC-21)
"""
from __future__ import annotations

import getpass
import hashlib
import ipaddress
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b\].*?(?:\x07|\x1b\\)", re.DOTALL)

MAX_BANNER_BYTES = 256
MAX_AUDIT_LINE = 2048

_STATE_DIR = Path.home() / ".portscanner"
AUDIT_LOG = _STATE_DIR / "audit.log"
SECRET_ENV_KEYS = ("PROXY_PASS", "PROXY_USER", "PASSWORD", "TOKEN", "SECRET")


def ensure_state_dir() -> Path:
    """Create per-user state dir with 0700-equivalent perms (security.md §6)."""
    _STATE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name == "posix":
        try:
            os.chmod(_STATE_DIR, 0o700)
            if AUDIT_LOG.exists():
                os.chmod(AUDIT_LOG, 0o600)
        except OSError:
            pass
    return _STATE_DIR


def is_local_or_private(target: str) -> bool:
    """Loopback / RFC1918 / link-local / u-la targets skip the consent prompt."""
    host = target.split("/")[0].strip()
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return host.lower() in ("localhost",)
    return (
        ip.is_loopback or ip.is_private or ip.is_link_local
        or ip.is_multicast or ip.is_unspecified
    )


CONFIRM_PHRASE = "I confirm I am authorized to scan these targets"


def authorization_gate(targets: list[str], interactive: bool, yes: bool) -> bool:
    """ISO 27001 A.8.8: technical vulnerability testing must be authorized.

    Returns True when the gate passes. Non-local targets require either
    `yes=True` (CLI --yes / GUI checkbox) or typing the confirmation phrase.
    Refusals are audited.
    """
    scope_private = all(is_local_or_private(t) for t in targets)
    if scope_private or yes:
        _audit("AUTHZ", f"granted (explicit={yes}, private_scope={scope_private})")
        return True
    if not interactive:
        _audit("AUTHZ", "DENIED (non-interactive, unconfirmed)")
        return False
    print("WARNING: scanning systems you are not authorized to test may be illegal.")
    print(f"Targets: {', '.join(targets[:8])}{' ...' if len(targets) > 8 else ''}")
    try:
        answer = input(f'Type exactly "{CONFIRM_PHRASE}" to continue: ')
    except (EOFError, KeyboardInterrupt):
        answer = ""
    if answer.strip() == CONFIRM_PHRASE:
        _audit("AUTHZ", "granted (interactive confirmation)")
        return True
    _audit("AUTHZ", "DENIED (wrong confirmation)")
    return False


def is_admin() -> bool:
    """Privilege pre-check (fail before sending packets, not at first probe)."""
    if os.name == "nt":
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001
            return False
    return os.geteuid() == 0


def _audit(event: str, detail: str) -> None:
    """Append-only audit trail: who / when / what (NIST AU-2)."""
    ensure_state_dir()
    who = getpass.getuser()
    ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
    line = f"{ts} | {who} | {event} | {redact(detail)}"
    try:
        with open(AUDIT_LOG, "a", encoding="utf-8") as fh:
            fh.write(line[:MAX_AUDIT_LINE] + "\n")
        if os.name == "posix":
            os.chmod(AUDIT_LOG, 0o600)
    except OSError:
        pass  # audit failure must not crash the scan; reported via warnings


def audit_scan_started(cfg) -> None:
    _audit("SCAN_START", f"targets={list(cfg.targets)} ports={len(cfg.ports)} "
                         f"type={cfg.scan_type} workers={cfg.workers}")


def audit_scan_finished(summary: str) -> None:
    _audit("SCAN_END", summary)


def sanitize_text(raw: bytes, limit: int = MAX_BANNER_BYTES) -> str:
    """Truncate + strip terminal escape sequences + control chars (OWASP A03:
    terminal escape injection via malicious service banners)."""
    text = raw[:limit].decode("utf-8", errors="replace")
    text = _ANSI_RE.sub("", text)
    return "".join(ch if ch.isprintable() or ch in "\t" else "\\x%02x" % ord(ch)
                   for ch in text)


def redact(text: str) -> str:
    """Remove anything that looks like a credential from logs/reports."""
    out = text
    for key in SECRET_ENV_KEYS:
        val = os.environ.get(key)
        if val:
            out = out.replace(val, f"<redacted:{key}>")
    return out


def sha256_of_file(path: Path) -> str:
    """Integrity reference for state.md / chain-of-custody (NIST SI-7)."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def safe_output_path(p: str, project_root: Path) -> Path:
    """Prevent path traversal in --output (OWASP A01). Resolved path must stay
    inside the project root or the user's own .portscanner dir."""
    resolved = Path(p).expanduser().resolve()
    allowed = [project_root.resolve(), (_STATE_DIR).resolve()]
    if not any(str(resolved).startswith(str(a)) for a in allowed):
        raise ValueError(
            f"--output path escapes allowed directories: {resolved}"
        )
    return resolved


def stderr_warn(msg: str) -> None:
    print(f"[warn] {redact(msg)}", file=sys.stderr)
