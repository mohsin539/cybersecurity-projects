"""Security guard layer. Implements the controls mapped in security.md:
input validation (A03), least privilege (A01), consent & authorization notice,
audit logging (A09), safe exports (CSV injection, A02/A03)."""

from __future__ import annotations

import logging
import os
import re
import threading
import time
from pathlib import Path

from arp_scanner.util.log import setup_logging

_APP_DIR_NAME = "ArpScanner"
_CONSENT_MARKER = "consent.v1"
_AUDIT_FILE = "audit.log"
_AUDIT_MAX_BYTES = 5 * 1024 * 1024

_logger = setup_logging(1)


class PermissionDenied(OSError):
    """Raised when raw packet access is not available."""


class ConsentRequired(RuntimeError):
    """Raised when the operator has not accepted the authorized-use notice."""


CONSENT_NOTICE = (
    "AUTHORIZED-USE NOTICE\n"
    "----------------------\n"
    "This ARP scanner performs live-host discovery on the local network segment.\n"
    "It sends ARP broadcast requests and records MAC addresses of responding\n"
    "devices. The operator confirms:\n"
    "  [1] They own the network OR have explicit written authorization to scan it,\n"
    "  [2] They will not use the tool for unauthorized reconnaissance, and\n"
    "  [3] They understand ARP traffic is visible to other network observers.\n"
    "Scan results may contain sensitive device identifiers (IP + MAC). Export\n"
    "files must be stored with restrictive permissions and protected access.\n"
    "Unauthorized scanning may violate local laws and regulations."
)


def app_data_dir() -> Path:
    """Per-user application data directory (respects APPDATA on Windows)."""
    base = os.environ.get("APPDATA")
    if base:
        path = Path(base) / _APP_DIR_NAME
    elif os.name == "posix":
        path = Path(os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config"))) / _app_dir_lower()
    else:
        path = Path.home() / _APP_DIR_NAME
    try:
        path.mkdir(parents=True, exist_ok=True)
        _restrict_permissions(path)
    except OSError:
        pass
    return path


def _app_dir_lower() -> str:
    return "arpscanner"


def consent_given() -> bool:
    return (app_data_dir() / _CONSENT_MARKER).exists()


def acknowledge_consent() -> None:
    marker = app_data_dir() / _CONSENT_MARKER
    try:
        marker.write_text(time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), encoding="utf-8")
        _restrict_permissions(marker)
        audit("consent acknowledged by operator")
    except OSError as exc:
        raise ConsentRequired(f"could not store consent marker: {exc}") from exc


def _restrict_permissions(path: Path) -> None:
    """Apply owner-only permissions where the OS supports it (ISO 27001 A.9.4)."""
    try:
        if os.name == "posix":
            os.chmod(path, 0o700 if path.is_dir() else 0o600)
    except OSError:
        pass


_audit_lock = threading.Lock()


def audit(message: str) -> None:
    """Append a structured, timestamped event to stderr and to the audit log
    (OWASP A09 / ISO 27001 A.12.4). Thread-safe."""
    stamp = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + "Z"
    line = f"{stamp} [{os.getpid()}] {message}"
    _logger.info("%s", message)
    try:
        with _audit_lock:
            log_file = app_data_dir() / _AUDIT_FILE
            if log_file.exists() and log_file.stat().st_size > _AUDIT_MAX_BYTES:
                log_file.with_suffix(".log.1").write_bytes(log_file.read_bytes())
                log_file.unlink()
            with log_file.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
            _restrict_permissions(log_file)
    except OSError:
        pass


_CSV_INJECT_RE = re.compile(r"^[=+\-@\t\r]")


def sanitize_cell(value) -> str:
    """Neutralize CSV formula injection (OWASP A03): prefix dangerous cells."""
    text = str(value)
    if _CSV_INJECT_RE.match(text) or text.startswith(("\t", "\r")):
        return "'" + text
    return text


_SAFE_FILENAME_RE = re.compile(r"[\x00-\x1f<>:\"\\|?*]")


def validate_export_path(path: str) -> Path:
    """Validate an export destination; forbid control chars / traversal. Returns
    an absolute-but-unresolved Path (resolution happens write-time)."""
    if not path or not path.strip():
        raise ValueError("export path is empty")
    candidate = Path(path.strip())
    if _SAFE_FILENAME_RE.search(candidate.name):
        raise ValueError("export filename contains invalid characters")
    if ".." in candidate.parts:
        raise ValueError("export path may not contain '..'")
    return candidate


def check_privileges(interface: str) -> None:
    """Verify raw L2 socket access is available. Raises PermissionDenied with
    platform-specific remediation (least privilege, detect at boundary)."""
    try:
        from scapy.all import L2Socket  # lazy import

        sock = L2Socket(iface=interface)
        sock.close()
    except PermissionError as exc:
        raise PermissionDenied(_privilege_hint()) from exc
    except OSError as exc:
        raise PermissionDenied(_privilege_hint()) from exc
    except Exception as exc:  # noqa: BLE001 - any failure = no packet access
        raise PermissionDenied(_privilege_hint()) from exc


def _privilege_hint() -> str:
    if os.name == "nt":
        return (
            "Raw packet access failed. Run the app as Administrator and verify "
            "Npcap is installed and running (https://npcap.com). Exit code 3."
        )
    if os.name == "posix":
        return (
            "Raw packet access failed. Re-run with sudo or grant CAP_NET_RAW / "
            "CAP_NET_ADMIN on the executable. Exit code 3."
        )
    return "Raw packet access failed (privileges or capture driver missing). Exit code 3."