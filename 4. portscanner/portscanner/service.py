"""Service identification (architecture.md §4.5) — second pass on open ports.

Banner grab → probe-payload matching → optional TLS certificate extraction.
Banners are sanitized via security.sanitize_text before entering results.
"""
from __future__ import annotations

import os
import re
import socket
import ssl
import threading

from .models import ServiceResult, TLSInfo
from .security import MAX_BANNER_BYTES, sanitize_text

TLS_HINT_PORTS = {443, 465, 563, 614, 448, 465, 614, 989, 990, 992, 993, 995,
                  8443, 8834, 9443}

# Ordered probe DB: payload → response regex → (service, product, version-extract)
# conceptually nmap-service-probes, smaller and embeddable (§4.5). Users extend
# via data/service-probes.toml (loaded if present).
DEFAULT_PROBES: list[dict] = [
    {"payload": b"", "re": rb"SSH-([\d\.\w]+)-?(\S*)", "service": "ssh",
     "product": "OpenSSH"},
    {"payload": b"", "re": rb"220[ -][^\r\n]*(?:SMTP|Postfix|Exim|Exchange)",
     "service": "smtp"},
    {"payload": b"", "re": rb"\+OK\s+[^\r\n]*(?:Pop|POP)", "service": "pop3"},
    {"payload": b"", "re": rb"\* (?:OK|NO|BAD)", "service": "imap"},
    {"payload": b"", "re": rb"HTTP/1\.[01]\s+(\d{3})", "service": "http"},
    {"payload": b"GET / HTTP/1.0\r\n\r\n", "re": rb"HTTP/1\.[01]\s+(\d{3})",
     "service": "http"},
    {"payload": b"", "re": rb"Redis\r?\n", "service": "redis"},
    {"payload": b"PING\r\n", "re": rb"\+PONG", "service": "redis"},
    {"payload": b"", "re": rb"SERVING", "service": "memcached"},
    {"payload": b"\x00", "re": rb"\x06", "service": "mongodb"},
]

# Optional user-extensible probe file (TOML, security.md: input validation)
try:
    import tomllib
    from pathlib import Path

    _probe_file = Path(__file__).resolve().parent.parent / "data" / "service-probes.toml"
    if _probe_file.exists():
        with open(_probe_file, "rb") as fh:
            _ext = tomllib.load(fh)
        for p in _ext.get("probe", []):
            try:
                DEFAULT_PROBES.insert(0, {
                    "payload": p["payload"].encode("latin-1"),
                    # Patterns match against raw response *bytes*, so compile as
                    # bytes (byte escapes like \x0a survive; see memory.md D9).
                    "re": re.compile(p["pattern"].encode("latin-1"), re.I),
                    "service": p["service"],
                })
            except Exception:  # noqa: BLE001 — skip bad user probe entries
                continue
except Exception:  # noqa: BLE001
    pass


def _dn(rdn_list: list) -> str:
    """Flatten an SSL decoded DN structure into 'C=US, O=Org, CN=Name'."""
    parts = [f"{k}={v}" for rdn in rdn_list or [] for k, v in rdn]
    return ", ".join(parts)[:256]


class ServiceDetector:
    def __init__(self, timeout_s: float = 3.0) -> None:
        self.timeout_s = timeout_s
        self._lock = threading.Lock()

    def identify(self, host: str, port: int, proto: str) -> ServiceResult:
        if proto != "tcp":
            res = ServiceResult(host=host, port=port, proto=proto, service="unknown")
            return res
        raw = self._grab(host, port)
        banner, match = self._match(raw)
        result = ServiceResult(
            host=host, port=port, proto=proto,
            service=match["service"] if match else ("unknown" if not banner else "unknown-banner"),
            product=match.get("product", "") if match else "",
            banner=banner,
            confidence=0.9 if match else (0.4 if banner else 0.1),
        )
        if match and match.get("groups"):
            self._extract_version(result, match)
        if port in TLS_HINT_PORTS or (banner and "STARTTLS" in banner):
            tls = self._tls_info(host, port)
            if tls:
                result.tls = tls
                result.service = result.service if result.service not in ("unknown", "unknown-banner") else "https"
                result.confidence = max(result.confidence, 0.85)
        return result

    # ---------- internals ----------
    def _grab(self, host: str, port: int) -> bytes:
        chunks: list[bytes] = []
        try:
            with socket.create_connection((host, port), timeout=self.timeout_s) as s:
                s.settimeout(self.timeout_s)
                for probe in DEFAULT_PROBES:
                    try:
                        if probe["payload"]:
                            s.sendall(probe["payload"])
                    except OSError:
                        break
                    try:
                        data = s.recv(MAX_BANNER_BYTES * 2)
                    except (socket.timeout, OSError):
                        continue
                    if data:
                        chunks.append(data)
                        if sum(len(c) for c in chunks) >= MAX_BANNER_BYTES:
                            break
        except OSError:
            pass
        return b"".join(chunks)

    def _match(self, raw: bytes) -> tuple[str, dict | None]:
        banner = sanitize_text(raw)
        for probe in DEFAULT_PROBES:
            m = probe["re"].search(raw)
            if m:
                probe = dict(probe)
                probe["groups"] = m.groups()
                return banner, probe
        return banner, None

    def _extract_version(self, result: ServiceResult, match: dict) -> None:
        groups = match.get("groups") or ()
        if result.service == "ssh" and groups:
            result.version = (groups[0] or b"").decode("ascii", "replace")
            if len(groups) > 1 and groups[1]:
                result.product = groups[1].decode("ascii", "replace") or result.product
        elif result.service == "http" and groups:
            result.version = f"HTTP/{groups[0].decode('ascii', 'replace')}"

    def _tls_info(self, host: str, port: int) -> TLSInfo | None:
        """Fingerprint-only TLS inspection (no trust decisions — security.md)."""
        import hashlib
        import tempfile
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((host, port), timeout=self.timeout_s) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as tls:
                    der = tls.getpeercert(binary_form=True)
            if not der:
                return None
            info = TLSInfo(not_after=hashlib.sha256(der).hexdigest()[:32])
            # stdlib cert parser needs a PEM file; sandboxed to a temp file
            pem = ssl.DER_cert_to_PEM_cert(der)
            fd, tmp_path = tempfile.mkstemp(suffix=".pem")
            try:
                with os.fdopen(fd, "w") as fh:
                    fh.write(pem)
                decoded = ssl._ssl._test_decode_cert(tmp_path)  # type: ignore[attr-defined]
                subject = decoded.get("subject", [])
                issuer = decoded.get("issuer", [])
                info.subject = _dn(subject)
                info.issuer = _dn(issuer)
                not_after = decoded.get("notAfter", "")
                info.not_after = not_after
                info.sans = [v for kind, v in decoded.get("subjectAltName", [])
                             if kind == "DNS"][:16]
            finally:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
            return info
        except (OSError, ssl.SSLError, ValueError):
            return None
