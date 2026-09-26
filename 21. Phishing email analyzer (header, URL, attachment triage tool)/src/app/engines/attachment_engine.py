"""Attachment triage engine: type verification (magic bytes), integrity hashes,
entropy, and static indicators for executable/script/macro/zip-bomb payloads.

Controls: SI-10 (type/limit validation), SI-4 (malicious code detection),
A.12.2/A.12.6 (malware protection). No attachment content is ever executed or
rendered inside the app (detonation is out-of-scope for a portable tool;
suspicious files are flagged for a sandbox).
"""
from __future__ import annotations

import hashlib
import io
import math
import re
import zipfile
from typing import Dict, List, Optional, Tuple

from ..sec import constants as C
from ..sec.validation import sanitize_filename
from .model import EngineResult, Severity

MAGIC_SIGNATURES: List[Tuple[bytes, int, str]] = [
    (b"%PDF-", 0, "pdf"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 0, "ole"),
    (b"PK\x03\x04", 0, "zip"),
    (b"PK\x05\x06", 0, "zip"),
    (b"PK\x07\x08", 0, "zip"),
    (b"\x7fELF", 0, "elf"),
    (b"MZ", 0, "pe"),
    (b"\x1f\x8b", 0, "gzip"),
    (b"7z\xbc\xaf\x27\x1c", 0, "7z"),
    (b"Rar!\x1a\x07", 0, "rar"),
    (b"\xd7\xcd\xc6\x9a", 0, "wmf"),
    (b"\x25\x21", 0, "posix-script"),
    (b"{\rtf", 0, "rtf"),
    (b"{\\rtf", 0, "rtf"),
    (b"BM", 0, "bmp"),
    (b"\xff\xd8\xff", 0, "jpeg"),
    (b"\x89PNG\r\n\x1a\n", 0, "png"),
    (b"GIF8", 0, "gif"),
    (b"ID3", 0, "mp3"),
]

SUSPICIOUS_EXTS = {
    ".exe", ".scr", ".hta", ".js", ".jse", ".vbs", ".vbe", ".ps1", ".psm1",
    ".bat", ".cmd", ".com", ".pif", ".lnk", ".msi", ".msp", ".iso", ".img",
    ".jar", ".py", ".wsf", ".wsh", ".cpl", ".reg", ".docm", ".xlsm", ".pptm",
}

HIGH_ENTROPY_THRESHOLD = 7.4      # bits/byte over sample
ZIP_PRECIOUS = ("vbaProject.bin", "macro", "oleObject", "embedd")
OLE_MACRO_MARKERS = (b"PROJECT", b"VB_ATTRIBUTES", b"VBA", b"Attribut")


def detect_magic(data: bytes) -> str:
    for sig, off, name in MAGIC_SIGNATURES:
        if data[off: off + len(sig)] == sig:
            return name
    return ""


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    sample = data[: 1 << 20]
    freq = [0] * 256
    for b in sample:
        freq[b] += 1
    n = len(sample)
    ent = 0.0
    for c in freq:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return round(ent, 3)


class AttachmentEngine:
    def __init__(self, msg):
        self.msg = msg
        self.attachments: List[Dict] = []

    def analyze(self) -> EngineResult:
        res = EngineResult("attachment")
        self._collect()
        res.meta["attachment_count"] = len(self.attachments)
        if not self.attachments:
            res.add("NO_ATTACHMENTS", Severity.INFO, "No attachments present", category="info")
            return res
        for att in self.attachments:
            res.meta.setdefault("attachments", []).append({k: att[k] for k in
                ("filename", "declared", "magic", "sha256", "size")})
            self._triage_attachment(res, att)
        return res

    def _collect(self) -> None:
        count = 0
        for part in self.msg.walk():
            if part.is_multipart():
                continue
            content_type = (part.get_content_type() or "application/octet-stream").lower()
            if content_type.startswith("text/") and not part.get_filename():
                continue
            payload = part.get_payload(decode=True)
            if payload is None:
                continue
            size = len(payload)
            filename = part.get_filename() or ""
            if size > C.MAX_ATTACHMENT_BYTES:
                continue
            true_type = detect_magic(payload[: 16])
            if content_type in ("text/plain", "text/html") and not filename and true_type not in ("zip", "ole", "pe"):
                continue
            count += 1
            if count > C.MAX_ATTACHMENTS:
                break
            self.attachments.append({
                "filename": sanitize_filename(filename),
                "declared": content_type,
                "magic": true_type,
                "sha256": hashlib.sha256(payload).hexdigest(),
                "sha1": hashlib.sha1(payload).hexdigest(),
                "md5": hashlib.md5(payload).hexdigest(),
                "size": size,
                "data": payload,
                "entropy": shannon_entropy(payload),
            })

    def _triage_attachment(self, res: EngineResult, att: Dict) -> None:
        fn = (att["filename"] or "unknownown").lower()
        ext = "." + fn.rsplit(".", 1)[-1] if "." in fn else ""
        f = att["filename"] or att["declared"]

        if ext in SUSPICIOUS_EXTS:
            res.add("ATT_EXEC", Severity.HIGH,
                    f"Attachment '{f}' has executable/script extension {ext} - never open untrusted",
                    detail=f"sha256={att['sha256'][:16]}", category="malicious")
        if fn.count(".") > 1 and ext not in (".zip", ".rar", ".7z", ".gz"):
            res.add("ATT_DOUBLE_EXT", Severity.MEDIUM,
                    f"Attachment '{f}' uses multiple extensions (2003_scan.pdf.exe trick)",
                    category="obfuscation")

        # MIME spoofing: declared text but magic says binary
        if att["declared"].startswith("text/") and att["magic"] in ("pe", "ole", "zip", "pdf", "rtf"):
            res.add("ATT_MIMESPOOF", Severity.HIGH,
                    f"Declared {att['declared']} but magic bytes identify {att['magic']} - type spoofing",
                    category="malicious")

        data = att["data"]
        if att["magic"] == "ole":
            self._inspect_ole(res, att, data)
        elif att["magic"] == "zip":
            self._inspect_zip(res, att, data)

        # HTML attachments with active content
        if att["magic"] == "" and (att["declared"] == "text/html" or ext == ".html"):
            if re.search(rb"(?i)\b(onmouseover|onload|onclick|javascript:|data:text/html)",
                         data[: min(len(data), 200_000)]):
                res.add("ATT_ACTIVE_HTML", Severity.HIGH,
                        "HTML attachment embeds active script handlers - phishing/beacon risk",
                        category="malicious")

        if att["entropy"] >= HIGH_ENTROPY_THRESHOLD and ext not in (".pdf",):
            res.add("ATT_HIGH_ENTROPY", Severity.LOW,
                    f"Attachment '{f}' entropy={att['entropy']} (encrypted/obfuscated payload signal)",
                    category="anomaly")

    # -- deep inspections -------------------------------------------------
    def _inspect_ole(self, res: EngineResult, att: Dict, data: bytes) -> None:
        if any(m in data for m in OLE_MACRO_MARKERS):
            res.add("ATT_OLE_MACRO", Severity.HIGH,
                    "OLE document contains VBA macro markers - macro-enabled documents are phishing vectors",
                    detail=f"sha256={att['sha256'][:16]}", category="malicious")

    def _inspect_zip(self, res: EngineResult, att: Dict, data: bytes) -> None:
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                members = zf.infolist()
                names = [m.filename.lower() for m in members]
                if len(members) > 2000 or sum(m.file_size for m in members) > 1 << 29:
                    res.add("ATT_ZIP_BOMB", Severity.HIGH,
                            "Archive has bomb-like size/entry profile (many entries or huge uncompressed)",
                            category="malicious")
                    return
                macros = [n for n in names if any(p in n for p in ZIP_PRECIOUS)]
                if macros:
                    res.add("ATT_DOC_MACRO", Severity.HIGH,
                            "Office archive embeds macro artifacts (vbaProject/macro/embedded object)",
                            detail=";".join(macros[:5]), category="malicious")
                # executable inside archive
                if any(n.endswith(tuple(SUSPICIOUS_EXTS)) for n in names):
                    res.add("ATT_ZIP_EXEC_INNER", Severity.HIGH,
                            "Archive contains executable content", category="malicious")
                # ratio check: heavily compressed payloads of Store members
                stored = [m for m in members if m.compress_type == zipfile.ZIP_STORED]
                raw = sum(m.file_size for m in stored)
                if stored and raw > (1 << 20) and raw / max(att["size"], 1) > 8:
                    res.add("ATT_STORED_RATIO", Severity.MEDIUM,
                            "Archive has unusually large stored (uncompressed) members",
                            category="anomaly")
        except (zipfile.BadZipFile, OSError, ValueError):
            res.add("ATT_BADZIP", Severity.LOW, "Declared/identified zip failed to parse",
                    category="anomaly")


def build_detection_payload(att: Dict) -> str:
    """Sanitized one-line IOC summary used for audit / export (data minimization)."""
    return (f"name={att['filename']} type={att['magic']} sha256={att['sha256']} "
            f"size={att['size']} entropy={att['entropy']}")