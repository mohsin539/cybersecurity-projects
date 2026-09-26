"""Carving signature database.

Each signature defines the *magic* significantly better than an extension.
Footers are order independent; a file is only ever carved when its header
is found and its (optional) footer/end-marker is located inside the
scan-free-space window.  Confidence is derived from anchor strength:

  * ``high``   → header + verified footer end-marker inside the region
  * ``medium`` → header + strong structural validation passes
  * ``low``    → scaroused at a hard size cap / no footer
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple

GROUPS = {
    "image": 0,
    "document": 1,
    "archive": 2,
    "audio": 3,
    "video": 4,
    "executable": 5,
    "database": 6,
    "other": 7,
}

GROUP_LABELS = {v: k for k, v in GROUPS.items()}


@dataclass(frozen=True)
class FileSig:
    name: str
    ext: str
    magic: bytes
    magic_offset: int = 0       # where the magic must appear (e.g. 4 for ftyp)
    footer: Optional[bytes] = None
    footer_offset: int = 0
    min_size: int = 0
    max_size: Optional[int] = None
    group: str = "other"

    def capability(self, has_footer: bool) -> Tuple[str, str]:
        if has_footer:
            return "high", "header+footer"
        return "medium", "header-only"


SIGNATURES: Tuple[FileSig, ...] = (
    # ----- images -----
    FileSig("JPEG", "jpg", b"\xff\xd8\xff", footer=b"\xff\xd9", min_size=512,
            max_size=100 * 1024 * 1024, group="image"),
    FileSig("PNG", "png", b"\x89PNG\r\n\x1a\n", footer=b"IEND\xaeB`\x82",
            min_size=16, max_size=100 * 1024 * 1024, group="image"),
    FileSig("GIF87a", "gif", b"GIF87a", footer=b";", min_size=16,
            max_size=64 * 1024 * 1024, group="image"),
    FileSig("GIF89a", "gif", b"GIF89a", footer=b";", min_size=16,
            max_size=64 * 1024 * 1024, group="image"),
    FileSig("Windows Bitmap", "bmp", b"BM", min_size=32,
            max_size=256 * 1024 * 1024, group="image"),
    FileSig("WebP", "webp", b"WEBP", magic_offset=8, min_size=32,
            max_size=64 * 1024 * 1024, group="image"),
    FileSig("Windows Icon", "ico", b"\x00\x00\x01\x00", min_size=22,
            max_size=64 * 1024 * 1024, group="image"),
    FileSig("TIFF (LE)", "tif", b"II*\x00", min_size=32,
            max_size=256 * 1024 * 1024, group="image"),
    FileSig("TIFF (BE)", "tif", b"MM\x00*", min_size=32,
            max_size=256 * 1024 * 1024, group="image"),
    FileSig("Photoshop PSD", "psd", b"8BPS", min_size=16,
            max_size=512 * 1024 * 1024, group="image"),
    # ----- documents -----
    FileSig("Portable Document Format", "pdf", b"%PDF-", footer=b"%%EOF",
            min_size=256, max_size=512 * 1024 * 1024, group="document"),
    FileSig("MS/Open XML (DOC/XLS/PPT)", "doc", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
            min_size=512, max_size=512 * 1024 * 1024, group="document"),
    FileSig("XML Document", "xml", b"<?xml", footer=b"</", min_size=64,
            max_size=32 * 1024 * 1024, group="document"),
    FileSig("Rich Text", "rtf", b"{\\rtf", footer=b"}", min_size=64,
            max_size=64 * 1024 * 1024, group="document"),
    FileSig("HTML", "html", b"<!DOCTYPE html", footer=b"</html>", min_size=128,
            max_size=64 * 1024 * 1024, group="document"),
    FileSig("HTML 4", "html", b"<html", footer=b"</html>", min_size=128,
            max_size=64 * 1024 * 1024, group="document"),
    # ----- archives / packages -----
    FileSig("ZIP Archive", "zip", b"PK\x03\x04", footer=b"PK\x05\x06",
            min_size=64, max_size=4 * 1024 * 1024 * 1024, group="archive"),
    FileSig("ZIP/Empty", "zip", b"PK\x05\x06", min_size=64,
            max_size=64 * 1024 * 1024, group="archive"),
    FileSig("7-Zip", "7z", b"7z\xbc\xaf\x27\x1c", min_size=64,
            max_size=4 * 1024 * 1024 * 1024, group="archive"),
    FileSig("RAR", "rar", b"Rar!\x1a\x07", min_size=64,
            max_size=4 * 1024 * 1024 * 1024, group="archive"),
    FileSig("TAR Archive", "tar", b"ustar", magic_offset=257, min_size=512,
            max_size=8 * 1024 * 1024 * 1024, group="archive"),
    FileSig("GZip", "gz", b"\x1f\x8b\x08", min_size=32,
            max_size=4 * 1024 * 1024 * 1024, group="archive"),
    # ----- audio / video -----
    FileSig("ID3 / MP3", "mp3", b"ID3", max_size=64 * 1024 * 1024, group="audio"),
    FileSig("MP3 Frame", "mp3", b"\xff\xfb", max_size=64 * 1024 * 1024, group="audio"),
    FileSig("MP3 Frame V2", "mp3", b"\xff\xf3", max_size=64 * 1024 * 1024, group="audio"),
    FileSig("MP3 Frame V2old", "mp3", b"\xff\xf2", max_size=64 * 1024 * 1024, group="audio"),
    FileSig("FLAC", "flac", b"fLaC", min_size=32, max_size=512 * 1024 * 1024, group="audio"),
    FileSig("WAVE Audio", "wav", b"WAVE", magic_offset=8, min_size=128,
            max_size=1 * 1024 * 1024 * 1024, group="audio"),
    FileSig("AVI Video", "avi", b"AVI ", magic_offset=8, min_size=256,
            max_size=4 * 1024 * 1024 * 1024, group="video"),
    FileSig("MP4/QuickTime", "mp4", b"ftyp", magic_offset=4, min_size=256,
            max_size=4 * 1024 * 1024 * 1024, group="video"),
    FileSig("Matroska/WebM", "mkv", b"\x1aE\xdf\xa3", min_size=256,
            max_size=4 * 1024 * 1024 * 1024, group="video"),
    # ----- executables / system -----
    FileSig("Windows EXE/DLL", "exe", b"MZ", min_size=512,
            max_size=2 * 1024 * 1024 * 1024, group="executable"),
    FileSig("ELF Binary", "elf", b"\x7fELF", min_size=64,
            max_size=2 * 1024 * 1024 * 1024, group="executable"),
    FileSig("Mach-O (64-bit)", "macho", b"\xcf\xfa\xed\xfe", min_size=64,
            max_size=2 * 1024 * 1024 * 1024, group="executable"),
    FileSig("Windows Shortcut", "lnk", b"\x4c\x00\x00\x00\x01\x14\x02\x00",
            min_size=16, max_size=16 * 1024 * 1024, group="other"),
    FileSig("Windows Registry Hive", "reg", b"regf", min_size=4096,
            max_size=1024 * 1024 * 1024, group="database"),
    FileSig("ESEDB", "edb", b"\xef\xcd\xab\x89", min_size=4096,
            max_size=8 * 1024 * 1024 * 1024, group="database"),
    # ----- databases -----
    FileSig("SQLite 3", "sqlite", b"SQLite format 3\x00", min_size=512,
            max_size=32 * 1024 * 1024 * 1024, group="database"),
    # ----- ISO images -----
    FileSig("ISO9660", "iso", b"\x43\x44\x30\x30\x31", magic_offset=0x8001,
            min_size=65536, max_size=8 * 1024 * 1024 * 1024, group="archive"),
)


def signature_lookup(ext: str):
    ex = ext.lower().lstrip(".")
    for s in SIGNATURES:
        if s.ext == ex:
            return s
    return None


def extensions_for_group(group: str) -> Tuple[str, ...]:
    return tuple(s.ext for s in SIGNATURES if s.group == group)


def validate_signature(sig: FileSig, data: bytes) -> bool:
    """Cheap structural smoke-test used to raise/lower confidence."""
    if sig.name == "PNG":
        if len(data) < 24:
            return False
        w, h = struct_ubint(data, 16, 4), struct_ubint(data, 20, 4)
        return 1 <= w <= 200000 and 1 <= h <= 200000
    if sig.name == "Windows Icon":
        if len(data) < 22:
            return False
        reserved, kind, count = struct.unpack_from("<HHH", data, 0)
        return reserved == 0 and kind in (1, 2) and 1 <= count <= 256
    if sig.name == "ESEDB":
        return len(data) >= 4096 and data[0x28:0x35] == b"Microsoft\x00\x00\x00\x00"
    if sig.ext == "pdf":
        return b"/Type" in data[:4000] or b"obj" in data[:4000]
    if sig.ext == "zip":
        return b"PK\x05\x06" in data[-32768:] if len(data) > 32768 else b"PK\x05\x06" in data
    if sig.ext in ("exe", "dll"):
        return len(data) > 1024
    if sig.ext in ("mp3",) and sig.name.startswith("ID3"):
        return len(data) >= 10
    return True


def struct_ubint(b: bytes, off: int, nbytes: int) -> int:
    return int.from_bytes(b[off:off + nbytes], "big")


def brain_stem_like_footer(sig: FileSig) -> bool:
    """Whether the signature *requires* a footer for a high-conf carve."""
    return sig.footer is not None and sig.ext not in ("doc", "zip", "exe", "mp3")