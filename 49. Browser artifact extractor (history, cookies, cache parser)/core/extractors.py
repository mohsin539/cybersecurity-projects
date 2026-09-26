"""Read-only parsers for browser artifacts.

Every function opens its source database through :func:`_open_db`, which copies
the file (plus any ``-wal`` / ``-shm`` sidecars) into a private temporary
directory before reading. This guarantees the original evidence is never
locked, modified or corrupted (ISO 27001 A.8.3, NIST SP 800-86 section 3.2).

Returned records are plain ``dict`` objects so they can be serialised to any
report format without further translation.
"""
from __future__ import annotations

import contextlib
import glob
import json
import os
import re
import shutil
import sqlite3
import struct
import tempfile
from typing import Dict, Iterable, List, Optional

from . import decrypt, winio

URL_RE = re.compile(rb"https?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{4,2048}")

# Chromium simple-cache file header magic.
_SIMPLE_CACHE_MAGIC = 0xFCFB6D1BA7725C30


# ---------------------------------------------------------------------------
# Safe database access
# ---------------------------------------------------------------------------
@contextlib.contextmanager
def _open_db(path: str):
    """Yield a read-only sqlite3 connection backed by a temporary copy.

    Acquisition escalates through :mod:`core.winio` (shared read -> backup
    semantics -> VSS snapshot). The original file is never opened for writing,
    so evidence integrity is preserved even for live, locked profiles.
    """
    tmpdir = tempfile.mkdtemp(prefix="bae_db_")
    base = os.path.basename(path)
    local = os.path.join(tmpdir, base)
    conn = None
    try:
        winio.copy_any(path, local)  # raises EvidenceLocked if impossible
        for sidecar in (path + "-wal", path + "-shm", path + "-journal"):
            if os.path.exists(sidecar):
                try:
                    winio.copy_any(sidecar,
                                   os.path.join(tmpdir, os.path.basename(sidecar)),
                                   allow_vss=False)
                except OSError:
                    pass
        conn = sqlite3.connect(local)
        conn.row_factory = sqlite3.Row
        conn.text_factory = lambda b: b.decode("utf-8", "replace")
        yield conn
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:  # noqa: BLE001
                pass
        shutil.rmtree(tmpdir, ignore_errors=True)


def _rows(conn: sqlite3.Connection, query: str, params: Iterable = ()) -> List[sqlite3.Row]:
    try:
        return list(conn.execute(query, tuple(params)))
    except sqlite3.Error:
        return []


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone()
    return row is not None


# ---------------------------------------------------------------------------
# History
# ---------------------------------------------------------------------------
def extract_history_chromium(path: str, limit: int = 0) -> List[Dict]:
    out: List[Dict] = []
    with _open_db(path) as conn:
        sql = (
            "SELECT u.url, u.title, u.visit_count, u.typed_count, "
            "       u.last_visit_time, v.visit_time, v.visit_duration, "
            "       v.transition, v.from_visit "
            "FROM urls u LEFT JOIN visits v ON v.url = u.id "
            "ORDER BY v.visit_time DESC"
        )
        if limit:
            sql += f" LIMIT {int(limit)}"
        for row in _rows(conn, sql):
            out.append({
                "url": row["url"],
                "title": row["title"],
                "visit_count": row["visit_count"],
                "typed_count": row["typed_count"],
                "last_visit": decrypt.chrome_time(row["last_visit_time"]),
                "visit_time": decrypt.chrome_time(row["visit_time"]),
                "visit_duration_sec": round((row["visit_duration"] or 0) / 1_000_000, 3),
                "transition": row["transition"],
            })
    return out


def extract_history_firefox(path: str, limit: int = 0) -> List[Dict]:
    out: List[Dict] = []
    with _open_db(path) as conn:
        sql = (
            "SELECT p.url, p.title, p.visit_count, p.typed, p.hidden, "
            "       p.last_visit_date, v.visit_date, v.visit_type "
            "FROM moz_places p LEFT JOIN moz_historyvisits v ON v.place_id = p.id "
            "ORDER BY v.visit_date DESC"
        )
        if limit:
            sql += f" LIMIT {int(limit)}"
        for row in _rows(conn, sql):
            out.append({
                "url": row["url"],
                "title": row["title"],
                "visit_count": row["visit_count"],
                "typed_count": row["typed"],
                "last_visit": decrypt.firefox_time(row["last_visit_date"]),
                "visit_time": decrypt.firefox_time(row["visit_date"]),
                "visit_duration_sec": None,
                "transition": row["visit_type"],
            })
    return out


# ---------------------------------------------------------------------------
# Downloads
# ---------------------------------------------------------------------------
def extract_downloads_chromium(path: str, limit: int = 0) -> List[Dict]:
    out: List[Dict] = []
    with _open_db(path) as conn:
        if not _table_exists(conn, "downloads"):
            return out
        sql = (
            "SELECT d.id, d.target_path, d.current_path, d.start_time, "
            "       d.received_bytes, d.total_bytes, d.state, d.danger_type, "
            "       d.tab_url, d.mime_type, d.original_mime_type, "
            "       (SELECT url FROM downloads_url_chains c "
            "        WHERE c.id = d.id ORDER BY c.chain_index LIMIT 1) AS chain_url "
            "FROM downloads d ORDER BY d.start_time DESC"
        )
        if limit:
            sql += f" LIMIT {int(limit)}"
        for row in _rows(conn, sql):
            out.append({
                "file": os.path.basename(row["target_path"] or row["current_path"] or ""),
                "path": row["target_path"] or row["current_path"],
                "url": row["chain_url"] or row["tab_url"],
                "start_time": decrypt.chrome_time(row["start_time"]),
                "received_bytes": row["received_bytes"],
                "total_bytes": row["total_bytes"],
                "state": row["state"],
                "danger_type": row["danger_type"],
                "mime_type": row["mime_type"],
            })
    return out


def extract_downloads_firefox(path: str, limit: int = 0) -> List[Dict]:
    out: List[Dict] = []
    with _open_db(path) as conn:
        sql = (
            "SELECT p.url, p.title, a.content AS dest, a.dateAdded "
            "FROM moz_annos a "
            "JOIN moz_anno_attributes at ON at.id = a.anno_attribute_id "
            "JOIN moz_places p ON p.id = a.place_id "
            "WHERE at.name = 'downloads/destinationFileURI' "
            "ORDER BY a.dateAdded DESC"
        )
        if limit:
            sql += f" LIMIT {int(limit)}"
        for row in _rows(conn, sql):
            dest = row["dest"] or ""
            if dest.startswith("file://"):
                dest = dest[7:]
            out.append({
                "file": os.path.basename(dest),
                "path": dest.replace("%20", " "),
                "url": row["url"],
                "start_time": decrypt.firefox_time(row["dateAdded"]),
                "received_bytes": None,
                "total_bytes": None,
                "state": 1,
                "danger_type": 0,
                "mime_type": None,
            })
    return out


# ---------------------------------------------------------------------------
# Cookies
# ---------------------------------------------------------------------------
def extract_cookies_chromium(path: str, key: Optional[bytes], do_decrypt: bool,
                             limit: int = 0) -> List[Dict]:
    out: List[Dict] = []
    with _open_db(path) as conn:
        if not _table_exists(conn, "cookies"):
            return out
        sql = (
            "SELECT host_key, name, value, encrypted_value, path, expires_utc, "
            "       creation_utc, last_access_utc, is_secure, is_httponly, "
            "       is_persistent, samesite, source_scheme "
            "FROM cookies ORDER BY host_key ASC, name ASC"
        )
        if limit:
            sql += f" LIMIT {int(limit)}"
        for row in _rows(conn, sql):
            plain = row["value"] or ""
            enc = row["encrypted_value"] or b""
            status = "plaintext"
            if isinstance(enc, str):
                enc = enc.encode("latin-1", "ignore")
            if enc:
                if do_decrypt:
                    plain, status = decrypt.decrypt_value(enc, key)
                else:
                    status = "encrypted"
                    plain = ""
            out.append({
                "host": row["host_key"],
                "name": row["name"],
                "value": plain,
                "value_status": status,
                "path": row["path"],
                "expires": decrypt.chrome_time(row["expires_utc"]),
                "created": decrypt.chrome_time(row["creation_utc"]),
                "last_access": decrypt.chrome_time(row["last_access_utc"]),
                "secure": bool(row["is_secure"]),
                "http_only": bool(row["is_httponly"]),
                "persistent": bool(row["is_persistent"]),
                "same_site": row["samesite"],
            })
    return out


def extract_cookies_firefox(path: str, do_decrypt: bool,
                            limit: int = 0) -> List[Dict]:
    out: List[Dict] = []
    with _open_db(path) as conn:
        if not _table_exists(conn, "moz_cookies"):
            return out
        sql = (
            "SELECT host, name, value, path, expiry, lastAccessed, creationTime, "
            "       isSecure, isHttpOnly, sameSite "
            "FROM moz_cookies ORDER BY host ASC, name ASC"
        )
        if limit:
            sql += f" LIMIT {int(limit)}"
        for row in _rows(conn, sql):
            out.append({
                "host": row["host"],
                "name": row["name"],
                "value": row["value"] if do_decrypt else "",
                "value_status": "plaintext" if do_decrypt else "encrypted",
                "path": row["path"],
                "expires": decrypt.firefox_time((row["expiry"] or 0) * 1_000_000),
                "created": decrypt.firefox_time(row["creationTime"]),
                "last_access": decrypt.firefox_time(row["lastAccessed"]),
                "secure": bool(row["isSecure"]),
                "http_only": bool(row["isHttpOnly"]),
                "persistent": True,
                "same_site": row["sameSite"],
            })
    return out


# ---------------------------------------------------------------------------
# Bookmarks
# ---------------------------------------------------------------------------
def extract_bookmarks_chromium(path: str) -> List[Dict]:
    out: List[Dict] = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            data = json.load(fh)
    except Exception:  # noqa: BLE001
        return out

    def walk(node: Dict, folder: str):
        node_type = node.get("type")
        if node_type == "url":
            out.append({
                "name": node.get("name", ""),
                "url": node.get("url", ""),
                "folder": folder,
                "date_added": decrypt.chrome_time(node.get("date_added")),
            })
        elif node_type == "folder":
            name = node.get("name", "")
            sub = f"{folder}/{name}" if folder else name
            for child in node.get("children", []):
                walk(child, sub)

    roots = data.get("roots", {})
    for root_name, node in roots.items():
        if isinstance(node, dict):
            walk(node, root_name)
    return out


def extract_bookmarks_firefox(path: str) -> List[Dict]:
    out: List[Dict] = []
    with _open_db(path) as conn:
        if not _table_exists(conn, "moz_bookmarks"):
            return out
        sql = (
            "SELECT b.title, p.url, b.dateAdded, b.position, b.parent "
            "FROM moz_bookmarks b JOIN moz_places p ON p.id = b.fk "
            "WHERE b.type = 1 ORDER BY b.parent, b.position"
        )
        for row in _rows(conn, sql):
            out.append({
                "name": row["title"],
                "url": row["url"],
                "folder": f"parent#{row['parent']}",
                "date_added": decrypt.firefox_time(row["dateAdded"]),
            })
    return out


# ---------------------------------------------------------------------------
# Autofill / form history
# ---------------------------------------------------------------------------
def extract_autofill_chromium(path: str, limit: int = 0) -> List[Dict]:
    out: List[Dict] = []
    with _open_db(path) as conn:
        if _table_exists(conn, "autofill"):
            sql = ("SELECT name, value, count, date_created, date_last_used "
                   "FROM autofill ORDER BY count DESC")
            if limit:
                sql += f" LIMIT {int(limit)}"
            for row in _rows(conn, sql):
                out.append({
                    "field": row["name"], "value": row["value"],
                    "times_used": row["count"],
                    "first_used": decrypt.chrome_time(row["date_created"]),
                    "last_used": decrypt.chrome_time(row["date_last_used"]),
                })
    return out


def extract_autofill_firefox(path: str, limit: int = 0) -> List[Dict]:
    out: List[Dict] = []
    with _open_db(path) as conn:
        if not _table_exists(conn, "moz_formhistory"):
            return out
        sql = ("SELECT fieldname, value, timesUsed, firstUsed, lastUsed "
               "FROM moz_formhistory ORDER BY timesUsed DESC")
        if limit:
            sql += f" LIMIT {int(limit)}"
        for row in _rows(conn, sql):
            out.append({
                "field": row["fieldname"], "value": row["value"],
                "times_used": row["timesUsed"],
                "first_used": decrypt.firefox_time(row["firstUsed"]),
                "last_used": decrypt.firefox_time(row["lastUsed"]),
            })
    return out


# ---------------------------------------------------------------------------
# Saved logins
# ---------------------------------------------------------------------------
def extract_logins_chromium(path: str, key: Optional[bytes], do_decrypt: bool,
                            limit: int = 0) -> List[Dict]:
    out: List[Dict] = []
    with _open_db(path) as conn:
        if not _table_exists(conn, "logins"):
            return out
        sql = (
            "SELECT origin_url, action_url, username_element, username_value, "
            "       password_element, password_value, signon_realm, "
            "       date_created, date_last_used, blacklisted_by_user "
            "FROM logins ORDER BY origin_url ASC"
        )
        if limit:
            sql += f" LIMIT {int(limit)}"
        for row in _rows(conn, sql):
            enc = row["password_value"] or b""
            if isinstance(enc, str):
                enc = enc.encode("latin-1", "ignore")
            pw, status = "", "encrypted"
            if do_decrypt:
                pw, status = decrypt.decrypt_value(enc, key)
            out.append({
                "origin": row["origin_url"],
                "action": row["action_url"],
                "username_field": row["username_element"],
                "username": row["username_value"],
                "password": pw,
                "password_status": status,
                "realm": row["signon_realm"],
                "created": decrypt.chrome_time(row["date_created"]),
                "last_used": decrypt.chrome_time(row["date_last_used"]),
                "blacklisted": bool(row["blacklisted_by_user"]),
            })
    return out


def extract_logins_firefox(path: str, do_decrypt: bool,
                           limit: int = 0) -> List[Dict]:
    out: List[Dict] = []
    if not os.path.isfile(path):
        return out
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            data = json.load(fh)
    except Exception:  # noqa: BLE001
        return out
    for entry in data.get("logins", [])[:limit or None]:
        out.append({
            "origin": entry.get("hostname"),
            "action": "",
            "username_field": entry.get("usernameField"),
            "username": entry.get("encryptedUsername"),
            "password": entry.get("encryptedPassword") if do_decrypt else "",
            "password_status": "encrypted" if do_decrypt else "encrypted",
            "realm": entry.get("formSubmitURL"),
            "created": decrypt.firefox_time(entry.get("timeCreated")),
            "last_used": decrypt.firefox_time(entry.get("timeLastUsed")),
            "blacklisted": False,
        })
    return out


# ---------------------------------------------------------------------------
# Search terms
# ---------------------------------------------------------------------------
def extract_search_terms_chromium(path: str, limit: int = 0) -> List[Dict]:
    out: List[Dict] = []
    with _open_db(path) as conn:
        if not _table_exists(conn, "keyword_search_terms"):
            return out
        sql = (
            "SELECT k.term, u.url, u.title, u.last_visit_time "
            "FROM keyword_search_terms k JOIN urls u ON u.id = k.url_id "
            "ORDER BY u.last_visit_time DESC"
        )
        if limit:
            sql += f" LIMIT {int(limit)}"
        for row in _rows(conn, sql):
            out.append({
                "term": row["term"], "url": row["url"], "title": row["title"],
                "last_visit": decrypt.chrome_time(row["last_visit_time"]),
            })
    return out


def extract_search_terms_firefox(path: str, limit: int = 0) -> List[Dict]:
    out: List[Dict] = []
    with _open_db(path) as conn:
        if not _table_exists(conn, "moz_keywords"):
            return out
        sql = ("SELECT k.keyword AS term, p.url, p.title, p.last_visit_date "
               "FROM moz_keywords k JOIN moz_places p ON p.id = k.place_id "
               "ORDER BY p.last_visit_date DESC")
        if limit:
            sql += f" LIMIT {int(limit)}"
        for row in _rows(conn, sql):
            out.append({
                "term": row["term"], "url": row["url"], "title": row["title"],
                "last_visit": decrypt.firefox_time(row["last_visit_date"]),
            })
    return out


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------
def _parse_simple_cache_key(blob: bytes) -> Optional[str]:
    if len(blob) < 20:
        return None
    try:
        magic, _version, key_len, _key_hash = struct.unpack_from("<QIII", blob, 0)
    except struct.error:
        return None
    if magic != _SIMPLE_CACHE_MAGIC or key_len <= 0 or key_len > 4096:
        return None
    key = blob[20:20 + key_len]
    try:
        return key.split(b"\x00", 1)[0].decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        return None


def extract_cache_chromium(directory: str, extract_urls: bool = True,
                           limit: int = 0) -> List[Dict]:
    """Parse Chromium simple-cache files, recovering cached request keys/URLs."""
    out: List[Dict] = []
    if not os.path.isdir(directory):
        return out
    files = glob.glob(os.path.join(directory, "**", "*"), recursive=True)
    for fp in files:
        if not os.path.isfile(fp):
            continue
        name = os.path.basename(fp)
        if not (name.startswith("f_") or name.endswith("_0")):
            continue
        try:
            size = os.path.getsize(fp)
            mtime = os.path.getmtime(fp)
        except OSError:
            continue
        record = {
            "file": name,
            "path": fp,
            "size_bytes": size,
            "modified": decrypt.chrome_time(int((mtime + 11644473600) * 1_000_000)),
            "key": "", "url": "", "source": "simple-cache",
        }
        try:
            with open(fp, "rb") as fh:
                head = fh.read(4096)
            key = _parse_simple_cache_key(head)
            if key:
                record["key"] = key
                if key.startswith("http"):
                    record["url"] = key
            if not record["url"] and extract_urls:
                match = URL_RE.search(head)
                if match:
                    record["url"] = match.group(0).decode("utf-8", "replace")
        except OSError:
            pass
        out.append(record)
        if limit and len(out) >= limit:
            break
    return out


def extract_cache_firefox(directory: str, extract_urls: bool = True,
                          limit: int = 0) -> List[Dict]:
    """Scan Firefox cache2 entries for recoverable URLs."""
    out: List[Dict] = []
    if not os.path.isdir(directory):
        return out
    files = glob.glob(os.path.join(directory, "**", "*"), recursive=True)
    for fp in files:
        if not os.path.isfile(fp):
            continue
        try:
            size = os.path.getsize(fp)
            mtime = os.path.getmtime(fp)
        except OSError:
            continue
        url = ""
        if extract_urls:
            try:
                with open(fp, "rb") as fh:
                    chunk = fh.read(8192)
                match = URL_RE.search(chunk)
                if match:
                    url = match.group(0).decode("utf-8", "replace")
            except OSError:
                pass
        rel = os.path.relpath(fp, directory)
        out.append({
            "file": os.path.basename(fp),
            "path": rel,
            "size_bytes": size,
            "modified": decrypt.chrome_time(int((mtime + 11644473600) * 1_000_000)),
            "key": "", "url": url, "source": "cache2",
        })
        if limit and len(out) >= limit:
            break
    return out
