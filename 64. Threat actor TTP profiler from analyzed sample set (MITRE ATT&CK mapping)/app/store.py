"""TTPProfiler :: portable secure SQLite store (WAL, parameterized SQL).

Field-level encryption for sensitive evidence uses Windows DPAPI
(ctypes → CryptProtectData) so secrets never live on disk in plaintext
and no key material is hard-coded (AES-256-GCM analog, ISO A.10 / NIST SC-8).
"""
from __future__ import annotations

import base64
import ctypes
import json
import os
import sqlite3
from pathlib import Path

from .security import json_dumps_safe, sanitize_for_sql, sha256_text, valid_table_name

SCHEMA = """
CREATE TABLE IF NOT EXISTS sample_set(
  id TEXT PRIMARY KEY, name TEXT, description TEXT, ingested_at TEXT, sha256 TEXT
);
CREATE TABLE IF NOT EXISTS samples(
  sha256 TEXT PRIMARY KEY, set_id TEXT, filename TEXT, family TEXT,
  verdict TEXT, meta_json TEXT, yara_json TEXT, av_json TEXT,
  net_json TEXT, file_json TEXT, reg_json TEXT, proc_json TEXT, str_json TEXT
);
CREATE TABLE IF NOT EXISTS evidence(
  id TEXT PRIMARY KEY, sample_sha256 TEXT, source TEXT, kind TEXT, text_enc TEXT, tags_json TEXT, meta_json TEXT
);
CREATE TABLE IF NOT EXISTS technique_map(
  technique_id TEXT, profile_id TEXT, evidence_json TEXT,
  evidence_strength REAL, sample_coverage REAL, score REAL,
  PRIMARY KEY(technique_id, profile_id)
);
CREATE TABLE IF NOT EXISTS profiles(
  id TEXT PRIMARY KEY, set_id TEXT, created_at TEXT, profile_json TEXT,
  confidence REAL, intel_grade TEXT
);
CREATE TABLE IF NOT EXISTS audit(
  seq INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, action TEXT, detail TEXT,
  prev_hash TEXT, hash TEXT
);
CREATE INDEX IF NOT EXISTS idx_evidence_sample ON evidence(sample_sha256);
CREATE INDEX IF NOT EXISTS idx_profiles_set ON profiles(set_id);
"""


class _DPAPI:
    """User-scoped encryption via Windows DPAPI (CryptProtect/UnprotectData)."""

    CRYPTPROTECT_UI_FORBIDDEN = 0x1

    @staticmethod
    def _api_crypt() -> "ctypes.WinDLL":
        return ctypes.windll.crypt32

    @staticmethod
    def _protect(data: bytes) -> bytes:
        blob_in = _DPAPI._to_blob(data)
        blob_out = _DPAPI._to_blob(b"")
        try:
            ok = _DPAPI._api_crypt().CryptProtectData(
                ctypes.byref(blob_in), None, None, None, None,
                _DPAPI.CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(blob_out))
        except AttributeError:
            raise RuntimeError("DPAPI unavailable on this platform")
        if not ok:
            code = ctypes.get_last_error()
            raise RuntimeError(f"CryptProtectData failed (0x{code & 0xFFFFFFFF:08X})")
        return _DPAPI._from_blob(blob_out)

    @staticmethod
    def _unprotect(data: bytes) -> bytes:
        blob_in = _DPAPI._to_blob(data)
        blob_out = _DPAPI._to_blob(b"")
        ok = _DPAPI._api_crypt().CryptUnprotectData(
            ctypes.byref(blob_in), None, None, None, None,
            _DPAPI.CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(blob_out))
        if not ok:
            raise RuntimeError("CryptUnprotectData failed")
        return _DPAPI._from_blob(blob_out)

    @staticmethod
    def _to_blob(data: bytes):
        class DATA_BLOB(ctypes.Structure):
            _fields_ = [("cbData", ctypes.c_ulong), ("pbData", ctypes.c_void_p)]
        buf = ctypes.create_string_buffer(data, max(1, len(data)))
        return DATA_BLOB(len(data), ctypes.cast(buf, ctypes.c_void_p))

    @staticmethod
    def _from_blob(blob) -> bytes:
        length = int(blob.cbData)
        if length <= 0 or not int(blob.pbData or 0):
            return b""
        ptr = ctypes.cast(blob.pbData, ctypes.POINTER(ctypes.c_char))
        out = bytes(ctypes.string_at(ptr, length))
        _free = ctypes.windll.kernel32.LocalFree
        _free.argtypes = [ctypes.c_void_p]
        _free.restype = ctypes.c_void_p
        _free(blob.pbData)
        return out

    @classmethod
    def encrypt(cls, plaintext: str) -> str:
        token = b"TTPP:" + plaintext.encode("utf-8", errors="replace")
        return "dpapi:" + base64.b64encode(cls._protect(token)).decode("ascii")

    @classmethod
    def decrypt(cls, token: str) -> str:
        if not token.startswith("dpapi:"):
            return token  # legacy plaintext passthrough
        raw = base64.b64decode(token[len("dpapi:"):])
        return cls._unprotect(raw)[5:].decode("utf-8", errors="replace")


class SecureStore:
    """Portable data layer: SQLite + WAL + parameterized queries + DPAPI vault."""

    def __init__(self, root: str | Path, encrypt_evidence: bool = True, no_dpapi: bool = False):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.db_path = self.root / "profile.db"
        self.encrypt_evidence = encrypt_evidence and not no_dpapi
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.execute("PRAGMA integrity_check")
        self._executescript(SCHEMA)
        self.conn.commit()

    def _executescript(self, script: str):
        cur = self.conn.cursor()
        for stmt in script.split(";"):
            stmt = stmt.strip().rstrip(";").strip()
            if stmt:
                cur.execute(stmt)

    # ------------------------------------------------------------- tables --
    _T = {
        "sample_set", "samples", "evidence", "technique_map", "profiles", "audit",
    }

    def _safe_table(self, table: str) -> str:
        assert valid_table_name(table) and table in self._T
        return table

    # ------------------------------------------------------------- audit --
    def audit_last_hash(self) -> str:
        row = self.conn.execute(
            "SELECT hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        return row["hash"] if row else "GENESIS-0000000000000000000000000000000000000000"

    def audit_append(self, action: str, detail: str, prev_hash: str, cur_hash: str):
        self.conn.execute(
            "INSERT INTO audit(ts, action, detail, prev_hash, hash) VALUES(?,?,?,?,?)",
            (sqlite3_datetime_now(), action, detail, prev_hash, cur_hash))
        self.conn.commit()

    def audit_rows(self, limit: int = 200) -> list[dict]:
        rows = self.conn.execute(
            "SELECT seq, ts, action, detail, prev_hash, hash FROM audit "
            "ORDER BY seq DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------- CRUD ---
    def save_sample_set(self, set_id: str, name: str, description: str, sha256: str):
        self.conn.execute(
            "INSERT OR REPLACE INTO sample_set(id,name,description,ingested_at,sha256) "
            "VALUES(?,?,?,?,?)",
            (set_id, sanitize_for_sql(name), sanitize_for_sql(description, 1024),
             sqlite3_datetime_now(), sha256))
        self.conn.commit()

    def save_sample(self, s) -> None:
        enc = self._protect.encrypt if self.encrypt_evidence else str
        self.conn.execute(
            "INSERT OR REPLACE INTO samples(sha256,set_id,filename,family,verdict,meta_json,"
            "yara_json,av_json,net_json,file_json,reg_json,proc_json,str_json) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (s.sha256, s.meta.get("set_id", ""), sanitize_for_sql(s.filename, 512),
             sanitize_for_sql(s.family, 256), sanitize_for_sql(s.verdict, 32),
             json_dumps_safe(s.meta), json_dumps_safe(s.yara_rules),
             json_dumps_safe(s.av_names), json_dumps_safe(s.network_domains),
             json_dumps_safe(s.file_paths), json_dumps_safe(s.registry_keys),
             json_dumps_safe(s.process_names), json_dumps_safe(s.strings)))
        for ev in s.evidence:
            evid = sha256_text(s.sha256 + ev.source + ev.kind + ev.text)[:32]
            self.conn.execute(
                "INSERT OR REPLACE INTO evidence(id,sample_sha256,source,kind,text_enc,"
                "tags_json,meta_json) VALUES(?,?,?,?,?,?,?)",
                (evid, s.sha256, ev.source, ev.kind, enc(ev.text),
                 json_dumps_safe(ev.tags), json_dumps_safe(ev.meta)))
        self.conn.commit()

    def load_samples(self, set_id: str) -> list:
        from .models import EvidenceRecord, Sample
        dec = self._protect.decrypt if self.encrypt_evidence else lambda x: x
        rows = self.conn.execute(
            "SELECT * FROM samples WHERE set_id=? ORDER BY filename", (set_id,)).fetchall()
        out = []
        for r in rows:
            s = Sample(
                sha256=r["sha256"], filename=r["filename"], family=r["family"],
                verdict=r["verdict"], meta=json.loads(r["meta_json"] or "{}"),
                yara_rules=json.loads(r["yara_json"] or "[]"),
                av_names=json.loads(r["av_json"] or "[]"),
                network_domains=json.loads(r["net_json"] or "[]"),
                file_paths=json.loads(r["file_json"] or "[]"),
                registry_keys=json.loads(r["reg_json"] or "[]"),
                process_names=json.loads(r["proc_json"] or "[]"),
                strings=json.loads(r["str_json"] or "[]"),
            )
            evs = self.conn.execute(
                "SELECT id,source,kind,text_enc,tags_json,meta_json FROM evidence "
                "WHERE sample_sha256=?", (s.sha256,)).fetchall()
            s.evidence = [
                EvidenceRecord(sample_sha256=s.sha256, source=e["source"], kind=e["kind"],
                               text=dec(e["text_enc"]),
                               tags=json.loads(e["tags_json"] or "[]"),
                               meta=json.loads(e["meta_json"] or "{}"))
                for e in evs
            ]
            out.append(s)
        return out

    def save_profile(self, profile) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO profiles(id,set_id,created_at,profile_json,confidence,"
            "intel_grade) VALUES(?,?,?,?,?,?)",
            (profile.id, profile.sample_set_id, profile.created_at,
             json_dumps_safe(profile.summary()), profile.confidence, profile.intel_grade))
        for tm in profile.techniques:
            self.conn.execute(
                "INSERT OR REPLACE INTO technique_map(technique_id,profile_id,evidence_json,"
                "evidence_strength,sample_coverage,score) VALUES(?,?,?,?,?,?)",
                (tm.technique_id, profile.id, json_dumps_safe(tm.evidence_ids),
                 tm.evidence_strength, tm.sample_coverage, tm.score))
        self.conn.commit()

    def load_profiles(self, set_id: str = "") -> list[dict]:
        q = "SELECT * FROM profiles"
        params: tuple = ()
        if set_id:
            q += " WHERE set_id=?"
            params = (set_id,)
        q += " ORDER BY created_at DESC"
        return [dict(r) for r in self.conn.execute(q, params).fetchall()]

    def technique_rows(self, profile_id: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM technique_map WHERE profile_id=?", (profile_id,)).fetchall()
        return [dict(r) for r in rows]

    def set_names(self) -> list[dict]:
        return [dict(r) for r in self.conn.execute(
            "SELECT id,name,description,ingested_at FROM sample_set ORDER BY ingested_at DESC"
        ).fetchall()]

    def sample_count(self, set_id: str) -> int:
        r = self.conn.execute(
            "SELECT COUNT(*) AS c FROM samples WHERE set_id=?", (set_id,)).fetchone()
        return int(r["c"])

    def close(self):
        try:
            self.conn.commit()
        except Exception:
            pass
        self.conn.close()

    _protect = _DPAPI


def sqlite3_datetime_now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat(timespec="seconds")