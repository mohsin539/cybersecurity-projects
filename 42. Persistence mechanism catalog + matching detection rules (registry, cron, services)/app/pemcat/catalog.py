import hashlib
import json
import os
import sqlite3
import threading
import time

ARTIFACT_TYPES = (
    "registry",
    "service",
    "scheduled_task",
    "cron",
    "startup",
    "wmi",
    "os_internal",
)

BASELINE_SEEN_THRESHOLD = 3


def canonical_fingerprint(record):
    payload = record.get("payload") or {}
    stable_payload = {}
    for key in sorted(payload.keys()):
        value = payload[key]
        if isinstance(value, str):
            value = " ".join(value.strip().lower().split())
        stable_payload[key] = value
    stable_fields = {
        "artifact_type": str(record.get("artifact_type") or "").strip().lower(),
        "mechanism": " ".join(str(record.get("mechanism") or "").strip().lower().split()),
        "image_path": " ".join(str(record.get("image_path") or "").strip().lower().split()),
        "command_line": " ".join(str(record.get("command_line") or "").strip().lower().split()),
        "payload": stable_payload,
    }
    canonical = json.dumps(stable_fields, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class Storage:
    def __init__(self, db_path):
        self.db_path = db_path
        self._lock = threading.RLock()
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self._init_schema()

    def _init_schema(self):
        with self._lock:
            cur = self.conn.cursor()
            cur.executescript(
                """
                CREATE TABLE IF NOT EXISTS artifacts (
                    artifact_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    host_id TEXT NOT NULL,
                    artifact_type TEXT NOT NULL,
                    mechanism TEXT NOT NULL,
                    image_path TEXT,
                    command_line TEXT,
                    payload_json TEXT,
                    fingerprint_sha256 TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    seen_count INTEGER NOT NULL DEFAULT 1,
                    is_baselined INTEGER NOT NULL DEFAULT 0,
                    source_rid TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_art_fp ON artifacts(fingerprint_sha256, host_id);
                CREATE INDEX IF NOT EXISTS idx_art_type ON artifacts(artifact_type);

                CREATE TABLE IF NOT EXISTS allowlist (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    fingerprint_sha256 TEXT NOT NULL UNIQUE,
                    reason TEXT,
                    created TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS matches (
                    evt_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    fingerprint_sha256 TEXT NOT NULL,
                    rule_id TEXT NOT NULL,
                    rule_name TEXT NOT NULL,
                    technique TEXT,
                    severity TEXT,
                    confidence REAL,
                    score REAL,
                    evidence_json TEXT,
                    status TEXT NOT NULL DEFAULT 'open',
                    detected_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_match_rule ON matches(rule_id);
                CREATE INDEX IF NOT EXISTS idx_match_status ON matches(status);

                CREATE TABLE IF NOT EXISTS rules (
                    rule_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    technique TEXT,
                    severity TEXT DEFAULT 'medium',
                    status TEXT NOT NULL DEFAULT 'active',
                    logic_json TEXT,
                    owner TEXT DEFAULT 'local'
                );

                CREATE TABLE IF NOT EXISTS audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    action TEXT NOT NULL,
                    object_id TEXT,
                    detail TEXT
                );
                """
            )
            self.conn.commit()

    def upsert_artifact(self, record):
        fingerprint = record.get("fingerprint_sha256") or canonical_fingerprint(record)
        host_id = record.get("host_id") or "localhost"
        now = time.strftime("%Y-%m-%dT%H:%M:%S")
        with self._lock:
            cur = self.conn.cursor()
            cur.execute(
                "SELECT artifact_id, seen_count, is_baselined FROM artifacts "
                "WHERE fingerprint_sha256 = ? AND host_id = ?",
                (fingerprint, host_id),
            )
            row = cur.fetchone()
            if row:
                artifact_id, seen_count, is_baselined = row
                seen_count += 1
                cur.execute(
                    "UPDATE artifacts SET last_seen = ?, seen_count = ?, is_baselined = ? "
                    "WHERE artifact_id = ?",
                    (now, seen_count, is_baselined, artifact_id),
                )
            else:
                cur.execute(
                    """
                    INSERT INTO artifacts
                    (host_id, artifact_type, mechanism, image_path, command_line,
                     payload_json, fingerprint_sha256, first_seen, last_seen,
                     seen_count, is_baselined, source_rid)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 0, ?)
                    """,
                    (
                        host_id,
                        record.get("artifact_type") or "unknown",
                        record.get("mechanism") or "",
                        record.get("image_path"),
                        record.get("command_line"),
                        json.dumps(record.get("payload") or {}),
                        fingerprint,
                        now,
                        now,
                        record.get("source_rid"),
                    ),
                )
                artifact_id = cur.lastrowid
            self.conn.commit()
            return artifact_id, fingerprint

    def _row_to_record(self, row):
        return {
            "artifact_id": row[0],
            "host_id": row[1],
            "artifact_type": row[2],
            "mechanism": row[3],
            "image_path": row[4],
            "command_line": row[5],
            "payload": json.loads(row[6] or "{}"),
            "fingerprint_sha256": row[7],
            "first_seen": row[8],
            "last_seen": row[9],
            "seen_count": row[10],
            "is_baselined": bool(row[11]),
            "source_rid": row[12],
        }

    def list_records(self, artifact_type=None, host_id=None, baselined=None, limit=None):
        sql = "SELECT * FROM artifacts WHERE 1=1"
        params = []
        if artifact_type:
            sql += " AND artifact_type = ?"
            params.append(artifact_type)
        if host_id:
            sql += " AND host_id = ?"
            params.append(host_id)
        if baselined is not None:
            sql += " AND is_baselined = ?"
            params.append(1 if baselined else 0)
        sql += " ORDER BY last_seen DESC"
        if limit:
            sql += " LIMIT ?"
            params.append(limit)
        with self._lock:
            rows = self.conn.execute(sql, params).fetchall()
        return [self._row_to_record(r) for r in rows]

    def stats(self):
        with self._lock:
            total = self.conn.execute("SELECT COUNT(*) FROM artifacts").fetchone()[0]
            by_type = dict(
                self.conn.execute(
                    "SELECT artifact_type, COUNT(*) FROM artifacts GROUP BY artifact_type"
                ).fetchall()
            )
            baselined = self.conn.execute(
                "SELECT COUNT(*) FROM artifacts WHERE is_baselined=1"
            ).fetchone()[0]
            return {"total": total, "by_type": by_type, "baselined": baselined}

    def refresh_baselines(self):
        with self._lock:
            self.conn.execute(
                "UPDATE artifacts SET is_baselined = 1 "
                "WHERE seen_count >= ? AND fingerprint_sha256 NOT IN "
                "(SELECT fingerprint_sha256 FROM matches)",
                (BASELINE_SEEN_THRESHOLD,),
            )
            self.conn.commit()

    def allowlist(self, fingerprint, reason="manual"):
        with self._lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO allowlist (fingerprint_sha256, reason, created) "
                "VALUES (?, ?, ?)",
                (fingerprint, reason, time.strftime("%Y-%m-%dT%H:%M:%S")),
            )
            self.conn.execute(
                "UPDATE artifacts SET is_baselined = 1 WHERE fingerprint_sha256 = ?",
                (fingerprint,),
            )
            self.conn.commit()

    def is_allowlisted(self, fingerprint):
        with self._lock:
            row = self.conn.execute(
                "SELECT 1 FROM allowlist WHERE fingerprint_sha256 = ?", (fingerprint,)
            ).fetchone()
        return row is not None

    def hosts(self):
        with self._lock:
            rows = self.conn.execute("SELECT DISTINCT host_id FROM artifacts").fetchall()
        return [r[0] for r in rows]

    def add_match(self, match):
        with self._lock:
            row = self.conn.execute(
                "SELECT 1 FROM matches WHERE fingerprint_sha256 = ? AND rule_id = ? "
                "AND status IN ('open','acked') LIMIT 1",
                (match.get("fingerprint_sha256"), match.get("rule_id")),
            ).fetchone()
            if row:
                return None
            cur = self.conn.cursor()
            cur.execute(
                """
                INSERT INTO matches
                (fingerprint_sha256, rule_id, rule_name, technique, severity,
                 confidence, score, evidence_json, status, detected_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'open', ?)
                """,
                (
                    match.get("fingerprint_sha256"),
                    match.get("rule_id"),
                    match.get("rule_name"),
                    match.get("technique"),
                    match.get("severity"),
                    match.get("confidence"),
                    match.get("score"),
                    json.dumps(match.get("evidence") or {}),
                    time.strftime("%Y-%m-%dT%H:%M:%S"),
                ),
            )
            self.conn.commit()
            return cur.lastrowid

    def list_matches(self, status=None, severity=None, rule_id=None, limit=None):
        sql = """
            SELECT m.evt_id, m.fingerprint_sha256, m.rule_id, m.rule_name, m.technique,
                   m.severity, m.confidence, m.score, m.evidence_json, m.status,
                   m.detected_at, a.host_id, a.artifact_type, a.mechanism, a.image_path
            FROM matches m
            LEFT JOIN artifacts a ON a.fingerprint_sha256 = m.fingerprint_sha256
            WHERE 1=1
        """
        params = []
        if status:
            sql += " AND m.status = ?"
            params.append(status)
        if severity:
            sql += " AND m.severity = ?"
            params.append(severity)
        if rule_id:
            sql += " AND m.rule_id = ?"
            params.append(rule_id)
        sql += " ORDER BY m.detected_at DESC"
        if limit:
            sql += " LIMIT ?"
            params.append(limit)
        with self._lock:
            rows = self.conn.execute(sql, params).fetchall()
        return [
            {
                "evt_id": r[0],
                "fingerprint_sha256": r[1],
                "rule_id": r[2],
                "rule_name": r[3],
                "technique": r[4],
                "severity": r[5],
                "confidence": r[6],
                "score": r[7],
                "evidence": json.loads(r[8] or "{}"),
                "status": r[9],
                "detected_at": r[10],
                "host_id": r[11],
                "artifact_type": r[12],
                "mechanism": r[13],
                "image_path": r[14],
            }
            for r in rows
        ]

    def update_match_status(self, evt_id, status, actor="analyst"):
        with self._lock:
            self.conn.execute(
                "UPDATE matches SET status = ? WHERE evt_id = ?", (status, evt_id)
            )
            self.conn.commit()
        self.audit(actor, "match-status-update", str(evt_id), f"status={status}")

    def set_rule_status(self, rule_id, status, actor="analyst"):
        with self._lock:
            self.conn.execute(
                "UPDATE rules SET status = ? WHERE rule_id = ?", (status, rule_id)
            )
            self.conn.commit()
        self.audit(actor, "rule-status-update", rule_id, f"status={status}")

    def seed_rules(self, rules):
        with self._lock:
            cur = self.conn.cursor()
            for rule in rules:
                cur.execute(
                    """
                    INSERT INTO rules
                    (rule_id, name, technique, severity, status, logic_json, owner)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(rule_id) DO UPDATE SET
                        name = excluded.name,
                        technique = excluded.technique,
                        severity = excluded.severity,
                        logic_json = excluded.logic_json,
                        owner = 'builtin'
                    """,
                    (
                        rule.get("id"),
                        rule.get("name"),
                        rule.get("technique"),
                        rule.get("severity"),
                        rule.get("status"),
                        json.dumps(rule.get("logic") or {}),
                        "builtin",
                    ),
                )
            self.conn.commit()

    def rules(self, status=None):
        sql = "SELECT * FROM rules WHERE 1=1"
        params = []
        if status:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY rule_id"
        with self._lock:
            rows = self.conn.execute(sql, params).fetchall()
        return [
            {
                "rule_id": r[0],
                "name": r[1],
                "technique": r[2],
                "severity": r[3],
                "status": r[4],
                "logic": json.loads(r[5] or "{}"),
                "owner": r[6],
            }
            for r in rows
        ]

    def add_user_rule(self, rule):
        with self._lock:
            self.conn.execute(
                """
                INSERT OR REPLACE INTO rules
                (rule_id, name, technique, severity, status, logic_json, owner)
                VALUES (?, ?, ?, ?, 'draft', ?, 'user')
                """,
                (
                    rule.get("id"),
                    rule.get("name"),
                    rule.get("technique"),
                    rule.get("severity"),
                    json.dumps(rule.get("logic") or {}),
                ),
            )
            self.conn.commit()
        self.audit("analyst", "rule-create", rule.get("id"), "user-defined rule")

    def audit(self, actor, action, object_id=None, detail=None):
        with self._lock:
            self.conn.execute(
                "INSERT INTO audit (ts, actor, action, object_id, detail) VALUES (?, ?, ?, ?, ?)",
                (
                    time.strftime("%Y-%m-%dT%H:%M:%S"),
                    actor,
                    action,
                    object_id,
                    detail,
                ),
            )
            self.conn.commit()

    def list_audit(self, limit=500):
        with self._lock:
            rows = self.conn.execute(
                "SELECT id, ts, actor, action, object_id, detail FROM audit "
                "ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [
            {"id": r[0], "ts": r[1], "actor": r[2], "action": r[3], "object_id": r[4], "detail": r[5]}
            for r in rows
        ]

    def close(self):
        with self._lock:
            self.conn.close()


def default_data_dir():
    candidates = []
    if os.name == "nt":
        candidates.append(os.path.join(os.environ.get("LOCALAPPDATA", ""), "PEMCAT"))
        candidates.append(os.path.join(os.getcwd(), "data"))
    else:
        candidates.append(os.path.expanduser("~/.pemcat"))
        candidates.append(os.path.join(os.getcwd(), "data"))
    for cand in candidates:
        if cand:
            try:
                os.makedirs(cand, exist_ok=True)
                probe = os.path.join(cand, ".write_test")
                with open(probe, "w") as fh:
                    fh.write("ok")
                os.remove(probe)
                return cand
            except OSError:
                continue
    return candidates[-1]


def db_path_for(data_dir):
    return os.path.join(data_dir, "pemcat.db")