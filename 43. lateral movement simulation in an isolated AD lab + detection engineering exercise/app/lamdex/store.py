import os
import sqlite3
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    technique_id TEXT,
    technique_name TEXT,
    source TEXT,
    target TEXT,
    user TEXT,
    ts REAL,
    record_count INTEGER,
    sha256 TEXT,
    is_lab INTEGER
);
CREATE TABLE IF NOT EXISTS detections (
    detection_id TEXT PRIMARY KEY,
    run_id TEXT,
    rule_id TEXT,
    rule_name TEXT,
    rule_technique TEXT,
    technique_id TEXT,
    level TEXT,
    confidence REAL,
    event_id TEXT,
    data_source TEXT,
    observable TEXT,
    src TEXT,
    tgt TEXT,
    usr TEXT,
    tp INTEGER,
    fp INTEGER,
    is_lab INTEGER,
    ts REAL
);
CREATE TABLE IF NOT EXISTS lab_state (
    key TEXT PRIMARY KEY,
    value TEXT
);
CREATE TABLE IF NOT EXISTS reports (
    report_id TEXT PRIMARY KEY,
    kind TEXT,
    format TEXT,
    path TEXT,
    sha256 TEXT,
    size INTEGER,
    ts REAL
);
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL,
    actor TEXT,
    action TEXT,
    detail TEXT
);
"""


class Storage:
    def __init__(self, path):
        os.makedirs(os.path.dirname(path), exist_ok=True) if os.path.dirname(path) else None
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.commit()

    def audit(self, actor, action, detail=""):
        self.conn.execute("INSERT INTO audit(ts, actor, action, detail) VALUES(?,?,?,?)",
                          (time.time(), actor, action, detail))
        self.conn.commit()

    def add_run(self, run):
        self.conn.execute(
            "INSERT OR REPLACE INTO runs(run_id, technique_id, technique_name, source, target, user, ts, record_count, sha256, is_lab) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (run["run_id"], run["technique_id"], run["technique_name"], run["source"],
             run["target"], run["user"], run["ts"], run["record_count"], run["sha256"],
             int(run["is_lab"])))
        self.conn.execute(
            "INSERT INTO lab_state(key, value) VALUES('last_run', ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (run["run_id"],))
        self.conn.commit()

    def add_detections(self, detections):
        for d in detections:
            self.conn.execute(
                "INSERT OR REPLACE INTO detections(detection_id, run_id, rule_id, rule_name, rule_technique, technique_id, level, confidence, event_id, data_source, observable, src, tgt, usr, tp, fp, is_lab, ts) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (d["detection_id"], d["run_id"], d["rule_id"], d["rule_name"],
                 d["rule_technique"], d["technique_id"], d["level"], d["confidence"],
                 d.get("event_id"), d["data_source"], d.get("observable"), d["source"],
                 d["target"], d["user"], int(d["tp"]), int(d["fp"]), int(d["is_lab"]), d["ts"]))
        self.conn.commit()

    def list_runs(self):
        rows = self.conn.execute(
            "SELECT run_id, technique_id, technique_name, source, target, user, ts, record_count, sha256, is_lab FROM runs ORDER BY ts DESC").fetchall()
        return [dict(r) for r in rows]

    def get_run(self, run_id):
        r = self.conn.execute("SELECT * FROM runs WHERE run_id=?", (run_id,)).fetchone()
        return dict(r) if r else None

    def list_detections(self, technique=None, level=None):
        q = "SELECT * FROM detections WHERE 1=1"
        args = []
        if technique:
            q += " AND technique_id=?"
            args.append(technique)
        if level:
            q += " AND level=?"
            args.append(level)
        q += " ORDER BY ts DESC, level DESC"
        rows = self.conn.execute(q, args).fetchall()
        return [dict(r) for r in rows]

    def detections_for_run(self, run_id):
        rows = self.conn.execute("SELECT * FROM detections WHERE run_id=? ORDER BY ts", (run_id,)).fetchall()
        return [dict(r) for r in rows]

    def set_lab_state(self, key, value):
        self.conn.execute(
            "INSERT INTO lab_state(key, value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value))
        self.conn.commit()

    def get_lab_state(self, key, default=None):
        r = self.conn.execute("SELECT value FROM lab_state WHERE key=?", (key,)).fetchone()
        return r["value"] if r else default

    def add_report(self, report_id, kind, fmt, path, sha256, size):
        self.conn.execute(
            "INSERT OR REPLACE INTO reports(report_id, kind, format, path, sha256, size, ts) VALUES(?,?,?,?,?,?,?)",
            (report_id, kind, fmt, path, sha256, size, time.time()))
        self.conn.commit()

    def list_reports(self):
        rows = self.conn.execute("SELECT report_id, kind, format, path, sha256, size, ts FROM reports ORDER BY ts DESC").fetchall()
        return [dict(r) for r in rows]

    def get_report(self, report_id):
        r = self.conn.execute("SELECT * FROM reports WHERE report_id=?", (report_id,)).fetchone()
        return dict(r) if r else None

    def list_audit(self, limit=100):
        rows = self.conn.execute(
            "SELECT id, ts, actor, action, detail FROM audit ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    def run_count(self):
        return self.conn.execute("SELECT COUNT(*) c FROM runs").fetchone()["c"]

    def detection_count(self):
        return self.conn.execute("SELECT COUNT(*) c FROM detections").fetchone()["c"]

    def close(self):
        self.conn.close()