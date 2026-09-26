import statistics

from app.db import execute, now_iso, query_all, query_one
from app.services.decryption import decrypt_session

DEFAULT_RULES = [
    {
        "rule_id": "R-001",
        "name": "Encrypted beacon heartbeat",
        "severity": "high",
        "support": "TLS metadata",
        "mitre_id": "T1071.001",
        "description": "Periodic POST /ping to same host at 30-60s cadence with stable interval",
    },
    {
        "rule_id": "R-002",
        "name": "Novel JA3/JA3S pair",
        "severity": "high",
        "support": "ciphertext-only",
        "mitre_id": "T1573.001",
        "description": "Client fingerprint unseen in historical baseline",
    },
    {
        "rule_id": "R-003",
        "name": "TLS + exfil burst",
        "severity": "medium",
        "support": "pcap analysis",
        "mitre_id": "T1041",
        "description": "High variance in flow/record size towards C2 destination",
    },
    {
        "rule_id": "R-004",
        "name": "Reg+ping+task cycle",
        "severity": "medium",
        "support": "decrypted study",
        "mitre_id": "T1105",
        "description": "Registration followed by periodic tasking and result callbacks",
    },
    {
        "rule_id": "R-005",
        "name": "mTLS-only endpoint",
        "severity": "medium",
        "support": "TLS metadata",
        "mitre_id": "T1573.002",
        "description": "Client-certificate authenticated channel to low-frequency destination",
    },
]


def seed_rules():
    existing = {r["rule_id"] for r in query_all("SELECT rule_id FROM rules")}
    for r in DEFAULT_RULES:
        if r["rule_id"] not in existing:
            execute(
                "INSERT INTO rules (rule_id, name, severity, support, mitre_id, enabled, description) "
                "VALUES (?,?,?,?,?,1,?)",
                (r["rule_id"], r["name"], r["severity"], r["support"], r["mitre_id"], r["description"]),
            )


def list_rules() -> list:
    return query_all("SELECT * FROM rules ORDER BY rule_id")


def toggle_rule(rule_id: str, enabled: bool):
    execute("UPDATE rules SET enabled=? WHERE rule_id=?", (1 if enabled else 0, rule_id))


def _r2(x):
    return round(x, 2)


def compute_risk(session_uuid: str) -> float:
    s = query_one("SELECT * FROM sessions WHERE uuid=?", (session_uuid,))
    if not s or s["status"] in ("dead", "flagged"):
        return 0.0
    pings = query_all(
        "SELECT CAST(strftime('%s', ts) AS INTEGER) AS t FROM traffic WHERE session_uuid=? AND event='ping' ORDER BY id",
        (session_uuid,),
    )
    intervals = [pings[i]["t"] - pings[i - 1]["t"] for i in range(1, len(pings))]
    if intervals:
        mu = statistics.mean(intervals)
        sd = statistics.pstdev(intervals)
        cv = sd / mu if mu else 1.0
        periodicity = 1.0 if cv < 0.25 else max(0.0, 1.0 - cv)
    else:
        periodicity = 0.0

    nj3 = query_all("SELECT COUNT(*) AS c FROM sessions WHERE ja3=?", (s["ja3"],))
    novelty = 1.0 if (nj3[0]["c"] if nj3 else 0) <= 1 else 0.4

    sizes = query_all(
        "SELECT COALESCE(record_len,0) AS r FROM traffic WHERE session_uuid=? AND record_len IS NOT NULL",
        (session_uuid,),
    )
    if sizes and len(sizes) > 1:
        vals = [r["r"] for r in sizes]
        sd = statistics.pstdev(vals)
        mu = statistics.mean(vals)
        size_anomaly = min(1.0, sd / (mu + 1))
    else:
        size_anomaly = 0.0

    dec = query_one(
        "SELECT COUNT(*) AS c FROM traffic WHERE session_uuid=? AND decrypted=1",
        (session_uuid,),
    )
    decrypt_success = 1.0 if dec and dec["c"] > 0 else 0.0

    rise = (
        0.35 * novelty
        + 0.25 * periodicity
        + 0.20 * novelty
        + 0.10 * size_anomaly
        + 0.10 * decrypt_success
    )
    return _r2(min(1.0, rise) * 100)


def run_rules(session_uuid: str):
    s = query_one("SELECT * FROM sessions WHERE uuid=?", (session_uuid,))
    if not s:
        return []
    seed_rules()
    fired = []
    enabled = {r["rule_id"] for r in query_all("SELECT rule_id FROM rules WHERE enabled=1")}

    pings = query_all(
        "SELECT CAST(strftime('%s', ts) AS INTEGER) AS t FROM traffic WHERE session_uuid=? AND event='ping' ORDER BY id",
        (session_uuid,),
    )
    intervals = [pings[i]["t"] - pings[i - 1]["t"] for i in range(1, len(pings))] if len(pings) > 1 else []

    score = compute_risk(session_uuid)

    if "R-001" in enabled and intervals and 25 <= statistics.mean(intervals) <= 75:
        fired.append(("R-001", score, f"regular beat, n={len(intervals)}, mean={int(statistics.mean(intervals))}s"))

    if "R-002" in enabled:
        cnt = query_one("SELECT COUNT(*) AS c FROM sessions WHERE ja3=?", (s["ja3"],))
        if cnt and cnt["c"] <= 1:
            fired.append(("R-002", score, f"unique fingerprint {s['ja3']}"))

    if "R-003" in enabled:
        sizes = query_all(
            "SELECT record_len AS r FROM traffic WHERE session_uuid=? AND record_len IS NOT NULL",
            (session_uuid,),
        )
        if len(sizes) > 2:
            vals = [r["r"] for r in sizes if r["r"]]
            if vals:
                cv = statistics.pstdev(vals) / (statistics.mean(vals) + 1)
                if cv > 0.45:
                    fired.append(("R-003", score, f"size variance cv={cv:.2f}"))

    if "R-004" in enabled:
        evts = [r["event"] for r in query_all(
            "SELECT DISTINCT event FROM traffic WHERE session_uuid=?",
            (session_uuid,),
        )]
        if {"register", "ping", "task"} <= set(evts):
            fired.append(("R-004", score, "registration -> periodic tasking -> callbacks"))

    if "R-005" in enabled and s["auth_method"] == "mtls":
        fired.append(("R-005", score, f"mTLS channel to {s['sni']}"))

    for rule_id, sc, detail in fired:
        meta = query_one("SELECT * FROM rules WHERE rule_id=?", (rule_id,))
        if query_one(
            "SELECT 1 AS ok FROM alerts WHERE session_uuid=? AND rule_id=? AND status='new'",
            (session_uuid, rule_id),
        ):
            continue
        execute(
            "INSERT INTO alerts (ts, rule_id, rule_name, session_uuid, severity, score, detail, status, mitre_id) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (now_iso(), rule_id, meta["name"], session_uuid, meta["severity"], sc, detail, "new", meta["mitre_id"]),
        )
    return fired


def list_alerts(limit=200) -> list:
    return query_all("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,))


def set_alert_status(alert_id: int, status: str):
    execute("UPDATE alerts SET status=? WHERE id=?", (status, alert_id))


def stats() -> dict:
    from app.db import query_all

    totals = query_one(
        "SELECT COUNT(*) AS total, SUM(CASE WHEN status='active' THEN 1 ELSE 0 END) AS active, "
        "SUM(CASE WHEN status='flagged' THEN 1 ELSE 0 END) AS flagged "
        "FROM sessions"
    ) or {"total": 0, "active": 0, "flagged": 0}
    traffic = query_one("SELECT COUNT(*) AS c FROM traffic") or {"c": 0}
    alerts = query_one(
        "SELECT COUNT(*) AS c, SUM(CASE WHEN status='new' THEN 1 ELSE 0 END) AS open FROM alerts"
    ) or {"c": 0, "open": 0}
    all_sessions = query_all("SELECT uuid FROM sessions")
    highest = max((compute_risk(s["uuid"]) for s in all_sessions), default=0)
    dec = query_one("SELECT COUNT(*) AS c FROM traffic WHERE decrypted=1") or {"c": 0}
    return {
        "sessions_total": totals["total"] or 0,
        "sessions_active": totals["active"] or 0,
        "sessions_flagged": totals["flagged"] or 0,
        "traffic_records": traffic["c"] or 0,
        "traffic_decrypted": dec["c"] or 0,
        "alerts_total": alerts["c"] or 0,
        "alerts_open": alerts["open"] or 0,
        "highest_risk": round(highest, 1),
        "active_rules": len([r for r in list_rules() if r["enabled"]]),
    }