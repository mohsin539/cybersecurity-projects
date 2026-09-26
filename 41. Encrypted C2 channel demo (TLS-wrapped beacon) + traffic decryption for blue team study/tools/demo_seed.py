import random
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.db import execute, init_db, now_iso
from app.services.detection import DEFAULT_RULES, seed_rules


def _hex(n=32):
    return uuid.uuid4().hex[:n]


AGENTS = [
    {
        "agent_name": "svc-ordering-sync",
        "os": "Windows 11", "ip": "10.0.20.7", "interval": 42.0, "jitter": 0.12,
        "sni": "orders-storage.example.net", "status": "active", "notes": "demo - periodic heartbeat",
        "risk_part": ["R-001", "R-003", "R-004"],
    },
    {
        "agent_name": "lab-beacon-charlie",
        "os": "Ubuntu 24.04", "ip": "10.0.20.9", "interval": 55.0, "jitter": 0.18,
        "sni": "msd-update-cdn.edge.example", "status": "flagged", "notes": "demo - kill switch test",
        "risk_part": ["R-002", "R-004", "R-005"],
    },
    {
        "agent_name": "defender-agent-probe",
        "os": "Windows Server 2022", "ip": "10.0.20.15", "interval": 300.0, "jitter": 0.6,
        "sni": "sccm.corp.example", "status": "active", "notes": "benign baseline pattern",
        "risk_part": [],
    },
]


def seed():
    import datetime

    init_db()
    seed_rules()
    from app.core.crypto import fingerprint
    from app.services.capture import record_traffic

    base = datetime.datetime.now(datetime.timezone.utc)
    for idx, a in enumerate(AGENTS):
        suid = str(uuid.uuid4())
        ja3 = fingerprint(f"cli:{suid}")[:16]
        ja3s = fingerprint(f"srv:{suid}")[:16]
        aes = _hex(64)
        execute(
            "INSERT INTO sessions (uuid, agent_name, hw_id, ip, os, status, first_seen, last_seen, "
            "beacon_interval, jitter, ja3, ja3s, sni, tls_version, cipher, auth_method, risk_score, kill_switch, notes) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                suid, a["agent_name"], _hex(16), a["ip"], a["os"], a["status"],
                now_iso(), now_iso(), a["interval"], a["jitter"], ja3, ja3s, a["sni"],
                "TLSv1.3", "TLS_AES_256_GCM_SHA384", "mtls",
                0.0, 1 if a["status"] == "flagged" else 0, a["notes"],
            ),
        )
        execute(
            "INSERT INTO keys (session_uuid, key_type, label, key_value, created_at, status) VALUES (?,?,?,?,?,?)",
            (suid, "session_aes", "AES-256-GCM inner-layer escrow", aes, now_iso(), "escrow"),
        )
        execute(
            "INSERT INTO keys (session_uuid, key_type, label, key_value, created_at, status) VALUES (?,?,?,?,?,?)",
            (suid, "sslkeylog", "simulated TLS (pre)-master capture", _hex(64), now_iso(), "escrow"),
        )

        t = base - datetime.timedelta(minutes=9 - idx)
        rec_len = random.randint(180, 320)
        record_traffic(suid, "client_hello", src_ip=a["ip"], dst_ip="10.0.30.10", dst_port=443, record_len=rec_len,
                       meta={"ja3": ja3, "sni": a["sni"], "tls_version": "TLSv1.3"}, ts=(t).isoformat(timespec="seconds"))
        t += datetime.timedelta(seconds=3)
        record_traffic(suid, "server_hello", src_ip="10.0.30.10", dst_ip=a["ip"], src_port=443, dst_port=0,
                       record_len=rec_len, meta={"ja3s": ja3s, "cipher": "TLS_AES_256_GCM_SHA384"}, ts=(t).isoformat(timespec="seconds"))
        t += datetime.timedelta(seconds=2)
        record_traffic(suid, "register", src_ip=a["ip"], dst_ip="10.0.30.10", dst_port=443, record_len=rec_len,
                       meta={"tls_version": "TLSv1.3"}, ts=(t).isoformat(timespec="seconds"))

        for p in range(8):
            t += datetime.timedelta(seconds=a["interval"] * random.uniform(1 - a["jitter"], 1 + a["jitter"]))
            rec_len = random.randint(64, 120)
            record_traffic(suid, "ping", src_ip=a["ip"], dst_ip="10.0.30.10", dst_port=443, record_len=rec_len,
                           meta={"nonce": "p"}, ts=(t).isoformat(timespec="seconds"))

        pings_after = []
        for _ in range(4):
            t += datetime.timedelta(seconds=a["interval"] * random.uniform(1 - a["jitter"], 1 + a["jitter"]))
            pings_after.append((t, "ping"))
        pings_after.append((t + datetime.timedelta(seconds=1), "task"))
        pings_after.append((t + datetime.timedelta(seconds=2), "result"))
        pings_after.append((t + datetime.timedelta(seconds=a["interval"]), "task"))
        pings_after.append((t + datetime.timedelta(seconds=a["interval"] + 1), "result"))
        for t2, e in pings_after:
            rec_len = random.randint(64, 400 if e == "result" else 120)
            plain = None
            cipher_txt = None
            if e == "task":
                plain = "queued: ipconfig /all"
            if e == "result":
                plain = f"ok|{a['agent_name']}|R-{random.randint(100,999)}"
                cipher_txt = "A" + _hex(40)
            record_traffic(suid, e, src_ip=a["ip"], dst_ip="10.0.30.10", dst_port=443, record_len=rec_len,
                           ciphertext=cipher_txt, plaintext=plain, ts=t2.isoformat(timespec="seconds"))

        for rule_id in a["risk_part"]:
            meta = next(r for r in DEFAULT_RULES if r["rule_id"] == rule_id)
            execute(
                "INSERT INTO alerts (ts, rule_id, rule_name, session_uuid, severity, score, detail, status, mitre_id) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    now_iso(), rule_id, meta["name"], suid, meta["severity"],
                    random.randint(40, 95), "seeded demo evidence", "new", meta["mitre_id"],
                ),
            )
    print("seeded", len(AGENTS), "sessions with demo evidence")


if __name__ == "__main__":
    seed()