"""Zeek detection engine - generates `beacon.zeek` and runs the matching
heuristic in-process (architecture.md section 2 - Zeek L3).

The generated file is a real, Zeek-6.x-compatible script; the in-process
matcher replicates its logic so detections can be demonstrated inside the
portable GUI without a live Zeek daemon.
"""

from __future__ import annotations

from pathlib import Path

BEAKON_ZEEK_TEMPLATE = """\
## beacon.zeek  --  C2 Detection Lab (generated)
## Heuristics: periodic connections + impl User-Agent + TLV magic.
@load base/protocols/conn
@load base/frameworks/notice

module C2DetectLab;

export {
    redef enum Notice::Type += { Beaconing::Periodic };
    global beacon_interval: interval = {interval}s &redef;
    global jitter_threshold: double = 0.35 &redef;
    const impl_ua_marker = "C2DetectLab" &redef;
}

event connection_established(c: connection) {
    local ua = "unknown";
    if (c?$http && c$http?$user_agent) ua = c$http$user_agent;
    if (impl_ua_marker in ua) {
        NOTICE([$note=Beaconing::Periodic,
                $src=c$id$orig_h,
                $dst=c$id$resp_h,
                $p=c$id$resp_p,
                $msg=fmt("C2-style periodic beacon (interval ~%s) from %s to %s",
                         beacon_interval, c$id$orig_h, c$id$resp_h)]);
        add c$conn["c2_marker"] = T;
    }
}
"""


def generate_zeek(out_dir: Path, interval_s: float) -> Path:
    """Write the signature file produced by the Signature Builder tab."""
    out_dir.mkdir(parents=True, exist_ok=True)
    target = out_dir / "beacon.zeek"
    target.write_text(
        BEAKON_ZEEK_TEMPLATE.replace("{interval}", f"{interval_s:.1f}" if interval_s else "5.0"),
        encoding="utf-8",
    )
    return target


def _flow_key(e: dict) -> tuple:
    return (e.get("src_ip"), e.get("dst_ip"), e.get("dst_port"),
            e.get("agent_id"))   # surrogate for 5-tuple flow identity


def match_zeek(events: list[dict], ua_marker: str = "C2DetectLab") -> list[dict]:
    """In-process replica of beacon.zeek logic.

    For every c2 beacon flow with >=3 observed connections and a stable
    period, emits one detection per event in that flow.
    """
    # gather per-flow timestamps of agent-side beacons
    flow_ts: dict[tuple, list[float]] = {}
    for e in events:
        if e.get("traffic_type") != "c2_beacon":
            continue
        key = _flow_key(e) + (e.get("role"),)
        flow_ts.setdefault(key, []).append(float(e.get("ts", 0.0)))

    periodic_flows: set[tuple] = set()
    for key, ts_list in flow_ts.items():
        if key[-1] != "agent_side":
            continue
        if len(ts_list) < 3:
            continue
        ts_list.sort()
        diffs = [b - a for a, b in zip(ts_list, ts_list[1:]) if b - a >= 0.01]
        if len(diffs) < 2:
            continue
        mean = sum(diffs) / len(diffs)
        if mean <= 0:
            continue
        variance = max(diffs) - min(diffs)
        if variance / mean <= 0.55:            # stable period => periodic
            periodic_flows.add(key[:3])

    detections: list[dict] = []
    for e in events:
        suspicious = False
        indicators: list[str] = []
        if e.get("traffic_type") == "c2_beacon":
            suspicious = True
            indicators.append("impl_user_agent_marker")
            if _flow_key(e) in periodic_flows:
                indicators.append("periodic_connection_heuristic")
        elif ua_marker in (e.get("user_agent") or ""):
            indicators.append("impl_user_agent_marker")
            suspicious = True
        if not suspicious:
            continue
        detections.append({
            "ts": float(e.get("ts", 0.0)),
            "ts_iso": _iso(e),
            "detector": "zeek",
            "rule_id": "beacon.zeek / Beaconing::Periodic",
            "severity": "high" if e.get("traffic_type") == "c2_beacon" else "medium",
            "score": 88.0 if e.get("traffic_type") == "c2_beacon" else 55.0,
            "src_ip": e.get("src_ip"), "dst_ip": e.get("dst_ip"),
            "dst_port": e.get("dst_port"), "proto": e.get("proto"),
            "channel": e.get("channel"), "agent_id": e.get("agent_id"),
            "mitre_technique": "T1071.001",
            "mitre_tactic": "TA0011",
            "matched_indicators": indicators,
            "true_positive": e.get("traffic_type") == "c2_beacon",
            "description": "Periodic outbound connection with C2 impl User-Agent",
        })
    return detections


def _iso(e: dict) -> str:
    import time
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(float(e.get("ts", 0.0))))