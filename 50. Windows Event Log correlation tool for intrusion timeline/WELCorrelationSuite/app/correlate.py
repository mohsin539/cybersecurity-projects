"""Correlation, intrusion-timeline and risk-scoring engine.

Builds a chronological intrusion timeline from normalized events, flags
incidents via the rule engine, clusters incidents sharing hosts/users/
source IPs into threat campaigns, performs simple time-series surge
detection, and produces an aggregated risk posture.
"""
from datetime import datetime, timezone

from .rules import severity_label

PHASE_COLORS = {
    "reconnaissance": "#8b5cf6",
    "initial_access": "#38bdf8",
    "execution": "#22d3ee",
    "persistence": "#a78bfa",
    "privilege_escalation": "#fbbf24",
    "credential_access": "#fb7185",
    "defense_evasion": "#f87171",
    "discovery": "#60a5fa",
    "lateral_movement": "#fb923c",
    "impact": "#ef4444",
    "c2": "#34d399",
}

PHASE_ORDER = [
    "reconnaissance", "initial_access", "execution", "persistence",
    "privilege_escalation", "credential_access", "discovery",
    "defense_evasion", "lateral_movement", "impact",
]

PHASE_WEIGHT = {
    "reconnaissance": 0.4, "initial_access": 0.8, "execution": 0.9,
    "persistence": 0.9, "privilege_escalation": 1.0,
    "credential_access": 1.0, "defense_evasion": 1.0,
    "discovery": 0.5, "lateral_movement": 1.0, "impact": 1.0,
}


def _phase_title(slug):
    return slug.replace("_", " ").title()


def _group_key(inc):
    host = str(inc.get("computer") or "?").lower()
    user = str(inc.get("target_user") or inc.get("subject_user") or "?").lower()
    ip = str(inc.get("source_ip") or "?").lower()
    return host, user, ip


def _keys_overlap(a, b):
    return any(x == y and x != "?" for x, y in zip(a, b))


def analyze(events, rules, options=None):
    """Run rule evaluation, timeline, clustering and risk scoring."""
    options = options or {}
    window_secs = int(options.get("cluster_window", 300))

    incidents = []
    for ev in events:
        for rule in rules:
            if rule.match(ev):
                incidents.append(rule.fire(ev))
    incidents.sort(key=lambda i: i.get("ts_epoch", 0))

    phases = _aggregate_phases(incidents)
    campaigns = _cluster(incidents, window_secs)
    spikes = _detect_spikes(events)
    mitigation = _mitigation(events, incidents)
    summary = _summary(events, incidents, phases, campaigns, spikes)

    return {
        "summary": summary,
        "incidents": incidents,
        "phases": phases,
        "campaigns": campaigns,
        "spikes": spikes,
        "mitre": _mitre_matrix(incidents),
        "mitigation": mitigation,
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }


def _aggregate_phases(incidents):
    agg = {slug: {"slug": slug, "name": _phase_title(slug),
                  "color": PHASE_COLORS.get(slug, "#94a3b8"),
                  "count": 0, "risk": 0, "first": None, "last": None}
           for slug in PHASE_ORDER}
    for inc in incidents:
        st = inc.get("stage") or "execution"
        if st not in agg:
            agg[st] = {"slug": st, "name": _phase_title(st),
                       "color": PHASE_COLORS.get(st, "#94a3b8"),
                       "count": 0, "risk": 0, "first": None, "last": None}
        a = agg[st]
        a["count"] += 1
        a["risk"] += int(inc.get("severity") or 0)
        ts = inc.get("ts") or ""
        if not a["first"] or ts < a["first"]:
            a["first"] = ts
        if not a["last"] or ts > a["last"]:
            a["last"] = ts
    return [agg[s] for s in PHASE_ORDER if agg[s]["count"] > 0]


def _cluster(incidents, window_secs):
    """Group sequential incidents sharing host/user/ip into campaigns."""
    groups = []
    for inc in incidents:
        keys = _group_key(inc)
        placed = None
        for g in reversed(groups):
            if _keys_overlap(keys, g["keys"]) and _within(inc, g, window_secs):
                placed = g
                break
        if placed is None:
            placed = {"keys": keys, "incidents": [], "first": 0.0, "last": 0.0,
                      "severity": 0, "hosts": set(), "users": set(), "ips": set(),
                      "stages": set(), "rule_ids": set()}
            groups.append(placed)
        placed["incidents"].append(inc)
        placed["hosts"].add(str(inc.get("computer") or "?"))
        placed["users"].add(str(inc.get("target_user") or inc.get("subject_user") or "?"))
        placed["ips"].add(str(inc.get("source_ip") or "?"))
        placed["stages"].add(inc.get("stage") or "?")
        placed["rule_ids"].add(inc.get("rule_id"))
        placed["severity"] = max(placed["severity"], int(inc.get("severity") or 0))
        ts = inc.get("ts_epoch") or 0.0
        if not groups[-1]["incidents"] or ts < placed["first"]:
            placed["first"] = ts
        if ts > placed["last"]:
            placed["last"] = ts

    campaigns = []
    for g in groups:
        if not g["incidents"]:
            continue
        seq = sorted(g["incidents"], key=lambda i: i.get("ts_epoch", 0))
        stage_seq = [i.get("stage") for i in seq]
        campaigns.append({
            "incidents": seq,
            "count": len(seq),
            "severity": g["severity"],
            "hosts": sorted(g["hosts"]),
            "users": sorted(g["users"]),
            "ips": sorted(g["ips"]),
            "stage_sequence": stage_seq,
            "rule_ids": sorted(g["rule_ids"]),
            "first_ts": seq[0].get("ts"),
            "last_ts": seq[-1].get("ts"),
            "window": "%is" % (g["last"] - g["first"]),
            "label": "Campaign %d - %s" % (len(campaigns) + 1, " -> ".join(stage_seq) or "?"),
        })
    campaigns.sort(key=lambda c: c["severity"], reverse=True)
    return campaigns


def _within(inc, g, window_secs):
    ts = inc.get("ts_epoch") or 0.0
    return ts - g["last"] <= window_secs
def _detect_spikes(events, bucket_secs=60, z_threshold=2.0):
    """Flag time buckets whose event rate deviates beyond baseline."""
    if len(events) < 4:
        return []
    from collections import defaultdict
    buckets = defaultdict(int)
    for ev in events:
        b = int((ev.get("ts_epoch") or 0) // bucket_secs) * bucket_secs
        if b:
            buckets[b] += 1
    counts = list(buckets.values())
    if len(counts) < 3:
        return []
    mean = sum(counts) / len(counts)
    var = sum((c - mean) ** 2 for c in counts) / len(counts)
    std = var ** 0.5 or 1.0
    spikes = []
    for b, c in sorted(buckets.items()):
        if mean and c > mean + z_threshold * std:
            spikes.append({
                "start_ts": datetime.fromtimestamp(b, timezone.utc).isoformat().replace("+00:00", "Z"),
                "end_ts": datetime.fromtimestamp(b + bucket_secs, timezone.utc).isoformat().replace("+00:00", "Z"),
                "count": c,
                "baseline": round(mean, 2),
                "deviation": round((c - mean) / std, 2),
            })
    return spikes


def _mitre_matrix(incidents):
    matrix = {}
    for inc in incidents:
        mitre = inc.get("mitre") or {}
        tactic = mitre.get("tactic") or "Unknown"
        techniques = mitre.get("technique") or []
        cell = matrix.setdefault(tactic, {})
        for t in techniques:
            cell[t] = cell.get(t, 0) + 1
    return matrix


def _mitigation(events, incidents):
    advice = []
    stages = {i.get("stage") for i in incidents}
    if "credential_access" in stages:
        advice.append("Force password reset for all accounts in the incident; enforce MFA and disable exposed legacy auth.")
    if "defense_evasion" in stages:
        advice.append("Rebuild logging/audit configuration; preserve and image affected hosts before restarting services.")
    if "persistence" in stages:
        advice.append("Inventory new accounts, services, scheduled tasks and autoruns; quarantine unknown binaries - review run keys and WMI subscriptions.")
    if "lateral_movement" in stages:
        advice.append("Block lateral movement paths: apply LAPS, restrict RDP/admin access, segment the network, monitor 4624/4648 flow.")
    if "execution" in stages or "initial_access" in stages:
        advice.append("Apply application control and PowerShell ScriptBlock/AMSI protection; constrain Office macros and script interpreters.")
    if "impact" in stages:
        advice.append("Initiate containment and recovery per IR runbook: isolate systems, validate backups offline, restore from known-good snapshots.")
    if not advice:
        advice.append("Review findings and optionally tune rules; no high-confidence attack chain surfaced.")
    return advice


def _summary(events, incidents, phases, campaigns, spikes):
    total = len(events)
    inc_count = len(incidents)
    max_sev = max((int(i.get("severity") or 0) for i in incidents), default=0)
    phase_count = len(phases)
    covered = [p["slug"] for p in phases]
    chain_score = 0.0
    for p in phases:
        chain_score += PHASE_WEIGHT.get(p["slug"], 0.5) * (p["count"] or 0)
    risk = round(min(100.0, (max_sev * 0.55) + min(30.0, phase_count * 4.0) + min(15.0, len(campaigns) * 5.0) + min(10.0, (inc_count * 0.5))), 1)
    hosts = {}
    users = {}
    ipset = set()
    for i in incidents:
        hosts[i.get("computer") or "?"] = hosts.get(i.get("computer") or "?", 0) + 1
        u = i.get("target_user") or i.get("subject_user") or "?"
        users[u] = users.get(u, 0) + 1
        if i.get("source_ip"):
            ipset.add(i["source_ip"])
    top_rules = {}
    for i in incidents:
        top_rules[i.get("rule_name", "")] = top_rules.get(i.get("rule_name", ""), 0) + 1
    return {
        "events": total,
        "incidents": inc_count,
        "max_severity": max_sev,
        "risk_score": risk,
        "risk_label": severity_label(risk),
        "phase_count": phase_count,
        "phases_covered": covered,
        "campaigns": len(campaigns),
        "spikes": len(spikes),
        "hosts_affected": len(hosts),
        "users_affected": len(users),
        "source_ips": len(ipset),
        "top_hosts": sorted(hosts.items(), key=lambda kv: kv[1], reverse=True)[:8],
        "top_users": sorted(users.items(), key=lambda kv: kv[1], reverse=True)[:8],
        "top_rules": sorted(top_rules.items(), key=lambda kv: kv[1], reverse=True)[:8],
    }