from .rules import BUILTIN_RULES, expected_rule_ids

SEVERITY_PRIO = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def _run_techniques(runs):
    return {r["run_id"]: r["technique_id"] for r in runs}


def technique_metrics(technique_id, runs, detections):
    run_ids = {r["run_id"] for r in runs if r["technique_id"] == technique_id}
    expected = expected_rule_ids(technique_id)
    affected = [d for d in detections if d["run_id"] in run_ids]
    tp = sum(1 for d in affected if d.get("tp"))
    fp = sum(1 for d in affected if not d.get("tp"))
    fn = max(0, len(expected) - tp)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 0.0 if (precision + recall) == 0 else 2 * precision * recall / (precision + recall)
    fired = {d["rule_id"] for d in affected if d.get("tp")}
    return {
        "technique_id": technique_id,
        "expected": len(expected),
        "covered": len(fired & set(expected)),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(f1, 3),
        "detection_count": len(affected),
    }


def compute(runs, detections):
    tech_ids = sorted({r["technique_id"] for r in runs})
    per_tech = [technique_metrics(tid, runs, detections) for tid in tech_ids]
    tp = sum(m["tp"] for m in per_tech)
    fp = sum(m["fp"] for m in per_tech)
    fn = sum(m["fn"] for m in per_tech)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 0.0 if (precision + recall) == 0 else 2 * precision * recall / (precision + recall)
    return {
        "per_technique": per_tech,
        "totals": {
            "tp": tp, "fp": fp, "fn": fn,
            "precision": round(precision, 3),
            "recall": round(recall, 3),
            "f1": round(f1, 3),
            "detections": len(detections),
            "runs": len(runs),
            "techniques_covered": len(tech_ids),
        },
    }


def coverage_matrix(detections):
    from .engine import TECHNIQUES
    rows = []
    for t in TECHNIQUES:
        exp = expected_rule_ids(t["technique_id"])
        covered = []
        fired_rule_ids = {d["rule_id"] for d in detections if d.get("tp")}
        for rid in exp:
            if rid in fired_rule_ids:
                covered.append(rid)
        rows.append({
            "technique_id": t["technique_id"],
            "name": t["name"],
            "severity": t["severity"],
            "coins": t["coins"],
            "expected": len(exp),
            "covered": len(covered),
            "ratio": (len(covered) / len(exp)) if exp else 0,
            "rules": covered,
        })
    return rows


def top_detections(detections, limit=10):
    ordered = sorted(detections, key=lambda d: (SEVERITY_PRIO.get(d["level"], 0), d["ts"]),
                     reverse=True)
    return ordered[:limit]