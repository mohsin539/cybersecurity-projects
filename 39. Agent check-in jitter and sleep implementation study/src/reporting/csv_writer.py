"""CSV writers (RFC-4180, UTF-8 BOM, CRLF) with formula-injection guard."""
from __future__ import annotations

import csv
import io

from src.security.sanitize import csv_cell


def _dump(path: str, rows: list[list], header: list[str] | None = None) -> None:
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\r\n")
    if header:
        writer.writerow([csv_cell(c) for c in header])
    for row in rows:
        writer.writerow([csv_cell(c) for c in row])
    data = "\ufeff" + buf.getvalue()  # BOM so Excel detects UTF-8
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(data)


def write_csv_bundle(model: dict, out_dir: str) -> list[str]:
    paths = []
    p = f"{out_dir}/manifest.csv"
    rows = [[k, v] for k, v in (("run_id", model["run_id"]), ("generated_at", model["generated_at"]),
                                 ("config_hash", model["config_hash"]), ("verdict", model["verdict_badge"]),
                                 ("verdict_text", model["verdict_text"]))]
    rows += [[f"scenario.{k}", v] for k, v in model["scenario"].items()]
    _dump(p, rows)
    paths.append(p)

    p = f"{out_dir}/summary.csv"
    if "baseline" in model["summary_rows"][0]:
        _dump(
            p,
            [[r["metric"], r["candidate_raw"], r["candidate_std"], r.get("baseline_raw", ""), r.get("baseline_std", "")] for r in model["summary_rows"]],
            ["metric", "candidate", "candidate_std", "baseline", "baseline_std"],
        )
    else:
        _dump(
            p,
            [[r["metric"], r["candidate_raw"], r["candidate_std"]] for r in model["summary_rows"]],
            ["metric", "candidate", "candidate_std"],
        )
    paths.append(p)

    p = f"{out_dir}/replicas.csv"
    if model["replica_rows"]:
        keys = list(model["replica_rows"][0].keys())
        _dump(p, [[r.get(k, "") for k in keys] for r in model["replica_rows"]], keys)
        paths.append(p)

    p = f"{out_dir}/comparisons.csv"
    if model["comparison_rows"]:
        keys = list(model["comparison_rows"][0].keys())
        _dump(p, [[r.get(k, "") for k in keys] for r in model["comparison_rows"]], keys)
        paths.append(p)

    p = f"{out_dir}/buckets.csv"
    cand = model["buckets"].get("candidate", [])
    base = model["buckets"].get("baseline", [])
    n = max(len(cand), len(base))
    if base:
        _dump(p, [[i, cand[i] if i < len(cand) else "", base[i] if i < len(base) else ""] for i in range(n)],
              ["second", "candidate", "baseline"])
    else:
        _dump(p, [[i, cand[i] if i < len(cand) else ""] for i in range(n)], ["second", "candidate"])
    paths.append(p)

    return paths