"""Output formatters (architecture.md §4.7, §11).

All formatters consume the same data; machine-readable output carries a
versioned schema_version (stability contract, §11).
"""
from __future__ import annotations

import csv
import io
import json

SCHEMA_VERSION = 1


def format_table(hosts: list[dict], meta: dict) -> str:
    lines = []
    for h in hosts:
        for p in h["ports"]:
            if p["state"] != "open":
                continue
            svc = next((s for s in h.get("services", [])
                        if s["port"] == p["port"] and s["proto"] == p["proto"]), {})
            lines.append((h["ip"], str(p["port"]), p["state"],
                          svc.get("service", "-"), svc.get("product", "-") or "-",
                          svc.get("version", "-") or "-"))
    if not lines:
        return "No open ports found."
    width = max(len(r[0]) for r in lines) + 2
    header = f"{'HOST':<{width}}{'PORT':<7}{'STATE':<9}{'SERVICE':<12}{'PRODUCT':<16}{'VERSION'}"
    out = [header, "-" * len(header)]
    for r in sorted(lines, key=lambda x: (x[0], int(x[1]))):
        out.append(f"{r[0]:<{width}}{r[1]:<7}{r[2]:<9}{r[3]:<12}{r[4]:<16}{r[5]}")
    stats = meta.get("stats", {})
    out.append("")
    out.append(f"Scanned {stats.get('probes_sent', '?')} probes in "
               f"{meta.get('duration_s', '?')}s — "
               f"open={stats.get('counts', {}).get('open', 0)}")
    if meta.get("warnings"):
        out.append(f"Warnings: {len(meta['warnings'])} (see stderr)")
    return "\n".join(out)


def format_json(hosts: list[dict], meta: dict) -> str:
    return json.dumps({
        "schema_version": SCHEMA_VERSION,
        "started_at": meta.get("started_at"),
        "finished_at": meta.get("finished_at"),
        "config": meta.get("config", {}),
        "hosts": hosts,
        "stats": meta.get("stats", {}),
    }, indent=2, default=str)


def format_jsonl(hosts: list[dict], meta: dict) -> str:
    buf = io.StringIO()
    for h in hosts:
        for p in h["ports"]:
            buf.write(json.dumps({
                "schema_version": SCHEMA_VERSION, "type": "port_result",
                "host": h["ip"], "port": p["port"], "proto": p["proto"],
                "state": p["state"], "ts": p.get("ts"),
            }) + "\n")
        for s in h.get("services", []):
            buf.write(json.dumps({
                "schema_version": SCHEMA_VERSION, "type": "service",
                **{k: v for k, v in s.items() if k != "tls"},
                "tls": s.get("tls"),
            }) + "\n")
    return buf.getvalue()


def format_csv(hosts: list[dict], meta: dict) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["host", "port", "proto", "state", "service", "product", "version"])
    for h in hosts:
        for p in h["ports"]:
            svc = next((s for s in h.get("services", [])
                        if s["port"] == p["port"] and s["proto"] == p["proto"]), {})
            w.writerow([h["ip"], p["port"], p["proto"], p["state"],
                        svc.get("service", ""), svc.get("product", ""),
                        svc.get("version", "")])
    return buf.getvalue()


def format_greppable(hosts: list[dict], meta: dict) -> str:
    lines = []
    for h in hosts:
        for p in h["ports"]:
            if p["state"] != "open":
                continue
            svc = next((s for s in h.get("services", [])
                        if s["port"] == p["port"]), {})
            lines.append(f"{h['ip']},{p['port']},{p['proto']},{p['state']},"
                         f"{svc.get('service', 'unknown')}")
    return "\n".join(lines)


FORMATTERS = {
    "table": format_table,
    "json": format_json,
    "jsonl": format_jsonl,
    "csv": format_csv,
    "greppable": format_greppable,
}


def render(fmt: str, hosts: list[dict], meta: dict) -> str:
    try:
        return FORMATTERS[fmt](hosts, meta)
    except KeyError:
        raise ValueError(f"no formatter for {fmt!r}") from None
