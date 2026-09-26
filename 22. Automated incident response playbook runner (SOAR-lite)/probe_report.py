"""Write one authoritative report of the REAL app state to probe_report.json.

Run:  python probe_report.py   (from the project root)
"""
from __future__ import annotations

import importlib
import inspect
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

out: dict = {"modules": {}, "errors": [], "db_tables": []}
MODULES = [
    "app.config", "app.db.base", "app.db.models", "app.main",
    "app.core.security", "app.core.audit", "app.core.cipher", "app.core.rate_limit",
    "app.core.logging_setup", "app.core.http_middleware", "app.core.redact", "app.core.ssrf",
    "app.services.playbook_validator", "app.services.expressions", "app.services.ingestion",
    "app.services.cases", "app.services.connector_runtime", "app.services.worker",
    "app.routers.auth", "app.routers.api", "app.routers.web",
]

for name in MODULES:
    try:
        mod = importlib.import_module(name)
    except Exception as exc:  # noqa: BLE001
        out["errors"].append({"module": name, "error": f"{exc.__class__.__name__}: {exc}"})
        continue
    members = {}
    for attr in dir(mod):
        if attr.startswith("_"):
            continue
        obj = getattr(mod, attr)
        kind = type(obj).__name__
        sig = ""
        if callable(obj):
            try:
                sig = str(inspect.signature(obj))
            except (TypeError, ValueError):
                pass
        if isinstance(obj, (str, int, float, bool)) or obj is None or isinstance(obj, (list, dict, set, tuple)):
            members[attr] = f"{kind}={str(obj)[:90]}"
        elif kind in ("function", "method", "builtin_function_or_method"):
            members[attr] = f"fn{sig}"
        elif kind == "type":
            members[attr] = "class"
        elif kind == "Settings":
            members[attr] = "Settings"
        else:
            members[attr] = kind
    out["modules"][name] = members

try:
    from app.db.base import init_db, SessionLocal

    init_db()
    db = SessionLocal()
    from sqlalchemy import inspect as sa_inspect

    out["db_tables"] = sorted(sa_inspect(db.bind).get_table_names())
    db.close()
except Exception as exc:  # noqa: BLE001
    out["errors"].append({"db_probe": f"{exc.__class__.__name__}: {exc}"})

with open("probe_report.json", "w", encoding="utf-8") as fh:
    json.dump(out, fh, indent=2)

print("ERRORS:", len(out["errors"]))
for e in out["errors"]:
    print("  -", e.get("module") or "db", "::", e["error"])
print("TABLES:", out["db_tables"])
for name, members in out["modules"].items():
    flagged = [k for k in members if members[k] == "class" and k not in ("Base",)]
    fns = [f"{k}{v[2:]}" for k, v in members.items() if v.startswith("fn")]
    print(f"\n== {name}")
    print("   classes:", ", ".join(flagged) or "-")
    print("   fns:", "; ".join(fns[:40]) or "-")