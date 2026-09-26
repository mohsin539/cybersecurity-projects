"""Print the real CFG attribute names (sorted, filtered) and confirm the exact
attrs main.py/auth.py reference all exist on CFG. No index invention.
Used by the final gate only, printed for the human."
"""
import re
import pathlib

import app.config as c

cfg = getattr(c, "CFG")
have = {n for n in dir(cfg) if not n.startswith("_")}

refs = set()
for f in ("app/main.py", "app/auth.py", "app/audit.py", "app/engine.py",
          "app/scope.py", "app/config.py"):
    t = pathlib.Path(f).read_text("utf-8")
    refs |= set(re.findall(r"\bCFG\.([a-zA-Z_][a-zA-Z0-9_]*)", t))

missing = sorted(refs - have)
print("CFG fields:", sorted(have))
print("referenced-but-missing:", missing or "NONE")

from app import db  # noqa: E402

print("db.get_conn ->", type(db.get_conn()).__name__)
print("db.q1              ->", callable(getattr(db, "q1", None)))
