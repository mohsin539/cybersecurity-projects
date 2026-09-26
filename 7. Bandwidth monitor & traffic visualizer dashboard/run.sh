#!/usr/bin/env bash
# ------------------------------------------------------------------
# Bandwidth Monitor - one-shot POSIX launcher.
# Picks a real Python interpreter automatically:
#   1. .venv/bin/python    (project virtualenv, preferred)
#   2. python3 on PATH
# ------------------------------------------------------------------
set -euo pipefail

if [ -x ".venv/bin/python" ]; then
    exec .venv/bin/python main.py "$@"
fi

if command -v python3 >/dev/null 2>&1; then
    exec python3 main.py "$@"
fi

echo "[bwmon] No usable Python interpreter found." >&2
echo "        Install Python 3.10+ or create a venv: python3 -m venv .venv && .venv/bin/pip install -r requirements.txt" >&2
exit 1
