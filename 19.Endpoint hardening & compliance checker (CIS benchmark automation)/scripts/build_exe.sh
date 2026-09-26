#!/usr/bin/env bash
# Portable exe build (bash/CI). Run from project root: bash scripts/build_exe.sh
set -euo pipefail
PY=.venv/Scripts/python
EXE=dist/CISGuard/CISGuard.exe

"$PY" -m pytest tests -q   # release gate: tests must pass
"$PY" -m PyInstaller portable.spec --noconfirm --clean

# Release gate: the frozen exe must actually work (GUI fix regression test:
# the dist previously shipped without Qt plugins and silently failed to start).
[ -f "$EXE" ] || { echo "ERROR: $EXE missing" >&2; exit 1; }
qplatform="$EXE" # onedir -> plugins live under the sibling _internal dir
plugin="dist/CISGuard/_internal/PySide6/plugins/platforms/qwindows.dll"
[ -f "$plugin" ] || { echo "ERROR: Qt platform plugin missing: $plugin" >&2; exit 1; }

SMOKE=build/smoke
rm -rf "$SMOKE"
"$EXE" --cli --data-dir "$SMOKE/data" --demo scan --out "$SMOKE/reports/report" >"$SMOKE.log" 2>&1 || rc=$?
grep -q "reports written:" "$SMOKE.log" || { echo "ERROR: CLI smoke test failed" >&2; cat "$SMOKE.log"; exit 1; }
[ -f "$SMOKE/reports/report.html" ] && [ -f "$SMOKE/reports/report.json" ] && [ -f "$SMOKE/reports/report.csv" ] || {
    echo "ERROR: smoke test did not produce reports" >&2; exit 1; }
echo "smoke OK (rc=${rc:-0}, failures expected => non-zero rc is normal)"

echo
echo "Portable build ready:"
ls -la "$EXE"