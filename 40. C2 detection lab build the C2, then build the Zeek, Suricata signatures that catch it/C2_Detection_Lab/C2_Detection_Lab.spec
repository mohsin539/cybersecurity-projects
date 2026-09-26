# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec - architecture section 3: one-file portable .EXE.

Build:  pyinstaller C2_Detection_Lab.spec
Flags:  --onefile --noconsole --name C2DetectionLab
"""

import sys

a = Analysis(
    ["main.py"],
    pathex=["."],
    binaries=[],
    datas=[],
    hiddenimports=[
        "openpyxl", "cryptography", "jinja2",
        "reporting.xlsx_report", "reporting.csv_report", "reporting.html_report",
        "core.compliance", "core.config", "core.audit", "core.lab_runner",
        "c2_sim.server", "c2_sim.agent", "c2_sim.traffic", "c2_sim.bus",
        "detectors.zeek", "detectors.suricata", "detectors.engine",
        "gui.app", "gui.theme", "gui.security",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["pytest", "mypy", "ruff"],
    noarchive=False,
    optimize=1,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="C2DetectionLab",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,          # --noconsole: portable GUI, no terminal
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)