# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for the portable Red Team Engagement Report GUI.

Build a single-file, windowed, portable .exe (no Python runtime required):

    PyInstaller --noconfirm --clean redteam_report.spec
    (or simply: .\\build_exe.ps1)

Result: dist/RedTeamReport.exe
"""

from PyInstaller.utils.hooks import collect_submodules

hiddenimports = collect_submodules("openpyxl") + collect_submodules("et_xmlfile")

a = Analysis(
    ["src/redteam_report_gui_launcher.py"],
    pathex=["src"],
    binaries=[],
    datas=[],
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=[
        "matplotlib",
        "numpy",
        "pandas",
        "IPython",
        "PyQt5",
        "PyQt6",
        "PySide2",
        "PySide6",
    ],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="RedTeamReport",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,          # GUI app: no console window
    disable_windowed_traceback=False,
    icon=None,
)