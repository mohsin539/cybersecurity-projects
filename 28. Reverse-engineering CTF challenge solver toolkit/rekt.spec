# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for the portable REkt build (ARCHITECTURE.md §9).

- onedir (NOT onefile): avoids AV-flagged self-extract temps, faster cold start
- windowed: no console window in the shipped GUI
- bundles rules/ + plugins/ + trust.pub next to the executable
"""
from PyInstaller.utils.hooks import collect_submodules

hiddenimports = collect_submodules("rekt") + ["rekt.sandbox.child"]

a = Analysis(
    ["rekt/__main__.py"],
    pathex=["."],
    binaries=[],
    datas=[
        ("rules", "rules"),
        ("plugins", "plugins"),
    ],
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=["tkinter", "unittest", "pydoc_data"],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="rekt",
    console=False,          # windowed GUI build
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,              # no UPX: fewer AV false positives (§9.4)
    name="rekt-portable",
)
