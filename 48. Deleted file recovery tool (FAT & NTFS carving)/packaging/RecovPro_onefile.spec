# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller build spec — RecovPro Secure (ONE-FILE portable build).

Produces a single ``dist/RecovProSecure.exe`` that requires no supporting
folders.  First launch extracts to a temp directory automatically.
"""

import os

from PyInstaller.utils.hooks import collect_all

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(SPEC)))
ASSETS = os.path.join(ROOT, "assets")
PACKAGING = os.path.dirname(os.path.abspath(SPEC))

datas = [(os.path.join(ASSETS, fname), "assets")
         for fname in os.listdir(ASSETS) if fname.lower().endswith(".ico")]
binaries = []
hiddenimports = []

for pkg in ("cryptography", "PIL"):
    d, b, h = collect_all(pkg)
    datas += d
    binaries += b
    hiddenimports += h

a = Analysis(
    [os.path.join(ROOT, "app", "main.py")],
    pathex=[ROOT],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="RecovProSecure",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=os.path.join(ASSETS, "app_icon.ico"),
    manifest=os.path.join(PACKAGING, "RecovPro.manifest"),
)