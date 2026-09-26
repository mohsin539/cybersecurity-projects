# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller build spec — RecovPro Secure (portable one-dir build).

Produces ``dist/RecovProSecure/`` containing ``RecovProSecure.exe`` plus all
runtime dependencies.  Copy the folder anywhere on Windows (x64, Win10/11);
no installation required.  Logical volumes work without admin rights; raw
physical-drive access requires an elevated invocation (handled in-app).

Build:
    python app/main.py --selftest      # verify engine before packaging
    python -m PyInstaller --noconfirm packaging/RecovPro.spec
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

# bundle cryptography + PIL fully (dynamic backends / plugins)
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
    [],
    exclude_binaries=True,
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

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="RecovProSecure",
)