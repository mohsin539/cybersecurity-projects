# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for ArpScanner.exe (windowed Qt app).

Collects all data/binaries for PySide6, scapy and psutil so the packaged exe is
self-contained. Run via:  pyinstaller --noconfirm arp_scanner.spec
"""

from PyInstaller.utils.hooks import collect_all, collect_submodules

datas = []
binaries = []
hiddenimports = []

for package in ("PySide6", "scapy", "psutil"):
    d, b, h = collect_all(package)
    datas += d
    binaries += b
    hiddenimports += h

hiddenimports += collect_submodules("scapy")

a = Analysis(
    ["run_app.py"],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["PySide6.QtWebEngineCore", "PySide6.QtWebEngineWidgets", "PySide6.QtQuick", "PySide6.QtQml"],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="ArpScanner",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
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
    upx=True,
    upx_exclude=[],
    name="ArpScanner",
)