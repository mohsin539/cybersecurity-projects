# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec — one-file portable build of the packet sniffer.

Build:   pyinstaller packet_sniffer.spec
Output:  dist/PacketSniffer.exe (~12-15 MB, self-contained)

Notes:
  * console=False  -> windowed app, no console flash.
  * No hiddenimports needed: all project imports are static
    (parsers, capture, storage, pcap_writer, threat, gui, gui_theme).
  * UAC: we do NOT request elevation in the manifest — the app detects
    missing privileges itself and shows a remediation hint (least privilege;
    user launches from an elevated terminal when they want raw capture).
"""
from PyInstaller.utils.hooks import collect_submodules

a = Analysis(
    ["packet_sniffer_gui.py"],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "pytest", "setuptools", "pkg_resources",
        "numpy", "pandas", "scipy", "PIL", "matplotlib",
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
    name="PacketSniffer",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
