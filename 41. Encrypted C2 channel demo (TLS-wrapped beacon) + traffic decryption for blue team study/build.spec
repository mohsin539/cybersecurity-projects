#!/usr/bin/env python3
"""C2 Deconfliction Lab — portable Windows build (PyInstaller)."""
import sys
import os

from PyInstaller.utils.hooks import collect_submodules

block_cipher = None

hidden = collect_submodules("cryptography")
hidden += collect_submodules("uvicorn")
hidden += collect_submodules("app")

a = Analysis(
    ["run_entrypoint.py"],
    pathex=[os.path.abspath(".")],
    binaries=[],
    datas=[
        ("app/static", "app/static"),
        ("app/templates", "app/templates"),
    ],
    hiddenimports=hidden,
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="C2DeconflictionLab",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    icon="app/static/c2lab.ico" if os.path.exists("app/static/c2lab.ico") else None,
)