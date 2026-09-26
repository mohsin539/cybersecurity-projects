# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for the portable Windows build:
#   cd backend && pyinstaller SentinelGraph.spec
# Prereq: frontend built once (backend/static exists).
import os

block_cipher = None
hidden = [
    "uvicorn.logging", "uvicorn.loops.auto", "uvicorn.loops.loopio",
    "uvicorn.protocols.http.auto", "uvicorn.protocols.http.h11_impl",
    "uvicorn.protocols.websockets.auto", "uvicorn.lifespan.on",
    "jose", "jose.jwt", "passlib.handlers.bcrypt",
]

a = Analysis(
    ["run.py"],
    pathex=["."],
    binaries=[],
    datas=[("static", "static")] if os.path.isdir("static") else [],
    hiddenimports=hidden,
    hookspath=[],
    runtime_hooks=[],
    excludes=["tkinter", "matplotlib", "numpy", "pytest"],
    cipher=block_cipher,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz, a.scripts, a.binaries, a.zipfiles, a.datas,
    name="SentinelGraph",
    console=True,            # lab tool: keep a console for audit visibility
    disable_windowed_traceback=False,
    upx=False,               # banks' AV often flags UPX-packed binaries
)
