@echo off
REM Build the standalone ArpScanner.exe using PyInstaller.
REM Requires: Python 3.12 via the 'py' launcher (Npcap for runtime, not build).
setlocal

echo [1/4] Creating build virtual environment (.venv_build)...
py -3.12 -m venv .venv_build || goto :error

call .venv_build\Scripts\activate.bat

echo [2/4] Installing dependencies + PyInstaller (this may take several minutes)...
python -m pip install --upgrade pip >nul
python -m pip install -r requirements.txt || goto :error

echo [3/4] Building executable...
pyinstaller --noconfirm --clean arp_scanner.spec || goto :error

echo.
echo [4/4] Done! Executable: dist\ArpScanner\ArpScanner.exe
echo Run it as Administrator; Npcap must be installed.
exit /b 0

:error
echo.
echo Build failed. See messages above.
exit /b 1