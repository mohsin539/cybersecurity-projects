@echo off
REM MobileForensicsLabPortable launcher
setlocal
cd /d "%~dp0"

where python >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Python not found on PATH. Install Python 3.10+ first.
    exit /b 1
)

echo [1/3] Ensuring dependencies...
python -m pip install -q -r requirements.txt

echo [2/3] Starting MobileForensicsLabPortable...
REM Create fresh instance dir if missing
if not exist "instance" mkdir "instance"

python app.py
endlocal