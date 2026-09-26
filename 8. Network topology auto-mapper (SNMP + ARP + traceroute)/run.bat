@echo off
rem NTM launcher - sets UTF-8, creates+enters venv, installs deps, starts API.
rem Usage:  double-click or  run.bat [--exe] [port]
setlocal
chcp 65001 >nul
cd /d "%~dp0"

set "PORT=%~2"
if "%PORT%"=="" set "PORT=8000"

if /i "%~1"=="--exe" goto :exe

where python >nul 2>nul
if errorlevel 1 (
  echo [ntm] Python not found on PATH. Install Python 3.12 and retry.
  pause
  exit /b 1
)

if not exist ".venv\Scripts\activate.bat" (
  echo [ntm] creating virtualenv...
  python -m venv .venv || goto :err
)
call ".venv\Scripts\activate.bat"
python -m pip install -q --disable-pip-version-check -r requirements.txt || goto :err
echo [ntm] starting API on http://127.0.0.1:%PORT%
python -X utf8 -m uvicorn app.main:app --host 127.0.0.1 --port %PORT%
goto :eof

:exe
python -m pip install -q --disable-pip-version-check pyinstaller || goto :err
powershell -NoProfile -ExecutionPolicy Bypass -File build_exe.ps1
goto :eof

:err
echo [ntm] FAILED - see message above.
pause
exit /b 1
