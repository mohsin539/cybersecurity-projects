@echo off
setlocal
REM ------------------------------------------------------------------
REM Bandwidth Monitor - one-shot Windows launcher.
REM Picks a real Python interpreter automatically:
REM   1. .venv\Scripts\python.exe        (project virtualenv, preferred)
REM   2. py -3                           (official Python launcher)
REM   3. python.exe found on PATH that is NOT the Microsoft Store stub
REM The Microsoft Store "python.exe" stub prints "Python was not found"
REM and exits with code 49, which is why plain `python main.py` often
REM appears broken on Windows. This script avoids it entirely.
REM ------------------------------------------------------------------

set "HOST_ARG="
if not "%~1"=="" set "HOST_ARG=%~1"

if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" main.py %HOST_ARG%
    goto :done
)

py -3 --version >nul 2>&1
if not errorlevel 1 (
    py -3 main.py %HOST_ARG%
    goto :done
)

where python >nul 2>&1
if not errorlevel 1 (
    python main.py %HOST_ARG%
    goto :done
)

echo [bwmon] No usable Python interpreter found.
echo         Install Python 3.10+ from https://www.python.org/downloads/
echo         or run: py -3 -m venv .venv ^&^& .venv\Scripts\pip install -r requirements.txt
exit /b 1

:done
endlocal
