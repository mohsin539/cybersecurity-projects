@echo off
rem ============================================================
rem  AegisLB - double-click launcher (Web GUI + API server)
rem  Uses the Windows "py" launcher explicitly, so it works even
rem  when the .py file association is broken or points to the
rem  Microsoft Store python alias.
rem ============================================================
cd /d "%~dp0"

where py >nul 2>nul
if errorlevel 1 goto :nopython

py -u run.py %*
set RC=%ERRORLEVEL%

if not "%RC%"=="0" (
  echo.
  echo [ERROR] AegisLB exited with code %RC%. See the messages above.
  echo If the port is busy, try:  py run.py serve --port 9000
  pause
)
exit /b %RC%

:nopython
echo [ERROR] Python "py" launcher was not found on PATH.
echo.
echo Install Python 3.12 or newer from:
echo     https://www.python.org/downloads/
echo and during setup make sure BOTH of these are enabled:
echo     [x] Use the Python "py" launcher
echo     [x] Add python.exe to PATH
echo.
echo (If it is already installed, search for "py" in the Windows
echo  Start Menu and reinstall/repair if necessary.)
pause
exit /b 1