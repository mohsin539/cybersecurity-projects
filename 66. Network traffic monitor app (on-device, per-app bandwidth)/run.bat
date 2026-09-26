@echo off
setlocal EnableExtensions EnableDelayedExpansion
title Network Traffic Monitor

rem ---------------------------------------------------------------
rem  run.bat - start the Network Traffic Monitor server + dashboard
rem  usage:  run.bat [--no-browser] [--foreground]
rem ---------------------------------------------------------------

set "ROOT=%~dp0"
set "PORT=8070"
set "URL=http://127.0.0.1:%PORT%"
set "BROWSER=1"
set "MODE=window"

:parse
if "%~1"=="" goto afterparse
if /i "%~1"=="--no-browser" ( set "BROWSER=0" & shift & goto parse )
if /i "%~1"=="--foreground" ( set "MODE=fg"    & shift & goto parse )
echo Unknown option: %~1
echo Usage: run.bat [--no-browser] [--foreground]
pause
exit /b 1

:afterparse
cd /d "%ROOT%"

echo ==========================================================
echo    Network Traffic Monitor
echo ==========================================================
echo.

where node >nul 2>&1
if errorlevel 1 (
  echo [X] Node.js was not found on PATH.
  echo     Install the LTS build from https://nodejs.org/ then re-run.
  echo.
  pause
  exit /b 1
)
for /f "delims=" %%v in ('node --version') do set "NODEVER=%%v"
echo [1/4] Node.js !NODEVER! detected.

if not exist "server\server.js" (
  echo [X] server\server.js not found - run this from the project root.
  pause
  exit /b 1
)
if not exist "public\index.html" (
  echo [X] public\index.html not found - dashboard assets missing.
  pause
  exit /b 1
)
echo [2/4] Project files verified.

rem free the port if a previous run is still holding it
for /f "delims=" %%p in ('netstat -ano ^| findstr /r /c:":%PORT% .*LISTENING"') do (
  echo       stopping previous instance ^(PID %%p^)
  taskkill /f /pid %%p >nul 2>&1
)
ping -n 2 127.0.0.1 >nul

if "!MODE!"=="fg" goto foreground

echo [3/4] Starting server...
start "Network Traffic Monitor Server" /min cmd /c "cd /d ""%ROOT%"" && node server\server.js"

echo       waiting for %URL% ...
set /a TRIES=0
set "FOUND="
:wait
set /a TRIES+=1
for /f "delims=" %%p in ('netstat -ano ^| findstr /r /c:":%PORT% .*LISTENING"') do set "FOUND=1"
if defined FOUND goto ready
if !TRIES! GEQ 25 goto timeout
ping -n 2 127.0.0.1 >nul
goto wait

:ready
echo [4/4] Server is live ^(~!TRIES!s^).
echo.
echo    Dashboard : %URL%
echo    Health    : %URL%/api/health
echo    API       : %URL%/api/stats ^| %URL%/api/history ^| %URL%/api/apps
echo.
if "!BROWSER!"=="1" (
  start "" "%URL%"
  echo    Browser opened.
) else (
  echo    Browser launch skipped ^(--no-browser^).
)
echo.
echo Close the minimized "Network Traffic Monitor Server" window to stop.
ping -n 6 127.0.0.1 >nul
exit /b 0

:foreground
echo [3/4] Starting server in this window - press Ctrl+C to stop.
echo.
node server\server.js
set "RC=%ERRORLEVEL%"
echo.
echo Server stopped ^(exit code %RC%^).
pause
exit /b %RC%

:timeout
echo [X] Server did not start listening on port %PORT% within ~25s.
echo     Check the server window for errors, or run:  run.bat --foreground
echo.
pause
exit /b 1
