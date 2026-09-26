@echo off
setlocal EnableDelayedExpansion
title WebXR Security Awareness Training Module

rem ==========================================================================
rem  run.bat - start the WebXR Security Awareness Training Module
rem
rem  Usage:   run.bat [port]
rem           run.bat 9443
rem           set PORT=9443 && run.bat
rem
rem  Default: http://localhost:8443
rem  Local mode: demo identities are seeded so the training can be explored.
rem  Override credentials / secrets via environment variables before running.
rem ==========================================================================

cd /d "%~dp0"

rem ── Port: first CLI argument wins, then %PORT%, then 8443 ───────────────
set "APP_PORT=%~1"
if not defined APP_PORT set "APP_PORT=%PORT%"
if not defined APP_PORT set "APP_PORT=8443"

rem ── Node.js presence and version check (>= 20 required) ─────────────────
set "NODE_BIN=node"
where node >nul 2>nul
if errorlevel 1 (
  echo.
  echo   [X] Node.js was not found on your PATH.
  echo.
  echo       This application needs Node.js 20 or newer.
  echo       Download it from https://nodejs.org/ and run this file again.
  echo.
  pause
  exit /b 1
)

for /f "tokens=1 delims=." %%v in ('node -p "process.versions.node"') do set "NODE_MAJOR=%%v"
if not defined NODE_MAJOR set "NODE_MAJOR=0"
if !NODE_MAJOR! LSS 20 (
  echo.
  echo   [X] Node.js !NODE_MAJOR! is installed, but version 20 or newer is required.
  echo       Run "node -v" to confirm, then update Node.js and retry.
  echo.
  pause
  exit /b 1
)

rem ── Local demo environment ──────────────────────────────────────────────
if not defined NODE_ENV               set "NODE_ENV=local"
if not defined ADMIN_SEED_PASSWORD    set "ADMIN_SEED_PASSWORD=Admin#Passw0rd!"
if not defined DATA_DIR               set "DATA_DIR=./data"

echo.
echo  ============================================================
echo   WebXR Security Awareness Training Module
echo  ============================================================
echo.
echo    Node.js     : v!NODE_MAJOR!  ^(node -v for the full version^)
echo    Mode        : !NODE_ENV!
echo    Data        : %DATA_DIR%
echo    URL         : http://localhost:%APP_PORT%
echo.
echo    Demo logins ^(local mode only^)
echo      admin@corp.example / Admin#Passw0rd!  - admin console
echo      learner demo    - press "Try demo (learner)" on the sign-in screen
echo.
echo    Press Ctrl+C to stop the server.
echo  --------------------------------------------------------
echo.

rem ── Open the browser once the port answers ──────────────────────────────
start "" /b powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$u='http://localhost:%APP_PORT%/'; for($i=0;$i -lt 40;$i++){ try{ $r=Invoke-WebRequest -Uri ($u+'api/health') -UseBasicParsing -TimeoutSec 2; if($r.StatusCode -eq 200){ Start-Process $u; exit 0 } }catch{}; Start-Sleep -Milliseconds 500 }"

rem ── Run the server (exec keeps Ctrl+C responsive) ───────────────────────
node server\src\index.js --port %APP_PORT%

set "EXIT_CODE=%errorlevel%"
if not "%EXIT_CODE%"=="0" (
  echo.
  echo   [!] The server exited with code %EXIT_CODE%.
  echo       Port %APP_PORT% may already be in use - try: run.bat 8543
  echo.
  pause
)
endlocal
exit /b %EXIT_CODE%
