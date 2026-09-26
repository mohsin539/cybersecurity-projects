@echo off
cd /d "%~dp0"
py gui.py %*
echo.
echo Exit code: %ERRORLEVEL%
echo.
pause