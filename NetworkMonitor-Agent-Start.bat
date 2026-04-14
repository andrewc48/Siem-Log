@echo off
setlocal enabledelayedexpansion

cd /d "%~dp0"

echo [Network Monitor Agent] Starting bootstrap...

where python >nul 2>&1
if errorlevel 1 (
  echo.
  echo Python was not found on PATH.
  echo Install Python 3.10+ from https://www.python.org/downloads/
  echo and check "Add Python to PATH" during install.
  pause
  exit /b 1
)

if not exist ".venv\Scripts\python.exe" (
  echo Creating virtual environment...
  python -m venv .venv
  if errorlevel 1 goto :fail
)

echo Activating virtual environment...
call ".venv\Scripts\activate.bat"
if errorlevel 1 goto :fail

echo Installing or updating dependencies...
python -m pip install --upgrade pip setuptools wheel
if errorlevel 1 goto :fail
python -m pip install -e .
if errorlevel 1 goto :fail

echo.
echo Launching endpoint agent...
echo Pass --server-url http://SERVER:8080 to skip discovery if needed.
echo Close this window to stop the agent.
echo.
siem-agent %*
exit /b %errorlevel%

:fail
echo.
echo Setup failed. Review the errors above.
pause
exit /b 1
