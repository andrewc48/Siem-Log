@echo off
setlocal enabledelayedexpansion

cd /d "%~dp0"

echo [Network Monitor - PCAP] Starting bootstrap...

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

echo Checking Npcap/scapy support...
python -c "import scapy.all as s; print('Scapy OK')" >nul 2>&1
if errorlevel 1 (
  echo.
  echo Scapy/Npcap capture support is not ready.
  echo Install Npcap on this VM and enable compatible mode if prompted.
  pause
  exit /b 1
)

echo.
echo Launching PCAP sensor dashboard on http://0.0.0.0:8080
echo This mode is intended for mirrored/bridged traffic capture.
echo Close this window to stop the server.
echo.
python run.py --capture-mode pcap --host 0.0.0.0 --port 8080
exit /b %errorlevel%

:fail
echo.
echo Setup failed. Review the errors above.
pause
exit /b 1
