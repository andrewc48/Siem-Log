@echo off
REM Validate-SIEM.bat - Validation wrapper for SIEM Tool
REM Runs the validation script and displays results before exiting

setlocal enabledelayedexpansion
cd /d "%~dp0"

echo.
echo ===== SIEM Tool Validation =====
echo.

REM Use workspace .venv Python
set PYTHON_EXE=.\.venv\Scripts\python.exe

REM Check if .venv exists
if not exist "%PYTHON_EXE%" (
    echo [err] Workspace .venv not found at %PYTHON_EXE%
    echo Please run: pip install -r requirements-runtime.txt -e .
    echo.
    pause
    exit /b 1
)

REM Run validation script
"%PYTHON_EXE%" validate.py
if errorlevel 1 (
    echo.
    echo [err] Validation failed with exit code %ERRORLEVEL%
    pause
    exit /b 1
)

echo.
echo [ok] Validation completed successfully
echo.
pause
exit /b 0
