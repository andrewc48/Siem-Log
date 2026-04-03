$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

Write-Host "[Network Monitor] Preparing build environment..."

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    throw "Python was not found on PATH. Install Python 3.10+ first."
}

if (-not (Test-Path ".venv\Scripts\python.exe")) {
    python -m venv .venv
}

& .\.venv\Scripts\python.exe -m pip install --upgrade pip setuptools wheel
& .\.venv\Scripts\python.exe -m pip install -e . pyinstaller

Write-Host "[Network Monitor] Building executable..."
& .\.venv\Scripts\pyinstaller `
  --name NetworkMonitor `
  --noconfirm `
  --onedir `
  --add-data "src/siem_tool/static;siem_tool/static" `
  --add-data "config;config" `
  run.py

Write-Host "Build complete: dist\NetworkMonitor\NetworkMonitor.exe"
