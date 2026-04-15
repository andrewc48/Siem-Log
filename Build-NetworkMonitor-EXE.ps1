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
& .\.venv\Scripts\python.exe -m pip install -r requirements-build.txt -e .

if (Test-Path "dist\NetworkMonitor") {
    Remove-Item -Recurse -Force "dist\NetworkMonitor"
}
if (Test-Path "dist\NetworkMonitor-Agent") {
    Remove-Item -Recurse -Force "dist\NetworkMonitor-Agent"
}

Write-Host "[Network Monitor] Building central server executable..."
& .\.venv\Scripts\pyinstaller `
  --name NetworkMonitor `
  --noconfirm `
  --onedir `
  --add-data "src/siem_tool/static;siem_tool/static" `
  --add-data "config;config" `
  run.py

Write-Host "[Network Monitor] Building endpoint agent executable..."
& .\.venv\Scripts\pyinstaller `
  --name NetworkMonitor-Agent `
  --noconfirm `
  --onedir `
  run_agent.py

Write-Host "Build complete:"
Write-Host "  dist\NetworkMonitor\NetworkMonitor.exe"
Write-Host "  dist\NetworkMonitor-Agent\NetworkMonitor-Agent.exe"

