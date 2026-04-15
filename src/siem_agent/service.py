from __future__ import annotations

import json
import os
import socket
import sys
import time
from pathlib import Path


def _service_config_dir() -> Path:
    program_data = os.environ.get("PROGRAMDATA", "")
    base = Path(program_data) if program_data else Path.cwd()
    path = base / "NetworkMonitorAgent"
    path.mkdir(parents=True, exist_ok=True)
    return path


def service_config_path() -> Path:
    return _service_config_dir() / "service_config.json"


def save_service_config(payload: dict) -> None:
    service_config_path().write_text(json.dumps(payload, indent=2), encoding="utf-8")


def load_service_config() -> dict:
    path = service_config_path()
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


if os.name == "nt":
    import win32event  # type: ignore
    import win32service  # type: ignore
    import win32serviceutil  # type: ignore
    import servicemanager  # type: ignore

    class SIEMAgentService(win32serviceutil.ServiceFramework):
        _svc_name_ = "NetworkMonitorAgent"
        _svc_display_name_ = "Network Monitor Agent"
        _svc_description_ = "Lightweight endpoint SIEM agent that forwards Windows telemetry to the central SIEM host."

        def __init__(self, args):
            super().__init__(args)
            self.stop_event = win32event.CreateEvent(None, 0, 0, None)
            socket.setdefaulttimeout(30)
            self.running = True

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            self.running = False
            win32event.SetEvent(self.stop_event)

        def SvcDoRun(self):
            servicemanager.LogInfoMsg("Network Monitor Agent service starting")
            try:
                self.main_loop()
            except Exception as exc:
                servicemanager.LogErrorMsg(f"Network Monitor Agent crashed: {exc}")
                raise

        def main_loop(self):
            from .cli import build_runtime, run_cycle

            config = load_service_config()
            runtime = build_runtime(config)
            interval = max(5, int(config.get("interval", 30) or 30))
            while self.running:
                try:
                    run_cycle(
                        runtime["transport"],
                        runtime["creds"],
                        runtime["collector"],
                        runtime["spool"],
                        runtime["sequence_path"],
                    )
                except Exception as exc:
                    servicemanager.LogErrorMsg(f"Network Monitor Agent cycle error: {exc}")
                if win32event.WaitForSingleObject(self.stop_event, interval * 1000) == win32event.WAIT_OBJECT_0:
                    break


def handle_service_command() -> None:
    if os.name != "nt":
        raise RuntimeError("Windows service mode is only available on Windows")
    import win32serviceutil  # type: ignore

    win32serviceutil.HandleCommandLine(SIEMAgentService)


if __name__ == "__main__":
    handle_service_command()