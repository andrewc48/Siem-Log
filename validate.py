from __future__ import annotations

import compileall
import importlib
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
SRC_DIR = ROOT / "src"

DEPENDENCY_IMPORTS = [
    ("psutil", "psutil", True),
    ("fastapi", "fastapi", True),
    ("uvicorn", "uvicorn", True),
    ("python-dotenv", "dotenv", True),
    ("openai", "openai", True),
    ("scapy", "scapy.all", True),
    ("pywin32", "pythoncom", sys.platform.startswith("win")),
]

PROJECT_IMPORTS = [
    "src.siem_tool.device_monitor",
    "src.siem_tool.network_health",
    "src.siem_tool.server",
    "src.siem_tool.cli",
    "src.siem_agent.cli",
    "src.siem_agent.transport",
]


def check_dependency_imports() -> list[str]:
    failures: list[str] = []
    for label, module_name, enabled in DEPENDENCY_IMPORTS:
        if not enabled:
            continue
        try:
            importlib.import_module(module_name)
            print(f"[ok] dependency import: {label} -> {module_name}")
        except Exception as exc:
            failures.append(f"dependency import failed for {label} ({module_name}): {exc}")
    return failures


def check_project_imports() -> list[str]:
    failures: list[str] = []
    for module_name in PROJECT_IMPORTS:
        try:
            importlib.import_module(module_name)
            print(f"[ok] project import: {module_name}")
        except Exception as exc:
            failures.append(f"project import failed for {module_name}: {exc}")
    return failures


def main() -> int:
    print(f"[info] validating with: {sys.executable}")
    print(f"[info] project root: {ROOT}")

    compile_ok = compileall.compile_dir(str(SRC_DIR), quiet=1, force=False)
    if compile_ok:
        print(f"[ok] compileall: {SRC_DIR}")
    else:
        print(f"[err] compileall: {SRC_DIR}")

    failures: list[str] = []
    if not compile_ok:
        failures.append(f"compileall failed for {SRC_DIR}")

    failures.extend(check_dependency_imports())
    failures.extend(check_project_imports())

    if failures:
        print("[err] validation failed")
        for failure in failures:
            print(f" - {failure}")
        return 1

    print("[ok] validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())