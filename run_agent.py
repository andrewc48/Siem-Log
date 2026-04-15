#!/usr/bin/env python3
"""
Quick launcher for the SIEM endpoint agent.

Usage:
    python run_agent.py --server-url http://192.168.1.10:8080 --token lab-enroll
    python run_agent.py --token lab-enroll
"""
from __future__ import annotations

import sys
from pathlib import Path

# Allow running from the workspace root without installing
sys.path.insert(0, str(Path(__file__).parent / "src"))


def main() -> None:
    from siem_agent.cli import main as agent_main

    agent_main()


if __name__ == "__main__":
    main()
