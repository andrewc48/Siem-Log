#!/usr/bin/env python3
"""
Quick launcher for the SIEM Dashboard.

Usage:
    python run.py
    python run.py --port 8080 --host 0.0.0.0
    python run.py --config config/my_config.json
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Allow running from the workspace root without installing
sys.path.insert(0, str(Path(__file__).parent / "src"))


def main() -> None:
    parser = argparse.ArgumentParser(description="SIEM Dashboard")
    parser.add_argument("--host",   default="127.0.0.1",                    help="Bind host  (default: 127.0.0.1)")
    parser.add_argument("--port",   default=8080, type=int,                  help="Bind port  (default: 8080)")
    parser.add_argument("--config", default="config/default_config.json",    help="Config file path")
    parser.add_argument("--capture-mode", choices=("host", "pcap"), default=None, help="host=local sockets, pcap=mirrored/bridged traffic")
    parser.add_argument("--capture-interface", default=None, help="Interface name for pcap mode")
    parser.add_argument("--capture-filter", default=None, help="Optional BPF filter for pcap mode")
    args = parser.parse_args()

    try:
        import uvicorn
    except ImportError:
        print("uvicorn not found.  Run:  pip install uvicorn")
        sys.exit(1)

    from siem_tool.config import load_config
    from siem_tool.server import app, start_background_engine

    config = load_config(args.config)
    if args.capture_mode is not None:
        config.capture_mode = args.capture_mode
    if args.capture_interface is not None:
        config.capture_interface = args.capture_interface
    if args.capture_filter is not None:
        config.capture_bpf = args.capture_filter
    start_background_engine(config)

    url = f"http://{'localhost' if args.host in ('0.0.0.0','127.0.0.1') else args.host}:{args.port}"
    print(f"\n  [SIEM] Dashboard running at {url}\n")
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
