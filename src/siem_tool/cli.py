from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from typing import Iterable

from .config import load_config
from .engine import SIEMEngine
from .models import DeviceRecord


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Simple SIEM network monitor")
    parser.add_argument(
        "--config",
        default="config/default_config.json",
        help="Path to JSON config file",
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=0,
        help="Run duration in seconds. 0 means run forever.",
    )
    parser.add_argument(
        "--set-device-name",
        nargs=2,
        metavar=("IP", "NAME"),
        help="Set a custom name for a discovered device IP.",
    )
    parser.add_argument(
        "--list-devices",
        action="store_true",
        help="List discovered devices and assigned names.",
    )
    parser.add_argument(
        "--clear-device-name",
        metavar="IP",
        help="Remove a custom name previously assigned to a device IP.",
    )
    parser.add_argument(
        "--scan-subnet",
        action="store_true",
        help="Ping-sweep local subnets to actively discover devices.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output --list-devices as JSON (useful for scripting).",
    )
    parser.add_argument(
        "--serve",
        action="store_true",
        help="Start the web dashboard (requires fastapi + uvicorn).",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host to bind the web server to (default: 127.0.0.1).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="Port for the web server (default: 8080).",
    )
    parser.add_argument(
        "--capture-mode",
        choices=("host", "pcap"),
        default=None,
        help="Traffic source: 'host' for local sockets, 'pcap' for mirrored/bridged traffic.",
    )
    parser.add_argument(
        "--capture-interface",
        default=None,
        help="Interface name for pcap sniffing (optional).",
    )
    parser.add_argument(
        "--capture-filter",
        default=None,
        help="Optional BPF filter for pcap mode (e.g. 'tcp or udp').",
    )
    return parser.parse_args()


def _print_devices(devices: Iterable[DeviceRecord], as_json: bool = False) -> None:
    rows = list(devices)
    if as_json:
        print(json.dumps([asdict(r) for r in rows], indent=2))
        return
    col_widths = (18, 20, 30, 19, 14, 34)
    header = (
        f"{'IP':<{col_widths[0]}} {'Alias':<{col_widths[1]}} "
        f"{'Hostname':<{col_widths[2]}} {'MAC':<{col_widths[3]}} {'Role':<{col_widths[4]}} {'Last Seen':<{col_widths[5]}}"
    )
    print(header)
    print("-" * sum(col_widths))
    for row in rows:
        role = "router" if row.is_router else ("not-router" if row.router_override == "not_router" else "-")
        print(
            f"{row.ip:<{col_widths[0]}} {(row.alias or '-'):<{col_widths[1]}} "
            f"{(row.hostname or '-'):<{col_widths[2]}} {(row.mac or '-'):<{col_widths[3]}} "
            f"{role:<{col_widths[4]}} {row.last_seen:<{col_widths[5]}}"
        )


def main() -> None:
    args = parse_args()
    config = load_config(args.config)
    if args.capture_mode is not None:
        config.capture_mode = args.capture_mode
    if args.capture_interface is not None:
        config.capture_interface = args.capture_interface
    if args.capture_filter is not None:
        config.capture_bpf = args.capture_filter
    engine = SIEMEngine(config)

    if args.set_device_name:
        ip, name = args.set_device_name
        engine.set_device_alias(ip=ip, alias=name)
        print(f"Saved device alias: {ip} -> {name}")
        return

    if args.clear_device_name:
        removed = engine.clear_device_alias(ip=args.clear_device_name)
        if removed:
            print(f"Removed alias for {args.clear_device_name}")
        else:
            print(f"No alias found for {args.clear_device_name}")
        return

    if args.serve:
        try:
            import uvicorn  # type: ignore
        except ImportError:
            print("uvicorn not found. Run: pip install uvicorn")
            return
        from .server import app, start_background_engine
        start_background_engine(config, server_host=args.host, server_port=args.port, server_scheme="http")
        url = f"http://{'localhost' if args.host in ('0.0.0.0', '127.0.0.1') else args.host}:{args.port}"
        print(f"\n  [SIEM] Dashboard running at {url}\n")
        uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
        return

    if args.scan_subnet:
        engine.scan_subnet()
        return

    if args.list_devices:
        _print_devices(engine.list_devices(), as_json=args.json)
        return

    if args.duration <= 0:
        engine.run(max_iterations=None)
        return

    iterations = max(args.duration // config.poll_interval_seconds, 1)
    engine.run(max_iterations=iterations)


if __name__ == "__main__":
    main()
