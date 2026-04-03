from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Iterable

from .models import Alert, BluetoothEvent, ConnectionEvent, FirewallBlockEvent, NetworkEvent, PacketEvent


class JsonlStore:
    def __init__(self, log_directory: str) -> None:
        self.log_directory = Path(log_directory)
        self.log_directory.mkdir(parents=True, exist_ok=True)
        self.events_file = self.log_directory / "events.jsonl"
        self.connections_file = self.log_directory / "connections.jsonl"
        self.alerts_file = self.log_directory / "alerts.jsonl"
        self.bluetooth_file = self.log_directory / "bluetooth.jsonl"
        self.packets_file = self.log_directory / "packets.jsonl"
        self.firewall_blocks_file = self.log_directory / "firewall_blocks.jsonl"

    def write_events(self, events: Iterable[NetworkEvent]) -> None:
        with self.events_file.open("a", encoding="utf-8") as handle:
            for event in events:
                handle.write(json.dumps(asdict(event), separators=(",", ":")) + "\n")

    def write_alerts(self, alerts: Iterable[Alert]) -> None:
        with self.alerts_file.open("a", encoding="utf-8") as handle:
            for alert in alerts:
                handle.write(json.dumps(asdict(alert), separators=(",", ":")) + "\n")

    def write_connections(self, events: Iterable[ConnectionEvent]) -> None:
        with self.connections_file.open("a", encoding="utf-8") as handle:
            for event in events:
                handle.write(json.dumps(asdict(event), separators=(",", ":")) + "\n")

    def write_bluetooth_events(self, events: Iterable[BluetoothEvent]) -> None:
        with self.bluetooth_file.open("a", encoding="utf-8") as handle:
            for event in events:
                handle.write(json.dumps(asdict(event), separators=(",", ":")) + "\n")

    def write_packets(self, events: Iterable[PacketEvent]) -> None:
        with self.packets_file.open("a", encoding="utf-8") as handle:
            for event in events:
                handle.write(json.dumps(asdict(event), separators=(",", ":")) + "\n")

    def write_firewall_blocks(self, events: Iterable[FirewallBlockEvent]) -> None:
        with self.firewall_blocks_file.open("a", encoding="utf-8") as handle:
            for event in events:
                handle.write(json.dumps(asdict(event), separators=(",", ":")) + "\n")
