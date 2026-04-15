from __future__ import annotations

import itertools
from typing import Optional

from .bluetooth_monitor import BluetoothMonitor
from .collector import NetworkCollector
from .config import SIEMConfig
from .detector import AnomalyDetector
from .device_monitor import DeviceMonitor
from .firewall_monitor import FirewallLogMonitor
from .storage import JsonlStore


class SIEMEngine:
    def __init__(self, config: SIEMConfig) -> None:
        self.config = config
        self.collector = NetworkCollector(
            poll_interval_seconds=config.poll_interval_seconds,
            include_connections=config.include_connections,
            max_connections_per_poll=config.max_connections_per_poll,
            max_packets_per_poll=config.max_packets_per_poll,
            packet_payload_preview_bytes=config.packet_payload_preview_bytes,
            tcp_reassembly_max_bytes=config.tcp_reassembly_max_bytes,
            tcp_reassembly_idle_seconds=config.tcp_reassembly_idle_seconds,
            capture_mode=config.capture_mode,
            capture_interface=config.capture_interface,
            capture_bpf=config.capture_bpf,
            pcap_write_rolling_file=config.pcap_write_rolling_file,
            pcap_rolling_file=config.pcap_rolling_file,
            pcap_rolling_max_mb=config.pcap_rolling_max_mb,
        )
        self.detector = AnomalyDetector(config)
        self.bluetooth_monitor = BluetoothMonitor(config)
        self.firewall_monitor = FirewallLogMonitor(
            log_path=config.firewall_log_path,
            enabled=config.include_firewall_logs,
        )
        self.device_monitor = DeviceMonitor(config)
        self.store = JsonlStore(config.log_directory)

    def run(self, max_iterations: Optional[int] = None) -> None:
        stream = self.collector.stream()
        iterator = stream if max_iterations is None else itertools.islice(stream, max_iterations)

        for batch in iterator:
            self.store.write_events(batch.network_events)
            if batch.connection_events:
                self.store.write_connections(batch.connection_events)
            if batch.packet_events:
                self.store.write_packets(batch.packet_events)
            self.device_monitor.refresh(batch.connection_events)

            bt_events = self.bluetooth_monitor.poll()
            if bt_events:
                self.store.write_bluetooth_events(bt_events)

            firewall_events = self.firewall_monitor.poll()
            if firewall_events:
                self.store.write_firewall_blocks(firewall_events)

            alerts = self.detector.evaluate(batch.network_events)
            if batch.connection_events:
                alerts.extend(self.detector.evaluate_connections(batch.connection_events))
            if batch.packet_events:
                alerts.extend(self.detector.evaluate_packet_events(batch.packet_events))
            if firewall_events:
                alerts.extend(self.detector.evaluate_firewall_blocks(firewall_events))

            if alerts:
                self.store.write_alerts(alerts)
                for alert in alerts:
                    print(
                        f"[{alert.severity.upper()}] {alert.rule}: "
                        f"{alert.message} | observed={alert.observed_value:.2f} "
                        f"threshold={alert.threshold:.2f}"
                    )

    def set_device_alias(self, ip: str, alias: str) -> None:
        self.device_monitor.set_alias(ip=ip, alias=alias)

    def clear_device_alias(self, ip: str) -> bool:
        return self.device_monitor.clear_alias(ip=ip)

    def set_device_router_override(self, ip: str, router_override: str) -> None:
        self.device_monitor.set_router_override(ip=ip, router_override=router_override)

    def primary_router_ip(self) -> str:
        return self.device_monitor.get_primary_router_ip()

    def scan_subnet(self) -> int:
        return self.device_monitor.scan_subnet()

    def list_devices(self) -> list:
        return self.device_monitor.list_devices()
