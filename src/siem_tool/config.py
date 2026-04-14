from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Tuple


@dataclass(slots=True)
class SIEMConfig:
    poll_interval_seconds: int = 2
    max_bytes_per_second: float = 5_000_000
    spike_multiplier: float = 3.0
    minimum_spike_baseline_bps: float = 10_000
    log_directory: str = "logs"
    include_connections: bool = True
    max_connections_per_poll: int = 1000
    max_packets_per_poll: int = 2000
    packet_payload_preview_bytes: int = 64
    tcp_reassembly_max_bytes: int = 16384
    tcp_reassembly_idle_seconds: int = 90
    capture_mode: str = "host"
    capture_interface: str = ""
    capture_bpf: str = ""
    pcap_write_rolling_file: bool = True
    pcap_rolling_file: str = "logs/capture_latest.pcap"
    pcap_rolling_max_mb: int = 256
    include_bluetooth: bool = True
    bluetooth_poll_interval_seconds: int = 15
    include_firewall_logs: bool = True
    firewall_log_path: str = r"C:\\Windows\\System32\\LogFiles\\Firewall\\pfirewall.log"
    high_risk_ports: Tuple[int, ...] = (21, 22, 23, 135, 139, 445, 1433, 3389, 5900)
    suspicious_ports: Tuple[int, ...] = (23, 445, 3389, 5900)
    max_established_connections_per_remote_ip: int = 30
    # Firewall brute-force / scan indicators
    firewall_block_burst_threshold: int = 40
    firewall_bruteforce_window_seconds: int = 300
    firewall_bruteforce_ports: Tuple[int, ...] = (22, 23, 445, 3389, 5900)
    # Packet-level indicators (pcap mode)
    syn_scan_unique_ports_threshold: int = 25
    syn_flood_packets_per_source_threshold: int = 120
    icmp_flood_packets_per_source_threshold: int = 160
    # General detection tuning
    detector_cooldown_seconds: int = 300
    beacon_window_seconds: int = 900
    beacon_min_observations: int = 12
    beacon_min_interval_seconds: int = 20
    beacon_max_interval_seconds: int = 120
    beacon_max_jitter_ratio: float = 0.35
    tls_fingerprint_fanout_threshold: int = 8
    incident_window_seconds: int = 900
    incident_min_alerts: int = 3
    incident_high_score_threshold: float = 12.0
    incident_medium_score_threshold: float = 6.0
    baseline_learning_enabled: bool = True
    baseline_learning_hours: int = 48
    resolve_device_hostnames: bool = True
    hostname_resolution_timeout_ms: int = 1200
    subnet_scan_timeout_ms: int = 500
    subnet_scan_workers: int = 64
    device_aliases_file: str = "logs/device_aliases.json"
    devices_inventory_file: str = "logs/devices.json"
    # Log retention
    events_retention_hours: float = 24.0
    alerts_retention_hours: float = 72.0
    archive_retention_days: int = 90
    log_prune_interval_minutes: int = 30
    network_health_enabled: bool = True
    network_health_probe_interval_seconds: int = 8
    network_health_timeout_ms: int = 1500
    network_health_targets: Tuple[str, ...] = ()
    agent_api_enabled: bool = True
    agent_enrollment_token: str = "lab-enroll"
    agent_discovery_enabled: bool = True
    agent_discovery_port: int = 55110
    agent_advertise_url: str = ""
    agent_heartbeat_timeout_seconds: int = 180


def load_config(config_path: str | None) -> SIEMConfig:
    if not config_path:
        return SIEMConfig()

    path = Path(config_path)
    raw = json.loads(path.read_text(encoding="utf-8"))
    suspicious_ports = tuple(int(port) for port in raw.get("suspicious_ports", [23, 445, 3389, 5900]))
    high_risk_ports = tuple(int(port) for port in raw.get("high_risk_ports", [21, 22, 23, 135, 139, 445, 1433, 3389, 5900]))
    firewall_bruteforce_ports = tuple(int(port) for port in raw.get("firewall_bruteforce_ports", [22, 23, 445, 3389, 5900]))
    network_health_targets = tuple(str(t).strip() for t in raw.get("network_health_targets", []) if str(t).strip())
    return SIEMConfig(
        poll_interval_seconds=int(raw.get("poll_interval_seconds", 2)),
        max_bytes_per_second=float(raw.get("max_bytes_per_second", 5_000_000)),
        spike_multiplier=float(raw.get("spike_multiplier", 3.0)),
        minimum_spike_baseline_bps=float(raw.get("minimum_spike_baseline_bps", 10_000)),
        log_directory=str(raw.get("log_directory", "logs")),
        include_connections=bool(raw.get("include_connections", True)),
        max_connections_per_poll=int(raw.get("max_connections_per_poll", 1000)),
        max_packets_per_poll=int(raw.get("max_packets_per_poll", 2000)),
        packet_payload_preview_bytes=int(raw.get("packet_payload_preview_bytes", 64)),
        tcp_reassembly_max_bytes=int(raw.get("tcp_reassembly_max_bytes", 16384)),
        tcp_reassembly_idle_seconds=int(raw.get("tcp_reassembly_idle_seconds", 90)),
        capture_mode=str(raw.get("capture_mode", "host")),
        capture_interface=str(raw.get("capture_interface", "")),
        capture_bpf=str(raw.get("capture_bpf", "")),
        pcap_write_rolling_file=bool(raw.get("pcap_write_rolling_file", True)),
        pcap_rolling_file=str(raw.get("pcap_rolling_file", "logs/capture_latest.pcap")),
        pcap_rolling_max_mb=int(raw.get("pcap_rolling_max_mb", 256)),
        include_bluetooth=bool(raw.get("include_bluetooth", True)),
        bluetooth_poll_interval_seconds=int(raw.get("bluetooth_poll_interval_seconds", 15)),
        include_firewall_logs=bool(raw.get("include_firewall_logs", True)),
        firewall_log_path=str(raw.get("firewall_log_path", r"C:\\Windows\\System32\\LogFiles\\Firewall\\pfirewall.log")),
        high_risk_ports=high_risk_ports,
        suspicious_ports=suspicious_ports,
        max_established_connections_per_remote_ip=int(
            raw.get("max_established_connections_per_remote_ip", 30)
        ),
        firewall_block_burst_threshold=int(raw.get("firewall_block_burst_threshold", 40)),
        firewall_bruteforce_window_seconds=int(raw.get("firewall_bruteforce_window_seconds", 300)),
        firewall_bruteforce_ports=firewall_bruteforce_ports,
        syn_scan_unique_ports_threshold=int(raw.get("syn_scan_unique_ports_threshold", 25)),
        syn_flood_packets_per_source_threshold=int(raw.get("syn_flood_packets_per_source_threshold", 120)),
        icmp_flood_packets_per_source_threshold=int(raw.get("icmp_flood_packets_per_source_threshold", 160)),
        detector_cooldown_seconds=int(raw.get("detector_cooldown_seconds", 300)),
        beacon_window_seconds=int(raw.get("beacon_window_seconds", 900)),
        beacon_min_observations=int(raw.get("beacon_min_observations", 12)),
        beacon_min_interval_seconds=int(raw.get("beacon_min_interval_seconds", 20)),
        beacon_max_interval_seconds=int(raw.get("beacon_max_interval_seconds", 120)),
        beacon_max_jitter_ratio=float(raw.get("beacon_max_jitter_ratio", 0.35)),
        tls_fingerprint_fanout_threshold=int(raw.get("tls_fingerprint_fanout_threshold", 8)),
        incident_window_seconds=int(raw.get("incident_window_seconds", 900)),
        incident_min_alerts=int(raw.get("incident_min_alerts", 3)),
        incident_high_score_threshold=float(raw.get("incident_high_score_threshold", 12.0)),
        incident_medium_score_threshold=float(raw.get("incident_medium_score_threshold", 6.0)),
        baseline_learning_enabled=bool(raw.get("baseline_learning_enabled", True)),
        baseline_learning_hours=int(raw.get("baseline_learning_hours", 48)),
        resolve_device_hostnames=bool(raw.get("resolve_device_hostnames", True)),
        hostname_resolution_timeout_ms=int(raw.get("hostname_resolution_timeout_ms", 1200)),
        subnet_scan_timeout_ms=int(raw.get("subnet_scan_timeout_ms", 500)),
        subnet_scan_workers=int(raw.get("subnet_scan_workers", 64)),
        device_aliases_file=str(raw.get("device_aliases_file", "logs/device_aliases.json")),
        devices_inventory_file=str(raw.get("devices_inventory_file", "logs/devices.json")),
        events_retention_hours=float(raw.get("events_retention_hours", 24.0)),
        alerts_retention_hours=float(raw.get("alerts_retention_hours", 72.0)),
        archive_retention_days=int(raw.get("archive_retention_days", 90)),
        log_prune_interval_minutes=int(raw.get("log_prune_interval_minutes", 30)),
        network_health_enabled=bool(raw.get("network_health_enabled", True)),
        network_health_probe_interval_seconds=int(raw.get("network_health_probe_interval_seconds", 8)),
        network_health_timeout_ms=int(raw.get("network_health_timeout_ms", 1500)),
        network_health_targets=network_health_targets,
        agent_api_enabled=bool(raw.get("agent_api_enabled", True)),
        agent_enrollment_token=str(raw.get("agent_enrollment_token", "lab-enroll") or "lab-enroll"),
        agent_discovery_enabled=bool(raw.get("agent_discovery_enabled", True)),
        agent_discovery_port=int(raw.get("agent_discovery_port", 55110)),
        agent_advertise_url=str(raw.get("agent_advertise_url", "") or ""),
        agent_heartbeat_timeout_seconds=int(raw.get("agent_heartbeat_timeout_seconds", 180)),
    )
