from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional


@dataclass(slots=True)
class NetworkEvent:
    timestamp: str
    interface: str
    bytes_sent_per_sec: float
    bytes_recv_per_sec: float

    @classmethod
    def create(
        cls,
        interface: str,
        bytes_sent_per_sec: float,
        bytes_recv_per_sec: float,
    ) -> "NetworkEvent":
        return cls(
            timestamp=datetime.now(timezone.utc).isoformat(),
            interface=interface,
            bytes_sent_per_sec=bytes_sent_per_sec,
            bytes_recv_per_sec=bytes_recv_per_sec,
        )


@dataclass(slots=True)
class Alert:
    timestamp: str
    severity: str
    rule: str
    message: str
    interface: str
    observed_value: float
    threshold: float
    evidence: Dict[str, Any] = field(default_factory=dict)
    muted: bool = False
    suppressed_reason: str = ""


@dataclass(slots=True)
class ConnectionEvent:
    timestamp: str
    family: str
    socket_type: str
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    status: str
    pid: Optional[int]
    process_name: str

    @classmethod
    def create(
        cls,
        family: str,
        socket_type: str,
        local_ip: str,
        local_port: int,
        remote_ip: str,
        remote_port: int,
        status: str,
        pid: Optional[int],
        process_name: str,
    ) -> "ConnectionEvent":
        return cls(
            timestamp=datetime.now(timezone.utc).isoformat(),
            family=family,
            socket_type=socket_type,
            local_ip=local_ip,
            local_port=local_port,
            remote_ip=remote_ip,
            remote_port=remote_port,
            status=status,
            pid=pid,
            process_name=process_name,
        )


@dataclass(slots=True)
class DeviceRecord:
    ip: str
    mac: str
    hostname: str
    alias: str
    first_seen: str
    last_seen: str


@dataclass(slots=True)
class BluetoothEvent:
    timestamp: str
    name: str
    address: str
    connected: bool
    paired: bool
    kind: str
    source: str
    details: Dict[str, Any]

    @classmethod
    def create(
        cls,
        name: str,
        address: str,
        connected: bool,
        paired: bool,
        kind: str,
        source: str,
        details: Dict[str, Any],
    ) -> "BluetoothEvent":
        return cls(
            timestamp=datetime.now(timezone.utc).isoformat(),
            name=name,
            address=address,
            connected=connected,
            paired=paired,
            kind=kind,
            source=source,
            details=details,
        )


@dataclass(slots=True)
class PacketEvent:
    timestamp: str
    interface: str
    direction: str
    protocol: str
    app_protocol: str
    frame_number: int | None
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    length: int
    tcp_flags: str
    tcp_seq: int | None
    tcp_ack: int | None
    payload_len: int
    payload_preview_hex: str
    dns_query: str
    dns_answers: str
    dns_rcode: str
    dns_txn_rtt_ms: float | None
    tls_sni: str
    tls_fingerprint: str
    http_host: str
    http_method: str
    http_path: str

    @classmethod
    def create(
        cls,
        interface: str,
        direction: str,
        protocol: str,
        app_protocol: str,
        frame_number: int | None,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        length: int,
        tcp_flags: str,
        tcp_seq: int | None,
        tcp_ack: int | None,
        payload_len: int,
        payload_preview_hex: str,
        dns_query: str,
        dns_answers: str,
        dns_rcode: str,
        dns_txn_rtt_ms: float | None,
        tls_sni: str,
        tls_fingerprint: str,
        http_host: str,
        http_method: str,
        http_path: str,
    ) -> "PacketEvent":
        return cls(
            timestamp=datetime.now(timezone.utc).isoformat(),
            interface=interface,
            direction=direction,
            protocol=protocol,
            app_protocol=app_protocol,
            frame_number=frame_number,
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            length=length,
            tcp_flags=tcp_flags,
            tcp_seq=tcp_seq,
            tcp_ack=tcp_ack,
            payload_len=payload_len,
            payload_preview_hex=payload_preview_hex,
            dns_query=dns_query,
            dns_answers=dns_answers,
            dns_rcode=dns_rcode,
            dns_txn_rtt_ms=dns_txn_rtt_ms,
            tls_sni=tls_sni,
            tls_fingerprint=tls_fingerprint,
            http_host=http_host,
            http_method=http_method,
            http_path=http_path,
        )


@dataclass(slots=True)
class FirewallBlockEvent:
    timestamp: str
    action: str
    protocol: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    direction: str
    interface: str
    raw: Dict[str, Any]

    @classmethod
    def create(
        cls,
        timestamp: str,
        action: str,
        protocol: str,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        direction: str,
        interface: str,
        raw: Dict[str, Any],
    ) -> "FirewallBlockEvent":
        return cls(
            timestamp=timestamp,
            action=action,
            protocol=protocol,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            direction=direction,
            interface=interface,
            raw=raw,
        )
