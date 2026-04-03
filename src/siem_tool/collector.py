from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
import socket
import ipaddress
from io import BytesIO
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Set, Tuple

import psutil

from .models import ConnectionEvent, NetworkEvent, PacketEvent


@dataclass(slots=True)
class InterfaceCounters:
    bytes_sent: int
    bytes_recv: int


@dataclass(slots=True)
class TelemetryBatch:
    network_events: List[NetworkEvent]
    connection_events: List[ConnectionEvent]
    packet_events: List[PacketEvent]


class NetworkCollector:
    def __init__(
        self,
        poll_interval_seconds: int,
        include_connections: bool,
        max_connections_per_poll: int,
        max_packets_per_poll: int,
        packet_payload_preview_bytes: int,
        tcp_reassembly_max_bytes: int,
        tcp_reassembly_idle_seconds: int,
        capture_mode: str,
        capture_interface: str,
        capture_bpf: str,
        pcap_write_rolling_file: bool,
        pcap_rolling_file: str,
        pcap_rolling_max_mb: int,
    ) -> None:
        self.poll_interval_seconds = poll_interval_seconds
        self.include_connections = include_connections
        self.max_connections_per_poll = max_connections_per_poll
        self.max_packets_per_poll = max_packets_per_poll
        self.packet_payload_preview_bytes = max(0, int(packet_payload_preview_bytes))
        self.tcp_reassembly_max_bytes = max(1024, int(tcp_reassembly_max_bytes))
        self.tcp_reassembly_idle_seconds = max(10, int(tcp_reassembly_idle_seconds))
        self.capture_mode = capture_mode.lower().strip() or "host"
        self.capture_interface = capture_interface.strip()
        self.capture_bpf = capture_bpf.strip()
        self.pcap_write_rolling_file = bool(pcap_write_rolling_file)
        self.pcap_rolling_file = Path(pcap_rolling_file)
        self.pcap_rolling_max_mb = max(16, int(pcap_rolling_max_mb))
        self._pcap_error_logged = False
        self._tcp_stream_buffers: Dict[Tuple[str, int, str, int], bytearray] = {}
        self._tcp_stream_last_seen: Dict[Tuple[str, int, str, int], float] = {}
        self._dns_txn_start: Dict[Tuple[str, int, str, int, int], Tuple[float, str]] = {}
        self._pcap_frame_counter = 0

        if self.pcap_write_rolling_file:
            try:
                self.pcap_rolling_file.parent.mkdir(parents=True, exist_ok=True)
                if self.pcap_rolling_file.exists():
                    self.pcap_rolling_file.unlink()
            except OSError:
                pass

    @staticmethod
    def _parse_dns_fields(payload_bytes: bytes, dns_layer: object) -> Tuple[str, str]:
        query = ""
        answers = ""
        if dns_layer is None:
            return query, answers
        try:
            qd = getattr(dns_layer, "qd", None)
            if qd is not None and hasattr(qd, "qname"):
                qname = getattr(qd, "qname", b"")
                if isinstance(qname, bytes):
                    query = qname.decode("utf-8", errors="replace").rstrip(".")
                else:
                    query = str(qname).rstrip(".")
        except Exception:
            query = ""

        try:
            ancount = int(getattr(dns_layer, "ancount", 0) or 0)
            rr = getattr(dns_layer, "an", None)
            names: List[str] = []
            for _ in range(min(ancount, 8)):
                if rr is None:
                    break
                rdata = getattr(rr, "rdata", None)
                if rdata is not None:
                    if isinstance(rdata, bytes):
                        names.append(rdata.decode("utf-8", errors="replace").rstrip("."))
                    else:
                        names.append(str(rdata).rstrip("."))
                rr = getattr(rr, "payload", None)
            if names:
                answers = ", ".join(n for n in names if n)
        except Exception:
            answers = ""

        if not query and payload_bytes:
            # best effort fallback for malformed DNS decode
            try:
                query = payload_bytes[12:].split(b"\x00", 1)[0].decode("utf-8", errors="replace").strip(".")
            except Exception:
                query = ""
        return query, answers

    @staticmethod
    def _parse_tls_fingerprint(payload_bytes: bytes) -> str:
        # JA3-style hash material: version,ciphers,extensions,curves,ec_point_formats
        if len(payload_bytes) < 9:
            return ""
        try:
            stream = BytesIO(payload_bytes)
            if stream.read(1) != b"\x16":
                return ""
            stream.read(2)  # record version
            rec_len = int.from_bytes(stream.read(2), "big")
            if rec_len <= 0 or rec_len > len(payload_bytes) - 5:
                return ""
            if stream.read(1) != b"\x01":
                return ""
            hs_len = int.from_bytes(stream.read(3), "big")
            body = stream.read(hs_len)
            if len(body) < 42:
                return ""

            p = 0
            client_version = int.from_bytes(body[p:p + 2], "big")
            p += 2
            p += 32  # random
            sid_len = body[p]
            p += 1 + sid_len

            cs_len = int.from_bytes(body[p:p + 2], "big")
            p += 2
            ciphers = []
            for i in range(0, cs_len, 2):
                if p + i + 2 > len(body):
                    break
                c = int.from_bytes(body[p + i:p + i + 2], "big")
                # skip GREASE values
                if (c & 0x0F0F) == 0x0A0A:
                    continue
                ciphers.append(str(c))
            p += cs_len

            comp_len = body[p]
            p += 1 + comp_len

            ext_len = int.from_bytes(body[p:p + 2], "big")
            p += 2
            end = min(p + ext_len, len(body))

            exts = []
            curves = []
            ecpf = []
            while p + 4 <= end:
                ext_type = int.from_bytes(body[p:p + 2], "big")
                ext_size = int.from_bytes(body[p + 2:p + 4], "big")
                p += 4
                ext_data = body[p:p + ext_size]
                p += ext_size
                if (ext_type & 0x0F0F) != 0x0A0A:
                    exts.append(str(ext_type))

                if ext_type == 10 and len(ext_data) >= 2:
                    gl = int.from_bytes(ext_data[0:2], "big")
                    q = 2
                    while q + 2 <= min(2 + gl, len(ext_data)):
                        g = int.from_bytes(ext_data[q:q + 2], "big")
                        if (g & 0x0F0F) != 0x0A0A:
                            curves.append(str(g))
                        q += 2
                elif ext_type == 11 and len(ext_data) >= 1:
                    fl = ext_data[0]
                    q = 1
                    while q < min(1 + fl, len(ext_data)):
                        ecpf.append(str(ext_data[q]))
                        q += 1

            ja3_string = ",".join([
                str(client_version),
                "-".join(ciphers),
                "-".join(exts),
                "-".join(curves),
                "-".join(ecpf),
            ])
            if not ja3_string.replace(",", "").replace("-", ""):
                return ""
            return hashlib.md5(ja3_string.encode("utf-8", errors="replace")).hexdigest()
        except Exception:
            return ""

    def _update_tcp_reassembly(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int, payload_bytes: bytes, now_mono: float) -> bytes:
        key = (src_ip, src_port, dst_ip, dst_port)
        buf = self._tcp_stream_buffers.get(key)
        if buf is None:
            buf = bytearray()
            self._tcp_stream_buffers[key] = buf
        if payload_bytes:
            buf.extend(payload_bytes)
            if len(buf) > self.tcp_reassembly_max_bytes:
                del buf[:-self.tcp_reassembly_max_bytes]
        self._tcp_stream_last_seen[key] = now_mono
        return bytes(buf)

    def _cleanup_tcp_reassembly(self, now_mono: float) -> None:
        cutoff = now_mono - float(self.tcp_reassembly_idle_seconds)
        stale = [k for k, ts in self._tcp_stream_last_seen.items() if ts < cutoff]
        for k in stale:
            self._tcp_stream_last_seen.pop(k, None)
            self._tcp_stream_buffers.pop(k, None)

    def _cleanup_dns_transactions(self, now_mono: float) -> None:
        cutoff = now_mono - 30.0
        stale = [k for k, (ts, _) in self._dns_txn_start.items() if ts < cutoff]
        for k in stale:
            self._dns_txn_start.pop(k, None)

    def _write_rolling_pcap(self, packets: List[object]) -> None:
        if not self.pcap_write_rolling_file or not packets:
            return
        try:
            from scapy.all import wrpcap  # type: ignore
            wrpcap(str(self.pcap_rolling_file), packets, append=True)
            if self.pcap_rolling_file.exists():
                size_mb = self.pcap_rolling_file.stat().st_size / (1024 * 1024)
                if size_mb > float(self.pcap_rolling_max_mb):
                    self.pcap_rolling_file.unlink(missing_ok=True)
                    self._pcap_frame_counter = 0
                    wrpcap(str(self.pcap_rolling_file), packets, append=False)
        except Exception:
            return

    @staticmethod
    def _parse_http_fields(payload_bytes: bytes) -> Tuple[str, str, str]:
        if not payload_bytes:
            return "", "", ""
        try:
            text = payload_bytes.decode("utf-8", errors="replace")
        except Exception:
            return "", "", ""

        lines = text.splitlines()
        if not lines:
            return "", "", ""
        first = lines[0].strip()
        method = ""
        path = ""
        host = ""

        method_candidates = ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE")
        parts = first.split()
        if len(parts) >= 2 and parts[0].upper() in method_candidates:
            method = parts[0].upper()
            path = parts[1]

        for line in lines[1:40]:
            if ":" not in line:
                continue
            k, v = line.split(":", 1)
            if k.strip().lower() == "host":
                host = v.strip()
                break

        if not method and not host:
            return "", "", ""
        return host, method, path

    @staticmethod
    def _parse_tls_sni(payload_bytes: bytes) -> str:
        # Minimal TLS ClientHello parser for SNI extraction.
        if len(payload_bytes) < 9:
            return ""
        try:
            stream = BytesIO(payload_bytes)
            content_type = stream.read(1)
            if content_type != b"\x16":
                return ""
            version = stream.read(2)
            if len(version) != 2:
                return ""
            rec_len = int.from_bytes(stream.read(2), "big")
            if rec_len <= 0 or rec_len > len(payload_bytes) - 5:
                return ""
            hs_type = stream.read(1)
            if hs_type != b"\x01":
                return ""
            hs_len = int.from_bytes(stream.read(3), "big")
            body = stream.read(hs_len)
            if len(body) < 42:
                return ""

            p = 0
            p += 2  # client_version
            p += 32  # random
            sid_len = body[p]
            p += 1 + sid_len
            cs_len = int.from_bytes(body[p:p + 2], "big")
            p += 2 + cs_len
            comp_len = body[p]
            p += 1 + comp_len
            ext_len = int.from_bytes(body[p:p + 2], "big")
            p += 2
            end = min(p + ext_len, len(body))

            while p + 4 <= end:
                ext_type = int.from_bytes(body[p:p + 2], "big")
                ext_size = int.from_bytes(body[p + 2:p + 4], "big")
                p += 4
                ext_data = body[p:p + ext_size]
                p += ext_size
                if ext_type != 0 or len(ext_data) < 5:
                    continue
                list_len = int.from_bytes(ext_data[0:2], "big")
                q = 2
                limit = min(2 + list_len, len(ext_data))
                while q + 3 <= limit:
                    name_type = ext_data[q]
                    name_len = int.from_bytes(ext_data[q + 1:q + 3], "big")
                    q += 3
                    if q + name_len > limit:
                        break
                    if name_type == 0:
                        return ext_data[q:q + name_len].decode("utf-8", errors="replace").strip().rstrip(".")
                    q += name_len
        except Exception:
            return ""
        return ""

    def _read_counters(self) -> Dict[str, InterfaceCounters]:
        counters = psutil.net_io_counters(pernic=True)
        return {
            nic: InterfaceCounters(bytes_sent=value.bytes_sent, bytes_recv=value.bytes_recv)
            for nic, value in counters.items()
        }

    @staticmethod
    def _safe_addr(addr: Optional[tuple]) -> tuple[str, int]:
        if not addr:
            return "", 0
        host = str(addr[0]) if len(addr) > 0 else ""
        port = int(addr[1]) if len(addr) > 1 else 0
        return host, port

    def _read_connections(self) -> List[ConnectionEvent]:
        if not self.include_connections:
            return []

        events: List[ConnectionEvent] = []
        try:
            connections = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError, OSError):
            return events

        for conn in connections[: self.max_connections_per_poll]:
            local_ip, local_port = self._safe_addr(conn.laddr)
            remote_ip, remote_port = self._safe_addr(conn.raddr)
            process_name = "unknown"
            if conn.pid is not None:
                try:
                    process_name = psutil.Process(conn.pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                    process_name = "unknown"

            events.append(
                ConnectionEvent.create(
                    family=socket.AddressFamily(conn.family).name,
                    socket_type=socket.SocketKind(conn.type).name,
                    local_ip=local_ip,
                    local_port=local_port,
                    remote_ip=remote_ip,
                    remote_port=remote_port,
                    status=conn.status,
                    pid=conn.pid,
                    process_name=process_name,
                )
            )

        return events

    @staticmethod
    def _local_ips() -> Set[str]:
        local: Set[str] = set()
        try:
            iface_addrs = psutil.net_if_addrs()
        except Exception:
            return local
        for addrs in iface_addrs.values():
            for addr in addrs:
                if addr.family not in (socket.AF_INET, socket.AF_INET6):
                    continue
                ip = str(addr.address).split("%", maxsplit=1)[0]
                if not ip:
                    continue
                try:
                    parsed = ipaddress.ip_address(ip)
                except ValueError:
                    continue
                if parsed.is_loopback:
                    continue
                local.add(ip)
        return local

    @staticmethod
    def _normalize_pair(
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        local_ips: Set[str],
    ) -> Tuple[str, int, str, int]:
        if src_ip in local_ips and dst_ip not in local_ips:
            return src_ip, src_port, dst_ip, dst_port
        if dst_ip in local_ips and src_ip not in local_ips:
            return dst_ip, dst_port, src_ip, src_port
        return src_ip, src_port, dst_ip, dst_port

    def _read_connections_and_packets_pcap(self) -> tuple[List[ConnectionEvent], List[PacketEvent]]:
        if not self.include_connections:
            return [], []

        try:
            from scapy.all import DNS, IP, IPv6, TCP, UDP, sniff  # type: ignore
        except Exception as exc:
            if not self._pcap_error_logged:
                print(f"[collector] pcap mode unavailable (install scapy/Npcap): {exc}")
                self._pcap_error_logged = True
            time.sleep(self.poll_interval_seconds)
            return [], []

        packets = sniff(
            iface=self.capture_interface or None,
            filter=self.capture_bpf or "ip or ip6",
            timeout=self.poll_interval_seconds,
            store=True,
            count=max(self.max_packets_per_poll, self.max_connections_per_poll),
        )

        local_ips = self._local_ips()
        seen: Set[Tuple[str, str, int, str, int, str]] = set()
        events: List[ConnectionEvent] = []
        packet_events: List[PacketEvent] = []

        now_mono = time.monotonic()
        self._cleanup_tcp_reassembly(now_mono)
        self._cleanup_dns_transactions(now_mono)

        for pkt in packets:
            family = "AF_INET"
            src_ip = ""
            dst_ip = ""
            if IP in pkt:
                src_ip = str(pkt[IP].src)
                dst_ip = str(pkt[IP].dst)
                family = "AF_INET"
            elif IPv6 in pkt:
                src_ip = str(pkt[IPv6].src)
                dst_ip = str(pkt[IPv6].dst)
                family = "AF_INET6"
            else:
                continue

            socket_type = "UNKNOWN"
            protocol = "IP"
            src_port = 0
            dst_port = 0
            tcp_flags = ""
            tcp_seq = None
            tcp_ack = None
            payload_bytes = b""
            app_protocol = ""
            dns_query = ""
            dns_answers = ""
            dns_rcode = ""
            dns_txn_rtt_ms = None
            tls_sni = ""
            tls_fingerprint = ""
            http_host = ""
            http_method = ""
            http_path = ""
            stream_payload = b""
            if TCP in pkt:
                socket_type = "SOCK_STREAM"
                protocol = "TCP"
                src_port = int(pkt[TCP].sport)
                dst_port = int(pkt[TCP].dport)
                tcp_flags = str(pkt[TCP].flags)
                tcp_seq = int(pkt[TCP].seq)
                tcp_ack = int(pkt[TCP].ack)
                payload_bytes = bytes(pkt[TCP].payload)
                stream_payload = self._update_tcp_reassembly(
                    src_ip=src_ip,
                    src_port=src_port,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    payload_bytes=payload_bytes,
                    now_mono=now_mono,
                )
            elif UDP in pkt:
                socket_type = "SOCK_DGRAM"
                protocol = "UDP"
                src_port = int(pkt[UDP].sport)
                dst_port = int(pkt[UDP].dport)
                payload_bytes = bytes(pkt[UDP].payload)
            else:
                continue

            if DNS in pkt or src_port == 53 or dst_port == 53:
                app_protocol = "DNS"
                dns_layer = pkt[DNS] if DNS in pkt else None
                dns_query, dns_answers = self._parse_dns_fields(payload_bytes, dns_layer)
                if dns_layer is not None:
                    try:
                        dns_id = int(getattr(dns_layer, "id", 0) or 0)
                        dns_qr = int(getattr(dns_layer, "qr", 0) or 0)
                        dns_rc = int(getattr(dns_layer, "rcode", 0) or 0)
                        dns_rcode = str(dns_rc)
                        if dns_qr == 0:
                            txn_key = (src_ip, src_port, dst_ip, dst_port, dns_id)
                            self._dns_txn_start[txn_key] = (now_mono, dns_query)
                        else:
                            txn_key = (dst_ip, dst_port, src_ip, src_port, dns_id)
                            start = self._dns_txn_start.pop(txn_key, None)
                            if start is not None:
                                dns_txn_rtt_ms = round((now_mono - start[0]) * 1000.0, 2)
                    except Exception:
                        pass
            elif protocol == "TCP":
                http_host, http_method, http_path = self._parse_http_fields(stream_payload or payload_bytes)
                if http_method or http_host:
                    app_protocol = "HTTP"
                else:
                    tls_sni = self._parse_tls_sni(stream_payload or payload_bytes)
                    if tls_sni:
                        app_protocol = "TLS"
                    tls_fingerprint = self._parse_tls_fingerprint(stream_payload or payload_bytes)

            self._pcap_frame_counter += 1
            frame_number = self._pcap_frame_counter

            local_ip, local_port, remote_ip, remote_port = self._normalize_pair(
                src_ip, src_port, dst_ip, dst_port, local_ips
            )
            direction = "unknown"
            if src_ip in local_ips and dst_ip not in local_ips:
                direction = "outbound"
            elif dst_ip in local_ips and src_ip not in local_ips:
                direction = "inbound"

            if len(packet_events) < self.max_packets_per_poll:
                packet_events.append(
                    PacketEvent.create(
                        interface=str(getattr(pkt, "sniffed_on", "") or self.capture_interface or "pcap"),
                        direction=direction,
                        protocol=protocol,
                        app_protocol=app_protocol,
                        frame_number=frame_number,
                        src_ip=src_ip,
                        src_port=src_port,
                        dst_ip=dst_ip,
                        dst_port=dst_port,
                        length=int(len(pkt)),
                        tcp_flags=tcp_flags,
                        tcp_seq=tcp_seq,
                        tcp_ack=tcp_ack,
                        payload_len=len(payload_bytes),
                        payload_preview_hex=payload_bytes[: self.packet_payload_preview_bytes].hex(" "),
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
                )

            key = (family, local_ip, local_port, remote_ip, remote_port, socket_type)
            if key in seen:
                continue
            if len(events) >= self.max_connections_per_poll:
                continue
            seen.add(key)

            events.append(
                ConnectionEvent.create(
                    family=family,
                    socket_type=socket_type,
                    local_ip=local_ip,
                    local_port=local_port,
                    remote_ip=remote_ip,
                    remote_port=remote_port,
                    status="OBSERVED",
                    pid=None,
                    process_name="pcap_sensor",
                )
            )

        self._write_rolling_pcap(packets)

        return events, packet_events

    def stream(self) -> Iterator[TelemetryBatch]:
        previous = self._read_counters()
        previous_time = time.monotonic()

        while True:
            if self.capture_mode == "host":
                time.sleep(self.poll_interval_seconds)
            current = self._read_counters()
            now = time.monotonic()
            elapsed = max(now - previous_time, 1e-6)

            network_events = []
            for nic, curr in current.items():
                prev = previous.get(nic)
                if prev is None:
                    continue

                sent_delta = max(curr.bytes_sent - prev.bytes_sent, 0)
                recv_delta = max(curr.bytes_recv - prev.bytes_recv, 0)

                network_events.append(
                    NetworkEvent.create(
                        interface=nic,
                        bytes_sent_per_sec=sent_delta / elapsed,
                        bytes_recv_per_sec=recv_delta / elapsed,
                    )
                )

            if self.capture_mode == "pcap":
                connection_events, packet_events = self._read_connections_and_packets_pcap()
            else:
                connection_events = self._read_connections()
                packet_events = []

            previous = current
            previous_time = now
            yield TelemetryBatch(
                network_events=network_events,
                connection_events=connection_events,
                packet_events=packet_events,
            )
