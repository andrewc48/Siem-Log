from __future__ import annotations

import concurrent.futures
import ipaddress
import json
import os
import re
import socket
import subprocess
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from .config import SIEMConfig
from .models import ConnectionEvent, DeviceRecord

_ARP_LINE = re.compile(
    r"^\s*(?P<ip>\d+\.\d+\.\d+\.\d+)\s+(?P<mac>[0-9a-fA-F:-]{11,17})\s+(?P<type>\w+)\s*$"
)
_PING_NAME_LINE = re.compile(r"^Pinging\s+(?P<name>[^\[]+)\s+\[[^\]]+\]", re.IGNORECASE)
_NBTSTAT_NAME_LINE = re.compile(r"^\s*(?P<name>[^\s<]+)\s+<00>\s+UNIQUE\s+Registered", re.IGNORECASE)


class DeviceMonitor:
    def __init__(self, config: SIEMConfig) -> None:
        self.resolve_device_hostnames = config.resolve_device_hostnames
        self.hostname_resolution_timeout_ms = int(config.hostname_resolution_timeout_ms)
        self.subnet_scan_timeout_ms = config.subnet_scan_timeout_ms
        self.subnet_scan_workers = config.subnet_scan_workers
        self.aliases_path = Path(config.device_aliases_file)
        self.inventory_path = Path(config.devices_inventory_file)
        self.aliases_path.parent.mkdir(parents=True, exist_ok=True)
        self.inventory_path.parent.mkdir(parents=True, exist_ok=True)
        self.aliases = self._load_json_map(self.aliases_path)
        self.devices = self._load_devices(self.inventory_path)
        self._hostname_cache: Dict[str, str] = {}

    @staticmethod
    def _utc_now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _load_json_map(path: Path) -> Dict[str, str]:
        if not path.exists():
            return {}
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}
        if not isinstance(raw, dict):
            return {}
        return {str(k): str(v) for k, v in raw.items()}

    @staticmethod
    def _load_devices(path: Path) -> Dict[str, DeviceRecord]:
        if not path.exists():
            return {}
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}

        devices: Dict[str, DeviceRecord] = {}
        if isinstance(raw, list):
            for row in raw:
                if isinstance(row, dict) and row.get("ip"):
                    ip = str(row["ip"])
                    devices[ip] = DeviceRecord(
                        ip=ip,
                        mac=str(row.get("mac", "")),
                        hostname=str(row.get("hostname", "")),
                        alias=str(row.get("alias", "")),
                        first_seen=str(row.get("first_seen", DeviceMonitor._utc_now())),
                        last_seen=str(row.get("last_seen", DeviceMonitor._utc_now())),
                    )
        return devices

    def _save_aliases(self) -> None:
        self.aliases_path.write_text(
            json.dumps(self.aliases, indent=2, sort_keys=True),
            encoding="utf-8",
        )

    def _save_devices(self) -> None:
        rows = [asdict(device) for device in self.list_devices()]
        self.inventory_path.write_text(json.dumps(rows, indent=2), encoding="utf-8")

    @staticmethod
    def _resolve_hostname(ip: str) -> str:
        try:
            host, _, _ = socket.gethostbyaddr(ip)
            return host
        except (socket.herror, socket.gaierror, OSError):
            return ""

    @staticmethod
    def _normalize_hostname(raw: str) -> str:
        name = (raw or "").strip().strip(".")
        if not name:
            return ""
        if name.lower() == "unknown":
            return ""
        return name

    @staticmethod
    def _resolve_hostname_from_ping_a(ip: str, timeout_ms: int) -> str:
        if os.name != "nt":
            return ""
        try:
            result = subprocess.run(
                ["ping", "-a", "-n", "1", "-w", str(max(200, int(timeout_ms))), ip],
                capture_output=True,
                text=True,
                check=False,
            )
        except OSError:
            return ""
        for line in result.stdout.splitlines():
            match = _PING_NAME_LINE.match(line.strip())
            if not match:
                continue
            return DeviceMonitor._normalize_hostname(match.group("name"))
        return ""

    @staticmethod
    def _resolve_hostname_from_nbtstat(ip: str) -> str:
        if os.name != "nt":
            return ""
        try:
            result = subprocess.run(
                ["nbtstat", "-A", ip],
                capture_output=True,
                text=True,
                check=False,
            )
        except OSError:
            return ""
        for line in result.stdout.splitlines():
            match = _NBTSTAT_NAME_LINE.match(line)
            if not match:
                continue
            return DeviceMonitor._normalize_hostname(match.group("name"))
        return ""

    def _resolve_best_hostname(self, ip: str) -> str:
        # Prefer reverse DNS, then fall back to common Windows network name probes.
        name = self._normalize_hostname(self._resolve_hostname(ip))
        if name:
            return name
        name = self._resolve_hostname_from_ping_a(ip=ip, timeout_ms=self.hostname_resolution_timeout_ms)
        if name:
            return name
        return self._resolve_hostname_from_nbtstat(ip)

    def _get_hostname(self, ip: str) -> str:
        if not self.resolve_device_hostnames:
            return ""
        if ip in self._hostname_cache:
            return self._hostname_cache[ip]
        resolved = self._resolve_best_hostname(ip)
        self._hostname_cache[ip] = resolved
        return resolved

    @staticmethod
    def _is_trackable_ip(ip: str) -> bool:
        if not ip:
            return False
        try:
            parsed = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if parsed.is_loopback or parsed.is_unspecified or parsed.is_multicast:
            return False

        if isinstance(parsed, ipaddress.IPv4Address):
            if parsed == ipaddress.IPv4Address("255.255.255.255"):
                return False
            last_octet = int(str(parsed).split(".")[-1])
            if last_octet in (0, 255):
                return False

        return parsed.is_private or parsed.is_link_local

    def _upsert_device(self, ip: str, mac: str = "", hostname: str = "") -> None:
        if not self._is_trackable_ip(ip):
            return

        now = self._utc_now()
        existing = self.devices.get(ip)
        alias = self.aliases.get(ip, "")

        if existing is None:
            self.devices[ip] = DeviceRecord(
                ip=ip,
                mac=mac,
                hostname=hostname or self._get_hostname(ip),
                alias=alias,
                first_seen=now,
                last_seen=now,
            )
            return

        existing.last_seen = now
        if mac and not existing.mac:
            existing.mac = mac
        if hostname and not existing.hostname:
            existing.hostname = hostname
        if not existing.hostname:
            existing.hostname = self._get_hostname(ip)
        existing.alias = alias

    def refresh_from_connections(self, events: Iterable[ConnectionEvent]) -> None:
        seen_ips = set()
        for event in events:
            if event.remote_ip:
                seen_ips.add(event.remote_ip)
            if event.local_ip:
                seen_ips.add(event.local_ip)

        for ip in seen_ips:
            self._upsert_device(ip)

    def refresh_from_arp_cache(self) -> None:
        try:
            result = subprocess.run(
                ["arp", "-a"],
                capture_output=True,
                text=True,
                check=False,
            )
        except OSError:
            return

        for line in result.stdout.splitlines():
            match = _ARP_LINE.match(line)
            if not match:
                continue
            ip = match.group("ip")
            mac = match.group("mac")
            self._upsert_device(ip=ip, mac=mac)

    def refresh(self, events: Iterable[ConnectionEvent]) -> None:
        self.refresh_from_connections(events)
        self.refresh_from_arp_cache()
        self._save_devices()

    def set_alias(self, ip: str, alias: str) -> None:
        cleaned_ip = ip.strip()
        cleaned_alias = alias.strip()
        if not cleaned_ip:
            raise ValueError("IP cannot be empty")

        self.aliases[cleaned_ip] = cleaned_alias
        self._save_aliases()
        self._upsert_device(cleaned_ip)
        self._save_devices()

    def clear_alias(self, ip: str) -> bool:
        """Remove a named alias for the given IP. Returns True if an alias was removed."""
        cleaned_ip = ip.strip()
        if cleaned_ip not in self.aliases:
            return False
        del self.aliases[cleaned_ip]
        self._save_aliases()
        if cleaned_ip in self.devices:
            self.devices[cleaned_ip].alias = ""
        self._save_devices()
        return True

    @staticmethod
    def _ping_host(ip: str, timeout_ms: int) -> Optional[str]:
        """Return ip if host responds to ICMP ping, else None."""
        try:
            result = subprocess.run(
                ["ping", "-n", "1", "-w", str(timeout_ms), ip],
                capture_output=True,
                check=False,
            )
            if result.returncode == 0:
                return ip
        except OSError:
            pass
        return None

    @staticmethod
    def _local_subnets() -> List[ipaddress.IPv4Network]:
        """Return a deduplicated list of /24-or-smaller IPv4 subnets from local interfaces."""
        try:
            import psutil  # optional — already installed as top-level dep
            iface_addrs = psutil.net_if_addrs()
        except Exception:
            return []

        seen: set = set()
        subnets: List[ipaddress.IPv4Network] = []
        for addrs in iface_addrs.values():
            for addr in addrs:
                if addr.family != socket.AF_INET:
                    continue
                try:
                    net = ipaddress.IPv4Network(
                        f"{addr.address}/{addr.netmask}", strict=False
                    )
                except (ValueError, AttributeError):
                    continue
                if net.is_loopback or net.is_link_local:
                    continue
                if net.prefixlen < 16:  # skip anything larger than a /16 to avoid huge scans
                    continue
                key = str(net)
                if key not in seen:
                    seen.add(key)
                    subnets.append(net)
        return subnets

    def scan_subnet(self, quiet: bool = False) -> int:
        """Ping-sweep all local subnets and add responsive hosts to device inventory.
        Returns the count of new hosts discovered.
        """
        subnets = self._local_subnets()
        if not subnets:
            if not quiet:
                print("[scan] No scannable local subnets found.")
            return 0

        if not quiet:
            for net in subnets:
                print(f"[scan] Scanning {net} ({net.num_addresses - 2} hosts) ...")

        all_ips = [
            str(host)
            for net in subnets
            for host in net.hosts()
        ]

        new_count = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.subnet_scan_workers) as pool:
            futures = {pool.submit(self._ping_host, ip, self.subnet_scan_timeout_ms): ip for ip in all_ips}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    pre_size = len(self.devices)
                    self._upsert_device(result)
                    if len(self.devices) > pre_size:
                        new_count += 1

        self.refresh_from_arp_cache()
        self._save_devices()
        if not quiet:
            print(f"[scan] Done. {new_count} new device(s) discovered.")
        return new_count

    def list_devices(self) -> List[DeviceRecord]:
        for ip, alias in self.aliases.items():
            if ip in self.devices:
                self.devices[ip].alias = alias

        filtered = [
            row for row in self.devices.values() if self._is_trackable_ip(row.ip)
        ]
        return sorted(filtered, key=lambda row: row.ip)
