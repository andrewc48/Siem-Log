from __future__ import annotations

import concurrent.futures
import ipaddress
import json
import os
import re
import socket
import subprocess
import time
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from .config import SIEMConfig
from .models import ConnectionEvent, DeviceRecord

_ARP_LINE = re.compile(
    r"^\s*(?P<ip>\d+\.\d+\.\d+\.\d+)\s+(?P<mac>[0-9a-fA-F:-]{11,17})\s+(?P<type>\w+)\s*$"
)
_PING_NAME_LINE = re.compile(r"^Pinging\s+(?P<name>[^\[]+)\s+\[[^\]]+\]", re.IGNORECASE)
_NBTSTAT_NAME_LINE = re.compile(r"^\s*(?P<name>[^\s<]+)\s+<00>\s+UNIQUE\s+Registered", re.IGNORECASE)
_ROUTER_NAME_HINT = re.compile(
    r"\b(router|gateway|firewall|pfsense|opnsense|mikrotik|unifi|ubiquiti|edgerouter|openwrt|dd-wrt|fortigate|sonicwall|meraki)\b",
    re.IGNORECASE,
)
_ROUTER_VENDOR_HINT = re.compile(
    r"\b(netgear|tp-link|tplink|linksys|d-link|dlink|asus|eero|arris|cisco|juniper|huawei|zyxel|belkin|fritz|amplifi|ubiquiti|unifi|mikrotik|meraki|fortinet|fortigate|sonicwall|openwrt|dd-wrt|opnsense|pfsense)\b",
    re.IGNORECASE,
)
_ROUTER_OVERRIDE_VALUES = {"router", "not_router"}
_ROUTER_MAC_PREFIXES = {
    "28-94-01": "Netgear",
    "9C-C9-EB": "Netgear",
    "E0-46-9A": "Netgear",
    "F8-1A-67": "TP-Link",
    "50-C7-BF": "TP-Link",
    "C0-56-27": "TP-Link",
    "18-A6-F7": "Ubiquiti",
    "24-5A-4C": "Ubiquiti",
    "68-72-51": "Ubiquiti",
    "00-1C-10": "Cisco",
    "00-25-45": "Cisco",
}


class DeviceMonitor:
    def __init__(self, config: SIEMConfig) -> None:
        self.resolve_device_hostnames = config.resolve_device_hostnames
        self.hostname_resolution_timeout_ms = int(config.hostname_resolution_timeout_ms)
        self.subnet_scan_timeout_ms = config.subnet_scan_timeout_ms
        self.subnet_scan_workers = config.subnet_scan_workers
        self.aliases_path = Path(config.device_aliases_file)
        self.role_overrides_path = Path(config.device_role_overrides_file)
        self.inventory_path = Path(config.devices_inventory_file)
        self.aliases_path.parent.mkdir(parents=True, exist_ok=True)
        self.role_overrides_path.parent.mkdir(parents=True, exist_ok=True)
        self.inventory_path.parent.mkdir(parents=True, exist_ok=True)
        self.aliases = self._load_json_map(self.aliases_path)
        self.role_overrides = self._load_role_overrides(self.role_overrides_path)
        self.devices = self._load_devices(self.inventory_path)
        self._hostname_cache: Dict[str, str] = {}
        self._gateway_ips_cache: List[str] = []
        self._gateway_cache_expiry = 0.0
        self._local_ipv4_cache: List[str] = []
        self._local_ipv4_cache_expiry = 0.0
        self._refresh_router_annotations()

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
    def _load_role_overrides(path: Path) -> Dict[str, str]:
        raw = DeviceMonitor._load_json_map(path)
        return {ip: value for ip, value in raw.items() if value in _ROUTER_OVERRIDE_VALUES}

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
                        is_router=bool(row.get("is_router", False)),
                        router_detection_source=str(row.get("router_detection_source", "")),
                        router_detection_reason=str(row.get("router_detection_reason", "")),
                        router_override=str(row.get("router_override", "")),
                        first_seen=str(row.get("first_seen", DeviceMonitor._utc_now())),
                        last_seen=str(row.get("last_seen", DeviceMonitor._utc_now())),
                    )
        return devices

    def _save_aliases(self) -> None:
        self.aliases_path.write_text(
            json.dumps(self.aliases, indent=2, sort_keys=True),
            encoding="utf-8",
        )

    def _save_role_overrides(self) -> None:
        self.role_overrides_path.write_text(
            json.dumps(self.role_overrides, indent=2, sort_keys=True),
            encoding="utf-8",
        )

    def _save_devices(self) -> None:
        rows = [asdict(device) for device in self.list_devices()]
        self.inventory_path.write_text(json.dumps(rows, indent=2), encoding="utf-8")

    @staticmethod
    def _normalize_router_override(value: str) -> str:
        cleaned = str(value or "").strip().lower()
        return cleaned if cleaned in _ROUTER_OVERRIDE_VALUES else ""

    @staticmethod
    def _normalize_mac_prefix(mac: str) -> str:
        text = str(mac or "").strip().upper().replace(":", "-")
        if len(text) < 8:
            return ""
        return "-".join(text.split("-")[:3])

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
                router_override=self.role_overrides.get(ip, ""),
                first_seen=now,
                last_seen=now,
            )
            self._apply_router_status(self.devices[ip], self._auto_router_candidates())
            return

        existing.last_seen = now
        if mac and not existing.mac:
            existing.mac = mac
        if hostname and not existing.hostname:
            existing.hostname = hostname
        if not existing.hostname:
            existing.hostname = self._get_hostname(ip)
        existing.alias = alias
        existing.router_override = self.role_overrides.get(ip, "")

    def _discover_gateway_ips(self) -> List[str]:
        now = time.monotonic()
        if now < self._gateway_cache_expiry:
            return list(self._gateway_ips_cache)

        gateways: List[str] = []
        try:
            result = subprocess.run(
                ["route", "print", "-4"],
                capture_output=True,
                text=True,
                check=False,
                timeout=5,
            )
        except OSError:
            result = None

        if result is not None:
            for line in result.stdout.splitlines():
                parts = line.strip().split()
                if len(parts) < 3:
                    continue
                if parts[0] != "0.0.0.0" or parts[1] != "0.0.0.0":
                    continue
                gateway = parts[2]
                if self._is_trackable_ip(gateway) and gateway not in gateways:
                    gateways.append(gateway)

        self._gateway_ips_cache = gateways
        self._gateway_cache_expiry = now + 30.0
        return list(gateways)

    def _local_ipv4_addresses(self) -> List[str]:
        now = time.monotonic()
        if now < self._local_ipv4_cache_expiry:
            return list(self._local_ipv4_cache)

        ips: List[str] = []
        try:
            import psutil

            for addrs in psutil.net_if_addrs().values():
                for addr in addrs:
                    if addr.family != socket.AF_INET:
                        continue
                    ip = str(getattr(addr, "address", "") or "").strip()
                    if self._is_trackable_ip(ip) and ip not in ips:
                        ips.append(ip)
        except Exception:
            ips = []

        self._local_ipv4_cache = ips
        self._local_ipv4_cache_expiry = now + 30.0
        return list(ips)

    @staticmethod
    def _looks_like_router_name(name: str) -> bool:
        return bool(_ROUTER_NAME_HINT.search(str(name or "")))

    @staticmethod
    def _looks_like_router_vendor(name: str) -> bool:
        return bool(_ROUTER_VENDOR_HINT.search(str(name or "")))

    def _router_vendor_from_mac(self, mac: str) -> str:
        return _ROUTER_MAC_PREFIXES.get(self._normalize_mac_prefix(mac), "")

    def _is_local_interface_ip(self, ip: str) -> bool:
        return ip in set(self._local_ipv4_addresses())

    def _subnet_gateway_score(self, device: DeviceRecord) -> int:
        try:
            parsed_ip = ipaddress.ip_address(device.ip)
        except ValueError:
            return -100
        if not isinstance(parsed_ip, ipaddress.IPv4Address):
            return -100
        if self._is_local_interface_ip(device.ip):
            return -100

        for subnet in self._local_subnets():
            if parsed_ip in subnet:
                break
        else:
            return -100

        score = 0
        suffix = int(str(parsed_ip).split(".")[-1])
        if suffix == 1:
            score += 22
        elif suffix == 254:
            score += 19
        elif suffix == 2:
            score += 10

        if device.mac:
            score += 4
        if device.hostname or device.alias:
            score += 3

        name_material = " ".join(part for part in (device.alias, device.hostname) if part)
        if name_material and self._looks_like_router_vendor(name_material):
            score += 10

        if self._router_vendor_from_mac(device.mac):
            score += 12

        return score

    @staticmethod
    def _build_candidate_reason(reasons: List[str]) -> str:
        text = [reason.strip() for reason in reasons if reason.strip()]
        if not text:
            return ""
        if len(text) == 1:
            return text[0]
        return "; ".join(text)

    @staticmethod
    def _candidate_source(sources: List[str]) -> str:
        unique: List[str] = []
        for source in sources:
            if source and source not in unique:
                unique.append(source)
        if not unique:
            return ""
        if len(unique) == 1:
            return unique[0]
        return "combined_heuristic"

    def _auto_router_candidates(self) -> Dict[str, Tuple[str, str]]:
        candidates: Dict[str, Tuple[str, str]] = {}
        gateway_ips = set(self._discover_gateway_ips())
        for ip, device in self.devices.items():
            if self._is_local_interface_ip(ip):
                continue

            reasons: List[str] = []
            sources: List[str] = []
            if ip in gateway_ips:
                sources.append("default_gateway")
                reasons.append("Observed as an IPv4 default gateway in the local route table.")

            name_material = " ".join(part for part in (device.alias, device.hostname) if part)
            if name_material and self._looks_like_router_name(name_material):
                sources.append("name_heuristic")
                reasons.append("Alias or hostname matches common router or gateway naming.")

            if name_material and self._looks_like_router_vendor(name_material):
                sources.append("vendor_name")
                reasons.append("Alias or hostname references a common router vendor.")

            mac_vendor = self._router_vendor_from_mac(device.mac)
            if mac_vendor:
                sources.append("mac_vendor")
                reasons.append(f"MAC prefix matches known router vendor {mac_vendor}.")

            subnet_score = self._subnet_gateway_score(device)
            if subnet_score >= 28:
                sources.append("subnet_rank")
                reasons.append(
                    f"Subnet gateway ranking scored {subnet_score} based on a common gateway address and supporting device signals."
                )

            source = self._candidate_source(sources)
            reason = self._build_candidate_reason(reasons)
            if source:
                candidates[ip] = (source, reason)

        return candidates

    def _apply_router_status(self, device: DeviceRecord, auto_candidates: Dict[str, Tuple[str, str]]) -> None:
        override = self._normalize_router_override(self.role_overrides.get(device.ip, device.router_override))
        device.router_override = override
        if override == "router":
            device.is_router = True
            device.router_detection_source = "manual_override"
            device.router_detection_reason = "Manually marked as a router."
            return
        if override == "not_router":
            device.is_router = False
            device.router_detection_source = "manual_override"
            device.router_detection_reason = "Manually marked as not a router."
            return

        source, reason = auto_candidates.get(device.ip, ("", ""))
        device.is_router = bool(source)
        device.router_detection_source = source
        device.router_detection_reason = reason

    def _refresh_router_annotations(self) -> None:
        auto_candidates = self._auto_router_candidates()
        for device in self.devices.values():
            self._apply_router_status(device, auto_candidates)

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
        self._refresh_router_annotations()
        self._save_devices()

    def set_alias(self, ip: str, alias: str) -> None:
        cleaned_ip = ip.strip()
        cleaned_alias = alias.strip()
        if not cleaned_ip:
            raise ValueError("IP cannot be empty")

        self.aliases[cleaned_ip] = cleaned_alias
        self._save_aliases()
        self._upsert_device(cleaned_ip)
        self._refresh_router_annotations()
        self._save_devices()

    def set_router_override(self, ip: str, router_override: str) -> None:
        cleaned_ip = ip.strip()
        if not cleaned_ip:
            raise ValueError("IP cannot be empty")

        normalized_override = self._normalize_router_override(router_override)
        if normalized_override:
            self.role_overrides[cleaned_ip] = normalized_override
        else:
            self.role_overrides.pop(cleaned_ip, None)
        self._save_role_overrides()
        self._upsert_device(cleaned_ip)
        self._refresh_router_annotations()
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
        self._refresh_router_annotations()
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
        self._refresh_router_annotations()
        self._save_devices()
        if not quiet:
            print(f"[scan] Done. {new_count} new device(s) discovered.")
        return new_count

    def get_primary_router_ip(self) -> str:
        devices = {device.ip: device for device in self.list_devices() if device.is_router}
        if not devices:
            for gateway in self._discover_gateway_ips():
                if self._is_trackable_ip(gateway):
                    return gateway
            return ""

        for gateway in self._discover_gateway_ips():
            row = devices.get(gateway)
            if row and row.router_override != "not_router":
                return gateway

        manual = sorted((row.ip for row in devices.values() if row.router_override == "router"))
        if manual:
            return manual[0]

        auto_gateway = sorted(
            row.ip for row in devices.values() if row.router_detection_source == "default_gateway"
        )
        if auto_gateway:
            return auto_gateway[0]

        return sorted(devices)[0]

    def list_devices(self) -> List[DeviceRecord]:
        for ip, alias in self.aliases.items():
            if ip in self.devices:
                self.devices[ip].alias = alias
        self._refresh_router_annotations()

        filtered = [
            row for row in self.devices.values() if self._is_trackable_ip(row.ip)
        ]
        return sorted(filtered, key=lambda row: row.ip)
