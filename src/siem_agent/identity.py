from __future__ import annotations

import hashlib
import os
import platform
import socket
import uuid
from pathlib import Path
from typing import Dict, List


def _machine_guid() -> str:
    node = hex(uuid.getnode())[2:]
    hostname = socket.gethostname()
    raw = f"{hostname}|{node}|{platform.platform()}"
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()


def get_local_ips() -> List[str]:
    ips: List[str] = []
    try:
        _, _, addrs = socket.gethostbyname_ex(socket.gethostname())
        ips.extend(addrs)
    except OSError:
        pass
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            ips.append(str(sock.getsockname()[0]))
    except OSError:
        pass
    seen = set()
    result: List[str] = []
    for ip in ips:
        ip = str(ip or "").strip()
        if not ip or ip.startswith("127."):
            continue
        if ip not in seen:
            seen.add(ip)
            result.append(ip)
    return result


def get_mac_addresses() -> List[str]:
    mac = uuid.getnode()
    if (mac >> 40) % 2:
        return []
    raw = f"{mac:012x}"
    return ["-".join(raw[i:i + 2] for i in range(0, 12, 2))]


def installation_id(state_dir: Path) -> str:
    path = state_dir / "installation_id.txt"
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        value = path.read_text(encoding="utf-8").strip()
        if value:
            return value
    value = _machine_guid()
    path.write_text(value, encoding="utf-8")
    return value


def host_identity(state_dir: Path) -> Dict[str, object]:
    return {
        "installation_id": installation_id(state_dir),
        "hostname": socket.gethostname(),
        "fqdn": socket.getfqdn(),
        "os": f"{platform.system()} {platform.release()}",
        "username": os.environ.get("USERNAME", "") or os.environ.get("USER", ""),
        "local_ips": get_local_ips(),
        "mac_addresses": get_mac_addresses(),
    }
