from __future__ import annotations

import json
import socket
from typing import Dict
from uuid import uuid4


def discover_server(port: int, timeout_seconds: float = 2.0) -> Dict[str, str]:
    payload = {
        "type": "siem_discovery_request",
        "agent_version": "0.1.0",
        "nonce": str(uuid4()),
    }
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(timeout_seconds)
        sock.sendto(raw, ("255.255.255.255", int(port)))
        while True:
            data, _addr = sock.recvfrom(8192)
            response = json.loads(data.decode("utf-8", errors="replace"))
            if str(response.get("type", "") or "") != "siem_discovery_response":
                continue
            if str(response.get("nonce", "") or "") != payload["nonce"]:
                continue
            return {
                "server_url": str(response.get("server_url", "") or "").strip(),
                "server_name": str(response.get("server_name", "") or "").strip(),
                "server_id": str(response.get("server_id", "") or "").strip(),
            }
