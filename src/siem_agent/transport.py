from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Dict, Optional


class AgentTransport:
    def __init__(self, server_url: str, timeout_seconds: float = 10.0) -> None:
        self.server_url = server_url.rstrip("/")
        self.timeout_seconds = timeout_seconds

    def post_json(self, path: str, payload: Dict[str, object]) -> Dict[str, object]:
        data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        req = urllib.request.Request(
            self.server_url + path,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"HTTP {exc.code}: {detail or exc.reason}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"Transport error: {exc.reason}") from exc

    def register(self, payload: Dict[str, object]) -> Dict[str, object]:
        return self.post_json("/api/agents/register", payload)

    def heartbeat(self, payload: Dict[str, object]) -> Dict[str, object]:
        return self.post_json("/api/agents/heartbeat", payload)

    def upload_events(self, payload: Dict[str, object]) -> Dict[str, object]:
        return self.post_json("/api/agents/events/bulk", payload)
