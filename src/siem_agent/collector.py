from __future__ import annotations

import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

import psutil

from .identity import host_identity
from .windows_events import DEFAULT_WINDOWS_CHANNELS, available_windows_channels, read_recent_windows_events


class AgentCollector:
    def __init__(self, state_dir: Path) -> None:
        self.state_dir = state_dir
        self.last_record_path = state_dir / "windows_event_offsets.json"
        self.last_windows_record: Dict[str, int] = self._load_offsets()
        self.started_mono = time.monotonic()
        self.sent_identity = False
        self.windows_channels = available_windows_channels(DEFAULT_WINDOWS_CHANNELS)
        self._process_name_cache: Dict[int, str] = {}

    def collect(self) -> List[Dict[str, object]]:
        rows: List[Dict[str, object]] = []
        if not self.sent_identity:
            rows.append({
                "event_type": "host_identity",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                **host_identity(self.state_dir),
            })
            self.sent_identity = True

        rows.extend(self._collect_connections())
        rows.extend(self._collect_windows_events())
        return rows

    def uptime_seconds(self) -> float:
        return max(0.0, time.monotonic() - self.started_mono)

    def _collect_connections(self) -> List[Dict[str, object]]:
        rows: List[Dict[str, object]] = []
        timestamp = datetime.now(timezone.utc).isoformat()
        try:
            conns = psutil.net_connections(kind="inet")
        except Exception:
            return rows
        for conn in conns[:300]:
            laddr = conn.laddr if conn.laddr else ()
            raddr = conn.raddr if conn.raddr else ()
            rows.append({
                "event_type": "connection_snapshot",
                "timestamp": timestamp,
                "family": str(getattr(conn.family, "name", conn.family)),
                "socket_type": str(getattr(conn.type, "name", conn.type)),
                "local_ip": str(laddr.ip if hasattr(laddr, "ip") else (laddr[0] if len(laddr) > 0 else "")),
                "local_port": int(laddr.port if hasattr(laddr, "port") else (laddr[1] if len(laddr) > 1 else 0)),
                "remote_ip": str(raddr.ip if hasattr(raddr, "ip") else (raddr[0] if len(raddr) > 0 else "")),
                "remote_port": int(raddr.port if hasattr(raddr, "port") else (raddr[1] if len(raddr) > 1 else 0)),
                "status": str(conn.status or ""),
                "pid": int(conn.pid) if conn.pid else None,
                "process_name": self._process_name(int(conn.pid)) if conn.pid else "",
            })
        return rows

    def _collect_windows_events(self) -> List[Dict[str, object]]:
        rows = read_recent_windows_events(self.windows_channels, self.last_windows_record)
        if not rows:
            return []
        for row in rows:
            channel = str(row.get("channel", "") or "")
            record_id = int(row.get("record_id", 0) or 0)
            if channel:
                self.last_windows_record[channel] = max(record_id, int(self.last_windows_record.get(channel, 0) or 0))
        self._save_offsets()
        return rows

    def _load_offsets(self) -> Dict[str, int]:
        if not self.last_record_path.exists():
            return {}
        try:
            import json
            raw = json.loads(self.last_record_path.read_text(encoding="utf-8"))
        except Exception:
            return {}
        if not isinstance(raw, dict):
            return {}
        return {str(k): int(v) for k, v in raw.items()}

    def _save_offsets(self) -> None:
        import json
        self.last_record_path.write_text(json.dumps(self.last_windows_record, indent=2), encoding="utf-8")

    def _process_name(self, pid: int) -> str:
        if pid <= 0:
            return ""
        if pid in self._process_name_cache:
            return self._process_name_cache[pid]
        try:
            name = psutil.Process(pid).name()
        except Exception:
            name = ""
        self._process_name_cache[pid] = str(name or "")
        if len(self._process_name_cache) > 2048:
            self._process_name_cache = dict(list(self._process_name_cache.items())[-1024:])
        return self._process_name_cache[pid]
