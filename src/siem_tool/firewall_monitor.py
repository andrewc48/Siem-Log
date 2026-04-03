from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

from .models import FirewallBlockEvent


class FirewallLogMonitor:
    """Tail the Windows firewall text log and emit DROP events."""

    def __init__(self, log_path: str, enabled: bool = True) -> None:
        self._enabled_requested = bool(enabled)
        self.enabled = enabled and os.name == "nt"
        self.log_path = Path(log_path)
        self._position = 0
        self._fields: List[str] = []
        self._initialized = False
        self._last_error = ""

    def status(self) -> Dict[str, object]:
        exists = self.log_path.exists() if self.enabled else False
        readable = os.access(self.log_path, os.R_OK) if exists else False
        if not self._enabled_requested:
            reason = "disabled in config"
        elif os.name != "nt":
            reason = "windows-only"
        elif not exists:
            reason = "log file not found"
        elif not readable:
            reason = "log file not readable"
        elif self._last_error:
            reason = self._last_error
        else:
            reason = "ok"
        return {
            "enabled": self.enabled,
            "requested": self._enabled_requested,
            "path": str(self.log_path),
            "exists": exists,
            "readable": readable,
            "reason": reason,
        }

    def poll(self) -> List[FirewallBlockEvent]:
        if not self.enabled or not self.log_path.exists():
            return []
        try:
            size = self.log_path.stat().st_size
            if not self._initialized:
                # Start from EOF on first read to avoid flooding historical rows.
                self._position = size
                self._initialized = True
                return []
            if size < self._position:
                self._position = 0

            events: List[FirewallBlockEvent] = []
            with self.log_path.open("r", encoding="utf-8", errors="replace") as handle:
                handle.seek(self._position)
                for raw_line in handle:
                    line = raw_line.strip()
                    if not line:
                        continue
                    if line.startswith("#Fields:"):
                        self._fields = line[len("#Fields:"):].strip().split()
                        continue
                    if line.startswith("#"):
                        continue
                    ev = self._parse_line(line)
                    if ev is not None:
                        events.append(ev)
                self._position = handle.tell()
            self._last_error = ""
            return events
        except Exception as exc:
            self._last_error = str(exc)
            return []

    def _parse_line(self, line: str) -> FirewallBlockEvent | None:
        if self._fields:
            parts = line.split()
            if len(parts) < len(self._fields):
                return None
            row = {self._fields[i]: parts[i] for i in range(len(self._fields))}
        else:
            parts = line.split()
            if len(parts) < 8:
                return None
            row = {
                "date": parts[0],
                "time": parts[1],
                "action": parts[2],
                "protocol": parts[3],
                "src-ip": parts[4],
                "dst-ip": parts[5],
                "src-port": parts[6],
                "dst-port": parts[7],
                "path": parts[-1] if parts else "",
            }

        action = str(row.get("action", "")).upper()
        if action != "DROP":
            return None

        ts = self._normalize_timestamp(str(row.get("date", "")), str(row.get("time", "")))
        protocol = str(row.get("protocol", ""))
        src_ip = str(row.get("src-ip", ""))
        dst_ip = str(row.get("dst-ip", ""))
        src_port = self._safe_int(row.get("src-port"))
        dst_port = self._safe_int(row.get("dst-port"))
        direction = str(row.get("path", "")).lower() or "unknown"
        interface = str(row.get("interface", ""))

        return FirewallBlockEvent.create(
            timestamp=ts,
            action=action,
            protocol=protocol,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            direction=direction,
            interface=interface,
            raw=row,
        )

    def _normalize_timestamp(self, date_str: str, time_str: str) -> str:
        raw = f"{date_str} {time_str}".strip()
        try:
            dt = datetime.strptime(raw, "%Y-%m-%d %H:%M:%S")
            return dt.replace(tzinfo=timezone.utc).isoformat()
        except ValueError:
            return datetime.now(timezone.utc).isoformat()

    def _safe_int(self, value: object) -> int:
        try:
            return int(str(value))
        except (TypeError, ValueError):
            return 0
