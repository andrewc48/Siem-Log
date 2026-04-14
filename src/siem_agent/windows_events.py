from __future__ import annotations

import json
import subprocess
from datetime import datetime, timedelta, timezone
from typing import Dict, List


def _powershell_json(command: str) -> List[Dict[str, object]]:
    completed = subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        return []
    raw = (completed.stdout or "").strip()
    if not raw:
        return []
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return []
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    if isinstance(payload, dict):
        return [payload]
    return []


def read_recent_windows_events(channels: List[str], last_record: Dict[str, int], max_events_per_channel: int = 60) -> List[Dict[str, object]]:
    rows: List[Dict[str, object]] = []
    now = datetime.now(timezone.utc)
    start = now - timedelta(minutes=10)
    start_iso = start.isoformat()
    for channel in channels:
        safe_channel = str(channel or "").strip()
        if not safe_channel:
            continue
        command = (
            f"$s=Get-Date '{start_iso}';"
            f"Get-WinEvent -FilterHashtable @{{LogName='{safe_channel}'; StartTime=$s}} -MaxEvents {int(max_events_per_channel)} "
            "| Select-Object TimeCreated, Id, ProviderName, LevelDisplayName, LogName, MachineName, RecordId, Message "
            "| Sort-Object RecordId "
            "| ConvertTo-Json -Depth 4"
        )
        for row in _powershell_json(command):
            record_id = int(row.get("RecordId", 0) or 0)
            if record_id <= int(last_record.get(safe_channel, 0) or 0):
                continue
            rows.append({
                "event_type": "windows_event",
                "channel": safe_channel,
                "timestamp": str(row.get("TimeCreated", "") or ""),
                "event_id": int(row.get("Id", 0) or 0),
                "provider": str(row.get("ProviderName", "") or ""),
                "level": str(row.get("LevelDisplayName", "") or ""),
                "machine": str(row.get("MachineName", "") or ""),
                "record_id": record_id,
                "message": str(row.get("Message", "") or "")[:4000],
            })
    return rows
