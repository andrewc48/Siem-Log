from __future__ import annotations

import json
import re
import subprocess
import time
from typing import Dict, List

from .config import SIEMConfig
from .models import BluetoothEvent

_ADDR12_RE = re.compile(r"([0-9A-Fa-f]{12})")

_NOISY_NAME_SUBSTRINGS = (
    "generic attribute profile",
    "generic access profile",
    "bluetooth le generic attribute service",
    "microsoft bluetooth enumerator",
    "microsoft bluetooth le enumerator",
    "service discovery service",
    "wireless bluetooth",
    "avrcp transport",
    "rfcomm",
)


class BluetoothMonitor:
    """Best-effort Bluetooth monitor for local host adapter/device state.

    On Windows, this polls `Get-PnpDevice -Class Bluetooth` and emits events
    when a device appears/disappears or its connection state changes.
    """

    def __init__(self, config: SIEMConfig) -> None:
        self.enabled = bool(config.include_bluetooth)
        self.poll_interval_seconds = max(int(config.bluetooth_poll_interval_seconds), 5)
        self._last_poll = 0.0
        self._initialized = False
        self._last_snapshot: Dict[str, Dict[str, object]] = {}
        self._error_logged = False

    @staticmethod
    def _normalize_address(instance_id: str) -> str:
        match = _ADDR12_RE.search(instance_id or "")
        if not match:
            return ""
        raw = match.group(1).upper()
        return ":".join(raw[i : i + 2] for i in range(0, 12, 2))

    @staticmethod
    def _is_noise_row(name: str, instance_id: str) -> bool:
        lowered = name.lower()
        if any(token in lowered for token in _NOISY_NAME_SUBSTRINGS):
            return True
        upper_id = instance_id.upper()
        # The BRB enumerator and low-level service endpoints add spam.
        if "MS_BTHBRB" in upper_id:
            return True
        return False

    @staticmethod
    def _logical_key(name: str, address: str, instance_id: str) -> str:
        if address:
            return f"addr:{address}"
        # Fallback when no parseable MAC is present.
        return f"name:{name.lower()}::{instance_id.split('\\')[0].lower()}"

    @staticmethod
    def _candidate_score(row: Dict[str, object]) -> int:
        score = 0
        if bool(row.get("connected", False)):
            score += 5
        if str(row.get("kind", "")) == "bluetooth":
            score += 3
        if str(row.get("address", "")):
            score += 2
        return score

    def _snapshot_windows(self) -> Dict[str, Dict[str, object]]:
        ps_cmd = (
            "Get-PnpDevice -Class Bluetooth "
            "| Select-Object FriendlyName,InstanceId,Status,Class "
            "| ConvertTo-Json -Depth 3"
        )
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            return {}

        try:
            raw = json.loads(result.stdout.strip() or "[]")
        except json.JSONDecodeError:
            return {}

        rows = raw if isinstance(raw, list) else [raw]
        grouped: Dict[str, Dict[str, object]] = {}
        for row in rows:
            if not isinstance(row, dict):
                continue
            instance_id = str(row.get("InstanceId", "")).strip()
            if not instance_id:
                continue
            name = str(row.get("FriendlyName", "")).strip() or "Bluetooth device"
            if self._is_noise_row(name, instance_id):
                continue
            status = str(row.get("Status", "")).strip() or "Unknown"
            connected = status.upper() == "OK"
            kind = "ble" if "BTHLE" in instance_id.upper() else "bluetooth"
            address = self._normalize_address(instance_id)
            logical = self._logical_key(name, address, instance_id)
            candidate = {
                "name": name,
                "address": address,
                "connected": connected,
                "status": status,
                "kind": kind,
                "instance_id": instance_id,
            }
            existing = grouped.get(logical)
            if existing is None or self._candidate_score(candidate) >= self._candidate_score(existing):
                grouped[logical] = candidate

        snapshot: Dict[str, Dict[str, object]] = {}
        for logical_key, chosen in grouped.items():
            chosen_copy = dict(chosen)
            chosen_copy["logical_key"] = logical_key
            snapshot[logical_key] = chosen_copy
        return snapshot

    def _snapshot(self) -> Dict[str, Dict[str, object]]:
        return self._snapshot_windows()

    def poll(self) -> List[BluetoothEvent]:
        if not self.enabled:
            return []

        now = time.monotonic()
        if (now - self._last_poll) < self.poll_interval_seconds:
            return []
        self._last_poll = now

        try:
            snapshot = self._snapshot()
        except Exception as exc:
            if not self._error_logged:
                print(f"[bluetooth] monitor unavailable: {exc}")
                self._error_logged = True
            return []

        events: List[BluetoothEvent] = []

        # New/changed devices
        for key, current in snapshot.items():
            prev = self._last_snapshot.get(key)
            if (not self._initialized) or prev is None or prev.get("connected") != current.get("connected"):
                events.append(
                    BluetoothEvent.create(
                        name=str(current.get("name", "Bluetooth device")),
                        address=str(current.get("address", "")),
                        connected=bool(current.get("connected", False)),
                        paired=True,
                        kind=str(current.get("kind", "bluetooth")),
                        source="windows_pnp",
                        details={
                            "status": str(current.get("status", "Unknown")),
                            "instance_id": str(current.get("instance_id", "")),
                            "logical_key": key,
                        },
                    )
                )

        # Devices that disappeared from enumeration are treated as disconnected.
        for key, prev in self._last_snapshot.items():
            if key in snapshot:
                continue
            events.append(
                BluetoothEvent.create(
                    name=str(prev.get("name", "Bluetooth device")),
                    address=str(prev.get("address", "")),
                    connected=False,
                    paired=True,
                    kind=str(prev.get("kind", "bluetooth")),
                    source="windows_pnp",
                    details={
                        "status": "Missing from PnP snapshot",
                        "instance_id": str(prev.get("instance_id", "")),
                        "logical_key": key,
                    },
                )
            )

        self._last_snapshot = snapshot
        self._initialized = True
        return events
