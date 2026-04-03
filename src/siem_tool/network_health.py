from __future__ import annotations

import re
import subprocess
import threading
import time
from collections import deque
from datetime import datetime, timezone
from statistics import mean
from typing import Callable, Deque, Dict, List

from .config import SIEMConfig

_TIME_RE = re.compile(r"time[=<]\s*(\d+(?:\.\d+)?)\s*ms", re.IGNORECASE)
_IPV4_RE = re.compile(r"(\d+\.\d+\.\d+\.\d+)")


class NetworkHealthMonitor:
    def __init__(
        self,
        config: SIEMConfig,
        device_targets_provider: Callable[[], List[str]] | None = None,
        device_details_provider: Callable[[], List[Dict[str, str]]] | None = None,
    ) -> None:
        self.enabled = bool(config.network_health_enabled)
        self.interval_seconds = max(2, int(config.network_health_probe_interval_seconds))
        self.timeout_ms = max(200, int(config.network_health_timeout_ms))
        self._targets = [t.strip() for t in config.network_health_targets if str(t).strip()]
        self._health_history: Deque[Dict[str, object]] = deque(maxlen=120)
        self._device_last: Dict[str, Dict[str, object]] = {}
        self._device_targets_provider = device_targets_provider
        self._device_details_provider = device_details_provider
        self._lock = threading.Lock()
        self._thread_started = False
        self._max_device_probes = 256
        self._last_error = ""

    def start(self) -> None:
        if not self.enabled or self._thread_started:
            return
        self._thread_started = True
        threading.Thread(target=self._loop, daemon=True).start()

    def status(self) -> Dict[str, object]:
        if not self.enabled:
            return {
                "enabled": False,
                "status": "disabled",
                "score": 0,
                "reason": "disabled in config",
                "router_probe": None,
                "targets": [],
                "device_probes": {
                    "total": 0,
                    "up": 0,
                    "down": 0,
                    "rows": [],
                },
                "metrics": {},
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }

        router_target = self._router_target()
        with self._lock:
            health_rows = list(self._health_history)
            device_rows = list(self._device_last.values())

        if not health_rows:
            return {
                "enabled": True,
                "status": "unknown",
                "score": 0,
                "reason": self._last_error or "collecting probes",
                "router_probe": {
                    "target": router_target,
                    "last_ok": None,
                    "last_rtt_ms": None,
                },
                "targets": [{"target": router_target, "last_ok": None, "last_rtt_ms": None}],
                "device_probes": {
                    "total": len(device_rows),
                    "up": sum(1 for d in device_rows if bool(d.get("ok"))),
                    "down": sum(1 for d in device_rows if not bool(d.get("ok"))),
                    "rows": self._device_rows(device_rows),
                },
                "metrics": {
                    "loss_pct": 0.0,
                    "avg_rtt_ms": 0.0,
                    "jitter_ms": 0.0,
                    "total_probes": 0,
                    "success_probes": 0,
                },
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }

        total = len(health_rows)
        success_rows = [r for r in health_rows if bool(r.get("ok"))]
        success = len(success_rows)
        loss_pct = ((total - success) / total) * 100.0 if total else 0.0
        rtts = [float(r.get("rtt_ms", 0.0)) for r in success_rows if r.get("rtt_ms") is not None]
        avg_rtt = mean(rtts) if rtts else 0.0
        jitter = self._calc_jitter(rtts)

        score = 100.0
        score -= min(loss_pct * 1.5, 70.0)
        score -= min(max(0.0, avg_rtt - 40.0) * 0.4, 20.0)
        score -= min(jitter * 0.6, 10.0)
        score = max(0.0, min(100.0, score))

        if loss_pct >= 20.0 or avg_rtt >= 300.0:
            health = "critical"
        elif loss_pct >= 5.0 or avg_rtt >= 120.0 or jitter >= 40.0:
            health = "degraded"
        else:
            health = "good"

        last_router = health_rows[-1] if health_rows else None
        up_count = sum(1 for d in device_rows if bool(d.get("ok")))
        down_count = sum(1 for d in device_rows if not bool(d.get("ok")))

        return {
            "enabled": True,
            "status": health,
            "score": round(score, 1),
            "reason": self._last_error or "ok",
            "router_probe": {
                "target": router_target,
                "last_ok": bool(last_router.get("ok")) if last_router else None,
                "last_rtt_ms": float(last_router.get("rtt_ms")) if last_router and last_router.get("rtt_ms") is not None else None,
            },
            "targets": [{
                "target": router_target,
                "last_ok": bool(last_router.get("ok")) if last_router else None,
                "last_rtt_ms": float(last_router.get("rtt_ms")) if last_router and last_router.get("rtt_ms") is not None else None,
            }],
            "device_probes": {
                "total": len(device_rows),
                "up": up_count,
                "down": down_count,
                "rows": self._device_rows(device_rows),
            },
            "metrics": {
                "loss_pct": round(loss_pct, 2),
                "avg_rtt_ms": round(avg_rtt, 2),
                "jitter_ms": round(jitter, 2),
                "total_probes": total,
                "success_probes": success,
            },
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }

    def _loop(self) -> None:
        while True:
            try:
                now_iso = datetime.now(timezone.utc).isoformat()
                router_target = self._router_target()
                ok, rtt = self._probe_target(router_target)
                router_row = {
                    "timestamp": now_iso,
                    "target": router_target,
                    "ok": ok,
                    "rtt_ms": rtt,
                }

                device_details = self._device_details_map()
                device_targets = self._device_targets(device_details)
                device_rows: Dict[str, Dict[str, object]] = {}
                for target in device_targets:
                    d_ok, d_rtt = self._probe_target(target)
                    detail = device_details.get(target, {})
                    device_rows[target] = {
                        "timestamp": now_iso,
                        "target": target,
                        "ip": target,
                        "mac": str(detail.get("mac", "") or ""),
                        "hostname": str(detail.get("hostname", "") or ""),
                        "alias": str(detail.get("alias", "") or ""),
                        "ok": d_ok,
                        "rtt_ms": d_rtt,
                    }

                with self._lock:
                    self._health_history.append(router_row)
                    self._device_last = device_rows
                self._last_error = ""
            except Exception as exc:
                self._last_error = str(exc)
            time.sleep(self.interval_seconds)

    def _router_target(self) -> str:
        targets = list(self._targets)
        if targets:
            return targets[0]
        gw = self._detect_default_gateway()
        if gw:
            return gw
        guessed = self._guess_router_from_discovered_devices()
        if guessed:
            return guessed
        return "127.0.0.1"

    def _guess_router_from_discovered_devices(self) -> str:
        if self._device_details_provider is None and self._device_targets_provider is None:
            return ""
        try:
            if self._device_details_provider is not None:
                ips = [
                    str(d.get("ip", "")).strip()
                    for d in self._device_details_provider()
                    if str(d.get("ip", "")).strip()
                ]
            else:
                ips = [str(ip).strip() for ip in self._device_targets_provider() if str(ip).strip()]
        except Exception:
            return ""

        valid_ips = [ip for ip in ips if _IPV4_RE.fullmatch(ip)]
        if not valid_ips:
            return ""

        # Common home/SOHO gateway endings when route table is unavailable.
        preferred_suffixes = (".1", ".254")
        for suffix in preferred_suffixes:
            for ip in valid_ips:
                if ip.endswith(suffix):
                    return ip
        return valid_ips[0]

    def _device_targets(self, details: Dict[str, Dict[str, str]] | None = None) -> List[str]:
        targets: List[str] = []
        if details is not None:
            targets = list(details.keys())
        elif self._device_targets_provider is not None:
            try:
                targets = [str(ip).strip() for ip in self._device_targets_provider() if str(ip).strip()]
            except Exception:
                targets = []

        router = self._router_target()
        filtered = [t for t in targets if t != router and _IPV4_RE.fullmatch(t)]
        unique = []
        seen = set()
        for t in filtered:
            if t not in seen:
                unique.append(t)
                seen.add(t)
        return unique[: self._max_device_probes]

    def _device_details_map(self) -> Dict[str, Dict[str, str]]:
        if self._device_details_provider is None:
            return {}
        try:
            details = self._device_details_provider()
        except Exception:
            return {}
        result: Dict[str, Dict[str, str]] = {}
        for row in details:
            ip = str(row.get("ip", "")).strip()
            if not ip or not _IPV4_RE.fullmatch(ip):
                continue
            result[ip] = {
                "ip": ip,
                "mac": str(row.get("mac", "") or ""),
                "hostname": str(row.get("hostname", "") or ""),
                "alias": str(row.get("alias", "") or ""),
            }
        return result

    def _device_rows(self, rows: List[Dict[str, object]]) -> List[Dict[str, object]]:
        sorted_rows = sorted(rows, key=lambda r: str(r.get("target", "")))
        return [
            {
                "target": str(r.get("target", "")),
                "ip": str(r.get("ip", r.get("target", "")) or ""),
                "mac": str(r.get("mac", "") or ""),
                "hostname": str(r.get("hostname", "") or ""),
                "alias": str(r.get("alias", "") or ""),
                "device_name": str(r.get("alias", "") or r.get("hostname", "") or r.get("target", "") or ""),
                "last_ok": bool(r.get("ok")),
                "last_rtt_ms": float(r.get("rtt_ms")) if r.get("rtt_ms") is not None else None,
            }
            for r in sorted_rows
        ]

    def ping_device(self, ip: str) -> Dict[str, object]:
        target = str(ip or "").strip()
        if not _IPV4_RE.fullmatch(target):
            raise ValueError("invalid IPv4 target")

        detail = self._device_details_map().get(target, {})
        now_iso = datetime.now(timezone.utc).isoformat()
        ok, rtt = self._probe_target(target)
        row = {
            "timestamp": now_iso,
            "target": target,
            "ip": target,
            "mac": str(detail.get("mac", "") or ""),
            "hostname": str(detail.get("hostname", "") or ""),
            "alias": str(detail.get("alias", "") or ""),
            "ok": ok,
            "rtt_ms": rtt,
        }
        with self._lock:
            self._device_last[target] = row
        return self._device_rows([row])[0]

    def _probe_target(self, target: str) -> tuple[bool, float | None]:
        cmd = ["ping", "-n", "1", "-w", str(self.timeout_ms), target]
        completed = subprocess.run(cmd, capture_output=True, text=True, timeout=max(2, self.timeout_ms / 1000 + 2))
        output = (completed.stdout or "") + "\n" + (completed.stderr or "")
        m = _TIME_RE.search(output)
        rtt = float(m.group(1)) if m else None
        return completed.returncode == 0, rtt

    def _detect_default_gateway(self) -> str:
        try:
            cmd = ["route", "print", "-4"]
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            for line in (out.stdout or "").splitlines():
                line = line.strip()
                if not line.startswith("0.0.0.0"):
                    continue
                parts = line.split()
                if len(parts) >= 3 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                    gw = parts[2]
                    if _IPV4_RE.fullmatch(gw):
                        return gw
        except Exception:
            pass
        return ""

    def _calc_jitter(self, rtts: List[float]) -> float:
        if len(rtts) < 2:
            return 0.0
        deltas = [abs(rtts[i] - rtts[i - 1]) for i in range(1, len(rtts))]
        return mean(deltas)
