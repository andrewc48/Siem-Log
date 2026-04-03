from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
import threading
from collections import deque
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Deque, Dict, List

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .config import SIEMConfig
from .engine import SIEMEngine
from .log_manager import LogManager
from .network_health import NetworkHealthMonitor

# Load .env on import so API key is available immediately
try:
    from dotenv import load_dotenv as _load_dotenv
    _load_dotenv(Path(".env"))
except ImportError:
    pass  # python-dotenv not installed yet; will still work if vars are set in env

# ── shared live state ─────────────────────────────────────────────────────────
_MAX_RECENT = 200

_recent_alerts: Deque[Dict[str, Any]] = deque(maxlen=_MAX_RECENT)
_recent_events: Deque[Dict[str, Any]] = deque(maxlen=_MAX_RECENT)
_recent_connections: Deque[Dict[str, Any]] = deque(maxlen=_MAX_RECENT)
_recent_bluetooth: Deque[Dict[str, Any]] = deque(maxlen=_MAX_RECENT)
_recent_packets: Deque[Dict[str, Any]] = deque(maxlen=2000)
_recent_firewall_blocks: Deque[Dict[str, Any]] = deque(maxlen=1000)
_sse_subscribers: List[asyncio.Queue] = []
_engine: SIEMEngine | None = None
_log_manager: LogManager | None = None
_health_monitor: NetworkHealthMonitor | None = None
_scan_lock = threading.Lock()
_started_at = datetime.now(timezone.utc)

# ── Settings persistence ──────────────────────────────────────────────────────
_SETTINGS_PATH = Path("logs/siem_settings.json")
_INCIDENT_TRIAGE_PATH = Path("logs/incidents_triage.json")
_DETECTOR_CONTROLS_PATH = Path("logs/detector_controls.json")
_SAVED_VIEWS_PATH = Path("logs/saved_views.json")
_ASSET_CRITICALITY_PATH = Path("logs/asset_criticality.json")
_INCIDENT_ACTIVITY_PATH = Path("logs/incident_activity.jsonl")


def _load_json_file(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def _save_json_file(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _append_jsonl(path: Path, row: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, separators=(",", ":")) + "\n")


def _load_persisted_settings() -> Dict[str, Any]:
    if not _SETTINGS_PATH.exists():
        return {}
    try:
        return json.loads(_SETTINGS_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_persisted_settings(data: Dict[str, Any]) -> None:
    _SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
    _SETTINGS_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _load_incident_triage() -> Dict[str, Dict[str, Any]]:
    if not _INCIDENT_TRIAGE_PATH.exists():
        return {}
    try:
        raw = json.loads(_INCIDENT_TRIAGE_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}
    if not isinstance(raw, dict):
        return {}
    result: Dict[str, Dict[str, Any]] = {}
    for key, value in raw.items():
        if not isinstance(key, str) or not isinstance(value, dict):
            continue
        result[key] = {
            "status": str(value.get("status", "open") or "open").lower(),
            "owner": str(value.get("owner", "") or ""),
            "notes": str(value.get("notes", "") or ""),
            "sla_hours": float(value.get("sla_hours", 24.0) or 24.0),
            "due_at": str(value.get("due_at", "") or ""),
            "reopen_reason": str(value.get("reopen_reason", "") or ""),
            "updated_at": str(value.get("updated_at", "") or ""),
        }
    return result


def _save_incident_triage(data: Dict[str, Dict[str, Any]]) -> None:
    _INCIDENT_TRIAGE_PATH.parent.mkdir(parents=True, exist_ok=True)
    _INCIDENT_TRIAGE_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _merge_incident_triage(incidents: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    triage = _load_incident_triage()
    merged: List[Dict[str, Any]] = []
    for inc in incidents:
        key = str(inc.get("incident_key", "") or "")
        row = dict(inc)
        t = triage.get(key, {})
        row["status"] = str(t.get("status", row.get("status", "open")) or "open").lower()
        row["owner"] = str(t.get("owner", "") or "")
        row["notes"] = str(t.get("notes", "") or "")
        row["sla_hours"] = float(t.get("sla_hours", 24.0) or 24.0)
        row["due_at"] = str(t.get("due_at", "") or "")
        row["reopen_reason"] = str(t.get("reopen_reason", "") or "")
        row["triage_updated_at"] = str(t.get("updated_at", "") or "")
        merged.append(row)
    return merged


def _write_env_key(key_name: str, value: str) -> None:
    """Insert or update a single KEY=value entry in .env."""
    env_path = Path(".env")
    if env_path.exists():
        lines = env_path.read_text(encoding="utf-8").splitlines()
        updated, found = [], False
        for line in lines:
            if line.strip().startswith(f"{key_name}="):
                updated.append(f"{key_name}={value}")
                found = True
            else:
                updated.append(line)
        if not found:
            updated.append(f"{key_name}={value}")
        env_path.write_text("\n".join(updated) + "\n", encoding="utf-8")
    else:
        env_path.write_text(f"{key_name}={value}\n", encoding="utf-8")


# ── FastAPI app ───────────────────────────────────────────────────────────────
app = FastAPI(title="SIEM Dashboard API", docs_url="/api/docs")

_static_dir = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=str(_static_dir)), name="static")


# ── background engine thread ──────────────────────────────────────────────────
def _run_engine(engine: SIEMEngine) -> None:
    """Run the SIEM engine forever; feed results into shared deques + SSE."""
    import itertools

    stream = engine.collector.stream()
    for batch in stream:
        engine.store.write_events(batch.network_events)
        if batch.connection_events:
            engine.store.write_connections(batch.connection_events)
        engine.device_monitor.refresh(batch.connection_events)

        for ev in batch.network_events:
            _recent_events.append(asdict(ev))

        for conn in batch.connection_events:
            _recent_connections.append(asdict(conn))

        if batch.packet_events:
            engine.store.write_packets(batch.packet_events)
            for pkt in batch.packet_events:
                _recent_packets.append(asdict(pkt))

        bt_events = engine.bluetooth_monitor.poll()
        if bt_events:
            engine.store.write_bluetooth_events(bt_events)
            for bt in bt_events:
                _recent_bluetooth.append(asdict(bt))

        firewall_events = engine.firewall_monitor.poll()
        if firewall_events:
            engine.store.write_firewall_blocks(firewall_events)
            for fw in firewall_events:
                _recent_firewall_blocks.append(asdict(fw))

        alerts = engine.detector.evaluate(batch.network_events)
        if batch.connection_events:
            alerts.extend(engine.detector.evaluate_connections(batch.connection_events))
        if batch.packet_events:
            alerts.extend(engine.detector.evaluate_packet_events(batch.packet_events))
        if firewall_events:
            alerts.extend(engine.detector.evaluate_firewall_blocks(firewall_events))

        if alerts:
            engine.store.write_alerts(alerts)
            for alert in alerts:
                d = asdict(alert)
                _recent_alerts.append(d)
                _broadcast_sse(d)


def _broadcast_sse(alert: Dict[str, Any]) -> None:
    for q in list(_sse_subscribers):
        try:
            q.put_nowait(alert)
        except asyncio.QueueFull:
            pass


def start_background_engine(config: SIEMConfig) -> None:
    global _engine, _log_manager, _health_monitor
    # Apply any previously saved retention overrides
    saved = _load_persisted_settings()
    if "events_retention_hours" in saved:
        config.events_retention_hours = float(saved["events_retention_hours"])
    if "alerts_retention_hours" in saved:
        config.alerts_retention_hours = float(saved["alerts_retention_hours"])
    _engine = SIEMEngine(config)
    persisted_controls = _load_json_file(_DETECTOR_CONTROLS_PATH, {})
    if isinstance(persisted_controls, dict):
        _engine.detector.set_controls(persisted_controls)
    _log_manager = LogManager(config)
    _health_monitor = NetworkHealthMonitor(
        config,
        device_targets_provider=lambda: [d.ip for d in _engine.list_devices()] if _engine is not None else [],
        device_details_provider=(
            lambda: [
                {
                    "ip": d.ip,
                    "mac": d.mac,
                    "hostname": d.hostname,
                    "alias": d.alias,
                }
                for d in _engine.list_devices()
            ] if _engine is not None else []
        ),
    )
    _health_monitor.start()
    _log_manager.start_background_pruner()
    t = threading.Thread(target=_run_engine, args=(_engine,), daemon=True)
    t.start()


def _is_admin_windows() -> bool:
    try:
        r = subprocess.run(["net", "session"], capture_output=True, text=True, timeout=5)
        return r.returncode == 0
    except Exception:
        return False


def _startup_diagnostics_payload() -> Dict[str, Any]:
    if _engine is None:
        return {
            "ready": False,
            "status": "starting",
            "blockers": ["Engine not initialized"],
            "suggestions": ["Wait for background engine startup"],
        }
    fw = _engine.firewall_monitor.status()
    pcap_dep = _pcap_dependency_status()
    tsh = _tshark_status(Path(_engine.config.pcap_rolling_file))
    admin = _is_admin_windows()
    blockers: List[str] = []
    suggestions: List[str] = []

    if _engine.config.capture_mode == "pcap":
        if not pcap_dep.get("ok", False):
            blockers.append("Scapy/Npcap dependency not available")
            suggestions.append("Install Npcap and ensure scapy can load pcap backend")
        if not pcap_dep.get("use_pcap", False):
            blockers.append("Npcap runtime backend inactive")
            suggestions.append("Reinstall Npcap with WinPcap compatibility and admin rights")
    if not admin:
        blockers.append("Process is not running with administrative privileges")
        suggestions.append("Run terminal as Administrator for full packet and connection visibility")
    if not fw.get("enabled", False):
        suggestions.append("Enable Windows Firewall dropped-packet logging for brute-force detections")
    if not tsh.get("available", False):
        suggestions.append("Install Wireshark/TShark for deep packet decode capabilities")

    return {
        "ready": len(blockers) == 0,
        "status": "ok" if len(blockers) == 0 else "degraded",
        "capture_mode": _engine.config.capture_mode,
        "checks": {
            "pcap_dependency": pcap_dep,
            "firewall_logging": fw,
            "tshark": tsh,
            "admin": {"ok": admin, "detail": "elevated" if admin else "not elevated"},
        },
        "blockers": blockers,
        "suggestions": suggestions,
    }


# ── helpers ───────────────────────────────────────────────────────────────────
def _tail_jsonl(path: Path, n: int) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    lines = path.read_text(encoding="utf-8").splitlines()
    result = []
    for line in lines[-n:]:
        line = line.strip()
        if line:
            try:
                result.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return result


def _to_epoch(ts: str) -> float:
    try:
        dt = datetime.fromisoformat(str(ts))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except Exception:
        return 0.0


def _aggregate_flows(packets: List[Dict[str, Any]], limit: int = 200) -> List[Dict[str, Any]]:
    flows: Dict[str, Dict[str, Any]] = {}
    for pkt in packets:
        src_ip = str(pkt.get("src_ip", "") or "")
        dst_ip = str(pkt.get("dst_ip", "") or "")
        src_port = int(pkt.get("src_port", 0) or 0)
        dst_port = int(pkt.get("dst_port", 0) or 0)
        proto = str(pkt.get("protocol", "") or "")
        app_proto = str(pkt.get("app_protocol", "") or "")
        key = f"{src_ip}:{src_port}>{dst_ip}:{dst_port}/{proto}"
        ts = str(pkt.get("timestamp", "") or "")
        epoch = _to_epoch(ts)

        row = flows.get(key)
        if row is None:
            row = {
                "flow_key": key,
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "protocol": proto,
                "app_protocols": set(),
                "packet_count": 0,
                "byte_count": 0,
                "first_seen": ts,
                "last_seen": ts,
                "first_seen_epoch": epoch,
                "last_seen_epoch": epoch,
                "dns_queries": set(),
                "dns_answers": set(),
                "tls_sni": set(),
                "tls_fingerprint": set(),
                "http_hosts": set(),
            }
            flows[key] = row

        row["packet_count"] += 1
        row["byte_count"] += int(pkt.get("length", 0) or 0)
        if app_proto:
            row["app_protocols"].add(app_proto)
        if pkt.get("dns_query"):
            row["dns_queries"].add(str(pkt.get("dns_query")))
        if pkt.get("dns_answers"):
            row["dns_answers"].add(str(pkt.get("dns_answers")))
        if pkt.get("tls_sni"):
            row["tls_sni"].add(str(pkt.get("tls_sni")))
        if pkt.get("tls_fingerprint"):
            row["tls_fingerprint"].add(str(pkt.get("tls_fingerprint")))
        if pkt.get("http_host"):
            row["http_hosts"].add(str(pkt.get("http_host")))
        if epoch < row["first_seen_epoch"]:
            row["first_seen_epoch"] = epoch
            row["first_seen"] = ts
        if epoch > row["last_seen_epoch"]:
            row["last_seen_epoch"] = epoch
            row["last_seen"] = ts

    result: List[Dict[str, Any]] = []
    for row in flows.values():
        duration = max(0.0, row["last_seen_epoch"] - row["first_seen_epoch"])
        pps = (row["packet_count"] / duration) if duration > 0 else float(row["packet_count"])
        bps = (row["byte_count"] / duration) if duration > 0 else float(row["byte_count"])
        result.append({
            "flow_key": row["flow_key"],
            "src_ip": row["src_ip"],
            "src_port": row["src_port"],
            "dst_ip": row["dst_ip"],
            "dst_port": row["dst_port"],
            "protocol": row["protocol"],
            "app_protocols": sorted(row["app_protocols"]),
            "packet_count": row["packet_count"],
            "byte_count": row["byte_count"],
            "first_seen": row["first_seen"],
            "last_seen": row["last_seen"],
            "duration_seconds": round(duration, 3),
            "pps": round(pps, 3),
            "bps": round(bps, 3),
            "dns_queries": sorted(row["dns_queries"]),
            "dns_answers": sorted(row["dns_answers"]),
            "tls_sni": sorted(row["tls_sni"]),
            "tls_fingerprint": sorted(row["tls_fingerprint"]),
            "http_hosts": sorted(row["http_hosts"]),
        })

    result.sort(key=lambda x: (x.get("byte_count", 0), x.get("packet_count", 0)), reverse=True)
    return result[: max(1, min(int(limit), 1000))]


def _aggregate_conversations(packets: List[Dict[str, Any]], limit: int = 200) -> List[Dict[str, Any]]:
    conversations: Dict[str, Dict[str, Any]] = {}
    for pkt in packets:
        a_ip = str(pkt.get("src_ip", "") or "")
        b_ip = str(pkt.get("dst_ip", "") or "")
        a_port = int(pkt.get("src_port", 0) or 0)
        b_port = int(pkt.get("dst_port", 0) or 0)
        proto = str(pkt.get("protocol", "") or "")
        left = (a_ip, a_port)
        right = (b_ip, b_port)
        if left <= right:
            ckey = f"{a_ip}:{a_port}<->{b_ip}:{b_port}/{proto}"
            a_to_b = True
        else:
            ckey = f"{b_ip}:{b_port}<->{a_ip}:{a_port}/{proto}"
            a_to_b = False

        row = conversations.get(ckey)
        if row is None:
            row = {
                "conversation_key": ckey,
                "endpoint_a_ip": ckey.split("<->", 1)[0].rsplit(":", 1)[0],
                "endpoint_b_ip": ckey.split("<->", 1)[1].split("/", 1)[0].rsplit(":", 1)[0],
                "protocol": proto,
                "packet_count": 0,
                "byte_count": 0,
                "a_to_b_packets": 0,
                "b_to_a_packets": 0,
                "a_to_b_bytes": 0,
                "b_to_a_bytes": 0,
                "app_protocols": set(),
                "last_seen": str(pkt.get("timestamp", "") or ""),
                "last_seen_epoch": _to_epoch(str(pkt.get("timestamp", "") or "")),
            }
            conversations[ckey] = row

        length = int(pkt.get("length", 0) or 0)
        row["packet_count"] += 1
        row["byte_count"] += length
        if pkt.get("app_protocol"):
            row["app_protocols"].add(str(pkt.get("app_protocol")))
        if a_to_b:
            row["a_to_b_packets"] += 1
            row["a_to_b_bytes"] += length
        else:
            row["b_to_a_packets"] += 1
            row["b_to_a_bytes"] += length
        ts = str(pkt.get("timestamp", "") or "")
        epoch = _to_epoch(ts)
        if epoch > row["last_seen_epoch"]:
            row["last_seen_epoch"] = epoch
            row["last_seen"] = ts

    result: List[Dict[str, Any]] = []
    for row in conversations.values():
        result.append({
            "conversation_key": row["conversation_key"],
            "endpoint_a_ip": row["endpoint_a_ip"],
            "endpoint_b_ip": row["endpoint_b_ip"],
            "protocol": row["protocol"],
            "app_protocols": sorted(row["app_protocols"]),
            "packet_count": row["packet_count"],
            "byte_count": row["byte_count"],
            "a_to_b_packets": row["a_to_b_packets"],
            "b_to_a_packets": row["b_to_a_packets"],
            "a_to_b_bytes": row["a_to_b_bytes"],
            "b_to_a_bytes": row["b_to_a_bytes"],
            "last_seen": row["last_seen"],
        })
    result.sort(key=lambda x: (x.get("byte_count", 0), x.get("packet_count", 0)), reverse=True)
    return result[: max(1, min(int(limit), 1000))]


def _incident_family(rule: str) -> str:
    r = str(rule or "").lower()
    if "bruteforce" in r or "firewall" in r:
        return "auth-abuse"
    if "flood" in r:
        return "flood"
    if "scan" in r or "sweep" in r:
        return "recon"
    if "beacon" in r or "dns" in r:
        return "c2"
    if "tls_fingerprint" in r:
        return "evasion"
    if "bandwidth" in r or "spike" in r:
        return "volumetric"
    return "general"


def _build_incidents(
    alerts: List[Dict[str, Any]],
    health: Dict[str, Any],
    now_epoch: float,
    *,
    window_seconds: int,
    min_alerts: int,
    medium_threshold: float,
    high_threshold: float,
    limit: int,
) -> List[Dict[str, Any]]:
    severity_weight = {"medium": 2.0, "high": 4.0}
    groups: Dict[str, Dict[str, Any]] = {}
    cutoff = now_epoch - float(max(60, int(window_seconds)))

    for alert in alerts:
        ts = str(alert.get("timestamp", "") or "")
        epoch = _to_epoch(ts)
        if epoch < cutoff:
            continue
        sev = str(alert.get("severity", "medium") or "medium").lower()
        rule = str(alert.get("rule", "") or "")
        actor = str(alert.get("interface", "unknown") or "unknown")
        fam = _incident_family(rule)
        key = f"{fam}|{actor}"

        g = groups.get(key)
        if g is None:
            g = {
                "incident_key": key,
                "family": fam,
                "actor": actor,
                "alert_count": 0,
                "score": 0.0,
                "max_severity": "medium",
                "related_rules": set(),
                "first_seen": ts,
                "last_seen": ts,
                "first_seen_epoch": epoch,
                "last_seen_epoch": epoch,
            }
            groups[key] = g

        g["alert_count"] += 1
        g["score"] += severity_weight.get(sev, 1.0)
        g["related_rules"].add(rule)
        if sev == "high":
            g["max_severity"] = "high"
        if epoch < g["first_seen_epoch"]:
            g["first_seen_epoch"] = epoch
            g["first_seen"] = ts
        if epoch > g["last_seen_epoch"]:
            g["last_seen_epoch"] = epoch
            g["last_seen"] = ts

    health_status = str(health.get("status", "unknown") or "unknown").lower()
    health_bias = 2.0 if health_status == "critical" else (1.0 if health_status == "degraded" else 0.0)

    incidents: List[Dict[str, Any]] = []
    criticality = _load_json_file(_ASSET_CRITICALITY_PATH, {})
    crit_map = criticality if isinstance(criticality, dict) else {}
    for g in groups.values():
        if g["alert_count"] < max(1, int(min_alerts)):
            continue
        diversity_bonus = min(3.0, float(len(g["related_rules"])) * 0.5)
        recency_bonus = 1.0 if (now_epoch - float(g["last_seen_epoch"])) <= 120.0 else 0.0
        base_score = float(g["score"]) + diversity_bonus + recency_bonus + health_bias
        actor_key = str(g["actor"])
        crit_weight = float(crit_map.get(actor_key, 1.0) or 1.0)
        crit_weight = max(0.5, min(3.0, crit_weight))
        score = base_score * crit_weight
        severity = "high" if score >= float(high_threshold) else ("medium" if score >= float(medium_threshold) else "low")
        incidents.append({
            "incident_key": g["incident_key"],
            "severity": severity,
            "family": g["family"],
            "actor": g["actor"],
            "alert_count": g["alert_count"],
            "score": round(score, 2),
            "criticality_weight": round(crit_weight, 3),
            "max_alert_severity": g["max_severity"],
            "related_rules": sorted(g["related_rules"]),
            "first_seen": g["first_seen"],
            "last_seen": g["last_seen"],
            "status": "open",
        })

    incidents.sort(key=lambda x: (x.get("score", 0), x.get("alert_count", 0)), reverse=True)
    return incidents[: max(1, min(int(limit), 1000))]


def _build_attack_chains(alerts: List[Dict[str, Any]], now_epoch: float, window_seconds: int = 1800) -> List[Dict[str, Any]]:
    cutoff = now_epoch - float(max(300, int(window_seconds)))
    by_actor: Dict[str, List[Dict[str, Any]]] = {}
    for a in alerts:
        ts = str(a.get("timestamp", "") or "")
        epoch = _to_epoch(ts)
        if epoch < cutoff:
            continue
        actor = str(a.get("interface", "unknown") or "unknown")
        by_actor.setdefault(actor, []).append({
            "epoch": epoch,
            "timestamp": ts,
            "rule": str(a.get("rule", "") or ""),
            "severity": str(a.get("severity", "") or "medium"),
        })

    chains: List[Dict[str, Any]] = []
    for actor, rows in by_actor.items():
        rows.sort(key=lambda r: r["epoch"])
        stages: List[str] = []
        for r in rows:
            rule = r["rule"].lower()
            if ("scan" in rule or "sweep" in rule) and "recon" not in stages:
                stages.append("recon")
            elif ("bruteforce" in rule or "service_attack" in rule) and "auth-abuse" not in stages:
                stages.append("auth-abuse")
            elif ("beacon" in rule or "dns" in rule) and "c2" not in stages:
                stages.append("c2")
            elif ("exfil" in rule or "bandwidth" in rule) and "exfil" not in stages:
                stages.append("exfil")
        if len(stages) >= 2:
            chains.append({
                "actor": actor,
                "stages": stages,
                "alert_count": len(rows),
                "first_seen": rows[0]["timestamp"],
                "last_seen": rows[-1]["timestamp"],
                "confidence": "high" if len(stages) >= 3 else "medium",
            })
    chains.sort(key=lambda c: (len(c.get("stages", [])), c.get("alert_count", 0)), reverse=True)
    return chains


def _captured_throughput_bps(window_seconds: int = 5) -> float:
    """Estimate network throughput from captured packets over a recent window."""
    if not _recent_packets:
        return 0.0
    now = datetime.now(timezone.utc)
    cutoff = now.timestamp() - float(window_seconds)
    total_bytes = 0
    for pkt in list(_recent_packets):
        ts = pkt.get("timestamp")
        if not ts:
            continue
        try:
            dt = datetime.fromisoformat(str(ts))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        if dt.timestamp() < cutoff:
            continue
        total_bytes += int(pkt.get("length", 0))
    return (total_bytes / max(window_seconds, 1)) if total_bytes > 0 else 0.0


def _captured_packet_rate_pps(window_seconds: int = 5) -> float:
    if not _recent_packets:
        return 0.0
    now = datetime.now(timezone.utc)
    cutoff = now.timestamp() - float(window_seconds)
    count = 0
    for pkt in list(_recent_packets):
        ts = pkt.get("timestamp")
        if not ts:
            continue
        try:
            dt = datetime.fromisoformat(str(ts))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        if dt.timestamp() >= cutoff:
            count += 1
    return (count / max(window_seconds, 1)) if count > 0 else 0.0


def _pcap_dependency_status() -> Dict[str, Any]:
    try:
        from scapy.all import conf  # type: ignore
        use_pcap = bool(getattr(conf, "use_pcap", False))
        return {
            "ok": True,
            "detail": "scapy loaded",
            "use_pcap": use_pcap,
        }
    except Exception as exc:
        return {
            "ok": False,
            "detail": f"scapy unavailable: {exc}",
            "use_pcap": False,
        }


def _sensor_checks(
    capture_mode: str,
    packet_rate_pps: float,
    fw_status: Dict[str, Any],
    health_status: Dict[str, Any],
) -> Dict[str, Any]:
    pcap_dep = _pcap_dependency_status()
    pcap_mode = capture_mode == "pcap"
    packet_flow_ok = (packet_rate_pps > 0.1) if pcap_mode else True
    packet_flow_detail = (
        f"{packet_rate_pps:.1f} pps"
        if pcap_mode
        else "n/a (host mode)"
    )

    return {
        "capture_mode_ok": {
            "ok": True,
            "detail": capture_mode,
        },
        "pcap_dependency_ok": {
            "ok": (pcap_dep.get("ok", False) if pcap_mode else True),
            "detail": pcap_dep.get("detail", "unknown"),
        },
        "pcap_runtime_ok": {
            "ok": (pcap_dep.get("use_pcap", False) if pcap_mode else True),
            "detail": (
                "Npcap backend active" if pcap_dep.get("use_pcap", False) else "Npcap backend not active"
            ) if pcap_mode else "n/a (host mode)",
        },
        "packet_flow_ok": {
            "ok": packet_flow_ok,
            "detail": packet_flow_detail,
        },
        "firewall_log_ok": {
            "ok": bool(fw_status.get("enabled") and fw_status.get("exists") and fw_status.get("readable")),
            "detail": str(fw_status.get("reason", "unknown")),
        },
        "network_health_probe_ok": {
            "ok": health_status.get("status") not in ("unknown", "disabled"),
            "detail": f"status={health_status.get('status', 'unknown')} score={health_status.get('score', 0)}",
        },
    }


def _get_tshark_cmd() -> str:
    raw = os.environ.get("TSHARK_PATH", "").strip()

    # Support users setting TSHARK_PATH with surrounding quotes, e.g.
    # "C:\\Program Files\\Wireshark\\tshark.exe".
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in ('"', "'"):
        raw = raw[1:-1].strip()

    if raw:
        if Path(raw).is_file():
            return raw
        resolved = shutil.which(raw)
        if resolved:
            return resolved

    resolved_default = shutil.which("tshark")
    if resolved_default:
        return resolved_default

    # Common Wireshark install paths on Windows when PATH wasn't updated.
    for candidate in (
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
    ):
        if Path(candidate).is_file():
            return candidate

    return raw or "tshark"


def _tshark_status(pcap_file: Path | None = None) -> Dict[str, Any]:
    cmd = _get_tshark_cmd()
    try:
        result = subprocess.run(
            [cmd, "-v"],
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
        if result.returncode != 0:
            return {
                "available": False,
                "command": cmd,
                "detail": (result.stderr or result.stdout or "tshark returned non-zero").strip(),
                "pcap_file": str(pcap_file) if pcap_file else "",
                "pcap_exists": bool(pcap_file and pcap_file.exists()),
            }
        first_line = (result.stdout or "").splitlines()[0] if result.stdout else "tshark available"
        return {
            "available": True,
            "command": cmd,
            "detail": first_line,
            "pcap_file": str(pcap_file) if pcap_file else "",
            "pcap_exists": bool(pcap_file and pcap_file.exists()),
        }
    except Exception as exc:
        return {
            "available": False,
            "command": cmd,
            "detail": str(exc),
            "pcap_file": str(pcap_file) if pcap_file else "",
            "pcap_exists": bool(pcap_file and pcap_file.exists()),
        }


# ── REST routes ───────────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def dashboard() -> HTMLResponse:
    html = (_static_dir / "index.html").read_text(encoding="utf-8")
    return HTMLResponse(html)


@app.get("/api/stats")
async def stats() -> JSONResponse:
    assert _engine is not None
    devices = _engine.list_devices()
    alerts_today = list(_recent_alerts)
    high = sum(1 for a in alerts_today if a.get("severity") == "high")
    med = sum(1 for a in alerts_today if a.get("severity") == "medium")
    host_bps = sum(
        e.get("bytes_sent_per_sec", 0) + e.get("bytes_recv_per_sec", 0)
        for e in list(_recent_events)[-10:]
    )
    host_avg_bps = round(host_bps / max(len(list(_recent_events)[-10:]), 1), 1)
    captured_bps = round(_captured_throughput_bps(window_seconds=5), 1)
    captured_pps = round(_captured_packet_rate_pps(window_seconds=5), 1)
    network_bps = captured_bps if _engine.config.capture_mode == "pcap" else host_avg_bps
    health = _health_monitor.status() if _health_monitor is not None else {
        "status": "unknown",
        "score": 0.0,
    }
    uptime_sec = int((datetime.now(timezone.utc) - _started_at).total_seconds())
    return JSONResponse({
        "device_count": len(devices),
        "alert_count_high": high,
        "alert_count_medium": med,
        "recent_bandwidth_bps": host_avg_bps,
        "host_bandwidth_bps": host_avg_bps,
        "captured_bandwidth_bps": captured_bps,
        "captured_packet_rate_pps": captured_pps,
        "network_bandwidth_bps": network_bps,
        "network_health_status": health.get("status", "unknown"),
        "network_health_score": health.get("score", 0.0),
        "capture_mode": _engine.config.capture_mode,
        "uptime_seconds": uptime_sec,
        "packet_buffer_size": len(_recent_packets),
    })


@app.get("/api/system/status")
async def system_status() -> JSONResponse:
    if _engine is None:
        return JSONResponse({"status": "starting"})
    fw_status = _engine.firewall_monitor.status()
    health = _health_monitor.status() if _health_monitor is not None else {
        "status": "unknown",
        "score": 0.0,
        "reason": "not initialized",
    }
    packet_rate = round(_captured_packet_rate_pps(window_seconds=5), 1)
    checks = _sensor_checks(
        capture_mode=_engine.config.capture_mode,
        packet_rate_pps=packet_rate,
        fw_status=fw_status,
        health_status=health,
    )
    return JSONResponse({
        "status": "running",
        "capture_mode": _engine.config.capture_mode,
        "capture_interface": _engine.config.capture_interface or "auto",
        "capture_filter": _engine.config.capture_bpf or "ip or ip6",
        "pcap_rolling_file": _engine.config.pcap_rolling_file,
        "pcap_write_rolling_file": _engine.config.pcap_write_rolling_file,
        "packet_buffer_size": len(_recent_packets),
        "recent_packet_rate_pps": packet_rate,
        "firewall_logging": fw_status,
        "network_health": health,
        "tshark": _tshark_status(Path(_engine.config.pcap_rolling_file)),
        "sensor_checks": checks,
        "started_at": _started_at.isoformat(),
    })


@app.get("/api/startup/diagnostics")
async def startup_diagnostics() -> JSONResponse:
    return JSONResponse(_startup_diagnostics_payload())


@app.get("/api/setup/wizard")
async def setup_wizard() -> JSONResponse:
    diag = _startup_diagnostics_payload()
    steps = [
        {"id": "capture", "title": "Capture readiness", "ok": not any("Npcap" in b or "Scapy" in b for b in diag.get("blockers", []))},
        {"id": "privileges", "title": "Administrative privileges", "ok": not any("administrative" in b for b in diag.get("blockers", []))},
        {"id": "firewall", "title": "Firewall logging", "ok": bool(diag.get("checks", {}).get("firewall_logging", {}).get("enabled", False))},
        {"id": "decode", "title": "TShark decode", "ok": bool(diag.get("checks", {}).get("tshark", {}).get("available", False))},
    ]
    return JSONResponse({
        "ready": bool(diag.get("ready", False)),
        "steps": steps,
        "blockers": diag.get("blockers", []),
        "auto_fix_suggestions": diag.get("suggestions", []),
    })


@app.get("/api/network/health")
async def get_network_health() -> JSONResponse:
    if _health_monitor is None:
        return JSONResponse({
            "enabled": False,
            "status": "unknown",
            "score": 0.0,
            "reason": "not initialized",
            "targets": [],
            "metrics": {},
        })
    return JSONResponse(_health_monitor.status())


class PingDeviceBody(BaseModel):
    ip: str


@app.post("/api/network/ping")
async def ping_network_device(body: PingDeviceBody) -> JSONResponse:
    if _health_monitor is None:
        raise HTTPException(status_code=503, detail="Health monitor unavailable")
    try:
        row = _health_monitor.ping_device(body.ip)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Ping failed: {exc}")
    return JSONResponse({"ok": True, "row": row})


@app.get("/api/devices")
async def list_devices() -> JSONResponse:
    assert _engine is not None
    return JSONResponse([asdict(d) for d in _engine.list_devices()])


class AliasBody(BaseModel):
    alias: str


@app.put("/api/devices/{ip}/alias")
async def set_alias(ip: str, body: AliasBody) -> JSONResponse:
    assert _engine is not None
    ip_decoded = ip.replace("__colon__", ":")
    _engine.set_device_alias(ip=ip_decoded, alias=body.alias)
    return JSONResponse({"ok": True})


@app.delete("/api/devices/{ip}/alias")
async def clear_alias(ip: str) -> JSONResponse:
    assert _engine is not None
    ip_decoded = ip.replace("__colon__", ":")
    removed = _engine.clear_device_alias(ip=ip_decoded)
    return JSONResponse({"ok": removed})


@app.post("/api/scan")
async def scan_subnet() -> JSONResponse:
    assert _engine is not None
    if not _scan_lock.acquire(blocking=False):
        raise HTTPException(status_code=409, detail="Scan already in progress")
    try:
        loop = asyncio.get_event_loop()
        count = await loop.run_in_executor(None, _engine.scan_subnet)
        return JSONResponse({"new_devices": count})
    finally:
        _scan_lock.release()


@app.get("/api/alerts")
async def get_alerts(limit: int = 50) -> JSONResponse:
    assert _engine is not None
    stored = _tail_jsonl(
        Path(_engine.config.log_directory) / "alerts.jsonl", limit
    )
    return JSONResponse(list(reversed(stored)))


@app.get("/api/incidents")
async def get_incidents(limit: int = 50) -> JSONResponse:
    if _engine is None:
        return JSONResponse([])
    lim = max(1, min(limit, 1000))
    alerts = list(_recent_alerts)
    if not alerts:
        alerts = _tail_jsonl(Path(_engine.config.log_directory) / "alerts.jsonl", 2000)
    health = _health_monitor.status() if _health_monitor is not None else {"status": "unknown"}
    now_epoch = datetime.now(timezone.utc).timestamp()
    incidents = _build_incidents(
        alerts,
        health,
        now_epoch,
        window_seconds=int(_engine.config.incident_window_seconds),
        min_alerts=int(_engine.config.incident_min_alerts),
        medium_threshold=float(_engine.config.incident_medium_score_threshold),
        high_threshold=float(_engine.config.incident_high_score_threshold),
        limit=lim,
    )
    return JSONResponse(_merge_incident_triage(incidents))


class IncidentTriageBody(BaseModel):
    incident_key: str
    status: str | None = None
    owner: str | None = None
    notes: str | None = None
    sla_hours: float | None = None
    due_at: str | None = None
    reopen_reason: str | None = None


@app.post("/api/incidents/triage")
async def upsert_incident_triage(body: IncidentTriageBody) -> JSONResponse:
    incident_key = str(body.incident_key or "").strip()
    if not incident_key:
        raise HTTPException(status_code=400, detail="incident_key is required")

    allowed_status = {"open", "acknowledged", "closed"}
    triage = _load_incident_triage()
    current = triage.get(incident_key, {})
    next_status = str(body.status or current.get("status", "open") or "open").lower()
    if next_status not in allowed_status:
        raise HTTPException(status_code=400, detail="status must be one of: open, acknowledged, closed")

    next_owner = str(body.owner if body.owner is not None else current.get("owner", "") or "").strip()
    next_notes = str(body.notes if body.notes is not None else current.get("notes", "") or "").strip()
    next_sla = float(body.sla_hours if body.sla_hours is not None else current.get("sla_hours", 24.0) or 24.0)
    next_due = str(body.due_at if body.due_at is not None else current.get("due_at", "") or "").strip()
    next_reopen = str(body.reopen_reason if body.reopen_reason is not None else current.get("reopen_reason", "") or "").strip()

    previous_status = str(current.get("status", "open") or "open").lower()
    if previous_status == "closed" and next_status == "open" and not next_reopen:
        raise HTTPException(status_code=400, detail="reopen_reason is required when reopening a closed incident")

    triage[incident_key] = {
        "status": next_status,
        "owner": next_owner,
        "notes": next_notes,
        "sla_hours": next_sla,
        "due_at": next_due,
        "reopen_reason": next_reopen,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    _save_incident_triage(triage)
    _append_jsonl(_INCIDENT_ACTIVITY_PATH, {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "incident_key": incident_key,
        "from_status": previous_status,
        "to_status": next_status,
        "owner": next_owner,
        "notes": next_notes,
        "reopen_reason": next_reopen,
    })
    return JSONResponse({"ok": True, "incident_key": incident_key, "triage": triage[incident_key]})


@app.get("/api/incidents/{incident_key}/timeline")
async def get_incident_timeline(incident_key: str, limit: int = 100) -> JSONResponse:
    rows = _tail_jsonl(_INCIDENT_ACTIVITY_PATH, max(1, min(limit, 1000)))
    key = str(incident_key or "")
    out = [r for r in rows if str(r.get("incident_key", "")) == key]
    return JSONResponse(out)


class DetectionControlsBody(BaseModel):
    rule_enabled: Dict[str, bool] = {}
    rule_mute_until_epoch: Dict[str, float] = {}
    rule_threshold_overrides: Dict[str, float] = {}
    suppression_rules: List[Dict[str, str]] = []


@app.get("/api/detections/controls")
async def get_detection_controls() -> JSONResponse:
    if _engine is None:
        return JSONResponse({})
    return JSONResponse(_engine.detector.get_controls())


@app.post("/api/detections/controls")
async def save_detection_controls(body: DetectionControlsBody) -> JSONResponse:
    if _engine is None:
        raise HTTPException(status_code=503, detail="Engine not initialized")
    payload = {
        "rule_enabled": body.rule_enabled,
        "rule_mute_until_epoch": body.rule_mute_until_epoch,
        "rule_threshold_overrides": body.rule_threshold_overrides,
        "suppression_rules": body.suppression_rules,
    }
    _engine.detector.set_controls(payload)
    _save_json_file(_DETECTOR_CONTROLS_PATH, payload)
    return JSONResponse({"ok": True})


class MarkExpectedBody(BaseModel):
    rule: str
    interface: str = ""
    contains: str = ""
    reason: str = "expected behavior"


@app.post("/api/alerts/mark-expected")
async def mark_alert_expected(body: MarkExpectedBody) -> JSONResponse:
    if _engine is None:
        raise HTTPException(status_code=503, detail="Engine not initialized")
    controls = _engine.detector.get_controls()
    suppression = list(controls.get("suppression_rules", []))
    suppression.append({
        "rule": str(body.rule or "").strip(),
        "interface": str(body.interface or "").strip(),
        "contains": str(body.contains or "").strip().lower(),
        "reason": str(body.reason or "expected behavior").strip(),
    })
    controls["suppression_rules"] = suppression
    _engine.detector.set_controls(controls)
    _save_json_file(_DETECTOR_CONTROLS_PATH, controls)
    return JSONResponse({"ok": True, "suppression_count": len(suppression)})


@app.get("/api/detections/baseline")
async def get_baseline_state() -> JSONResponse:
    if _engine is None:
        return JSONResponse({"enabled": False})
    return JSONResponse(_engine.detector.get_baseline_state())


@app.post("/api/detections/baseline/apply-suggestion")
async def apply_baseline_suggestion() -> JSONResponse:
    if _engine is None:
        raise HTTPException(status_code=503, detail="Engine not initialized")
    state = _engine.detector.get_baseline_state()
    suggested = float(state.get("suggested_max_bytes_per_second", _engine.config.max_bytes_per_second) or _engine.config.max_bytes_per_second)
    _engine.config.max_bytes_per_second = suggested
    saved = _load_persisted_settings()
    saved["max_bytes_per_second"] = suggested
    _save_persisted_settings(saved)
    return JSONResponse({"ok": True, "max_bytes_per_second": suggested})


@app.get("/api/incidents/chains")
async def get_incident_chains(window_seconds: int = 1800) -> JSONResponse:
    if _engine is None:
        return JSONResponse([])
    alerts = list(_recent_alerts) or _tail_jsonl(Path(_engine.config.log_directory) / "alerts.jsonl", 3000)
    now_epoch = datetime.now(timezone.utc).timestamp()
    return JSONResponse(_build_attack_chains(alerts, now_epoch, window_seconds=window_seconds))


@app.get("/api/risk/hosts")
async def get_host_risk(limit: int = 200) -> JSONResponse:
    if _engine is None:
        return JSONResponse([])
    lim = max(1, min(limit, 2000))
    alerts = list(_recent_alerts) or _tail_jsonl(Path(_engine.config.log_directory) / "alerts.jsonl", 3000)
    health = _health_monitor.status() if _health_monitor is not None else {"device_probes": {"rows": []}}
    fw_events = list(_recent_firewall_blocks) or _tail_jsonl(Path(_engine.config.log_directory) / "firewall_blocks.jsonl", 3000)
    health_rows = list((health.get("device_probes") or {}).get("rows") or [])
    health_map = {str(r.get("ip") or r.get("target") or ""): r for r in health_rows}
    score: Dict[str, Dict[str, Any]] = {}
    for a in alerts:
        actor = str(a.get("interface", "") or "")
        if not actor:
            continue
        row = score.setdefault(actor, {"host": actor, "score": 0.0, "alerts": 0, "high": 0, "medium": 0, "firewall_blocks": 0, "health_penalty": 0.0})
        row["alerts"] += 1
        sev = str(a.get("severity", "medium") or "medium").lower()
        if sev == "high":
            row["high"] += 1
            row["score"] += 4.0
        else:
            row["medium"] += 1
            row["score"] += 2.0
    for fw in fw_events:
        src = str(fw.get("src_ip", "") or "")
        if not src:
            continue
        row = score.setdefault(src, {"host": src, "score": 0.0, "alerts": 0, "high": 0, "medium": 0, "firewall_blocks": 0, "health_penalty": 0.0})
        row["firewall_blocks"] += 1
        row["score"] += 0.1
    for host, row in score.items():
        hr = health_map.get(host)
        if hr and hr.get("last_ok") is False:
            row["health_penalty"] = 2.0
            row["score"] += 2.0
    out = sorted(score.values(), key=lambda r: float(r.get("score", 0.0)), reverse=True)
    return JSONResponse(out[:lim])


@app.get("/api/assets/criticality")
async def get_asset_criticality() -> JSONResponse:
    payload = _load_json_file(_ASSET_CRITICALITY_PATH, {})
    return JSONResponse(payload if isinstance(payload, dict) else {})


class AssetCriticalityBody(BaseModel):
    host: str
    weight: float


@app.post("/api/assets/criticality")
async def upsert_asset_criticality(body: AssetCriticalityBody) -> JSONResponse:
    host = str(body.host or "").strip()
    if not host:
        raise HTTPException(status_code=400, detail="host is required")
    weight = max(0.5, min(3.0, float(body.weight)))
    payload = _load_json_file(_ASSET_CRITICALITY_PATH, {})
    if not isinstance(payload, dict):
        payload = {}
    payload[host] = weight
    _save_json_file(_ASSET_CRITICALITY_PATH, payload)
    return JSONResponse({"ok": True, "host": host, "weight": weight})


@app.delete("/api/assets/criticality/{host}")
async def delete_asset_criticality(host: str) -> JSONResponse:
    payload = _load_json_file(_ASSET_CRITICALITY_PATH, {})
    if not isinstance(payload, dict):
        payload = {}
    removed = payload.pop(str(host), None)
    _save_json_file(_ASSET_CRITICALITY_PATH, payload)
    return JSONResponse({"ok": True, "removed": removed is not None})


@app.get("/api/views/saved")
async def get_saved_views() -> JSONResponse:
    payload = _load_json_file(_SAVED_VIEWS_PATH, [])
    return JSONResponse(payload if isinstance(payload, list) else [])


class SavedViewBody(BaseModel):
    name: str
    filters: Dict[str, Any] = {}


@app.post("/api/views/saved")
async def save_view(body: SavedViewBody) -> JSONResponse:
    rows = _load_json_file(_SAVED_VIEWS_PATH, [])
    if not isinstance(rows, list):
        rows = []
    now_iso = datetime.now(timezone.utc).isoformat()
    name = str(body.name or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="name is required")
    rows = [r for r in rows if str(r.get("name", "")) != name]
    rows.append({"name": name, "filters": body.filters, "updated_at": now_iso})
    _save_json_file(_SAVED_VIEWS_PATH, rows)
    return JSONResponse({"ok": True, "count": len(rows)})


@app.delete("/api/views/saved/{name}")
async def delete_view(name: str) -> JSONResponse:
    rows = _load_json_file(_SAVED_VIEWS_PATH, [])
    if not isinstance(rows, list):
        rows = []
    before = len(rows)
    rows = [r for r in rows if str(r.get("name", "")) != str(name)]
    _save_json_file(_SAVED_VIEWS_PATH, rows)
    return JSONResponse({"ok": True, "removed": before - len(rows)})


class SimulateDetectionsBody(BaseModel):
    network_events: List[Dict[str, Any]] = []
    connection_events: List[Dict[str, Any]] = []
    packet_events: List[Dict[str, Any]] = []
    firewall_events: List[Dict[str, Any]] = []


@app.post("/api/detections/simulate")
async def simulate_detections(body: SimulateDetectionsBody) -> JSONResponse:
    if _engine is None:
        raise HTTPException(status_code=503, detail="Engine not initialized")
    alerts: List[Dict[str, Any]] = []
    try:
        from .models import ConnectionEvent, FirewallBlockEvent, NetworkEvent, PacketEvent

        ne = [NetworkEvent(**e) for e in body.network_events]
        ce = [ConnectionEvent(**e) for e in body.connection_events]
        pe = [PacketEvent(**e) for e in body.packet_events]
        fe = [FirewallBlockEvent(**e) for e in body.firewall_events]

        out = []
        if ne:
            out.extend(_engine.detector.evaluate(ne))
        if ce:
            out.extend(_engine.detector.evaluate_connections(ce))
        if pe:
            out.extend(_engine.detector.evaluate_packet_events(pe))
        if fe:
            out.extend(_engine.detector.evaluate_firewall_blocks(fe))
        alerts = [asdict(a) for a in out]
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"simulation failed: {exc}")
    return JSONResponse({"count": len(alerts), "alerts": alerts})


@app.get("/api/incidents/summary")
async def get_incidents_summary() -> JSONResponse:
    if _engine is None:
        return JSONResponse({"total": 0, "high": 0, "medium": 0, "low": 0})
    health = _health_monitor.status() if _health_monitor is not None else {"status": "unknown"}
    alerts = list(_recent_alerts) or _tail_jsonl(Path(_engine.config.log_directory) / "alerts.jsonl", 2000)
    now_epoch = datetime.now(timezone.utc).timestamp()
    incidents = _merge_incident_triage(_build_incidents(
        alerts,
        health,
        now_epoch,
        window_seconds=int(_engine.config.incident_window_seconds),
        min_alerts=int(_engine.config.incident_min_alerts),
        medium_threshold=float(_engine.config.incident_medium_score_threshold),
        high_threshold=float(_engine.config.incident_high_score_threshold),
        limit=200,
    ))
    return JSONResponse({
        "total": len(incidents),
        "high": sum(1 for i in incidents if i.get("severity") == "high"),
        "medium": sum(1 for i in incidents if i.get("severity") == "medium"),
        "low": sum(1 for i in incidents if i.get("severity") == "low"),
        "open": sum(1 for i in incidents if i.get("status") == "open"),
        "acknowledged": sum(1 for i in incidents if i.get("status") == "acknowledged"),
        "closed": sum(1 for i in incidents if i.get("status") == "closed"),
    })


@app.get("/api/events")
async def get_events(limit: int = 30) -> JSONResponse:
    return JSONResponse(list(_recent_events)[-limit:])


@app.get("/api/connections")
async def get_connections(limit: int = 50) -> JSONResponse:
    return JSONResponse(list(_recent_connections)[-limit:])


@app.get("/api/bluetooth")
async def get_bluetooth(limit: int = 100) -> JSONResponse:
    if _engine is None:
        return JSONResponse([])
    if _recent_bluetooth:
        return JSONResponse(list(_recent_bluetooth)[-limit:])
    stored = _tail_jsonl(Path(_engine.config.log_directory) / "bluetooth.jsonl", limit)
    return JSONResponse(stored)


@app.get("/api/packets")
async def get_packets(limit: int = 500) -> JSONResponse:
    if _engine is None:
        return JSONResponse([])
    lim = max(1, min(limit, 5000))
    if _recent_packets:
        return JSONResponse(list(_recent_packets)[-lim:])
    stored = _tail_jsonl(Path(_engine.config.log_directory) / "packets.jsonl", lim)
    return JSONResponse(stored)


@app.get("/api/packets/export")
async def export_packets(limit: int = 5000) -> JSONResponse:
    if _engine is None:
        return JSONResponse({"rows": []})
    lim = max(1, min(limit, 10000))
    rows = list(_recent_packets)[-lim:] if _recent_packets else _tail_jsonl(
        Path(_engine.config.log_directory) / "packets.jsonl", lim
    )
    return JSONResponse({"rows": rows, "count": len(rows)})


@app.get("/api/packets/flows")
async def get_packet_flows(limit: int = 200) -> JSONResponse:
    if _engine is None:
        return JSONResponse([])
    lim = max(1, min(limit, 1000))
    rows = list(_recent_packets) if _recent_packets else _tail_jsonl(Path(_engine.config.log_directory) / "packets.jsonl", 5000)
    return JSONResponse(_aggregate_flows(rows, limit=lim))


@app.get("/api/packets/conversations")
async def get_packet_conversations(limit: int = 200) -> JSONResponse:
    if _engine is None:
        return JSONResponse([])
    lim = max(1, min(limit, 1000))
    rows = list(_recent_packets) if _recent_packets else _tail_jsonl(Path(_engine.config.log_directory) / "packets.jsonl", 5000)
    return JSONResponse(_aggregate_conversations(rows, limit=lim))


@app.get("/api/integrations/tshark")
async def tshark_status() -> JSONResponse:
    pcap_file = Path(_engine.config.pcap_rolling_file) if _engine is not None else None
    return JSONResponse(_tshark_status(pcap_file=pcap_file))


@app.get("/api/packets/decode")
async def decode_packet(frame_number: int) -> JSONResponse:
    if _engine is None:
        raise HTTPException(status_code=503, detail="Engine not initialized")
    if frame_number <= 0:
        raise HTTPException(status_code=400, detail="frame_number must be positive")

    pcap_file = Path(_engine.config.pcap_rolling_file)
    status = _tshark_status(pcap_file=pcap_file)
    if not status.get("available"):
        raise HTTPException(status_code=503, detail=f"tshark unavailable: {status.get('detail', 'unknown error')}")
    if not pcap_file.exists():
        raise HTTPException(status_code=404, detail=f"PCAP file not found: {pcap_file}")

    cmd = _get_tshark_cmd()
    try:
        result = subprocess.run(
            [cmd, "-r", str(pcap_file), "-Y", f"frame.number=={frame_number}", "-V", "-c", "1"],
            capture_output=True,
            text=True,
            check=False,
            timeout=15,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to run tshark: {exc}")

    output = (result.stdout or "").strip()
    if result.returncode != 0:
        detail = (result.stderr or "").strip() or "tshark returned non-zero"
        raise HTTPException(status_code=500, detail=detail)
    if not output:
        raise HTTPException(status_code=404, detail=f"Frame {frame_number} not found in rolling capture")
    return JSONResponse({
        "frame_number": frame_number,
        "decode": output,
        "pcap_file": str(pcap_file),
    })


@app.get("/api/firewall/blocked")
async def get_firewall_blocked(limit: int = 100) -> JSONResponse:
    if _engine is None:
        return JSONResponse([])
    lim = max(1, min(limit, 2000))
    if _recent_firewall_blocks:
        return JSONResponse(list(_recent_firewall_blocks)[-lim:])
    stored = _tail_jsonl(Path(_engine.config.log_directory) / "firewall_blocks.jsonl", lim)
    return JSONResponse(stored)


# ── Server-Sent Events ────────────────────────────────────────────────────────
@app.get("/api/stream/alerts")
async def stream_alerts(request: Request) -> StreamingResponse:
    queue: asyncio.Queue = asyncio.Queue(maxsize=50)
    _sse_subscribers.append(queue)

    async def event_generator():
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    alert = await asyncio.wait_for(queue.get(), timeout=15)
                    payload = json.dumps(alert)
                    yield f"data: {payload}\n\n"
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
        finally:
            _sse_subscribers.remove(queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── Settings API ──────────────────────────────────────────────────────────────
@app.get("/api/settings")
async def get_settings() -> JSONResponse:
    assert _engine is not None
    saved = _load_persisted_settings()
    return JSONResponse({
        "events_retention_hours": saved.get(
            "events_retention_hours", _engine.config.events_retention_hours
        ),
        "alerts_retention_hours": saved.get(
            "alerts_retention_hours", _engine.config.alerts_retention_hours
        ),
        "archive_retention_days": saved.get(
            "archive_retention_days", _engine.config.archive_retention_days
        ),
        "poll_interval_seconds": _engine.config.poll_interval_seconds,
        "ai_key_configured": bool(os.environ.get("OPENAI_API_KEY", "").strip()),
    })


class SettingsBody(BaseModel):
    events_retention_hours: float | None = None
    alerts_retention_hours: float | None = None
    archive_retention_days: int | None = None
    openai_api_key: str | None = None


@app.post("/api/settings")
async def save_settings_endpoint(body: SettingsBody) -> JSONResponse:
    saved = _load_persisted_settings()
    if body.events_retention_hours is not None:
        saved["events_retention_hours"] = body.events_retention_hours
    if body.alerts_retention_hours is not None:
        saved["alerts_retention_hours"] = body.alerts_retention_hours
    if body.archive_retention_days is not None:
        saved["archive_retention_days"] = int(body.archive_retention_days)
    _save_persisted_settings(saved)
    if _log_manager is not None:
        _log_manager.update_retention(
            events_hours=float(saved.get("events_retention_hours", _log_manager.events_retention_hours)),
            alerts_hours=float(saved.get("alerts_retention_hours", _log_manager.alerts_retention_hours)),
            archive_days=int(saved.get("archive_retention_days", _log_manager.archive_retention_days)),
        )
    if body.openai_api_key:
        key = body.openai_api_key.strip()
        _write_env_key("OPENAI_API_KEY", key)
        os.environ["OPENAI_API_KEY"] = key
    return JSONResponse({"ok": True})


# ── Log prune API ─────────────────────────────────────────────────────────────
@app.post("/api/logs/prune")
async def prune_logs() -> JSONResponse:
    if _log_manager is None:
        raise HTTPException(status_code=503, detail="Log manager not initialized")
    loop = asyncio.get_event_loop()
    removed = await loop.run_in_executor(None, _log_manager.prune_all)
    return JSONResponse({"removed": removed})


@app.post("/api/logs/archive/clear")
async def clear_archived_logs() -> JSONResponse:
    if _log_manager is None:
        raise HTTPException(status_code=503, detail="Log manager not initialized")
    loop = asyncio.get_event_loop()
    removed = await loop.run_in_executor(None, _log_manager.clear_archive)
    return JSONResponse({"removed": removed})


# ── AI Analyze API ────────────────────────────────────────────────────────────
_AI_SYSTEM_PROMPTS: Dict[str, str] = {
    "alert_triage": (
        "You are Alert Triage Agent for a SIEM dashboard. "
        "Analyze only the supplied evidence and clearly mark assumptions. "
        "Classify likely scenario (scan, brute force, beaconing, flood, false positive, other), "
        "state confidence, estimate impact scope, and provide prioritized containment steps. "
        "Format: 1) Finding 2) Confidence 3) Impact 4) Immediate actions 5) Next validation steps."
    ),
    "incident_commander": (
        "You are Incident Commander Agent for correlated incidents. "
        "Interpret severity, score, status, owner, notes, and related rules, then produce an operational plan. "
        "Include escalation criteria and closure criteria. "
        "Format: 1) Incident summary 2) Probable root cause 3) Containment plan 4) Escalation criteria 5) Closure checklist."
    ),
    "traffic_forensics": (
        "You are Traffic Forensics Agent. "
        "Analyze connection/packet behavior for suspicious endpoints, cadence, fanout, C2 signals, and exfil indicators. "
        "Separate baseline from outliers and propose concrete validation queries. "
        "Format: 1) Key anomalies 2) Benign explanations considered 3) Threat hypothesis 4) Verification queries 5) Recommended mitigations."
    ),
    "device_risk": (
        "You are Device Risk Agent. "
        "Evaluate host exposure from inventory and health context, prioritize weaknesses, and recommend hardening by effort/impact. "
        "Format: 1) Device risk summary 2) Top weaknesses 3) Hardening actions 4) Monitoring checks."
    ),
    "network_health_reliability": (
        "You are Network Health Reliability Agent. "
        "Use loss, RTT, jitter, and host availability to determine operational vs security causes. "
        "Distinguish router-path problems from endpoint-local issues and provide runbook steps. "
        "Format: 1) Health diagnosis 2) Fault domain 3) Investigation steps 4) Recovery actions 5) Security crossover checks."
    ),
    "soc_copilot": (
        "You are a SIEM SOC Copilot. "
        "Provide concise, practical security guidance, avoid overclaiming certainty, and ask for missing critical context only when required. "
        "Format: 1) Direct answer 2) Why likely 3) Next best action."
    ),
}


def _select_ai_agent(body: "AIAnalyzeBody") -> str:
    if body.agent_type and body.agent_type in _AI_SYSTEM_PROMPTS:
        return body.agent_type
    if body.context_incidents:
        return "incident_commander"
    if body.context_alerts:
        return "alert_triage"
    if body.context_connections or body.context_events:
        return "traffic_forensics"
    if body.context_devices:
        return "device_risk"
    if body.context_health:
        return "network_health_reliability"
    return "soc_copilot"


class AIAnalyzeBody(BaseModel):
    message: str
    agent_type: str = ""
    history: list = []
    context_alerts: list = []
    context_events: list = []
    context_connections: list = []
    context_devices: list = []
    context_incidents: list = []
    context_health: list = []


@app.post("/api/ai/analyze")
async def ai_analyze(body: AIAnalyzeBody) -> JSONResponse:
    key = os.environ.get("OPENAI_API_KEY", "").strip()
    if not key:
        raise HTTPException(
            status_code=400,
            detail=(
                "No OPENAI_API_KEY configured. "
                "Go to Settings, paste your key, and click Save."
            ),
        )
    try:
        from openai import AsyncOpenAI  # type: ignore
    except ImportError:
        raise HTTPException(
            status_code=500,
            detail="openai package not installed. Run: pip install openai",
        )

    client = AsyncOpenAI(api_key=key)
    model = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
    agent_type = _select_ai_agent(body)
    system_prompt = _AI_SYSTEM_PROMPTS.get(agent_type, _AI_SYSTEM_PROMPTS["soc_copilot"])

    messages: List[Dict[str, Any]] = [{"role": "system", "content": system_prompt}]
    for msg in body.history[-12:]:
        if msg.get("role") in ("user", "assistant"):
            messages.append({"role": msg["role"], "content": str(msg["content"])})

    ctx_parts: List[str] = []
    if body.context_alerts:
        ctx_parts.append("=== ALERTS ===\n" + json.dumps(body.context_alerts, indent=2))
    if body.context_events:
        ctx_parts.append("=== NETWORK EVENTS ===\n" + json.dumps(body.context_events, indent=2))
    if body.context_connections:
        ctx_parts.append("=== CONNECTIONS ===\n" + json.dumps(body.context_connections, indent=2))
    if body.context_devices:
        ctx_parts.append("=== DEVICES ===\n" + json.dumps(body.context_devices, indent=2))
    if body.context_incidents:
        ctx_parts.append("=== INCIDENTS ===\n" + json.dumps(body.context_incidents, indent=2))
    if body.context_health:
        ctx_parts.append("=== HEALTH ===\n" + json.dumps(body.context_health, indent=2))

    user_content = body.message
    if ctx_parts:
        user_content = "\n\n".join(ctx_parts) + "\n\n---\nUser question: " + body.message

    messages.append({"role": "user", "content": user_content})

    try:
        response = await client.chat.completions.create(
            model=model,
            messages=messages,
            max_tokens=1200,
            temperature=0.2,
        )
        return JSONResponse({
            "reply": response.choices[0].message.content,
            "agent_type": agent_type,
        })
    except Exception as exc:
        # Surface the real OpenAI error message to the frontend instead of a
        # generic 500.  This covers auth failures, quota limits, bad model
        # names, network timeouts, etc.
        import openai as _oai  # type: ignore
        if isinstance(exc, _oai.AuthenticationError):
            raise HTTPException(status_code=401, detail="OpenAI authentication failed. Check that your API key is correct in Settings.")
        if isinstance(exc, _oai.RateLimitError):
            raise HTTPException(status_code=429, detail="OpenAI rate limit reached. Wait a moment then try again.")
        if isinstance(exc, _oai.NotFoundError):
            raise HTTPException(status_code=400, detail=f"OpenAI model not found: '{model}'. Set OPENAI_MODEL to a valid model name (e.g. gpt-4o-mini).")
        if isinstance(exc, _oai.APIConnectionError):
            raise HTTPException(status_code=502, detail="Could not reach OpenAI. Check your internet connection.")
        # For any other OpenAI or unexpected error, include the message text.
        raise HTTPException(status_code=502, detail=f"OpenAI error: {exc}")
