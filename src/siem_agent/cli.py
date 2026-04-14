from __future__ import annotations

import argparse
import json
import time
from datetime import datetime, timezone
from pathlib import Path

from .collector import AgentCollector
from .discovery import discover_server
from .identity import host_identity, installation_id
from .spool import AgentSpool
from .transport import AgentTransport


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="SIEM endpoint agent")
    parser.add_argument("--server-url", default="", help="Manual central server URL override")
    parser.add_argument("--token", default="lab-enroll", help="Enrollment token")
    parser.add_argument("--discovery-port", type=int, default=55110, help="UDP discovery port")
    parser.add_argument("--state-dir", default="agent_state", help="Agent state directory")
    parser.add_argument("--interval", type=int, default=30, help="Collection interval seconds")
    parser.add_argument("--once", action="store_true", help="Run one collection cycle and exit")
    return parser.parse_args()


def _load_json(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def resolve_server_url(args: argparse.Namespace, state_dir: Path) -> str:
    if args.server_url:
        return str(args.server_url).strip().rstrip("/")
    cached = _load_json(state_dir / "server.json")
    if cached.get("server_url"):
        return str(cached["server_url"]).strip().rstrip("/")
    discovered = discover_server(args.discovery_port)
    server_url = str(discovered.get("server_url", "") or "").strip().rstrip("/")
    if not server_url:
        raise RuntimeError("No SIEM server discovered")
    _save_json(state_dir / "server.json", discovered)
    return server_url


def enroll_if_needed(transport: AgentTransport, args: argparse.Namespace, state_dir: Path) -> dict:
    agent_path = state_dir / "agent.json"
    payload = _load_json(agent_path)
    if payload.get("agent_id") and payload.get("agent_key"):
        return payload
    identity = host_identity(state_dir)
    response = transport.register({
        **identity,
        "token": args.token,
        "agent_version": "0.1.0",
    })
    payload = {
        "agent_id": response.get("agent_id", ""),
        "agent_key": response.get("agent_key", ""),
        "server_url": response.get("server_url", transport.server_url),
        "installation_id": installation_id(state_dir),
    }
    if not payload["agent_id"] or not payload["agent_key"]:
        raise RuntimeError("Enrollment did not return agent credentials")
    _save_json(agent_path, payload)
    return payload


def flush_spool(transport: AgentTransport, creds: dict, spool: AgentSpool) -> None:
    rows = spool.read_all()
    if not rows:
        return
    remaining = []
    for row in rows:
        try:
            transport.upload_events(row)
        except Exception:
            remaining.append(row)
    spool.replace(remaining)


def run_cycle(transport: AgentTransport, creds: dict, collector: AgentCollector, spool: AgentSpool, sequence_path: Path) -> None:
    sequence_info = _load_json(sequence_path)
    current_sequence = int(sequence_info.get("sequence", 0) or 0)
    events = collector.collect()
    if events:
        current_sequence += 1
        batch = {
            "agent_id": creds["agent_id"],
            "agent_key": creds["agent_key"],
            "sequence": current_sequence,
            "sent_at": datetime.now(timezone.utc).isoformat(),
            "events": events,
        }
        spool.append_batch(batch)
        _save_json(sequence_path, {"sequence": current_sequence})

    flush_spool(transport, creds, spool)
    transport.heartbeat({
        "agent_id": creds["agent_id"],
        "agent_key": creds["agent_key"],
        "queue_depth": spool.depth(),
        "service_uptime_seconds": collector.uptime_seconds(),
        "collector_status": "ok",
        "local_ips": host_identity(collector.state_dir).get("local_ips", []),
    })


def main() -> None:
    args = parse_args()
    state_dir = Path(args.state_dir)
    state_dir.mkdir(parents=True, exist_ok=True)
    server_url = resolve_server_url(args, state_dir)
    transport = AgentTransport(server_url)
    creds = enroll_if_needed(transport, args, state_dir)
    transport = AgentTransport(str(creds.get("server_url", server_url) or server_url))
    collector = AgentCollector(state_dir)
    spool = AgentSpool(state_dir)
    sequence_path = state_dir / "sequence.json"

    if args.once:
        run_cycle(transport, creds, collector, spool, sequence_path)
        return

    while True:
        try:
            run_cycle(transport, creds, collector, spool, sequence_path)
        except Exception as exc:
            print(f"[agent] cycle error: {exc}")
        time.sleep(max(5, int(args.interval)))


if __name__ == "__main__":
    main()