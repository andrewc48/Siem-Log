# SIEM Dashboard

A self-contained Python network security monitor with a live web dashboard, AI-powered analysis, and automatic log management.

## Features

- **Real-time network monitoring** — bandwidth per interface, active TCP/UDP connections, process names
- **Live packet stream** — packet metadata table with network + app-layer context (timestamp, src/dst, protocol, app protocol, length, direction)
- **Packet detail inspector** — per-packet details including TCP flags, seq/ack, DNS query/answers, TLS SNI, HTTP host/path, and hex payload preview
- **Advanced packet analysis** — TCP stream-aware parsing, TLS fingerprint hashing, DNS transaction RTT correlation, and NXDOMAIN visibility
- **Flow + conversation analytics** — directional flow and bidirectional conversation rollups from captured packets
- **Phase 4 correlated incidents** — weighted alert correlation by actor + behavior family for triage prioritization
- **Optional deep decode** — TShark frame decode API for selected packets when `tshark` is installed
- **Sensor mode (pcap)** — optional packet capture mode for mirrored/bridged interfaces to observe whole-LAN traffic flows
- **Anomaly detection** — absolute threshold, spike detection (EWMA), suspicious-port alerts, connection fan-out detection
- **Device inventory** — ARP-cache scanning, subnet ping-sweep, custom device names, persistent inventory
- **Bluetooth monitor (local host)** — logs Bluetooth device connect/disconnect state changes (Windows PnP based)
- **Live web dashboard** — dark-theme single-page app with Overview, Devices, Alerts, Traffic, Settings, and AI Analyzer views
- **AI Analyzer** — chat interface backed by OpenAI (gpt-4o-mini by default); load any alert, connection, or device as context for instant analysis
- **Log retention** — configurable per-category retention (hours); background pruner runs automatically; manual prune-now button in UI
- **Portable** — runs locally (127.0.0.1) or exposed on a server (0.0.0.0); no external services required except OpenAI (optional)

---

## Quick Start (Local)

### 1 · Prerequisites

- Python 3.10 or newer
- Windows, macOS, or Linux

### 2 · Install

```bash
# Clone or download the project, then:
cd "SIEM Tool"
pip install -e .
```

### 3 · Run the dashboard

```bash
python run.py
```

Open **http://localhost:8080** in your browser.

Or use the CLI entry point:

```bash
siem --serve

# Whole-network sensor mode (requires Npcap + mirrored/bridged NIC)
python run.py --capture-mode pcap
```

## Run Without VS Code (One Click)

For Windows machines, you can launch with a double-click and automatic dependency setup:

1. Double-click `NetworkMonitor-Start.bat`
2. The script will:
  - create `.venv` if missing
  - install/update required dependencies
  - start the dashboard

Open `http://localhost:8080` after it starts.

This is the easiest way to run on another device without opening VS Code.

For sensor nodes that should capture mirrored traffic, use:

- `NetworkMonitor-Start-PCAP.bat`

This launches in `pcap` mode and binds to `0.0.0.0:8080`.

## Build a Portable EXE (Optional)

If you want a packaged executable directory:

1. Right-click PowerShell and run:

```powershell
powershell -ExecutionPolicy Bypass -File .\Build-NetworkMonitor-EXE.ps1
```

2. Output is created at:

```text
dist\NetworkMonitor\NetworkMonitor.exe
```

Notes:
- First run can take a few minutes.
- The packaged app still needs Npcap installed if you use `pcap` mode.
- Firewall logging access rules still apply as before.

## Proxmox Windows VM Deployment Notes

If this runs inside a Windows VM on Proxmox:

1. Install Npcap in the VM (required for `pcap` capture).
2. Use a bridged NIC model (VirtIO or Intel e1000) in Proxmox.
3. If you expect full-LAN visibility, feed mirrored traffic to the Proxmox host NIC (SPAN/TAP upstream).
4. Ensure your VM/network path permits promiscuous capture where needed.
5. Start with `NetworkMonitor-Start-PCAP.bat` or run:

```bash
python run.py --capture-mode pcap --host 0.0.0.0 --port 8080
```

Important:
- A VM in normal bridged mode does not automatically see all switched traffic.
- To see the entire network, configure switch/router mirroring to the sensor path.

### 4 · (Optional) Configure the AI Analyzer

1. Copy `.env.example` to `.env`
2. Paste your OpenAI API key — OR — go to **Settings & Logs → AI Analyzer** in the dashboard and paste it there (it will be written to `.env` automatically)

```
OPENAI_API_KEY=sk-...
```

---

## Command-Line Options

```
python run.py [--host HOST] [--port PORT] [--config CONFIG]

  --host    Bind address (default: 127.0.0.1 — localhost only)
            Use 0.0.0.0 to expose on all interfaces (server deployment)
  --port    Port number (default: 8080)
  --config  Path to JSON config file (default: config/default_config.json)
```

### CLI without the web UI

```bash
siem --list-devices                    # tabular device list
siem --list-devices --json             # JSON output
siem --set-device-name 192.168.1.5 NAS
siem --clear-device-name 192.168.1.5
siem --scan-subnet                     # active ping sweep
siem --duration 60                     # run CLI monitor for 60 s
```

---

## Configuration

Edit `config/default_config.json` or supply a custom path with `--config`.

| Key | Default | Description |
|-----|---------|-------------|
| `poll_interval_seconds` | 2 | How often telemetry is collected |
| `max_bytes_per_second` | 5 000 000 | Bytes/s threshold for HIGH alerts |
| `spike_multiplier` | 3.0 | EWMA baseline multiplier for spike detection |
| `include_connections` | true | Collect active TCP/UDP connection metadata |
| `capture_mode` | host | `host` = local sockets only, `pcap` = mirrored/bridged packet sensor |
| `capture_interface` | "" | Optional interface name for pcap sniffing |
| `capture_bpf` | "" | Optional BPF filter for pcap mode (example: `tcp or udp`) |
| `max_packets_per_poll` | 2000 | Packet rows captured per poll in `pcap` mode |
| `packet_payload_preview_bytes` | 64 | Max payload bytes stored as hex preview per packet |
| `tcp_reassembly_max_bytes` | 16384 | Max bytes retained per TCP direction for stream-aware parsers |
| `tcp_reassembly_idle_seconds` | 90 | Idle timeout before dropping TCP reassembly state |
| `pcap_write_rolling_file` | true | Save rolling PCAP file for external decode tools |
| `pcap_rolling_file` | logs/capture_latest.pcap | Path to rolling PCAP capture file |
| `pcap_rolling_max_mb` | 256 | Max rolling PCAP size before truncation/reset |
| `include_bluetooth` | true | Enable local Bluetooth polling and event logging |
| `bluetooth_poll_interval_seconds` | 15 | Poll interval for Bluetooth device state |
| `suspicious_ports` | [23,445,3389,5900] | Ports that trigger MEDIUM alerts |
| `firewall_block_burst_threshold` | 40 | Firewall block count threshold per source/port for brute-force style alerts |
| `firewall_bruteforce_window_seconds` | 300 | Intended time window for brute-force style firewall analysis |
| `firewall_bruteforce_ports` | [22,23,445,3389,5900] | Service ports tracked for brute-force/probing behavior |
| `syn_scan_unique_ports_threshold` | 25 | Unique destination ports from one source before SYN-scan alert |
| `syn_flood_packets_per_source_threshold` | 120 | SYN packet volume threshold per source in one polling batch |
| `icmp_flood_packets_per_source_threshold` | 160 | ICMP packet volume threshold per source in one polling batch |
| `beacon_window_seconds` | 900 | Sliding window for periodic beaconing analysis |
| `beacon_min_observations` | 12 | Minimum packet observations before beaconing rule evaluates |
| `beacon_min_interval_seconds` | 20 | Minimum interval considered for beaconing cadence |
| `beacon_max_interval_seconds` | 120 | Maximum interval considered for beaconing cadence |
| `beacon_max_jitter_ratio` | 0.35 | Max relative timing jitter allowed for periodic beacon alerts |
| `tls_fingerprint_fanout_threshold` | 8 | Distinct destination fan-out threshold for one TLS fingerprint |
| `incident_window_seconds` | 900 | Correlation window used to build incidents from alert activity |
| `incident_min_alerts` | 3 | Minimum alert count required before opening an incident |
| `incident_medium_score_threshold` | 6.0 | Score threshold for medium incident severity |
| `incident_high_score_threshold` | 12.0 | Score threshold for high incident severity |
| `detector_cooldown_seconds` | 300 | Per-rule cooldown to reduce duplicate alert noise |
| `resolve_device_hostnames` | true | Attempt to resolve device names for inventory entries |
| `hostname_resolution_timeout_ms` | 1200 | Timeout for Windows name discovery probes (for example `ping -a`) |
| `events_retention_hours` | 24 | How long event/connection logs are kept |
| `alerts_retention_hours` | 72 | How long alert logs are kept (3 days) |
| `log_prune_interval_minutes` | 30 | How often the background pruner runs |

All retention settings can also be changed live from the dashboard **Settings** view.

---

## Server Deployment

To expose the dashboard on a remote server:

```bash
python run.py --host 0.0.0.0 --port 8080
```

> **Security note:** Bind behind a reverse proxy (nginx / Caddy) with TLS and authentication. Do not expose port 8080 to the public internet without protection.

## Whole-Network Capture Setup (VM/Old PC)

To capture traffic from devices other than the SIEM host itself, you must feed traffic to the SIEM sensor NIC:

1. **Switch mirror (SPAN) or TAP**: mirror router/uplink traffic to the sensor NIC.
2. **VM networking**: use **bridged mode** and allow **promiscuous mode**.
3. **Windows packet capture driver**: install **Npcap**.
4. Start SIEM in packet-sensor mode:

```bash
python run.py --capture-mode pcap --capture-filter "tcp or udp"
```

Without mirroring/TAP, the SIEM can still discover devices (ARP/ping), but it cannot observe their inter-device traffic.

### Deployment Validation Checklist (Dedicated Sensor + Managed Switch)

Use this after wiring your dedicated sensor host to a mirror/SPAN destination port.

1. Switch/SPAN setup
  - Mirror router uplink and key VLAN trunks/uplinks.
  - Mirror both ingress and egress where your switch supports it.
  - Confirm mirror destination port is sensor-only and not used by normal clients.
2. Sensor host prerequisites
  - Install Npcap on Windows.
  - Use a dedicated machine with stable power and SSD storage.
  - Ensure NIC speed can handle expected mirrored throughput.
3. SIEM runtime checks
  - Start with `python run.py --capture-mode pcap --capture-filter "ip or ip6"`.
  - Open `/api/system/status` and confirm `pcap_dependency_ok`, `pcap_runtime_ok`, and `packet_flow_ok` are true.
  - Verify packet rate is non-zero during known traffic.
4. Telemetry verification
  - Confirm `logs/packets.jsonl`, `logs/firewall_blocks.jsonl`, and `logs/alerts.jsonl` are updating.
  - Trigger benign test traffic (DNS queries, SSH/RDP login attempts) and verify events appear.
5. Detection verification
  - SYN-scan test: run a controlled scan against a lab host and verify `possible_syn_port_scan` alert.
  - Brute-force style test: repeated failed inbound attempts to monitored ports should trigger `possible_bruteforce_or_service_attack`.
  - Flood test in lab: high-rate ICMP/SYN traffic should trigger flood alerts.

### Additional Attack Coverage Implemented

With pcap mode and firewall logs enabled, the detector now includes:

- SYN port-scan detection (`possible_syn_port_scan`)
- SYN flood detection (`possible_syn_flood`)
- ICMP flood detection (`possible_icmp_flood`)
- Repeated blocked attempts on sensitive service ports (`possible_bruteforce_or_service_attack`)
- High generic firewall block volume from one source (`high_firewall_block_volume`)

---

## Project Structure

```
SIEM Tool/
├── run.py                          ← standalone launcher
├── .env                            ← your API keys (gitignored)
├── .env.example                    ← copy to .env
├── config/
│   └── default_config.json         ← base SIEM configuration
├── logs/                           ← auto-created; all persistent data
│   ├── events.jsonl
│   ├── connections.jsonl
│   ├── packets.jsonl
│   ├── alerts.jsonl
│   ├── bluetooth.jsonl
│   ├── devices.json
│   ├── device_aliases.json
│   └── siem_settings.json          ← runtime settings saved via UI
└── src/siem_tool/
    ├── config.py                   ← SIEMConfig dataclass + loader
    ├── models.py                   ← NetworkEvent, Alert, ConnectionEvent, DeviceRecord
    ├── collector.py                ← psutil telemetry collector
    ├── detector.py                 ← rule-based anomaly detector
    ├── storage.py                  ← JSONL persistence
    ├── device_monitor.py           ← ARP scanning, device inventory, aliases
    ├── engine.py                   ← orchestrates all components
    ├── log_manager.py              ← log retention / pruning
    ├── server.py                   ← FastAPI app (REST + SSE + AI)
    ├── cli.py                      ← argparse CLI entry point
    └── static/
        ├── index.html
        ├── style.css
        └── app.js
```

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Dashboard HTML |
| GET | `/api/stats` | Summary counts + bandwidth |
| GET | `/api/system/status` | Runtime sensor status + health checks |
| GET | `/api/startup/diagnostics` | Startup blockers and remediation suggestions |
| GET | `/api/setup/wizard` | First-run readiness checklist |
| GET | `/api/devices` | All discovered devices |
| PUT | `/api/devices/{ip}/alias` | Set device name |
| DELETE | `/api/devices/{ip}/alias` | Clear device name |
| POST | `/api/scan` | Trigger subnet ping-sweep |
| POST | `/api/network/ping` | Ping a specific device by IP and return current health row |
| GET | `/api/alerts?limit=N` | Alert history |
| GET | `/api/incidents?limit=N` | Correlated incidents (Phase 4) |
| GET | `/api/incidents/summary` | Incident totals by severity |
| POST | `/api/incidents/triage` | Update incident status/owner/notes (`open`, `acknowledged`, `closed`) |
| GET | `/api/incidents/{incident_key}/timeline` | Incident activity timeline |
| GET | `/api/incidents/chains` | Time-based attack chain correlations |
| GET | `/api/events?limit=N` | Recent bandwidth events |
| GET | `/api/connections?limit=N` | Recent connections |
| GET | `/api/packets?limit=N` | Recent packet metadata + app-layer enrichment (pcap mode) |
| GET | `/api/packets/flows?limit=N` | Aggregated directional packet flows (top by bytes/packets) |
| GET | `/api/packets/conversations?limit=N` | Aggregated bidirectional packet conversations |
| GET | `/api/risk/hosts` | Host threat scoring from multi-source telemetry |
| GET | `/api/detections/controls` | Per-rule noise controls and suppression rules |
| POST | `/api/detections/controls` | Save rule enable/mute/threshold/suppression controls |
| POST | `/api/alerts/mark-expected` | Suppress expected/false-positive alert patterns |
| GET | `/api/detections/baseline` | Baseline learning status and tuning suggestion |
| POST | `/api/detections/baseline/apply-suggestion` | Apply baseline-derived threshold recommendation |
| POST | `/api/detections/simulate` | Rule test harness with sample telemetry payloads |
| GET | `/api/views/saved` | Saved dashboard filters/views |
| POST | `/api/views/saved` | Save named dashboard view/filter set |
| DELETE | `/api/views/saved/{name}` | Delete saved view |
| GET | `/api/assets/criticality` | Asset criticality weight map |
| POST | `/api/assets/criticality` | Set criticality weight for host/IP |
| DELETE | `/api/assets/criticality/{host}` | Remove host criticality override |
| GET | `/api/integrations/tshark` | TShark availability + rolling pcap status |
| GET | `/api/packets/decode?frame_number=N` | Deep decode (`tshark -V`) for a captured frame |
| GET | `/api/bluetooth?limit=N` | Recent Bluetooth events |
| GET | `/api/stream/alerts` | SSE live alert stream |
| GET | `/api/settings` | Current retention settings |
| POST | `/api/settings` | Update retention + API key |
| POST | `/api/logs/prune` | Archive old active log entries by retention policy |
| POST | `/api/logs/archive/clear` | Clear long-term archived log storage |
| POST | `/api/ai/analyze` | AI analysis (requires `OPENAI_API_KEY`) |
| GET | `/api/docs` | Interactive Swagger API docs |

`/api/ai/analyze` supports agent routing with `agent_type` values:
- `alert_triage`
- `incident_commander`
- `traffic_forensics`
- `device_risk`
- `network_health_reliability`
- `soc_copilot`

Additional optional context arrays are supported:
- `context_incidents`
- `context_health`


## Current Scope (Phase 1)

- Local single-host collection
- Polling-based telemetry every N seconds
- Rule-based anomaly detection:
	- absolute bandwidth threshold
	- relative bandwidth spike detection
	- suspicious local port activity
  - SYN scan / SYN flood / ICMP flood indicators (pcap mode)
  - firewall-block burst brute-force indicators
  - periodic beaconing indicators (timing/jitter based)
  - unusual TLS fingerprint fan-out indicators
	- correlated incidents (Phase 4 actor/family scoring)
	- high established-connection fan-out from one remote IP
- Local JSONL output

## Future Scope (Phase 2+)

- Stream ingestion from multiple agents
- Authentication between agents and server
- Central event pipeline (e.g., queue + database)
- Alert routing (email, webhook, Slack)
- Enrichment and correlation rules

## Quick Start

1. Create and activate a Python virtual environment.
2. Install editable package:

```bash
pip install -e .
```

3. Run with defaults:

```bash
siem
```

4. Run with custom settings:

```bash
siem --config config/default_config.json --duration 120
```

5. List discovered devices:

```bash
siem --list-devices
```

6. Assign a custom name to a device IP:

```bash
siem --set-device-name 192.168.1.20 "Office-Laptop"
```

## Output

- `logs/events.jsonl`: one network event per line
- `logs/connections.jsonl`: one connection event per line
- `logs/packets.jsonl`: packet metadata rows in pcap mode
- `logs/firewall_blocks.jsonl`: parsed Windows Firewall block events
- `logs/alerts.jsonl`: one alert per line
- `logs/devices.json`: current discovered device inventory
- `logs/device_aliases.json`: user-defined names by IP
- `logs/archive/*.jsonl`: long-term archived records moved from active logs by retention pruning

Retention controls:
- `events_retention_hours`: active events/connections/packets/bluetooth/firewall retention window
- `alerts_retention_hours`: active alerts retention window
- `archive_retention_days`: maximum age for archived files before auto-delete

## Notes

- In `host` capture mode, telemetry is based on host counters and active local sockets.
- In `pcap` capture mode, packet metadata and payload previews are captured from mirrored traffic.
- Connection collection relies on `psutil.net_connections` and may require elevated privileges on some hosts.
- Device inventory is local-network focused by default (private/link-local addresses, excluding broadcast-style addresses).
- Device naming attempts include reverse DNS and (on Windows) network-display fallbacks such as `ping -a` and `nbtstat -A`.
- You may need elevated privileges on some environments for richer network data sources.
