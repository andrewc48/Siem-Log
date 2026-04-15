# Agent / Server SIEM Design

## Goal

Evolve the current local-first SIEM into a central server plus lightweight endpoint agents.

- The central server runs the full dashboard, storage, enrichment, detection, incident workflow, and analyst UI.
- A lightweight endpoint agent runs on user devices and forwards local telemetry to the central host.
- Agents should be able to discover the central server on the local network automatically, while still supporting manual override.

This keeps collection distributed and operations centralized, which is much closer to a real SIEM deployment model.

---

## Target Topology

### Central Server

Runs on one host only.

Responsibilities:

- receive agent registrations and heartbeats
- ingest event batches from agents
- normalize all incoming records into a common event schema
- enrich events with asset context, criticality, threat intel, and geo metadata
- run detections and correlation
- persist raw and derived data
- serve the web UI and API
- manage agent inventory and health state

Existing repo pieces that stay on the server:

- FastAPI dashboard/API
- alerting and correlation logic
- storage and retention
- incidents, views, criticality, and analyst workflow

### Endpoint Agent

Runs on every monitored device.

Responsibilities:

- discover the central server
- collect local telemetry only
- batch and compress events
- queue locally if the server is unavailable
- retry delivery with backoff
- expose only minimal local state

The agent should not include the dashboard, AI, or heavy triage features.

---

## Recommended Collection Split

### Keep On Server

- dashboard and API
- correlation and incident building
- alert suppression controls
- enrichment and asset scoring
- long-term storage and retention
- analyst search and investigation workflows

### Move To Agent

- Windows Event Log / Sysmon collection
- process and connection inventory
- local firewall log ingestion
- local device identity and heartbeat
- optional host-only packet metadata collection

### Optional Hybrid

- leave mirrored LAN packet capture on the central sensor only
- allow agents to send host telemetry but avoid full packet capture unless explicitly enabled

That gives you two telemetry classes:

- network sensor telemetry from the central SIEM host
- endpoint telemetry from distributed agents

---

## Discovery Design

Automatic discovery is reasonable on the same subnet, but it should not be the only mechanism.

### Primary Discovery Method

Use UDP broadcast discovery on a fixed port.

Flow:

1. Agent starts and checks for cached server configuration.
2. If none exists, it sends a UDP broadcast probe on the local subnet.
3. Central server listens on a discovery port and replies with:
   - server name
   - server IP
   - API port
   - TLS enabled or not
   - server instance ID
   - enrollment mode
4. Agent validates the response and attempts registration.
5. Agent caches the chosen server endpoint locally.

Recommended broadcast payload:

```json
{
  "type": "siem_discovery_request",
  "agent_version": "0.1.0",
  "hostname": "WKSTN-014",
  "nonce": "uuid"
}
```

Recommended server reply:

```json
{
  "type": "siem_discovery_response",
  "server_name": "SIEM-HOST",
  "server_url": "https://192.168.1.10:8443",
  "server_id": "uuid",
  "enrollment": "token-required",
  "nonce": "same-uuid"
}
```

### Fallback Discovery Methods

- manual server URL in agent config
- DNS name such as `siem.local` or `siem.company.lan`
- mDNS advertisement for small labs

### Important Constraint

Broadcast discovery generally works only inside the same subnet or VLAN. For routed networks, VPNs, or segmented labs, you still need DNS or manual configuration.

---

## Enrollment And Trust

Automatic discovery should not mean unauthenticated enrollment.

### Recommended Enrollment Model

Use bootstrap tokens.

Flow:

1. Analyst creates an enrollment token on the server.
2. Agent discovers the server or is pointed to it manually.
3. Agent sends token plus device identity during registration.
4. Server validates token and issues an agent ID plus API key or client certificate.
5. Agent stores the issued credential locally and uses it for future uploads.

### Registration Payload

```json
{
  "hostname": "WKSTN-014",
  "fqdn": "wkstn-014.lab.local",
  "os": "Windows 11",
  "username": "current-user-if-allowed",
  "local_ips": ["192.168.1.44"],
  "mac_addresses": ["aa-bb-cc-dd-ee-ff"],
  "agent_version": "0.1.0",
  "token": "bootstrap-token"
}
```

### Credential Options

Best:

- HTTPS with per-agent API key or mutual TLS

Good enough for first implementation:

- HTTPS with bootstrap token exchanged for long-lived agent secret

Do not rely on unauthenticated plaintext UDP plus open HTTP as the steady-state transport.

### Current Repo Reality

The current implementation is intentionally lab-friendly:

- UDP discovery is plaintext and only for same-subnet discovery.
- Event upload currently uses the configured HTTP server endpoint unless you place the app behind TLS.
- Enrollment uses a shared bootstrap token and then server-issued agent secret.

That is acceptable for a home lab or resume demo, but for any serious environment the next step is to put the server behind TLS and rotate away from the default token.

---

## Transport Design

### Protocol

Use HTTPS JSON APIs for control plane and event upload.

Reasons:

- easy to build on top of existing FastAPI server
- simple to debug in a lab
- consistent with future auth and TLS

### Control Plane Endpoints

- `POST /api/agents/register`
- `POST /api/agents/heartbeat`
- `GET /api/agents/config/{agent_id}`
- `POST /api/agents/checkin`

### Data Plane Endpoints

- `POST /api/agents/events/bulk`
- `POST /api/agents/status`
- `POST /api/agents/logs/firewall`

For the first version, one bulk ingest endpoint is enough if each record includes `event_type`.

### Event Upload Format

Use batched NDJSON or JSON arrays with gzip compression.

Recommended shape:

```json
{
  "agent_id": "uuid",
  "sequence": 1482,
  "sent_at": "2026-04-14T22:10:00Z",
  "events": [
    {
      "event_type": "windows_event",
      "collected_at": "2026-04-14T22:09:59Z",
      "host": "WKSTN-014",
      "source": "Security",
      "event_id": 4625,
      "level": "warning",
      "provider": "Microsoft-Windows-Security-Auditing",
      "record": {"...": "raw fields"}
    }
  ]
}
```

---

## Agent Telemetry Scope

Keep the agent intentionally small.

### Phase 1 Agent Data

- heartbeat and host identity
- Windows Event Logs
  - Security
  - System
  - Application
  - Sysmon if installed
- active connection snapshots
- process metadata tied to connections where possible
- local firewall dropped events

### Phase 2 Agent Data

- scheduled task creation
- service install/change events
- PowerShell operational logs
- USB device events
- Defender events

### Avoid In First Agent Version

- full packet capture by default
- heavy local analytics
- local UI
- direct analyst actions beyond basic diagnostics

The server should remain the brain; the agent should remain the collector.

---

## Server-Side Processing Pipeline

Recommended ingest path:

1. Agent uploads raw event batch.
2. Server authenticates agent and attaches asset identity.
3. Server normalizes events into a common schema.
4. Server stores raw source event and normalized event.
5. Detection engine evaluates normalized events.
6. Correlation engine builds alerts, incidents, and host risk.
7. UI shows agent state, telemetry health, and detections.

### Common Event Shape

Add a generalized event model in addition to the current network-specific models.

Suggested fields:

- `event_type`
- `event_subtype`
- `timestamp`
- `agent_id`
- `host`
- `user`
- `source`
- `provider`
- `severity`
- `raw`
- `normalized`
- `tags`

This lets one pipeline handle network, endpoint, and Windows log records consistently.

---

## Reliability Design

### Agent Local Queue

Agents should keep a small on-disk spool.

Behavior:

- append events locally before sending
- mark sent only after server ACK
- retry with exponential backoff
- cap spool size to avoid disk growth
- drop oldest low-value telemetry first if the spool is full

### Sequence Numbers

Each agent should send monotonic sequence numbers so the server can detect gaps, duplicates, or replay.

### Heartbeats

Agents should heartbeat every 30 to 60 seconds with:

- hostname
- current IPs
- queue depth
- last successful upload time
- collector health
- service uptime

The server dashboard should show:

- online
- degraded
- offline
- stale

---

## Security Design

If this is intended to look like a real SIEM on a resume, security controls matter.

Minimum acceptable design:

- TLS for agent-to-server traffic
- per-agent credentials after enrollment
- server-side validation of event size and schema
- replay protection with sequence numbers and timestamps
- audit logs for enrollment, revocation, and configuration changes

Practical guidance for this repository:

- change `agent_enrollment_token` before deploying beyond a personal lab
- do not expose the server directly to the public internet
- prefer reverse proxy TLS termination if you keep the FastAPI app on plain HTTP internally
- treat UDP discovery as convenience only, not trust
- prefer explicit `--server-url` on routed or segmented networks
- keep agent state directories protected because they contain the issued agent credential

Good follow-up design:

- mutual TLS
- enrollment approval workflow
- signed agent packages
- role-based access for agent management in the UI

---

## UI Additions On The Server

Add an Agents view to the central dashboard.

Suggested columns:

- agent status
- hostname
- last seen
- IPs
- OS
- version
- event throughput
- queue depth
- health
- assigned server

Suggested actions:

- approve or revoke agent
- regenerate enrollment token
- view last heartbeat
- inspect per-agent ingest errors
- mute noisy hosts

---

## Suggested Repo Structure

Keep the current app as the server package and add a second package for the endpoint collector.

```text
src/
  siem_tool/
    server.py
    engine.py
    detector.py
    storage.py
    agent_api.py
    agent_registry.py
    normalizer.py
    ingest.py
  siem_agent/
    __init__.py
    cli.py
    discovery.py
    collector.py
    windows_events.py
    transport.py
    spool.py
    heartbeat.py
    identity.py
```

This keeps server and agent concerns separated without forcing a separate repository.

---

## Recommended Build Order

### Step 1

Add server-side agent registry and authenticated ingest endpoints.

### Step 2

Create a minimal agent that:

- discovers server
- registers with token
- sends heartbeat
- uploads simple host identity plus connection snapshots

### Step 3

Add Windows Event Log collection on the agent.

### Step 4

Normalize endpoint events on the server and feed them into detection.

### Step 5

Add agent inventory and health UI.

### Step 6

Add local durable spool and delivery retries.

### Step 7

Add stronger auth, TLS hardening, and enrollment approval.

---

## Resume Framing

This design supports resume bullets like:

- Designed a centralized SIEM architecture with lightweight Windows endpoint agents and automatic server discovery.
- Built secure agent enrollment, heartbeat monitoring, and batched event ingestion over authenticated APIs.
- Separated endpoint collection from central correlation, storage, and incident workflows to mirror production SIEM patterns.
- Implemented resilient event delivery with local spooling, retries, and per-agent health tracking.

---

## Implementation Notes For This Repo

Pragmatic first cut for this codebase:

- keep the current dashboard host as the central server
- keep current packet sensor capability on the server
- add a new `siem_agent` package for endpoint telemetry
- use UDP broadcast discovery only for same-subnet labs
- always support manual `--server-url` override
- use HTTPS plus token enrollment for real uploads

That gets you a design that is realistic, explainable, and implementable without overbuilding the first version.