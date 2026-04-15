# Lab Deployment Guide

## Goal

Deploy the SIEM in a small analyst-style lab with one central host and one or more Windows endpoints.

This is the recommended way to demonstrate the project on a resume because it shows:

- centralized monitoring
- distributed endpoint collection
- optional network sensor visibility
- analyst-facing investigation workflow in one UI

---

## Recommended Lab Layout

### Central SIEM Host

Run the full dashboard and server on one Windows machine or VM.

Suggested role:

- `SIEM-SERVER`

Responsibilities:

- host the dashboard/API
- receive agent enrollments and uploads
- store telemetry and alerts
- correlate incidents
- optionally run `pcap` mode for mirrored LAN visibility

### Monitored Endpoints

Run the lightweight endpoint agent on one or more Windows systems.

Suggested roles:

- `WIN-CLIENT-01`
- `WIN-CLIENT-02`
- `WIN-LAB-ADMIN`

Responsibilities:

- collect local Windows Event Logs
- collect connection snapshots
- heartbeat to the central host
- forward host telemetry to the SIEM server

---

## Minimum Useful Demo

For a solid portfolio demo, use:

1. One central SIEM host
2. Two Windows endpoints running the agent
3. Optional mirrored/SPAN traffic to the SIEM host for packet visibility

That setup is enough to demonstrate:

- centralized endpoint telemetry
- cross-host alerting
- incident grouping
- analyst triage from one dashboard

---

## Deployment Steps

### 1. Prepare The Central SIEM Host

Install Python and launch the central server:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .
python run.py --host 0.0.0.0 --port 8080
```

Or use:

- `NetworkMonitor-Start.bat`

Optional network sensor mode:

```powershell
python run.py --capture-mode pcap --host 0.0.0.0 --port 8080
```

If you use `pcap` mode, install Npcap and feed mirrored traffic to this host.

### 2. Set The Enrollment Token

Edit `config/default_config.json` on the server and set:

- `agent_enrollment_token`

For resume/demo purposes, use something better than the default lab token.

### 3. Start Endpoint Agents

On each monitored Windows endpoint:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .
siem-agent --server-url http://SIEM-SERVER:8080 --token YOUR_TOKEN
```

Or use:

- `NetworkMonitor-Agent-Start.bat --server-url http://SIEM-SERVER:8080 --token YOUR_TOKEN`

If the systems are on the same subnet and discovery is enabled:

```powershell
siem-agent --token YOUR_TOKEN
```

If you want the agent to survive reboot in a more analyst-like deployment, install it as a Windows service:

```powershell
siem-agent --server-url https://SIEM-SERVER --token YOUR_TOKEN --ca-cert C:\certs\lab-ca.pem --install-service
```

To remove it later:

```powershell
siem-agent --uninstall-service
```

### 4. Verify In The Dashboard

Open the central dashboard and check:

1. `Overview` shows agent counts and recent endpoint activity.
2. `Agents` lists endpoints as `online`.
3. `Agents` telemetry table shows Windows events and connection snapshots.
4. `Alerts` and `Incidents` begin including endpoint-driven detections.

---

## Good Analyst Demo Scenarios

Use benign tests that generate realistic telemetry.

### Failed Logon Test

- Trigger a few failed Windows logons on an endpoint.
- Verify the SIEM raises `agent_windows_failed_logon`.

### Audit Log Clear Test

- In a controlled lab, clear the Security log.
- Verify the SIEM raises `agent_windows_audit_log_cleared`.

### Sensitive Account Change Test

- Create a test local user or add a user to a local group in the lab.
- Verify the SIEM raises `agent_windows_account_change`.

### Network + Endpoint Correlation Demo

- Generate suspicious network activity from an endpoint.
- If the server is also running packet capture, show both:
  - endpoint Windows events
  - network-side packet or flow evidence

This demonstrates a more realistic SIEM use case than host-only or packet-only views.

### PowerShell / Defender / Sysmon Demo

- Install Sysmon on one endpoint if you want richer host telemetry.
- Generate a benign PowerShell test that appears in the operational log.
- Trigger a controlled Defender detection or sample event in a lab.
- Verify those events appear in the `Agents` view and, when applicable, raise endpoint-driven alerts.

---

## Recommended Resume Framing

Good phrasing for the project:

- Built a centralized Python SIEM with distributed Windows endpoint agents and optional packet-sensor support.
- Implemented agent discovery, enrollment, heartbeat monitoring, and batched telemetry upload to a central analysis server.
- Correlated endpoint Windows events with network telemetry in a unified analyst dashboard for alerting and incident triage.

---

## Practical Next Additions

The best next improvements for a stronger analyst-style lab are:

1. Install the agent as a Windows service.
2. Add Sysmon ingestion on endpoints.
3. Add Defender and PowerShell telemetry.
4. Put the server behind HTTPS or a reverse proxy.

## Certificate-Based Auth In Practice

For this repository, certificate-based auth should be implemented with a reverse proxy in front of the SIEM server.

Recommended setup:

1. Reverse proxy terminates HTTPS.
2. Reverse proxy requires client certificates for `/api/agents/*`.
3. Reverse proxy forwards certificate subject and fingerprint headers only after successful mTLS validation.
4. SIEM server is configured with:
  - `agent_require_client_certificate: true`
  - trusted proxy IPs in `agent_trusted_proxy_ips`
5. Agents connect with:
  - `--ca-cert`
  - `--client-cert`
  - `--client-key`

This keeps trust anchored in TLS and lets the SIEM server bind each enrolled endpoint to a certificate fingerprint.
