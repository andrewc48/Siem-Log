# SIEM Implementation Plan

## Goal
Build a simple, local-first Python SIEM that ingests network information and flags unusual activity, while keeping architecture ready for future server deployment.

## Phase 1 (Implemented)

1. Telemetry ingestion from host network interfaces.
2. Connection telemetry ingestion from active socket state.
2. Basic anomaly detection:
- absolute traffic threshold
- relative spike vs moving baseline
 - suspicious monitored local ports
 - remote-IP connection fan-out
3. Structured JSONL persistence for events and alerts.
4. CLI entry point with config and run duration.
5. Device inventory tracking with custom naming aliases.

## Why This First Step

- It proves end-to-end data flow quickly.
- It avoids premature complexity in packet parsing and distributed design.
- It creates stable interfaces (`collector`, `detector`, `storage`) for future expansion.

## Phase 2 (Next)

1. Add richer telemetry sources:
- active connections and ports
- process-level network ownership
 - DNS query metadata
2. Add alert suppression and dedup windows.
3. Add tests for detector rule behavior.
4. Add health metrics and heartbeat logs.
5. Add subnet-scoped active host discovery and periodic refresh cadence controls.

## Phase 3 (Server Deployment Path)

1. Split into agent + server modes.
2. Ship events over HTTPS or message queue.
3. Centralize storage (PostgreSQL/Elastic/OpenSearch).
4. Add authN/authZ, certificates, and signed agent identity.
5. Build dashboard and alert integrations.

See `docs/agent-server-design.md` for the proposed central-host plus lightweight-agent architecture.

## Operational Notes

- Start as local service or scheduled task.
- Keep event schema stable to simplify migration.
- Preserve raw events and derived alerts separately.
