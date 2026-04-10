# AVA CORE – Architecture Overview

## System Purpose

AVA CORE is a **defensive industrial monitoring platform** designed to provide real-time awareness and anomaly detection for electrical cabinets and OT/IT environments.

It runs as a lightweight edge agent on Windows systems, continuously monitoring:

- Telemetry from PLCs, circuit breakers, sensors and other field devices
- Network connections to detect unknown external hosts and anomalous traffic
- System state and asset health

---

## Directory Structure

```
ava-core/
├── apps/
│   ├── api/            # REST API (future: Node.js / FastAPI)
│   ├── edge-agent/     # PowerShell MVP edge monitoring agent
│   └── ui/             # Web dashboard (future)
├── services/
│   ├── asset-graph/    # Asset relationship graph engine
│   ├── twin-mapper/    # Digital twin mapping service
│   ├── detection-engine/   # Rule and ML-based anomaly detection
│   ├── response-engine/    # Automated response orchestration
│   ├── explain-engine/     # Alert explanation and context generation
│   └── security-engine/    # Security policy evaluation
├── connectors/
│   ├── opcua/          # OPC-UA connector
│   ├── mqtt/           # MQTT connector
│   ├── files/          # File-based CSV/JSON telemetry ingestion
│   └── camera/         # Camera image capture connector
├── models/
│   ├── schemas/        # JSON schemas for assets, alerts, telemetry
│   └── ml/             # Machine-learning model artefacts
├── data/
│   ├── seeds/          # Default/seed data for cabinets and assets
│   └── examples/       # Example telemetry datasets
├── infra/
│   ├── docker/         # Docker Compose and Dockerfiles
│   └── k8s/            # Kubernetes manifests
└── docs/
    ├── architecture/   # Architecture documentation (this file)
    ├── api/            # API reference documentation
    └── playbooks/      # Operational response playbooks
```

---

## Edge Agent (MVP)

The **AVA-Core-Edge.ps1** PowerShell script is the MVP implementation. It runs on a Windows host inside or near the electrical cabinet.

### Monitoring Pipeline (per cycle)

```
Telemetry source (CSV / JSON / Demo)
        │
        ▼
Test-TelemetryRules
  ├─ Temperature threshold
  ├─ Current threshold
  └─ Voltage range
        │
        ▼
Get-NetworkSnapshot  (Get-NetTCPConnection)
        │
        ▼
Test-NetworkAnomalies
  ├─ Unknown external IP  →  Invoke-BlockIP (optional)
  ├─ Disallowed remote port
  └─ Connection flood detection
        │
        ▼
Add-AlertsToFile  (reports/alerts.json, max 500 entries)
        │
        ▼
Write-StatusReport  (reports/status.json)
        │
        ▼
Save State  (state/runtime_state.json)
```

### Data Flow

| Input | Location | Format |
|-------|----------|--------|
| Telemetry (live) | `data/telemetry.json` | JSON array |
| Telemetry (batch) | `data/telemetry.csv` | CSV |
| Asset catalogue | `config/assets.json` | JSON |
| Runtime config | `config/ava_config.json` | JSON |

| Output | Location | Description |
|--------|----------|-------------|
| Alerts | `reports/alerts.json` | Detected anomalies (last 500) |
| Status | `reports/status.json` | Latest cycle summary |
| Network snapshot | `reports/network_snapshot.json` | TCP connection map |
| Runtime state | `state/runtime_state.json` | Seen IPs, last run time |
| Log | `logs/ava_core.log` | Timestamped event log |

---

## Asset Model

Assets are described in JSON conforming to `models/schemas/asset.schema.json`.

Key fields:
- `asset_id` – unique identifier (e.g. `CAB1-QF1`)
- `type` – device type (circuit_breaker, plc, sensor, …)
- `criticality` – `low | medium | high | critical`
- `allowed_actions` – what AVA may do autonomously
- `dependencies` – other asset IDs this asset depends on
- `telemetry` – tag mapping for temperature, current, voltage

---

## Alert Severity Levels

| Severity | Meaning |
|----------|---------|
| `low` | Informational, no immediate action required |
| `medium` | Attention needed soon |
| `high` | Immediate investigation required |
| `critical` | System integrity at risk, automated response triggered |

---

## Automated Containment

When `actions.blockUnknownExternalIPs` and `actions.createFirewallRules` are enabled in the config, AVA will automatically create outbound Windows Firewall rules to block unknown external IPs on first detection.

Rules are named `AVA_Block_<IP>` and are persistent across reboots.

> **Note:** Requires Administrator privileges.

---

## Future Architecture (Planned)

- **API layer** (Node.js / FastAPI) exposing alerts, assets, and status over REST/WebSocket
- **Web dashboard** for real-time monitoring and asset map visualisation
- **Digital twin mapper** linking physical assets to their telemetry and network identity
- **ML anomaly detection** replacing static thresholds with learned baselines
- **OPC-UA / MQTT connectors** for direct PLC integration
- **Kubernetes deployment** for multi-cabinet edge fleet management
