# AVA CORE

AVA CORE is a **defensive industrial monitoring platform** for electrical cabinets and OT/IT environments.

It continuously monitors telemetry and network activity to detect anomalies and, where configured, respond automatically.

---

## Project Structure

| Directory | Purpose |
|-----------|---------|
| `apps/edge-agent/` | PowerShell MVP edge monitoring agent (**start here**) |
| `apps/api/` | REST API server (planned) |
| `apps/ui/` | Web dashboard (planned) |
| `connectors/opcua/` | OPC-UA telemetry connector (planned) |
| `connectors/mqtt/` | MQTT telemetry connector (planned) |
| `connectors/files/` | CSV/JSON file-based telemetry (implemented) |
| `connectors/camera/` | Camera connector (planned) |
| `services/detection-engine/` | Rule and ML-based anomaly detection (planned) |
| `services/response-engine/` | Automated response orchestration (planned) |
| `services/asset-graph/` | Asset relationship graph (planned) |
| `services/twin-mapper/` | Digital twin mapping (planned) |
| `services/explain-engine/` | Alert explanation and context (planned) |
| `services/security-engine/` | Security policy evaluation (planned) |
| `models/schemas/` | JSON schemas for assets, alerts, telemetry |
| `data/seeds/` | Default cabinet and asset data |
| `data/examples/` | Example telemetry datasets |
| `infra/docker/` | Docker Compose setup (planned) |
| `infra/k8s/` | Kubernetes manifests (planned) |
| `docs/architecture/` | Architecture documentation |
| `docs/playbooks/` | Operational response playbooks |

---

## Quick Start

See [`docs/architecture/getting-started.md`](docs/architecture/getting-started.md) for full instructions.

```powershell
# Run a single monitoring cycle
powershell -ExecutionPolicy Bypass -File .\apps\edge-agent\AVA-Core-Edge.ps1 -RunOnce

# Run continuously (1-second cycle)
powershell -ExecutionPolicy Bypass -File .\apps\edge-agent\AVA-Core-Edge.ps1

# Install as a Windows Scheduled Task (requires Admin)
powershell -ExecutionPolicy Bypass -File .\apps\edge-agent\AVA-Core-Edge.ps1 -InstallTask
```

---

## Key Concepts

- **Asset** – a physical device in the cabinet (circuit breaker, PLC, sensor, …) described by `models/schemas/asset.schema.json`
- **Alert** – a detected anomaly (temperature, current, voltage, network) described by `models/schemas/alert.schema.json`
- **Defensive mode** – AVA monitors and alerts; in auto-containment mode it may also block unknown external IPs via Windows Firewall
- **Telemetry** – sensor readings (temperature °C, current A, voltage V) provided via file, MQTT, or OPC-UA

---

## Documentation

- [Architecture Overview](docs/architecture/overview.md)
- [Getting Started](docs/architecture/getting-started.md)
- [Response Playbooks](docs/playbooks/response-playbooks.md)

---

## Asset Example

```json
{
  "asset_id": "CAB1-QF1",
  "type": "circuit_breaker",
  "cabinet": "CAB1",
  "criticality": "high",
  "dependencies": ["CAB1-K1", "CAB1-PLC1"],
  "allowed_actions": ["alert", "safe_shutdown_request"]
}
```

---

## License

See repository root `license` file.
