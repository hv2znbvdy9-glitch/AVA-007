# MQTT Connector

Connects AVA CORE to an MQTT broker for real-time telemetry ingestion from IoT sensors and gateways.

## Planned Functionality

- Subscribe to MQTT topics mapped to AVA asset telemetry tags
- Support TLS and authentication
- Write normalised telemetry to `data/telemetry.json`

## Configuration (planned)

```json
{
  "mqtt": {
    "broker": "mqtt://192.168.1.100:1883",
    "clientId": "ava-core-edge",
    "topics": [
      { "topic": "cabinet/cab1/qf1/temp",    "tag": "cab1.qf1.temp" },
      { "topic": "cabinet/cab1/qf1/current", "tag": "cab1.qf1.current" }
    ]
  }
}
```

## Status

🚧 **Planned** – not yet implemented.
