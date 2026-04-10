# OPC-UA Connector

Connects AVA CORE to OPC-UA servers for real-time telemetry ingestion from PLCs and field devices.

## Planned Functionality

- Subscribe to OPC-UA node values by tag name
- Map OPC-UA node IDs to AVA asset telemetry tags (`cab1.qf1.temp`, etc.)
- Write normalised telemetry to `data/telemetry.json` for the edge agent

## Configuration (planned)

```json
{
  "opcua": {
    "endpoint": "opc.tcp://192.168.1.10:4840",
    "securityMode": "SignAndEncrypt",
    "subscriptionInterval": 1000,
    "nodes": [
      { "nodeId": "ns=2;s=Cabinet1.QF1.Temperature", "tag": "cab1.qf1.temp" },
      { "nodeId": "ns=2;s=Cabinet1.QF1.Current",     "tag": "cab1.qf1.current" }
    ]
  }
}
```

## Status

🚧 **Planned** – not yet implemented.
