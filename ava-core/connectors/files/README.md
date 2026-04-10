# File Connector

Reads telemetry from CSV or JSON files written by external data exporters or SCADA historians.

## Supported Formats

- **CSV** (`telemetry.csv`): `timestamp,asset_id,tempC,currentA,voltageV`
- **JSON** (`telemetry.json`): array of objects with the same fields

## Usage

Place `telemetry.csv` or `telemetry.json` in the edge agent's `data/` directory.  
The edge agent automatically reads the newest records each cycle.

See `data/examples/` for sample files.

## Status

✅ **Implemented** – supported by the edge agent MVP.
