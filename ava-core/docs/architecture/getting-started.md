# AVA CORE – Getting Started

## Requirements

- Windows 10 / Windows Server 2016 or later
- PowerShell 5.1 or later
- Administrator privileges (required for network monitoring and firewall rules)

## Quick Start

### 1. Run once (manual check)

```powershell
powershell -ExecutionPolicy Bypass -File .\apps\edge-agent\AVA-Core-Edge.ps1 -RunOnce
```

### 2. Run continuously (foreground loop, 1-second cycles)

```powershell
powershell -ExecutionPolicy Bypass -File .\apps\edge-agent\AVA-Core-Edge.ps1
```

### 3. Install as a Windows Scheduled Task (starts at boot, runs as SYSTEM)

```powershell
# Must be run as Administrator
powershell -ExecutionPolicy Bypass -File .\apps\edge-agent\AVA-Core-Edge.ps1 -InstallTask
```

### 4. Custom base path and loop interval

```powershell
powershell -ExecutionPolicy Bypass -File .\apps\edge-agent\AVA-Core-Edge.ps1 `
    -BasePath "D:\AVA_CORE" `
    -LoopSeconds 5
```

## Configuration

On first run, AVA creates the following structure under `%ProgramData%\AVA_CORE\` (or the path given by `-BasePath`):

```
AVA_CORE\
├── config\
│   ├── ava_config.json    ← main configuration
│   └── assets.json        ← asset catalogue
├── data\
│   ├── telemetry.csv      ← optional: write live telemetry here
│   └── telemetry.json     ← optional: write live telemetry here (preferred)
├── logs\
│   └── ava_core.log
├── reports\
│   ├── alerts.json
│   ├── status.json
│   └── network_snapshot.json
└── state\
    └── runtime_state.json
```

Edit `config/ava_config.json` to adjust thresholds and network rules. Changes are picked up on the next monitoring cycle without restarting.

## Providing Telemetry

Place a `telemetry.json` file in the `data/` directory.  
AVA reads it each cycle. See `data/examples/telemetry_sample.json` for the expected format.

If no telemetry file is present, AVA generates randomised demo values for all configured assets.

## Reviewing Output

| File | Contents |
|------|----------|
| `reports/alerts.json` | All detected anomalies (last 500) |
| `reports/status.json` | Latest cycle summary (health, alert counts) |
| `reports/network_snapshot.json` | Snapshot of all active TCP connections |
| `logs/ava_core.log` | Full timestamped event log |
