# AVA CORE Edge Agent – Operational Playbooks

## PB-001: High Temperature Alert

**Trigger:** `type: temperature`, `severity: high`

**Steps:**
1. Identify the `asset_id` in the alert.
2. Physically inspect the cabinet for blocked ventilation, failed fans, or heat sources.
3. Check current load (`currentA`) – high current produces heat.
4. If temperature exceeds 65 °C on a critical asset, initiate safe shutdown via `allowed_actions: safe_shutdown_request`.
5. Do not resume operation until root cause is resolved.

**Threshold:** `telemetryThresholds.maxTemperatureC` (default: 55 °C)

---

## PB-002: Overcurrent Alert

**Trigger:** `type: current`, `severity: high`

**Steps:**
1. Identify `asset_id` – check whether it is a circuit breaker (`QF`) or PLC.
2. Verify actual load versus rated current for the device.
3. If the circuit breaker has not tripped, investigate downstream loads for shorts or overloads.
4. If `currentA` remains elevated after load reduction, escalate to maintenance.

**Threshold:** `telemetryThresholds.maxCurrentA` (default: 16 A)

---

## PB-003: Voltage Out-of-Range Alert

**Trigger:** `type: voltage`, `severity: medium`

**Steps:**
1. Check the cabinet's incoming supply voltage at the main terminals.
2. Verify the power supply unit (PSU) output if present.
3. Low voltage (`< 210 V`) may indicate supply issues or heavy load elsewhere.
4. High voltage (`> 250 V`) may damage sensitive electronics – consider disconnecting non-critical loads.

**Threshold:** `telemetryThresholds.minVoltageV` / `maxVoltageV` (default: 210–250 V)

---

## PB-004: Unknown External IP Detected

**Trigger:** `type: unknown_ip`, `severity: high`

**Steps:**
1. Check `evidence.remoteAddress` and `evidence.processName`.
2. Verify whether the process is expected to access the internet.
3. If `action_taken: firewall_block:<IP>` is set, the IP is already blocked by AVA.
4. If the connection is legitimate, add the IP to `network.allowedRemoteIPs` in `ava_config.json`.
5. If the connection is not legitimate, investigate the process for malware or unauthorised software.
6. Review `reports/network_snapshot.json` for the full connection context.

---

## PB-005: Connection Flood

**Trigger:** `type: connection_flood`, `severity: high`

**Steps:**
1. Identify the `remoteAddress` with excessive connections.
2. Determine which processes own those connections (`reports/network_snapshot.json`).
3. If this is a scanning or DDoS attempt, block the IP via the firewall.
4. Reduce `network.maxConnectionsPerRemoteIP` in config if threshold was too permissive.

---

## PB-006: Port Anomaly

**Trigger:** `type: port_anomaly`, `severity: medium`

**Steps:**
1. Review `evidence.remotePort` and `evidence.processName`.
2. Assess whether the process has a legitimate reason to use this port.
3. If unexpected, investigate the process and consider terminating it.
4. Add the port to `network.allowedPorts` if it is a known-good service.

---

## General Escalation

| Condition | Action |
|-----------|--------|
| 3+ high alerts in one cycle | Notify on-call engineer |
| Critical asset unreachable | Initiate emergency response procedure |
| AVA agent not running | Check Windows Task Scheduler (`AVA_CORE_Edge_Monitor`) |
| Log file growing rapidly | Review `logs/ava_core.log` for ERROR entries |
