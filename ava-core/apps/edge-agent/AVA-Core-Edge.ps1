#Requires -Version 5.1
<#
AVA CORE EDGE - Defensives Monitoring MVP
-----------------------------------------
Funktionen:
- Erstellt eine AVA-Arbeitsstruktur
- Liest Konfiguration aus JSON
- Überwacht Telemetrie aus CSV/JSON oder Demo-Daten
- Erkennt Temperatur-, Strom- und Spannungs-Anomalien
- Überwacht Netzwerkverbindungen
- Erkennt unbekannte externe Ziele
- Optional: blockiert auffällige externe IPs per Firewall
- Schreibt Alerts, Status und Reports

Start:
  powershell -ExecutionPolicy Bypass -File .\AVA-Core-Edge.ps1

Optional:
  powershell -ExecutionPolicy Bypass -File .\AVA-Core-Edge.ps1 -InstallTask
  powershell -ExecutionPolicy Bypass -File .\AVA-Core-Edge.ps1 -RunOnce
#>

[CmdletBinding()]
param(
    [switch]$InstallTask,
    [switch]$RunOnce,
    [string]$BasePath = "$env:ProgramData\AVA_CORE",
    [int]$LoopSeconds = 1
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ------------------------------------------------------------
# HILFSFUNKTIONEN
# ------------------------------------------------------------

function Test-IsAdmin {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Ensure-Admin {
    if (-not (Test-IsAdmin)) {
        throw "Dieses Skript muss als Administrator gestartet werden."
    }
}

function Ensure-Directory {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -Path $Path -ItemType Directory -Force | Out-Null
    }
}

function Write-Log {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO','WARN','ERROR','ALERT','ACTION')][string]$Level = 'INFO'
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = "[$timestamp] [$Level] $Message"
    $logFile = Join-Path $script:LogPath 'ava_core.log'
    Add-Content -Path $logFile -Value $line -Encoding UTF8
    Write-Host $line
}

function Save-Json {
    param(
        [Parameter(Mandatory)]$Object,
        [Parameter(Mandatory)][string]$Path
    )
    $Object | ConvertTo-Json -Depth 10 | Set-Content -Path $Path -Encoding UTF8
}

function Load-Json {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        return $null
    }
    return (Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json)
}

function Initialize-Workspace {
    $script:ConfigPath  = Join-Path $BasePath 'config'
    $script:DataPath    = Join-Path $BasePath 'data'
    $script:LogPath     = Join-Path $BasePath 'logs'
    $script:ReportPath  = Join-Path $BasePath 'reports'
    $script:StatePath   = Join-Path $BasePath 'state'

    Ensure-Directory -Path $BasePath
    Ensure-Directory -Path $script:ConfigPath
    Ensure-Directory -Path $script:DataPath
    Ensure-Directory -Path $script:LogPath
    Ensure-Directory -Path $script:ReportPath
    Ensure-Directory -Path $script:StatePath

    $script:ConfigFile   = Join-Path $script:ConfigPath 'ava_config.json'
    $script:AssetFile    = Join-Path $script:ConfigPath 'assets.json'
    $script:TelemetryCsv = Join-Path $script:DataPath   'telemetry.csv'
    $script:TelemetryJson= Join-Path $script:DataPath   'telemetry.json'
    $script:AlertFile    = Join-Path $script:ReportPath 'alerts.json'
    $script:StatusFile   = Join-Path $script:ReportPath 'status.json'
    $script:NetworkFile  = Join-Path $script:ReportPath 'network_snapshot.json'
    $script:StateFile    = Join-Path $script:StatePath  'runtime_state.json'
}

function Initialize-DefaultFiles {
    if (-not (Test-Path -LiteralPath $script:ConfigFile)) {
        $defaultConfig = @{
            system = @{
                name    = 'AVA CORE EDGE'
                version = '1.0'
                mode    = 'defensive'
            }
            runtime = @{
                loopSeconds        = $LoopSeconds
                autoContainment    = $true
                maxAlertsPerCycle  = 25
            }
            telemetryThresholds = @{
                maxTemperatureC = 55
                maxCurrentA     = 16
                minVoltageV     = 210
                maxVoltageV     = 250
            }
            network = @{
                allowedRemoteIPs = @(
                    '8.8.8.8',
                    '1.1.1.1'
                )
                allowedPorts            = @(80, 443, 53)
                ignorePrivateRanges     = $true
                maxConnectionsPerRemoteIP = 30
            }
            actions = @{
                blockUnknownExternalIPs = $true
                createFirewallRules     = $true
                firewallRulePrefix      = 'AVA_Block_'
            }
        }
        Save-Json -Object $defaultConfig -Path $script:ConfigFile
    }

    if (-not (Test-Path -LiteralPath $script:AssetFile)) {
        $defaultAssets = @{
            cabinet = @{
                id       = 'CAB1'
                name     = 'Schaltschrank 1'
                location = 'Werkbank / Demo'
            }
            devices = @(
                @{
                    asset_id    = 'CAB1-QF1'
                    type        = 'circuit_breaker'
                    name        = 'Leitungsschutzschalter QF1'
                    telemetry   = @{
                        tempTag    = 'cab1.qf1.temp'
                        currentTag = 'cab1.qf1.current'
                        voltageTag = 'cab1.qf1.voltage'
                    }
                    criticality = 'high'
                },
                @{
                    asset_id    = 'CAB1-PLC1'
                    type        = 'plc'
                    name        = 'PLC1'
                    telemetry   = @{
                        tempTag    = 'cab1.plc1.temp'
                        currentTag = 'cab1.plc1.current'
                        voltageTag = 'cab1.plc1.voltage'
                    }
                    criticality = 'high'
                }
            )
        }
        Save-Json -Object $defaultAssets -Path $script:AssetFile
    }

    if (-not (Test-Path -LiteralPath $script:AlertFile)) {
        @() | ConvertTo-Json | Set-Content -Path $script:AlertFile -Encoding UTF8
    }

    if (-not (Test-Path -LiteralPath $script:StateFile)) {
        $state = @{
            seenRemoteIPs = @()
            lastRun       = $null
            lastTelemetry = @{}
        }
        Save-Json -Object $state -Path $script:StateFile
    }

    if (-not (Test-Path -LiteralPath $script:TelemetryCsv)) {
@"
timestamp,asset_id,tempC,currentA,voltageV
$(Get-Date -Format s),CAB1-QF1,32.5,7.1,229.0
$(Get-Date -Format s),CAB1-PLC1,35.2,2.8,230.0
"@ | Set-Content -Path $script:TelemetryCsv -Encoding UTF8
    }
}

function Load-ConfigData {
    $script:Config = Load-Json -Path $script:ConfigFile
    $script:Assets = Load-Json -Path $script:AssetFile
    $script:State  = Load-Json -Path $script:StateFile

    if (-not $script:Config) { throw "Konfiguration konnte nicht geladen werden: $script:ConfigFile" }
    if (-not $script:Assets) { throw "Assets konnten nicht geladen werden: $script:AssetFile" }
    if (-not $script:State)  { throw "State konnte nicht geladen werden: $script:StateFile" }
}

function Get-DemoTelemetry {
    $rows = foreach ($device in $script:Assets.devices) {
        [pscustomobject]@{
            timestamp = Get-Date
            asset_id  = $device.asset_id
            tempC     = [math]::Round((Get-Random -Minimum 28 -Maximum 65) + (Get-Random) / 100, 2)
            currentA  = [math]::Round((Get-Random -Minimum 1  -Maximum 20) + (Get-Random) / 100, 2)
            voltageV  = [math]::Round((Get-Random -Minimum 205 -Maximum 252) + (Get-Random) / 100, 2)
        }
    }
    return $rows
}

function Get-Telemetry {
    if (Test-Path -LiteralPath $script:TelemetryJson) {
        try {
            $raw = Get-Content -LiteralPath $script:TelemetryJson -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($raw -is [System.Collections.IEnumerable]) {
                return $raw
            }
            return @($raw)
        }
        catch {
            Write-Log -Level 'WARN' -Message "telemetry.json konnte nicht gelesen werden. Es werden Demo-Daten genutzt."
            return Get-DemoTelemetry
        }
    }

    if (Test-Path -LiteralPath $script:TelemetryCsv) {
        try {
            $csv = Import-Csv -LiteralPath $script:TelemetryCsv
            if ($csv.Count -gt 0) {
                return $csv
            }
        }
        catch {
            Write-Log -Level 'WARN' -Message "telemetry.csv konnte nicht gelesen werden. Es werden Demo-Daten genutzt."
        }
    }

    return Get-DemoTelemetry
}

function New-AlertObject {
    param(
        [string]$Type,
        [string]$Severity,
        [string]$AssetId,
        [string]$Message,
        [hashtable]$Evidence
    )

    return [pscustomobject]@{
        time         = Get-Date -Format 's'
        type         = $Type
        severity     = $Severity
        asset_id     = $AssetId
        message      = $Message
        evidence     = $Evidence
        action_taken = $null
        acknowledged = $false
    }
}

function Add-AlertsToFile {
    param([Parameter(Mandatory)][object[]]$Alerts)

    $existing = @()
    if (Test-Path -LiteralPath $script:AlertFile) {
        try {
            $loaded = Get-Content -LiteralPath $script:AlertFile -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($loaded) {
                $existing = @($loaded)
            }
        }
        catch {
            $existing = @()
        }
    }

    $merged = @($existing + $Alerts) | Select-Object -Last 500
    Save-Json -Object $merged -Path $script:AlertFile
}

function Test-TelemetryRules {
    param([Parameter(Mandatory)][object[]]$TelemetryRows)

    $alerts = New-Object System.Collections.Generic.List[object]
    $t = $script:Config.telemetryThresholds

    foreach ($row in $TelemetryRows) {
        $assetId  = [string]$row.asset_id
        $tempC    = [double]$row.tempC
        $currentA = [double]$row.currentA
        $voltageV = [double]$row.voltageV

        if ($tempC -gt [double]$t.maxTemperatureC) {
            $alerts.Add((New-AlertObject -Type 'temperature' -Severity 'high' -AssetId $assetId `
                -Message "Temperatur zu hoch: $tempC °C" `
                -Evidence @{ tempC = $tempC; threshold = [double]$t.maxTemperatureC }))
        }

        if ($currentA -gt [double]$t.maxCurrentA) {
            $alerts.Add((New-AlertObject -Type 'current' -Severity 'high' -AssetId $assetId `
                -Message "Strom zu hoch: $currentA A" `
                -Evidence @{ currentA = $currentA; threshold = [double]$t.maxCurrentA }))
        }

        if ($voltageV -lt [double]$t.minVoltageV -or $voltageV -gt [double]$t.maxVoltageV) {
            $alerts.Add((New-AlertObject -Type 'voltage' -Severity 'medium' -AssetId $assetId `
                -Message "Spannung außerhalb Bereich: $voltageV V" `
                -Evidence @{ voltageV = $voltageV; min = [double]$t.minVoltageV; max = [double]$t.maxVoltageV }))
        }
    }

    return @($alerts)
}

function Test-IsPrivateIPv4 {
    param([Parameter(Mandatory)][string]$IPAddress)

    if ($IPAddress -match '^10\.')                            { return $true }
    if ($IPAddress -match '^127\.')                           { return $true }
    if ($IPAddress -match '^192\.168\.')                      { return $true }
    if ($IPAddress -match '^172\.(1[6-9]|2[0-9]|3[01])\.')   { return $true }
    if ($IPAddress -eq '0.0.0.0')                            { return $true }
    if ($IPAddress -eq '::')                                  { return $true }
    if ($IPAddress -eq '::1')                                 { return $true }
    return $false
}

function Get-NetworkSnapshot {
    $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
        Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess

    $processMap = @{}
    foreach ($proc in Get-Process -ErrorAction SilentlyContinue) {
        $processMap[$proc.Id] = $proc.ProcessName
    }

    $enriched = foreach ($c in $connections) {
        [pscustomobject]@{
            localAddress  = $c.LocalAddress
            localPort     = $c.LocalPort
            remoteAddress = $c.RemoteAddress
            remotePort    = $c.RemotePort
            state         = $c.State
            owningProcess = $c.OwningProcess
            processName   = if ($processMap.ContainsKey($c.OwningProcess)) { $processMap[$c.OwningProcess] } else { 'unknown' }
        }
    }

    return @($enriched)
}

function Test-NetworkAnomalies {
    param([Parameter(Mandatory)][object[]]$Connections)

    $alerts  = New-Object System.Collections.Generic.List[object]
    $netCfg  = $script:Config.network
    $actCfg  = $script:Config.actions

    $allowedIPs    = @($netCfg.allowedRemoteIPs)
    $allowedPorts  = @($netCfg.allowedPorts)
    $ignorePrivate = [bool]$netCfg.ignorePrivateRanges
    $maxPerIP      = [int]$netCfg.maxConnectionsPerRemoteIP

    # Count connections per remote IP for flood detection
    $ipCount = @{}
    foreach ($conn in $Connections) {
        $remote = [string]$conn.remoteAddress
        if ($ignorePrivate -and (Test-IsPrivateIPv4 -IPAddress $remote)) { continue }
        if (-not $ipCount.ContainsKey($remote)) { $ipCount[$remote] = 0 }
        $ipCount[$remote]++
    }

    # Track seen IPs for new-IP detection
    $seenIPs = [System.Collections.Generic.HashSet[string]]::new(
        [string[]]@($script:State.seenRemoteIPs),
        [System.StringComparer]::OrdinalIgnoreCase
    )
    $newlySeenIPs = New-Object System.Collections.Generic.List[string]

    foreach ($conn in $Connections) {
        $remote = [string]$conn.remoteAddress
        $rport  = [int]$conn.remotePort

        # Skip loopback / private ranges if configured
        if ($ignorePrivate -and (Test-IsPrivateIPv4 -IPAddress $remote)) { continue }

        # Detect unknown external IP
        $isAllowedIP = $allowedIPs -contains $remote
        if (-not $isAllowedIP) {
            if (-not $seenIPs.Contains($remote)) {
                $newlySeenIPs.Add($remote)
                $seenIPs.Add($remote) | Out-Null

                $alert = New-AlertObject -Type 'unknown_ip' -Severity 'high' `
                    -AssetId $null `
                    -Message "Unbekannte externe IP erkannt: $remote (Prozess: $($conn.processName))" `
                    -Evidence @{
                        remoteAddress = $remote
                        remotePort    = $rport
                        localPort     = [int]$conn.localPort
                        processName   = [string]$conn.processName
                        owningProcess = [int]$conn.owningProcess
                    }

                # Automatic containment: block via firewall
                if ([bool]$actCfg.blockUnknownExternalIPs -and [bool]$actCfg.createFirewallRules) {
                    $blocked = Invoke-BlockIP -IPAddress $remote -Prefix ([string]$actCfg.firewallRulePrefix)
                    if ($blocked) {
                        $alert.action_taken = "firewall_block:$remote"
                        Write-Log -Level 'ACTION' -Message "Firewall-Regel erstellt: $remote gesperrt."
                    }
                }

                $alerts.Add($alert)
            }
        }

        # Detect disallowed remote port
        if ($allowedPorts.Count -gt 0 -and $rport -notin $allowedPorts) {
            $alerts.Add((New-AlertObject -Type 'port_anomaly' -Severity 'medium' `
                -AssetId $null `
                -Message "Verbindung auf unerlaubtem Port $rport zu $remote (Prozess: $($conn.processName))" `
                -Evidence @{
                    remoteAddress = $remote
                    remotePort    = $rport
                    processName   = [string]$conn.processName
                }))
        }
    }

    # Detect connection floods
    foreach ($ip in $ipCount.Keys) {
        if ($ipCount[$ip] -gt $maxPerIP) {
            $alerts.Add((New-AlertObject -Type 'connection_flood' -Severity 'high' `
                -AssetId $null `
                -Message "Verbindungsflut von $ip : $($ipCount[$ip]) gleichzeitige Verbindungen (Limit: $maxPerIP)" `
                -Evidence @{
                    remoteAddress     = $ip
                    connectionCount   = $ipCount[$ip]
                    maxAllowed        = $maxPerIP
                }))
        }
    }

    # Persist updated seen-IPs list
    if ($newlySeenIPs.Count -gt 0) {
        $updatedSeen = [System.Linq.Enumerable]::ToArray(
            [System.Linq.Enumerable]::Union(
                [string[]]@($script:State.seenRemoteIPs),
                [string[]]$newlySeenIPs.ToArray()
            )
        )
        $script:State.seenRemoteIPs = $updatedSeen
    }

    return @($alerts)
}

function Invoke-BlockIP {
    param(
        [Parameter(Mandatory)][string]$IPAddress,
        [string]$Prefix = 'AVA_Block_'
    )

    $ruleName = "$Prefix$IPAddress"
    try {
        $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        if ($existing) {
            return $true   # Rule already exists
        }

        New-NetFirewallRule `
            -DisplayName   $ruleName `
            -Direction     Outbound `
            -Action        Block `
            -RemoteAddress $IPAddress `
            -Protocol      Any `
            -Profile       Any `
            -Enabled       True `
            -ErrorAction   Stop | Out-Null

        return $true
    }
    catch {
        Write-Log -Level 'WARN' -Message "Konnte Firewall-Regel für $IPAddress nicht erstellen: $_"
        return $false
    }
}

function Write-StatusReport {
    param(
        [int]$TelemetryAlerts,
        [int]$NetworkAlerts,
        [int]$CycleNumber
    )

    $status = [pscustomobject]@{
        timestamp       = Get-Date -Format 's'
        cycleNumber     = $CycleNumber
        mode            = [string]$script:Config.system.mode
        telemetryAlerts = $TelemetryAlerts
        networkAlerts   = $NetworkAlerts
        totalAlerts     = $TelemetryAlerts + $NetworkAlerts
        seenRemoteIPs   = $script:State.seenRemoteIPs.Count
        health          = if (($TelemetryAlerts + $NetworkAlerts) -eq 0) { 'OK' } else { 'ALERT' }
    }

    Save-Json -Object $status -Path $script:StatusFile
    return $status
}

function Invoke-MonitoringCycle {
    param([int]$CycleNumber = 1)

    Write-Log -Level 'INFO' -Message "=== Zyklus $CycleNumber gestartet ==="

    # --- Reload config & state each cycle to pick up changes ---
    Load-ConfigData

    $cycleAlerts = New-Object System.Collections.Generic.List[object]

    # --- Telemetrie ---
    try {
        $telemetry = Get-Telemetry
        Write-Log -Level 'INFO' -Message "Telemetrie: $($telemetry.Count) Datensätze gelesen."
        $telAlerts = Test-TelemetryRules -TelemetryRows $telemetry
        foreach ($a in $telAlerts) {
            Write-Log -Level 'ALERT' -Message "$($a.type.ToUpper()): $($a.message)"
            $cycleAlerts.Add($a)
        }
    }
    catch {
        Write-Log -Level 'ERROR' -Message "Fehler bei Telemetrie-Verarbeitung: $_"
    }

    # --- Netzwerk ---
    try {
        $snapshot = Get-NetworkSnapshot
        Save-Json -Object $snapshot -Path $script:NetworkFile
        Write-Log -Level 'INFO' -Message "Netzwerk: $($snapshot.Count) Verbindungen erfasst."
        $netAlerts = Test-NetworkAnomalies -Connections $snapshot
        foreach ($a in $netAlerts) {
            Write-Log -Level 'ALERT' -Message "$($a.type.ToUpper()): $($a.message)"
            $cycleAlerts.Add($a)
        }
    }
    catch {
        Write-Log -Level 'ERROR' -Message "Fehler bei Netzwerk-Analyse: $_"
    }

    # --- Alerts speichern ---
    $maxAlerts = [int]$script:Config.runtime.maxAlertsPerCycle
    $toSave = @($cycleAlerts | Select-Object -First $maxAlerts)
    if ($toSave.Count -gt 0) {
        Add-AlertsToFile -Alerts $toSave
    }

    # --- Status schreiben ---
    $telCount = ($cycleAlerts | Where-Object { $_.type -in @('temperature','current','voltage') }).Count
    $netCount = ($cycleAlerts | Where-Object { $_.type -notin @('temperature','current','voltage') }).Count
    $status = Write-StatusReport -TelemetryAlerts $telCount -NetworkAlerts $netCount -CycleNumber $CycleNumber

    # --- State persistieren ---
    $script:State.lastRun = Get-Date -Format 's'
    Save-Json -Object $script:State -Path $script:StateFile

    Write-Log -Level 'INFO' -Message "Zyklus $CycleNumber abgeschlossen. Status: $($status.health) | Alerts: $($status.totalAlerts)"
}

function Install-ScheduledTask {
    Ensure-Admin

    $taskName   = 'AVA_CORE_Edge_Monitor'
    $scriptPath = $MyInvocation.ScriptName

    $action  = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument "-ExecutionPolicy Bypass -NonInteractive -WindowStyle Hidden -File `"$scriptPath`""

    $trigger = New-ScheduledTaskTrigger -AtStartup

    $settings = New-ScheduledTaskSettingsSet `
        -ExecutionTimeLimit (New-TimeSpan -Hours 0) `
        -RestartCount 5 `
        -RestartInterval (New-TimeSpan -Minutes 1) `
        -MultipleInstances IgnoreNew

    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest

    Register-ScheduledTask `
        -TaskName  $taskName `
        -Action    $action `
        -Trigger   $trigger `
        -Settings  $settings `
        -Principal $principal `
        -Force | Out-Null

    Write-Log -Level 'INFO' -Message "Geplante Aufgabe '$taskName' wurde registriert."
    Write-Host "Aufgabe '$taskName' erfolgreich registriert. Das Monitoring startet automatisch beim nächsten Systemstart."
}

# ============================================================
# EINSTIEGSPUNKT
# ============================================================

try {
    Initialize-Workspace
    Initialize-DefaultFiles
    Load-ConfigData

    Write-Log -Level 'INFO' -Message "AVA CORE EDGE $($script:Config.system.version) gestartet. Modus: $($script:Config.system.mode)"
    Write-Log -Level 'INFO' -Message "Basispfad: $BasePath"

    if ($InstallTask) {
        Ensure-Admin
        Install-ScheduledTask
        exit 0
    }

    if ($RunOnce) {
        Invoke-MonitoringCycle -CycleNumber 1
        exit 0
    }

    # Dauerschleife
    $cycle = 0
    while ($true) {
        $cycle++
        try {
            Invoke-MonitoringCycle -CycleNumber $cycle
        }
        catch {
            Write-Log -Level 'ERROR' -Message "Unbehandelter Fehler in Zyklus $cycle : $_"
        }
        Start-Sleep -Seconds $LoopSeconds
    }
}
catch {
    # Ensure the log path is available before writing
    if ($script:LogPath -and (Test-Path -LiteralPath $script:LogPath)) {
        Write-Log -Level 'ERROR' -Message "Fataler Fehler: $_"
    }
    else {
        Write-Error "Fataler Fehler: $_"
    }
    exit 1
}
