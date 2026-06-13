#requires -RunAsAdministrator
<#
AVA CORE STACK v1
Defensiv / Lokal / Read-Only

Funktionen:
  - Prozess-Graphen (Parent <-> Child <-> Netzwerk)
  - Remote-IP-Reputation (Anzeige/Einordnung, offline Heuristik)
  - Trendanalyse ueber mehrere Tage
  - AVA Memory <-> Alert <-> Prozess <-> Netzwerk Verknuepfung
  - Risiko-Score mit Begruendung
  - Portal-Dashboard mit Zeitachse
  - Integritaetspruefung der AVA-Dateien selbst
  - Windows Defender Telemetrie
  - Baseline + Delta Engine
  - Tangle Hash Chain Event-Log
  - Optional: Nmap-Erkennung (kein Scan)
#>

param(
    [switch]$RunOnce,
    [switch]$CreateBaseline,
    [switch]$OpenPortal
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

# ---------------------------------------------------------------------------
# PATHS
# ---------------------------------------------------------------------------
$Root      = "C:\Windows\SecurityGuardian"
$LogDir    = Join-Path $Root "Logs"
$StateDir  = Join-Path $Root "State"
$ReportDir = Join-Path $Root "Reports"

$EventLog       = Join-Path $LogDir  "events_tangle.jsonl"
$AlertLog       = Join-Path $LogDir  "alerts.jsonl"
$TrendDir       = Join-Path $StateDir "Trend"
$BaselineFile   = Join-Path $StateDir "baseline_core.json"
$TangleState    = Join-Path $StateDir "tangle_state.json"
$IntegrityStore = Join-Path $StateDir "ava_integrity.json"
$PortalFile     = Join-Path $ReportDir "ava_core_portal.html"

foreach ($d in @($Root, $LogDir, $StateDir, $ReportDir, $TrendDir)) {
    New-Item -ItemType Directory -Force -Path $d | Out-Null
}

# ---------------------------------------------------------------------------
# SCRIPT-LEVEL CONSTANTS
# ---------------------------------------------------------------------------

# Suspicious command-line patterns for PowerShell process detection
$SuspiciousCmdPatterns = @(
    "-enc","encodedcommand","-nop","noprofile",
    "-w hidden","windowstyle hidden",
    "downloadstring","invoke-expression","iex ",
    "bypass","-ep bypass","frombase64string"
)

# Ports with elevated network risk
$RiskPorts = @(21, 23, 135, 139, 445, 3389, 5985, 5986)

# Well-known SID for the built-in Administrators group (language-independent)
$AdminGroupSid = "S-1-5-32-544"

# ---------------------------------------------------------------------------
# UTILITY
# ---------------------------------------------------------------------------
function HtmlEncode($v) {
    if ($null -eq $v) { return "" }
    return [System.Net.WebUtility]::HtmlEncode([string]$v)
}

function Sha256Text($Text) {
    $sha   = [System.Security.Cryptography.SHA256]::Create()
    $bytes = [Text.Encoding]::UTF8.GetBytes([string]$Text)
    $hash  = $sha.ComputeHash($bytes)
    return (($hash | ForEach-Object { $_.ToString("x2") }) -join "")
}

function Sha256File($Path) {
    if (-not (Test-Path $Path)) { return $null }
    return (Get-FileHash -Path $Path -Algorithm SHA256).Hash
}

# ---------------------------------------------------------------------------
# TANGLE HASH CHAIN
# ---------------------------------------------------------------------------
function Get-LastTangleHash {
    if (Test-Path $TangleState) {
        try { return (Get-Content $TangleState -Raw | ConvertFrom-Json).last_hash }
        catch {}
    }
    return "GENESIS"
}

function Write-TangleEvent {
    param(
        [string]$Type,
        [string]$Severity = "INFO",
        [string]$Message,
        [hashtable]$Data = @{}
    )

    $prev = Get-LastTangleHash

    $obj = [ordered]@{
        time          = (Get-Date).ToString("s")
        computer      = $env:COMPUTERNAME
        user          = $env:USERNAME
        type          = $Type
        severity      = $Severity
        message       = $Message
        data          = $Data
        previous_hash = $prev
    }

    $raw  = ($obj | ConvertTo-Json -Depth 8 -Compress)
    $hash = Sha256Text $raw
    $obj["hash"] = $hash

    ($obj | ConvertTo-Json -Depth 8 -Compress) | Add-Content -Path $EventLog -Encoding UTF8

    @{ last_hash = $hash; updated = (Get-Date).ToString("s") } |
        ConvertTo-Json | Set-Content $TangleState -Encoding UTF8

    if ($Severity -in @("LOW","MEDIUM","HIGH","CRITICAL")) {
        ($obj | ConvertTo-Json -Depth 8 -Compress) | Add-Content -Path $AlertLog -Encoding UTF8
    }
}

# ---------------------------------------------------------------------------
# INTEGRITY CHECK (AVA files)
# ---------------------------------------------------------------------------
function Get-AvaFiles {
    $avaDir = Split-Path $PSCommandPath -Parent
    $files  = @()
    if (Test-Path $avaDir) {
        $files += Get-ChildItem -Path $avaDir -Filter "AVA*.ps1" -ErrorAction SilentlyContinue |
                  Select-Object -ExpandProperty FullName
    }
    $files += @($EventLog, $AlertLog, $BaselineFile) | Where-Object { Test-Path $_ }
    return $files | Select-Object -Unique
}

function Save-IntegrityBaseline {
    $hashes = [ordered]@{}
    foreach ($f in (Get-AvaFiles)) {
        $hashes[$f] = Sha256File $f
    }
    $hashes | ConvertTo-Json | Set-Content $IntegrityStore -Encoding UTF8
}

function Test-IntegrityBaseline {
    $results = New-Object System.Collections.Generic.List[object]
    if (-not (Test-Path $IntegrityStore)) {
        $results.Add([ordered]@{
            file   = $IntegrityStore
            status = "NO_BASELINE"
            detail = "Integritaets-Baseline fehlt. Wird jetzt erstellt."
        })
        Save-IntegrityBaseline
        return $results
    }

    try {
        $stored = Get-Content $IntegrityStore -Raw | ConvertFrom-Json
    } catch {
        $results.Add([ordered]@{ file = $IntegrityStore; status = "PARSE_ERROR"; detail = $_.Exception.Message })
        return $results
    }

    foreach ($f in (Get-AvaFiles)) {
        $current = Sha256File $f
        $expected = $stored.$f
        if ($null -eq $expected) {
            $results.Add([ordered]@{ file = $f; status = "NEW_FILE";     current = $current })
        } elseif ($expected -ne $current) {
            $results.Add([ordered]@{ file = $f; status = "TAMPERED";     current = $current; expected = $expected })
        } else {
            $results.Add([ordered]@{ file = $f; status = "OK";           hash = $current })
        }
    }

    foreach ($kv in $stored.PSObject.Properties) {
        if (-not (Test-Path $kv.Name)) {
            $results.Add([ordered]@{ file = $kv.Name; status = "DELETED" })
        }
    }

    return $results
}

# ---------------------------------------------------------------------------
# DEFENDER
# ---------------------------------------------------------------------------
function Get-DefenderInfo {
    try {
        $mp = Get-MpComputerStatus
        return [ordered]@{
            available           = $true
            realtime_protection = $mp.RealTimeProtectionEnabled
            antivirus_enabled   = $mp.AntivirusEnabled
            antispyware_enabled = $mp.AntispywareEnabled
            signature_age       = $mp.AntivirusSignatureAge
            last_quick_scan     = $mp.QuickScanEndTime
            last_full_scan      = $mp.FullScanEndTime
            tamper_protection   = $mp.IsTamperProtected
        }
    } catch {
        return [ordered]@{ available = $false; error = $_.Exception.Message }
    }
}

# ---------------------------------------------------------------------------
# PROCESS GRAPH (parent <-> child <-> network)
# ---------------------------------------------------------------------------
function Get-ProcessGraph {
    $allProcs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue

    # Build a PID->CIM map
    $pidMap = @{}
    foreach ($p in $allProcs) { $pidMap[[int]$p.ProcessId] = $p }

    # Build TCP ownership map PID -> @(connections)
    $tcpByPid = @{}
    try {
        $tcpConns = Get-NetTCPConnection -ErrorAction SilentlyContinue
        foreach ($c in $tcpConns) {
            $pid = [int]$c.OwningProcess
            if (-not $tcpByPid.ContainsKey($pid)) { $tcpByPid[$pid] = @() }
            $tcpByPid[$pid] += [ordered]@{
                local_port     = $c.LocalPort
                remote_address = $c.RemoteAddress
                remote_port    = $c.RemotePort
                state          = [string]$c.State
            }
        }
    } catch {}

    $nodes = foreach ($p in $allProcs) {
        $pid  = [int]$p.ProcessId
        $ppid = [int]$p.ParentProcessId
        $cmd  = [string]$p.CommandLine
        $lower = $cmd.ToLowerInvariant()
        $hits  = @($SuspiciousCmdPatterns | Where-Object { $lower.Contains($_) })

        $parentName = if ($pidMap.ContainsKey($ppid)) { $pidMap[$ppid].Name } else { "N/A" }

        [ordered]@{
            pid          = $pid
            ppid         = $ppid
            name         = $p.Name
            parent_name  = $parentName
            path         = $p.ExecutablePath
            command_line = $cmd
            suspicious   = ($hits.Count -gt 0)
            hits         = $hits
            connections  = if ($tcpByPid.ContainsKey($pid)) { $tcpByPid[$pid] } else { @() }
        }
    }

    return @($nodes)
}

function Get-PowerShellProcessInfo {
    Get-CimInstance Win32_Process |
        Where-Object { $_.Name -in @("powershell.exe","pwsh.exe") } |
        ForEach-Object {
            $cmd   = [string]$_.CommandLine
            $lower = $cmd.ToLowerInvariant()
            $hits  = @($SuspiciousCmdPatterns | Where-Object { $lower.Contains($_) })

            [ordered]@{
                pid          = $_.ProcessId
                ppid         = $_.ParentProcessId
                name         = $_.Name
                path         = $_.ExecutablePath
                command_line = $cmd
                suspicious   = ($hits.Count -gt 0)
                hits         = $hits
            }
        }
}

# ---------------------------------------------------------------------------
# REMOTE IP REPUTATION (offline heuristic, no external calls)
# ---------------------------------------------------------------------------
function Get-IpReputation($ip) {
    if ([string]::IsNullOrWhiteSpace($ip) -or $ip -eq "0.0.0.0" -or $ip -eq "::") {
        return [ordered]@{ ip = $ip; category = "LOCAL"; risk = "NONE"; detail = "Kein Remote" }
    }

    # RFC 1918 / loopback
    if ($ip -match '^127\.' -or $ip -eq "::1") {
        return [ordered]@{ ip = $ip; category = "LOOPBACK"; risk = "NONE"; detail = "Loopback" }
    }
    if ($ip -match '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)') {
        return [ordered]@{ ip = $ip; category = "PRIVATE"; risk = "LOW"; detail = "Privates Netz" }
    }

    # Cloud metadata endpoint must be checked before the generic 169.254.* link-local range
    if ($ip -eq "169.254.169.254") {
        return [ordered]@{ ip = $ip; category = "CLOUD_METADATA"; risk = "CRITICAL"; detail = "Cloud-Metadaten-Endpunkt" }
    }
    if ($ip -match '^169\.254\.') {
        return [ordered]@{ ip = $ip; category = "LINK_LOCAL"; risk = "LOW"; detail = "Link-Local" }
    }

    # Tor exit-node heuristic — small representative sample compiled 2025-06.
    # Review periodically against https://check.torproject.org/torbulkexitlist
    $torRanges = @('185\.220\.','45\.142\.','199\.249\.','51\.15\.','91\.108\.')
    foreach ($r in $torRanges) {
        if ($ip -match $r) {
            return [ordered]@{ ip = $ip; category = "TOR_LIKELY"; risk = "HIGH"; detail = "Moeglicherweise Tor-Exit-Node (Heuristik)" }
        }
    }

    # Bogon / documentation ranges
    if ($ip -match '^(0\.|100\.64\.|192\.0\.(0|2)\.|198\.(18|19)\.|198\.51\.100\.|203\.0\.113\.|240\.)') {
        return [ordered]@{ ip = $ip; category = "BOGON"; risk = "MEDIUM"; detail = "Bogon/Reserviert" }
    }

    return [ordered]@{ ip = $ip; category = "PUBLIC"; risk = "INFO"; detail = "Oeffentliche IP (keine Heuristik-Treffer)" }
}

# ---------------------------------------------------------------------------
# NETWORK
# ---------------------------------------------------------------------------
function Get-NetworkInfo {
    $tcp = @(); $udp = @()

    try {
        $tcp = Get-NetTCPConnection |
            Where-Object { $_.State -eq "Established" } |
            Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess
    } catch {}

    try {
        $udp = Get-NetUDPEndpoint |
            Select-Object LocalAddress,LocalPort,OwningProcess
    } catch {}

    $procMap = @{}
    Get-Process | ForEach-Object { $procMap[[int]$_.Id] = $_.ProcessName }

    $tcpOut = foreach ($c in $tcp) {
        $rep = Get-IpReputation $c.RemoteAddress
        [ordered]@{
            protocol       = "TCP"
            local_address  = $c.LocalAddress
            local_port     = $c.LocalPort
            remote_address = $c.RemoteAddress
            remote_port    = $c.RemotePort
            state          = $c.State
            pid            = $c.OwningProcess
            process        = $procMap[[int]$c.OwningProcess]
            ip_reputation  = $rep
        }
    }

    $udpOut = foreach ($u in $udp) {
        [ordered]@{
            protocol      = "UDP"
            local_address = $u.LocalAddress
            local_port    = $u.LocalPort
            pid           = $u.OwningProcess
            process       = $procMap[[int]$u.OwningProcess]
        }
    }

    [ordered]@{ tcp = @($tcpOut); udp = @($udpOut) }
}

# ---------------------------------------------------------------------------
# ADMINS / TASKS / SERVICES
# ---------------------------------------------------------------------------
function Get-Admins {
    # Use the well-known SID S-1-5-32-544 (built-in Administrators) for language independence
    try {
        $group = Get-LocalGroup | Where-Object { $_.SID -eq $AdminGroupSid } | Select-Object -First 1
        if ($group) {
            return Get-LocalGroupMember -Group $group.Name |
                       Select-Object Name,ObjectClass,PrincipalSource
        }
    } catch {}
    # Fallback: try common localized names
    foreach ($name in @("Administrators","Administratoren")) {
        try {
            return Get-LocalGroupMember -Group $name |
                       Select-Object Name,ObjectClass,PrincipalSource
        } catch {}
    }
    return @()
}

function Get-TasksLite {
    try {
        Get-ScheduledTask |
            Where-Object {
                $_.TaskPath -notlike "\Microsoft\*" -and
                $_.TaskName -notlike "AVA*"
            } |
            Select-Object TaskName,TaskPath,State
    } catch { @() }
}

function Get-ServiceLite {
    try {
        Get-CimInstance Win32_Service |
            Where-Object { $_.State -eq "Running" } |
            Select-Object Name,DisplayName,State,StartMode,StartName,PathName
    } catch { @() }
}

function Get-NmapInfo {
    $nmap = Get-Command nmap.exe -ErrorAction SilentlyContinue
    if (-not $nmap) {
        return [ordered]@{ installed = $false; note = "Nmap nicht gefunden. Optional installieren." }
    }
    return [ordered]@{ installed = $true; path = $nmap.Source; note = "Nur Erkennung. Kein Scan ausgefuehrt." }
}

# ---------------------------------------------------------------------------
# SNAPSHOT
# ---------------------------------------------------------------------------
function New-Snapshot {
    [ordered]@{
        time          = (Get-Date).ToString("s")
        computer      = $env:COMPUTERNAME
        user          = $env:USERNAME
        defender      = Get-DefenderInfo
        powershell    = @(Get-PowerShellProcessInfo)
        process_graph = @(Get-ProcessGraph)
        network       = Get-NetworkInfo
        admins        = @(Get-Admins)
        tasks         = @(Get-TasksLite)
        services      = @(Get-ServiceLite)
        nmap          = Get-NmapInfo
    }
}

# ---------------------------------------------------------------------------
# RISK SCORE ENGINE
# ---------------------------------------------------------------------------
function Compute-RiskScore {
    param($Snapshot, $Alerts, $IntegrityResults)

    $score   = 0
    $reasons = New-Object System.Collections.Generic.List[string]

    # Defender checks
    if ($Snapshot.defender.available) {
        if (-not $Snapshot.defender.realtime_protection) {
            $score += 40; $reasons.Add("Defender Echtzeitschutz deaktiviert (+40)")
        }
        if (-not $Snapshot.defender.antivirus_enabled) {
            $score += 30; $reasons.Add("Defender Antivirenschutz deaktiviert (+30)")
        }
        $age = [int]$Snapshot.defender.signature_age
        if ($age -gt 7) {
            $inc = [Math]::Min(20, $age * 2)
            $score += $inc; $reasons.Add("Signaturen $age Tage alt (+$inc)")
        }
    }

    # Suspicious PowerShell
    foreach ($p in $Snapshot.powershell) {
        if ($p.suspicious) {
            $score += 25; $reasons.Add("Verdaechtiger PS-Prozess PID $($p.pid): $($p.hits -join ', ') (+25)")
        }
    }

    # Network reputation
    $highRepCount = 0
    foreach ($c in $Snapshot.network.tcp) {
        $rep = $c.ip_reputation
        if ($rep) {
            switch ($rep.risk) {
                "HIGH"     { $score += 20; $highRepCount++; $reasons.Add("Hochrisiko-IP $($rep.ip) ($($rep.category)) (+20)") }
                "CRITICAL" { $score += 40;                  $reasons.Add("Kritische IP $($rep.ip) ($($rep.category)) (+40)") }
                "MEDIUM"   { $score += 5 }
            }
        }
    }
    if ($highRepCount -gt 2) { $score += 15; $reasons.Add("Mehr als 2 Hochrisiko-Verbindungen (+15)") }

    # Risk ports — score each risky connection independently
    foreach ($c in $Snapshot.network.tcp) {
        if ($RiskPorts -contains [int]$c.local_port -or $RiskPorts -contains [int]$c.remote_port) {
            $score += 10; $reasons.Add("Risikoport $($c.local_port)/$($c.remote_port) Prozess $($c.process) (+10)")
        }
    }

    # Alert severity contribution
    foreach ($a in $Alerts) {
        switch ($a.severity) {
            "CRITICAL" { $score += 30 }
            "HIGH"     { $score += 15 }
            "MEDIUM"   { $score += 5  }
            "LOW"      { $score += 2  }
        }
    }

    # Integrity
    foreach ($r in $IntegrityResults) {
        if ($r.status -eq "TAMPERED") {
            $score += 50; $reasons.Add("INTEGRITAET VERLETZT: $($r.file) (+50)")
        } elseif ($r.status -eq "DELETED") {
            $score += 20; $reasons.Add("AVA-Datei geloescht: $($r.file) (+20)")
        }
    }

    $label = switch ($true) {
        { $score -ge 100 } { "KRITISCH" ; break }
        { $score -ge 60  } { "HOCH"     ; break }
        { $score -ge 30  } { "MITTEL"   ; break }
        { $score -ge 10  } { "NIEDRIG"  ; break }
        default            { "MINIMAL"  }
    }

    [ordered]@{
        score   = $score
        label   = $label
        reasons = @($reasons)
    }
}

# ---------------------------------------------------------------------------
# COMPARE WITH BASELINE
# ---------------------------------------------------------------------------
function Compare-WithBaseline {
    param($Snapshot)

    $alerts = New-Object System.Collections.Generic.List[object]

    if (-not (Test-Path $BaselineFile)) {
        $alerts.Add([ordered]@{
            severity = "LOW"
            type     = "BASELINE"
            message  = "Keine Baseline vorhanden. Starte mit -CreateBaseline."
        })
        return $alerts
    }

    try { $base = Get-Content $BaselineFile -Raw | ConvertFrom-Json }
    catch {
        $alerts.Add([ordered]@{ severity = "HIGH"; type = "BASELINE_CORRUPT"; message = "Baseline-Datei korrumpiert." })
        return $alerts
    }

    # Suspicious PowerShell
    foreach ($p in $Snapshot.powershell) {
        if ($p.suspicious) {
            $alerts.Add([ordered]@{
                severity = "HIGH"; type = "POWERSHELL"
                message  = "Verdaechtiger PowerShell-Prozess erkannt: PID $($p.pid)"
                data     = $p; process_pid = $p.pid
            })
        }
    }

    # Defender realtime off
    if ($Snapshot.defender.available -and -not $Snapshot.defender.realtime_protection) {
        $alerts.Add([ordered]@{ severity = "CRITICAL"; type = "DEFENDER"; message = "Defender Echtzeitschutz ist AUS." })
    }

    # New admins
    $baseAdmins = @($base.admins | ForEach-Object { $_.Name })
    foreach ($a in $Snapshot.admins) {
        if ($baseAdmins -notcontains $a.Name) {
            $alerts.Add([ordered]@{
                severity = "HIGH"; type = "ADMIN_DELTA"
                message  = "Neuer lokaler Admin seit Baseline: $($a.Name)"
                data     = @{ admin = $a.Name }
            })
        }
    }

    # New scheduled tasks
    $baseTasks = @($base.tasks | ForEach-Object { "$($_.TaskPath)$($_.TaskName)" })
    foreach ($t in $Snapshot.tasks) {
        $id = "$($t.TaskPath)$($t.TaskName)"
        if ($baseTasks -notcontains $id) {
            $alerts.Add([ordered]@{ severity = "MEDIUM"; type = "TASK_DELTA"; message = "Neue Aufgabe seit Baseline: $id" })
        }
    }

    # Risk ports
    foreach ($c in $Snapshot.network.tcp) {
        if ($RiskPorts -contains [int]$c.local_port -or $RiskPorts -contains [int]$c.remote_port) {
            $alerts.Add([ordered]@{
                severity = "MEDIUM"; type = "NETWORK_RISK_PORT"
                message  = "Risikorelevante TCP-Verbindung: $($c.process) PID $($c.pid)"
                data     = $c; process_pid = $c.pid
            })
        }
    }

    # High-risk remote IPs
    foreach ($c in $Snapshot.network.tcp) {
        $rep = $c.ip_reputation
        if ($rep -and $rep.risk -in @("HIGH","CRITICAL")) {
            $alerts.Add([ordered]@{
                severity = if ($rep.risk -eq "CRITICAL") { "CRITICAL" } else { "HIGH" }
                type     = "REMOTE_IP_RISK"
                message  = "Verbindung zu Risiko-IP $($rep.ip) ($($rep.category)): $($c.process)"
                data     = $c; process_pid = $c.pid
            })
        }
    }

    return $alerts
}

# ---------------------------------------------------------------------------
# TREND ANALYSIS
# ---------------------------------------------------------------------------
function Save-TrendSnapshot {
    param($Snapshot, $RiskScore)
    $day  = (Get-Date).ToString("yyyy-MM-dd")
    $file = Join-Path $TrendDir "trend_$day.jsonl"
    [ordered]@{
        time        = $Snapshot.time
        risk_score  = $RiskScore.score
        risk_label  = $RiskScore.label
        ps_count    = @($Snapshot.powershell).Count
        tcp_count   = @($Snapshot.network.tcp).Count
        udp_count   = @($Snapshot.network.udp).Count
        admin_count = @($Snapshot.admins).Count
        task_count  = @($Snapshot.tasks).Count
        svc_count   = @($Snapshot.services).Count
        defender_ok = ($Snapshot.defender.available -and $Snapshot.defender.realtime_protection)
    } | ConvertTo-Json -Compress | Add-Content -Path $file -Encoding UTF8
}

function Get-TrendData {
    param([int]$Days = 7)
    $cutoff = (Get-Date).AddDays(-$Days)
    $trend  = New-Object System.Collections.Generic.List[object]

    $files = Get-ChildItem -Path $TrendDir -Filter "trend_*.jsonl" -ErrorAction SilentlyContinue |
             Sort-Object Name
    foreach ($f in $files) {
        $dateStr = $f.BaseName -replace "trend_",""
        try {
            $fileDate = [datetime]::ParseExact($dateStr,"yyyy-MM-dd",$null)
            if ($fileDate -lt $cutoff) { continue }
        } catch { continue }

        Get-Content $f.FullName |
            ForEach-Object {
                try { $trend.Add(($_ | ConvertFrom-Json)) } catch {}
            }
    }
    return @($trend)
}

# ---------------------------------------------------------------------------
# MEMORY LINK MAP  (Memory <-> Alert <-> Process <-> Network)
# ---------------------------------------------------------------------------
function Build-MemoryLinks {
    param($Alerts, $ProcessGraph, $Network)

    $links = New-Object System.Collections.Generic.List[object]

    foreach ($a in $Alerts) {
        $link = [ordered]@{
            alert_type    = $a.type
            alert_message = $a.message
            severity      = $a.severity
            processes     = @()
            connections   = @()
        }

        # Link by PID if the alert carries one
        $pid = $null
        if ($a.PSObject.Properties.Name -contains "process_pid") { $pid = $a.process_pid }
        elseif ($a.data -and $a.data.PSObject.Properties.Name -contains "pid") { $pid = $a.data.pid }

        if ($pid) {
            $matchProcs = @($ProcessGraph | Where-Object { [string]$_.pid -eq [string]$pid })
            $link.processes = $matchProcs | ForEach-Object {
                [ordered]@{ pid = $_.pid; name = $_.name; parent = $_.parent_name; suspicious = $_.suspicious }
            }
            $matchConns = @($Network.tcp | Where-Object { [string]$_.pid -eq [string]$pid })
            $link.connections = $matchConns | ForEach-Object {
                [ordered]@{ remote = $_.remote_address; port = $_.remote_port; rep = $_.ip_reputation.category }
            }
        }

        $links.Add($link)
    }

    return @($links)
}

# ---------------------------------------------------------------------------
# HTML PORTAL
# ---------------------------------------------------------------------------
function Build-Portal {
    param($Snapshot, $Alerts, $RiskScore, $IntegrityResults, $TrendData, $MemoryLinks)

    # ---- helpers ----
    function SevColor($sev) {
        switch ($sev) {
            "CRITICAL" { return "#ff4d4d" }
            "HIGH"     { return "#ffa500" }
            "MEDIUM"   { return "#ffd54f" }
            "LOW"      { return "#81c784" }
            default    { return "#90caf9" }
        }
    }

    function RiskBgColor($label) {
        switch ($label) {
            "KRITISCH" { return "#3d1a1a" }
            "HOCH"     { return "#3d2a1a" }
            "MITTEL"   { return "#3a3520" }
            "NIEDRIG"  { return "#1a2e1a" }
            default    { return "#1a2530" }
        }
    }

    # ---- Alert rows ----
    $alertRows = foreach ($a in $Alerts) {
        $col = SevColor $a.severity
        "<tr style='border-left:4px solid $col'>
          <td style='color:$col;font-weight:bold'>$(HtmlEncode $a.severity)</td>
          <td>$(HtmlEncode $a.type)</td>
          <td>$(HtmlEncode $a.message)</td>
        </tr>"
    }

    # ---- Integrity rows ----
    $intRows = foreach ($r in $IntegrityResults) {
        $col = switch ($r.status) { "OK" { "#81c784" } "NO_BASELINE" { "#90caf9" } default { "#ff4d4d" } }
        "<tr><td style='color:$col'>$(HtmlEncode $r.status)</td><td>$(HtmlEncode $r.file)</td></tr>"
    }

    # ---- Process graph rows (parent -> name, with connections) ----
    $pgRows = foreach ($p in ($Snapshot.process_graph | Where-Object { $_.suspicious -eq $true } | Select-Object -First 40)) {
        $connsStr = if ($p.connections.Count -gt 0) {
            ($p.connections | ForEach-Object { "$($_.remote_address):$($_.remote_port)[$($_.state)]" }) -join "; "
        } else { "—" }
        $col = if ($p.suspicious) { "#ffa500" } else { "#eee" }
        "<tr style='color:$col'>
          <td>$(HtmlEncode $p.pid)</td>
          <td>$(HtmlEncode $p.parent_name) → $(HtmlEncode $p.name)</td>
          <td>$(HtmlEncode ($p.hits -join ', '))</td>
          <td>$(HtmlEncode $connsStr)</td>
        </tr>"
    }
    if (-not $pgRows) { $pgRows = "<tr><td colspan='4' style='color:#81c784'>Keine verdaechtigen Prozesse erkannt.</td></tr>" }

    # ---- TCP rows with IP reputation ----
    $tcpRows = foreach ($c in ($Snapshot.network.tcp | Select-Object -First 60)) {
        $rep = $c.ip_reputation
        $repCol = if ($rep) {
            switch ($rep.risk) { "CRITICAL" { "#ff4d4d" } "HIGH" { "#ffa500" } "MEDIUM" { "#ffd54f" } default { "#81c784" } }
        } else { "#eee" }
        "<tr>
          <td>$(HtmlEncode $c.process)</td>
          <td>$(HtmlEncode $c.pid)</td>
          <td>$(HtmlEncode $c.local_port)</td>
          <td>$(HtmlEncode $c.remote_address)</td>
          <td>$(HtmlEncode $c.remote_port)</td>
          <td style='color:$repCol'>$(HtmlEncode $rep.category) / $(HtmlEncode $rep.risk)</td>
          <td>$(HtmlEncode $rep.detail)</td>
        </tr>"
    }
    if (-not $tcpRows) { $tcpRows = "<tr><td colspan='7' style='color:#81c784'>Keine aktiven TCP-Verbindungen.</td></tr>" }

    # ---- Trend chart data (JSON for inline JS) ----
    $trendLabels = ($TrendData | ForEach-Object { '"' + $_.time + '"' }) -join ","
    $trendScores = ($TrendData | ForEach-Object { [string]$_.risk_score }) -join ","
    $trendTcp    = ($TrendData | ForEach-Object { [string]$_.tcp_count }) -join ","

    # ---- Memory link rows ----
    $memRows = foreach ($m in $MemoryLinks) {
        $procs  = if ($m.processes.Count  -gt 0) { ($m.processes  | ForEach-Object { "$($_.pid):$($_.name)" }) -join "; " } else { "—" }
        $conns  = if ($m.connections.Count -gt 0) { ($m.connections | ForEach-Object { "$($_.remote):$($_.port)[$($_.rep)]" }) -join "; " } else { "—" }
        $col    = SevColor $m.severity
        "<tr>
          <td style='color:$col;font-weight:bold'>$(HtmlEncode $m.severity)</td>
          <td>$(HtmlEncode $m.alert_type)</td>
          <td>$(HtmlEncode $m.alert_message)</td>
          <td>$(HtmlEncode $procs)</td>
          <td>$(HtmlEncode $conns)</td>
        </tr>"
    }
    if (-not $memRows) { $memRows = "<tr><td colspan='5' style='color:#81c784'>Keine Verknuepfungen.</td></tr>" }

    # ---- Risk score reasons ----
    $reasonList = ($RiskScore.reasons | ForEach-Object { "<li>$(HtmlEncode $_)</li>" }) -join ""
    if (-not $reasonList) { $reasonList = "<li>Keine Risikofaktoren erkannt.</li>" }

    # ---- Defender info ----
    $defInfo = if ($Snapshot.defender.available) {
        $rt  = if ($Snapshot.defender.realtime_protection) { "<span style='color:#81c784'>AN</span>" } else { "<span style='color:#ff4d4d'>AUS</span>" }
        $av  = if ($Snapshot.defender.antivirus_enabled)   { "<span style='color:#81c784'>AN</span>" } else { "<span style='color:#ff4d4d'>AUS</span>" }
        $age = [string]$Snapshot.defender.signature_age
        "Echtzeitschutz: $rt &nbsp;|&nbsp; Antivirenschutz: $av &nbsp;|&nbsp; Signaturen: $age Tage alt"
    } else { "<span style='color:#ffd54f'>Defender-Status nicht verfuegbar.</span>" }

    $riskBg    = RiskBgColor $RiskScore.label
    $riskScore = HtmlEncode $RiskScore.score
    $riskLabel = HtmlEncode $RiskScore.label
    $snapTime  = HtmlEncode $Snapshot.time
    $computer  = HtmlEncode $Snapshot.computer
    $user      = HtmlEncode $Snapshot.user
    $alertCount = @($Alerts).Count
    $psCount    = @($Snapshot.powershell).Count
    $tcpCount   = @($Snapshot.network.tcp).Count

@"
<!DOCTYPE html>
<html lang="de">
<head>
<meta charset="utf-8">
<title>AVA CORE STACK v1 — Dashboard</title>
<style>
  :root{--bg:#121212;--bg2:#1e1e1e;--bg3:#252525;--border:#333;--text:#e0e0e0;--accent:#00ffcc;--accent2:#7c4dff}
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:'Segoe UI',Tahoma,Arial,sans-serif;background:var(--bg);color:var(--text);padding:16px}
  h1{color:var(--accent);font-size:1.6rem;border-bottom:2px solid var(--accent);padding-bottom:8px;margin-bottom:16px}
  h2{color:var(--accent2);font-size:1.1rem;margin:20px 0 8px 0}
  .grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:12px;margin-bottom:20px}
  .card{background:var(--bg2);border-radius:8px;padding:14px;border:1px solid var(--border)}
  .card .val{font-size:2rem;font-weight:bold;color:var(--accent)}
  .card .lbl{font-size:.8rem;color:#aaa;margin-top:4px}
  .risk-card{background:$riskBg;border:2px solid $(SevColor 'HIGH');border-radius:8px;padding:16px;margin-bottom:20px}
  .risk-score{font-size:3rem;font-weight:bold;color:#fff}
  .risk-label{font-size:1.2rem;color:#ffd54f;margin-top:4px}
  table{width:100%;border-collapse:collapse;font-size:.82rem;margin-bottom:20px}
  th{background:var(--bg3);color:var(--accent2);text-align:left;padding:6px 8px;border-bottom:1px solid var(--border)}
  td{padding:5px 8px;border-bottom:1px solid var(--border);vertical-align:top;word-break:break-all}
  tr:hover td{background:var(--bg3)}
  canvas{background:var(--bg2);border-radius:8px;border:1px solid var(--border);max-width:100%;margin-bottom:20px}
  .section{background:var(--bg2);border-radius:8px;padding:16px;margin-bottom:20px;border:1px solid var(--border)}
  .tag{display:inline-block;padding:2px 7px;border-radius:4px;font-size:.75rem;font-weight:bold}
  .defender-bar{margin-bottom:16px;padding:10px;background:var(--bg3);border-radius:6px;font-size:.9rem}
  ul.reasons{padding-left:18px;color:#ccc;font-size:.85rem;line-height:1.7}
  .ts{font-size:.75rem;color:#888}
  .footer{margin-top:24px;font-size:.75rem;color:#555;text-align:center}
</style>
</head>
<body>

<h1>🌀 AVA CORE STACK v1 &mdash; Security Dashboard</h1>

<div class="ts">Snapshot: $snapTime &nbsp;|&nbsp; Rechner: $computer &nbsp;|&nbsp; Nutzer: $user</div>

<br>

<!-- KPIs -->
<div class="grid">
  <div class="card"><div class="val">$alertCount</div><div class="lbl">Aktive Alerts</div></div>
  <div class="card"><div class="val">$psCount</div><div class="lbl">PowerShell-Prozesse</div></div>
  <div class="card"><div class="val">$tcpCount</div><div class="lbl">TCP-Verbindungen</div></div>
  <div class="card"><div class="val">$(HtmlEncode (@($Snapshot.admins).Count))</div><div class="lbl">Lokale Admins</div></div>
  <div class="card"><div class="val">$(HtmlEncode (@($Snapshot.tasks).Count))</div><div class="lbl">Geplante Aufgaben</div></div>
  <div class="card"><div class="val">$(HtmlEncode (@($Snapshot.services).Count))</div><div class="lbl">Laufende Dienste</div></div>
</div>

<!-- Risiko-Score -->
<div class="risk-card">
  <div class="risk-score">$riskScore / &infin;</div>
  <div class="risk-label">Risikostufe: $riskLabel</div>
  <h2 style="margin-top:12px">Begruendung</h2>
  <ul class="reasons">$reasonList</ul>
</div>

<!-- Defender -->
<div class="defender-bar">🛡️ &nbsp; $defInfo</div>

<!-- Alerts -->
<div class="section">
  <h2>⚠️ Alerts ($alertCount)</h2>
  <table>
    <tr><th>Schweregrad</th><th>Typ</th><th>Meldung</th></tr>
    $($alertRows -join "")
  </table>
</div>

<!-- Memory Links -->
<div class="section">
  <h2>🔗 Memory-Links (Alert ↔ Prozess ↔ Netzwerk)</h2>
  <table>
    <tr><th>Schweregrad</th><th>Typ</th><th>Meldung</th><th>Prozesse</th><th>Verbindungen</th></tr>
    $($memRows -join "")
  </table>
</div>

<!-- Process Graph -->
<div class="section">
  <h2>🧠 Prozess-Graph (verdaechtige Prozesse)</h2>
  <table>
    <tr><th>PID</th><th>Eltern → Prozess</th><th>Treffer</th><th>Verbindungen</th></tr>
    $($pgRows -join "")
  </table>
</div>

<!-- TCP + IP Reputation -->
<div class="section">
  <h2>🌐 TCP-Verbindungen mit IP-Reputation</h2>
  <table>
    <tr><th>Prozess</th><th>PID</th><th>Lok.Port</th><th>Remote-IP</th><th>R.Port</th><th>Kategorie / Risiko</th><th>Detail</th></tr>
    $($tcpRows -join "")
  </table>
</div>

<!-- Integrity -->
<div class="section">
  <h2>🔒 Integritaet AVA-Dateien</h2>
  <table>
    <tr><th>Status</th><th>Datei</th></tr>
    $($intRows -join "")
  </table>
</div>

<!-- Trend Chart -->
<div class="section">
  <h2>📈 Trendanalyse (letzte 7 Tage)</h2>
  <canvas id="trendChart" height="100"></canvas>
</div>

<script>
(function(){
  var labels = [$trendLabels];
  var scores = [$trendScores];
  var tcps   = [$trendTcp];

  if (labels.length === 0) {
    document.getElementById('trendChart').style.display = 'none';
    var p = document.createElement('p');
    p.style.color = '#888'; p.style.fontSize = '.85rem';
    p.textContent = 'Noch keine Trenddaten verfuegbar. Nach mehreren Laeufen erscheint hier ein Diagramm.';
    document.getElementById('trendChart').parentNode.appendChild(p);
    return;
  }

  var canvas = document.getElementById('trendChart');
  var ctx    = canvas.getContext('2d');
  canvas.width  = canvas.parentElement.clientWidth - 32;
  canvas.height = 200;

  var W = canvas.width, H = canvas.height;
  var pad = {top:20,right:20,bottom:50,left:50};
  var w = W - pad.left - pad.right;
  var h = H - pad.top  - pad.bottom;

  var maxScore = Math.max.apply(null, scores.concat([1]));
  var maxTcp   = Math.max.apply(null, tcps.concat([1]));
  var n = labels.length;

  ctx.clearRect(0,0,W,H);

  // Grid lines
  ctx.strokeStyle='#333'; ctx.lineWidth=1;
  for(var i=0;i<=4;i++){
    var y = pad.top + h - (h * i / 4);
    ctx.beginPath(); ctx.moveTo(pad.left,y); ctx.lineTo(pad.left+w,y); ctx.stroke();
    ctx.fillStyle='#666'; ctx.font='11px Segoe UI'; ctx.textAlign='right';
    ctx.fillText(Math.round(maxScore*i/4), pad.left-4, y+4);
  }

  function drawLine(data, maxV, color) {
    ctx.beginPath(); ctx.strokeStyle=color; ctx.lineWidth=2;
    data.forEach(function(v,i){
      var x = pad.left + (n===1?w/2:i*w/(n-1));
      var y = pad.top  + h - (h * v / maxV);
      i===0 ? ctx.moveTo(x,y) : ctx.lineTo(x,y);
    });
    ctx.stroke();
    data.forEach(function(v,i){
      var x = pad.left + (n===1?w/2:i*w/(n-1));
      var y = pad.top  + h - (h * v / maxV);
      ctx.beginPath(); ctx.arc(x,y,4,0,2*Math.PI);
      ctx.fillStyle=color; ctx.fill();
    });
  }

  drawLine(scores, maxScore, '#ffa500');
  if(maxTcp>0) drawLine(tcps, maxTcp, '#00ffcc');

  // X labels
  ctx.fillStyle='#888'; ctx.font='10px Segoe UI'; ctx.textAlign='center';
  labels.forEach(function(l,i){
    var x = pad.left + (n===1?w/2:i*w/(n-1));
    var short = l.substring(0,16);
    ctx.fillText(short, x, H-10);
  });

  // Legend
  ctx.fillStyle='#ffa500'; ctx.fillRect(pad.left,8,12,12);
  ctx.fillStyle='#ccc'; ctx.font='12px Segoe UI'; ctx.textAlign='left';
  ctx.fillText('Risiko-Score', pad.left+16, 19);
  ctx.fillStyle='#00ffcc'; ctx.fillRect(pad.left+120,8,12,12);
  ctx.fillStyle='#ccc'; ctx.fillText('TCP-Verbindungen', pad.left+136, 19);
})();
</script>

<div class="footer">AVA CORE STACK v1 &mdash; Lokal / Defensiv / Read-Only &mdash; $snapTime</div>
</body>
</html>
"@ | Set-Content -Path $PortalFile -Encoding UTF8
}

# ===========================================================================
# MAIN
# ===========================================================================

# 1. Integrity check
$integrityResults = @(Test-IntegrityBaseline)

foreach ($r in $integrityResults) {
    if ($r.status -eq "TAMPERED") {
        Write-TangleEvent -Type "INTEGRITY_VIOLATION" -Severity "CRITICAL" `
            -Message "AVA-Datei manipuliert: $($r.file)" -Data @{ file = $r.file; expected = $r.expected; current = $r.current }
    } elseif ($r.status -eq "DELETED") {
        Write-TangleEvent -Type "INTEGRITY_DELETED" -Severity "HIGH" `
            -Message "AVA-Datei geloescht: $($r.file)" -Data @{ file = $r.file }
    }
}

# 2. Snapshot
$snapshot = New-Snapshot

# 3. Baseline creation
if ($CreateBaseline) {
    $snapshot | ConvertTo-Json -Depth 12 | Set-Content $BaselineFile -Encoding UTF8
    Write-TangleEvent -Type "BASELINE" -Severity "INFO" -Message "Baseline erstellt." -Data @{ path = $BaselineFile }
    Write-Host "AVA Baseline erstellt: $BaselineFile" -ForegroundColor Green
    Save-IntegrityBaseline
}

# 4. Delta / alerts
$alerts = @(Compare-WithBaseline -Snapshot $snapshot)

# 5. Risk score
$riskScore = Compute-RiskScore -Snapshot $snapshot -Alerts $alerts -IntegrityResults $integrityResults

# 6. Memory links
$memoryLinks = @(Build-MemoryLinks -Alerts $alerts -ProcessGraph $snapshot.process_graph -Network $snapshot.network)

# 7. Trend data
Save-TrendSnapshot -Snapshot $snapshot -RiskScore $riskScore
$trendData = @(Get-TrendData -Days 7)

# 8. Tangle events
Write-TangleEvent -Type "SNAPSHOT" -Severity "INFO" -Message "Snapshot erstellt." -Data @{
    risk_score       = $riskScore.score
    risk_label       = $riskScore.label
    powershell_count = @($snapshot.powershell).Count
    tcp_count        = @($snapshot.network.tcp).Count
    udp_count        = @($snapshot.network.udp).Count
    admin_count      = @($snapshot.admins).Count
    task_count       = @($snapshot.tasks).Count
    service_count    = @($snapshot.services).Count
}

foreach ($a in $alerts) {
    $sev = if ($a.severity) { $a.severity } else { "LOW" }
    $typ = if ($a.type)     { $a.type }     else { "ALERT" }
    $msg = if ($a.message)  { $a.message }  else { "Alert ohne Meldung" }
    Write-TangleEvent -Type $typ -Severity $sev -Message $msg -Data @{ alert = $a }
}

# 9. Build portal
Build-Portal `
    -Snapshot          $snapshot `
    -Alerts            $alerts `
    -RiskScore         $riskScore `
    -IntegrityResults  $integrityResults `
    -TrendData         $trendData `
    -MemoryLinks       $memoryLinks

# 10. Update integrity baseline after successful run
Save-IntegrityBaseline

# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "AVA CORE STACK v1 abgeschlossen." -ForegroundColor Cyan
Write-Host "  Risiko-Score : $($riskScore.score) ($($riskScore.label))" -ForegroundColor Yellow
Write-Host "  Alerts       : $(@($alerts).Count)" -ForegroundColor $(if (@($alerts).Count -gt 0) { "Red" } else { "Green" })
Write-Host "  Portal       : $PortalFile" -ForegroundColor Green
Write-Host "  Eventlog     : $EventLog" -ForegroundColor Green
Write-Host "  Alerts-Log   : $AlertLog" -ForegroundColor Green

if ($OpenPortal) { Start-Process $PortalFile }
