#requires -RunAsAdministrator
<#
AVA IMMUNE SYSTEM v2
Lokal / Defensiv / SOC / Baseline / Risk Score / HTML Dashboard

Start normal:
powershell -ExecutionPolicy Bypass -File .\AVA_Immune_System_v2.ps1 -RunOnce

Start mit Safe-Auto-Block:
powershell -ExecutionPolicy Bypass -File .\AVA_Immune_System_v2.ps1 -RunOnce -AutoBlock

Installiere 60-Sekunden Guardian Task:
powershell -ExecutionPolicy Bypass -File .\AVA_Immune_System_v2.ps1 -InstallTask

Entferne Guardian Task:
powershell -ExecutionPolicy Bypass -File .\AVA_Immune_System_v2.ps1 -RemoveTask

Rollback AVA Firewall Blocks:
powershell -ExecutionPolicy Bypass -File .\AVA_Immune_System_v2.ps1 -RollbackBlocks
#>

param(
    [switch]$RunOnce,
    [switch]$InstallTask,
    [switch]$RemoveTask,
    [switch]$AutoBlock,
    [switch]$RollbackBlocks
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# =========================
# CONFIG
# =========================
$Root      = "C:\Windows\SecurityGuardian"
$LogDir    = Join-Path $Root "Logs"
$ReportDir = Join-Path $Root "Reports"
$StateDir  = Join-Path $Root "State"

$TaskName   = "AVA_Immune_System_v2"
$RulePrefix = "AVA_Immune_Block_"

$Now = Get-Date -Format "yyyyMMdd_HHmmss"

$EventsLog  = Join-Path $LogDir "immune_events.jsonl"
$AlertsLog  = Join-Path $LogDir "immune_alerts.jsonl"
$Baseline   = Join-Path $StateDir "immune_baseline.json"
$BlockState = Join-Path $StateDir "immune_blocks.json"

$JsonReport = Join-Path $ReportDir "ava_immune_report_$Now.json"
$TxtReport  = Join-Path $ReportDir "ava_immune_report_$Now.txt"
$HtmlReport = Join-Path $ReportDir "ava_immune_report_$Now.html"

$HighRiskPorts = @(21,23,135,139,445,3389,4444,5555,5900,5985,5986,8080,8443,9001,1337)

$FloodConnectionThreshold = 40   # TCP connections from a single remote IP triggering flood detection

$RiskScoreCritical = 90   # MaxRisk >= this → Status CRITICAL
$RiskScoreElevated = 70   # MaxRisk >= this → Status ELEVATED
$RiskScoreWatch    = 30   # MaxRisk >= this → Status WATCH

$NeverBlockIPs = @(
    "127.0.0.1",
    "::1",
    "0.0.0.0",
    "::",
    "255.255.255.255"
)

$SuspiciousPSFlags = @(
    "-enc",
    "encodedcommand",
    "-nop",
    "-w hidden",
    "windowstyle hidden",
    "-executionpolicy bypass",
    "-ep bypass",
    "iex ",
    "invoke-expression"
)

# =========================
# INIT
# =========================
foreach ($d in @($Root,$LogDir,$ReportDir,$StateDir)) {
    if (-not (Test-Path -LiteralPath $d)) {
        New-Item -ItemType Directory -Path $d -Force | Out-Null
    }
}

$Findings = New-Object System.Collections.Generic.List[object]
$Alerts   = New-Object System.Collections.Generic.List[object]

function Write-JsonLine {
    param(
        [string]$Path,
        [object]$Object
    )
    $Object | ConvertTo-Json -Depth 12 -Compress | Out-File -FilePath $Path -Append -Encoding UTF8
}

function Add-Finding {
    param(
        [string]$Title,
        [string]$Severity = "INFO",
        [int]$Score = 0,
        [object]$Details = $null
    )

    $item = [PSCustomObject]@{
        Time     = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        Title    = $Title
        Severity = $Severity
        Score    = $Score
        Details  = $Details
    }

    $Findings.Add($item) | Out-Null
    Write-JsonLine -Path $EventsLog -Object $item

    if ($Severity -in @("MEDIUM","HIGH","CRITICAL")) {
        $Alerts.Add($item) | Out-Null
        Write-JsonLine -Path $AlertsLog -Object $item
    }
}

function HtmlEncode {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function Is-PrivateIPv4 {
    param([string]$IP)

    if ($IP -match "^10\.") { return $true }
    if ($IP -match "^192\.168\.") { return $true }
    if ($IP -match "^172\.(1[6-9]|2[0-9]|3[0-1])\.") { return $true }
    if ($IP -match "^169\.254\.") { return $true }
    return $false
}

function Safe-BlockRemoteIP {
    param([string]$RemoteIP, [string]$Reason)

    if (-not $AutoBlock) {
        Add-Finding -Title "AutoBlock wäre ausgelöst worden, ist aber deaktiviert" -Severity "MEDIUM" -Score 40 -Details @{
            RemoteIP = $RemoteIP
            Reason   = $Reason
            Action   = "Kein Block, weil -AutoBlock nicht gesetzt ist"
        }
        return
    }

    if (-not $RemoteIP) { return }
    if ($NeverBlockIPs -contains $RemoteIP) { return }
    if (Is-PrivateIPv4 $RemoteIP) {
        Add-Finding -Title "AutoBlock übersprungen: private/lokale IP" -Severity "INFO" -Score 0 -Details @{
            RemoteIP = $RemoteIP
            Reason   = "Private IP wird nicht automatisch blockiert"
        }
        return
    }

    $safeName = ($RemoteIP -replace "[^a-zA-Z0-9\.\-]", "_")
    $ruleName = "$RulePrefix$safeName"

    $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    if ($existing) {
        Add-Finding -Title "Firewall Block existiert bereits" -Severity "INFO" -Score 0 -Details $ruleName
        return
    }

    New-NetFirewallRule `
        -DisplayName $ruleName `
        -Direction Inbound `
        -Action Block `
        -RemoteAddress $RemoteIP `
        -Profile Any `
        -Description "AVA Immune System v2 AutoBlock: $Reason" | Out-Null

    $blockEntry = [PSCustomObject]@{
        Time     = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        RuleName = $ruleName
        RemoteIP = $RemoteIP
        Reason   = $Reason
    }

    Write-JsonLine -Path $BlockState -Object $blockEntry

    Add-Finding -Title "Remote-IP automatisch geblockt" -Severity "HIGH" -Score 85 -Details $blockEntry
}

function Rollback-AVA-Blocks {
    $rules = Get-NetFirewallRule -DisplayName "$RulePrefix*" -ErrorAction SilentlyContinue
    if (-not $rules) {
        Write-Host "Keine AVA Immune Firewall-Regeln gefunden." -ForegroundColor Yellow
        return
    }

    foreach ($r in $rules) {
        Remove-NetFirewallRule -Name $r.Name -ErrorAction SilentlyContinue
        Write-Host "Entfernt: $($r.DisplayName)" -ForegroundColor Green
    }
}

function Install-GuardianTask {
    $scriptPath = $PSCommandPath
    if (-not $scriptPath) {
        throw "Speichere das Skript zuerst als .ps1 Datei, bevor du -InstallTask nutzt."
    }

    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" -RunOnce"
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1)
    $trigger.Repetition = New-ScheduledTaskRepetitionSettings -Interval (New-TimeSpan -Minutes 1) -Duration ([TimeSpan]::MaxValue)
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest

    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null

    Write-Host "AVA Guardian Task installiert: $TaskName" -ForegroundColor Green
}

function Remove-GuardianTask {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host "AVA Guardian Task entfernt: $TaskName" -ForegroundColor Green
}

# =========================
# CONTROL ACTIONS
# =========================
if ($RollbackBlocks) {
    Rollback-AVA-Blocks
    return
}

if ($InstallTask) {
    Install-GuardianTask
    return
}

if ($RemoveTask) {
    Remove-GuardianTask
    return
}

# =========================
# SNAPSHOT
# =========================
Add-Finding -Title "AVA IMMUNE SYSTEM v2 gestartet" -Severity "INFO" -Score 0 -Details @{
    Computer  = $env:COMPUTERNAME
    User      = $env:USERNAME
    Root      = $Root
    AutoBlock = [bool]$AutoBlock
}

# Firewall
try {
    $fw = Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction
    Add-Finding -Title "Firewall Profile" -Severity "INFO" -Score 0 -Details $fw

    foreach ($p in $fw) {
        if (-not $p.Enabled) {
            Add-Finding -Title "Firewall Profil ist deaktiviert" -Severity "CRITICAL" -Score 100 -Details $p
        }
    }
} catch {
    Add-Finding -Title "Firewall Status konnte nicht gelesen werden" -Severity "MEDIUM" -Score 30 -Details $_.Exception.Message
}

# Defender
try {
    $def = Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled,AntispywareEnabled,IsTamperProtected,AntivirusSignatureLastUpdated
    Add-Finding -Title "Microsoft Defender Status" -Severity "INFO" -Score 0 -Details $def

    if (-not $def.RealTimeProtectionEnabled) {
        Add-Finding -Title "Defender Echtzeitschutz ist deaktiviert" -Severity "CRITICAL" -Score 100 -Details $def
    }
} catch {
    Add-Finding -Title "Defender Status konnte nicht gelesen werden" -Severity "MEDIUM" -Score 30 -Details $_.Exception.Message
}

# TCP Connections
$connections = @()
try {
    $connections = Get-NetTCPConnection -ErrorAction SilentlyContinue |
        Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess

    Add-Finding -Title "TCP Verbindungen Snapshot" -Severity "INFO" -Score 0 -Details $connections

    $listening  = $connections | Where-Object { $_.State -eq "Listen" }
    $riskListen = $listening   | Where-Object { $HighRiskPorts -contains $_.LocalPort }

    if ($riskListen) {
        Add-Finding -Title "Auffällige lokale Listening Ports" -Severity "HIGH" -Score 80 -Details $riskListen
    }

    $remoteGroups = $connections |
        Where-Object {
            $_.RemoteAddress -and
            $_.RemoteAddress -notin $NeverBlockIPs -and
            $_.RemoteAddress -notlike "fe80*"
        } |
        Group-Object RemoteAddress |
        Sort-Object Count -Descending

    Add-Finding -Title "Top Remote IPs" -Severity "INFO" -Score 0 -Details ($remoteGroups | Select-Object -First 10 Name,Count)

    foreach ($g in $remoteGroups) {
        if ($g.Count -ge $FloodConnectionThreshold) {
            Add-Finding -Title "Mögliches Scan-/Flood-Muster" -Severity "HIGH" -Score 85 -Details @{
                RemoteIP    = $g.Name
                Connections = $g.Count
                Reason      = "Viele TCP-Verbindungen von einer Quelle"
            }

            Safe-BlockRemoteIP -RemoteIP $g.Name -Reason "Viele TCP-Verbindungen von einer Quelle"
        }
    }
} catch {
    Add-Finding -Title "TCP Analyse fehlgeschlagen" -Severity "MEDIUM" -Score 30 -Details $_.Exception.Message
}

# Process Mapping
try {
    $procMap = @{}
    Get-Process | ForEach-Object { $procMap[$_.Id] = $_.ProcessName }

    $connProc = $connections | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess,
        @{Name="ProcessName";Expression={
            if ($procMap.ContainsKey($_.OwningProcess)) { $procMap[$_.OwningProcess] } else { "Unknown" }
        }}

    Add-Finding -Title "Verbindungen mit Prozess-Zuordnung" -Severity "INFO" -Score 0 -Details $connProc

    $riskyProcConn = $connProc | Where-Object {
        ($HighRiskPorts -contains $_.LocalPort) -or ($HighRiskPorts -contains $_.RemotePort)
    }

    if ($riskyProcConn) {
        Add-Finding -Title "Verbindung über High-Risk-Port mit Prozessbezug" -Severity "HIGH" -Score 80 -Details $riskyProcConn
    }
} catch {
    Add-Finding -Title "Prozess-Mapping fehlgeschlagen" -Severity "MEDIUM" -Score 30 -Details $_.Exception.Message
}

# PowerShell Audit
try {
    $ps = Get-CimInstance Win32_Process |
        Where-Object { $_.Name -in @("powershell.exe","pwsh.exe") } |
        Select-Object ProcessId,Name,CommandLine,CreationDate

    Add-Finding -Title "PowerShell Prozesse" -Severity "INFO" -Score 0 -Details $ps

    foreach ($p in $ps) {
        $cmd = ""
        if ($p.CommandLine) { $cmd = $p.CommandLine.ToLowerInvariant() }

        $hits = @(foreach ($flag in $SuspiciousPSFlags) {
            if ($cmd.Contains($flag)) { $flag }
        })

        if ($hits.Count -gt 0) {
            Add-Finding -Title "Auffälliger PowerShell Prozess" -Severity "CRITICAL" -Score 95 -Details @{
                PID         = $p.ProcessId
                Flags       = $hits
                CommandLine = $p.CommandLine
            }
        }
    }
} catch {
    Add-Finding -Title "PowerShell Audit fehlgeschlagen" -Severity "MEDIUM" -Score 30 -Details $_.Exception.Message
}

# Admins
try {
    $admins = Get-LocalGroupMember -Group "Administrators" |
        Select-Object Name,ObjectClass,PrincipalSource,SID

    Add-Finding -Title "Lokale Administratoren" -Severity "INFO" -Score 0 -Details $admins
} catch {
    Add-Finding -Title "Admin-Gruppe konnte nicht gelesen werden" -Severity "MEDIUM" -Score 30 -Details $_.Exception.Message
}

# Non-Microsoft Tasks
try {
    $tasks = Get-ScheduledTask |
        Where-Object { $_.TaskPath -notlike "\Microsoft*" } |
        Select-Object TaskName,TaskPath,State

    Add-Finding -Title "Nicht-Microsoft Scheduled Tasks" -Severity "INFO" -Score 0 -Details $tasks
} catch {
    Add-Finding -Title "Scheduled Tasks konnten nicht gelesen werden" -Severity "MEDIUM" -Score 30 -Details $_.Exception.Message
}

# Services running as non-standard accounts
try {
    $services = Get-CimInstance Win32_Service |
        Where-Object {
            $_.StartName -and
            $_.StartName -notin @("LocalSystem","NT AUTHORITY\LocalService","NT AUTHORITY\NetworkService") -and
            $_.State -eq "Running"
        } |
        Select-Object Name,DisplayName,StartName,State,StartMode

    Add-Finding -Title "Dienste mit speziellen Startkonten" -Severity "INFO" -Score 0 -Details $services
} catch {
    Add-Finding -Title "Service Audit fehlgeschlagen" -Severity "MEDIUM" -Score 30 -Details $_.Exception.Message
}

# Baseline Diff
try {
    $currentBaseline = [PSCustomObject]@{
        Time              = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        Admins            = @($admins | ForEach-Object { "$($_.Name)|$($_.SID)" })
        ListeningPorts    = @($connections | Where-Object State -eq "Listen" | ForEach-Object { "$($_.LocalAddress):$($_.LocalPort)|PID:$($_.OwningProcess)" })
        NonMicrosoftTasks = @($tasks | ForEach-Object { "$($_.TaskPath)$($_.TaskName)" })
    }

    if (-not (Test-Path -LiteralPath $Baseline)) {
        $currentBaseline | ConvertTo-Json -Depth 8 | Out-File -FilePath $Baseline -Encoding UTF8
        Add-Finding -Title "Neue Baseline erstellt" -Severity "INFO" -Score 0 -Details $Baseline
    } else {
        $old = Get-Content -LiteralPath $Baseline -Raw | ConvertFrom-Json

        $newAdmins = @($currentBaseline.Admins | Where-Object { $old.Admins -notcontains $_ })
        $newPorts  = @($currentBaseline.ListeningPorts | Where-Object { $old.ListeningPorts -notcontains $_ })
        $newTasks  = @($currentBaseline.NonMicrosoftTasks | Where-Object { $old.NonMicrosoftTasks -notcontains $_ })

        if ($newAdmins.Count -gt 0) {
            Add-Finding -Title "Baseline Änderung: neue Administratoren" -Severity "CRITICAL" -Score 100 -Details $newAdmins
        }

        if ($newPorts.Count -gt 0) {
            Add-Finding -Title "Baseline Änderung: neue Listening Ports" -Severity "HIGH" -Score 80 -Details $newPorts
        }

        if ($newTasks.Count -gt 0) {
            Add-Finding -Title "Baseline Änderung: neue Nicht-Microsoft Tasks" -Severity "HIGH" -Score 75 -Details $newTasks
        }

        $currentBaseline | ConvertTo-Json -Depth 8 | Out-File -FilePath $Baseline -Encoding UTF8
    }
} catch {
    Add-Finding -Title "Baseline Vergleich fehlgeschlagen" -Severity "MEDIUM" -Score 35 -Details $_.Exception.Message
}

# =========================
# SUMMARY
# =========================
$MaxScore = 0
if ($Findings.Count -gt 0) {
    $MaxScore = ($Findings | Measure-Object Score -Maximum).Maximum
}

$Critical = @($Findings | Where-Object Severity -eq "CRITICAL").Count
$High     = @($Findings | Where-Object Severity -eq "HIGH").Count
$Medium   = @($Findings | Where-Object Severity -eq "MEDIUM").Count
$Info     = @($Findings | Where-Object Severity -eq "INFO").Count

$Status = "STABLE"
if ($MaxScore -ge $RiskScoreCritical)     { $Status = "CRITICAL" }
elseif ($MaxScore -ge $RiskScoreElevated) { $Status = "ELEVATED" }
elseif ($MaxScore -ge $RiskScoreWatch)    { $Status = "WATCH" }

$Summary = [PSCustomObject]@{
    Time       = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    Computer   = $env:COMPUTERNAME
    User       = $env:USERNAME
    Status     = $Status
    MaxRisk    = $MaxScore
    Critical   = $Critical
    High       = $High
    Medium     = $Medium
    Info       = $Info
    AutoBlock  = [bool]$AutoBlock
    JsonReport = $JsonReport
    TxtReport  = $TxtReport
    HtmlReport = $HtmlReport
}

$Output = [PSCustomObject]@{
    Summary  = $Summary
    Findings = $Findings
}

$Output | ConvertTo-Json -Depth 14 | Out-File -FilePath $JsonReport -Encoding UTF8

# TXT
$txt = New-Object System.Collections.Generic.List[string]
$txt.Add("AVA IMMUNE SYSTEM v2")
$txt.Add("====================")
$txt.Add("Zeit: $($Summary.Time)")
$txt.Add("Computer: $($Summary.Computer)")
$txt.Add("User: $($Summary.User)")
$txt.Add("Status: $($Summary.Status)")
$txt.Add("MaxRisk: $($Summary.MaxRisk)")
$txt.Add("Critical: $Critical | High: $High | Medium: $Medium | Info: $Info")
$txt.Add("AutoBlock: $($Summary.AutoBlock)")
$txt.Add("")
$txt.Add("Kernsatz: Fakten vor Angst. Baseline vor Chaos. Sichtbarkeit vor Kontrolle.")
$txt.Add("")

foreach ($f in $Findings) {
    $txt.Add("------------------------------------------------")
    $txt.Add("[$($f.Severity)] $($f.Title) | Score: $($f.Score)")
    $txt.Add("Zeit: $($f.Time)")
    $txt.Add(($f.Details | Out-String))
    $txt.Add("")
}

$txt -join "`r`n" | Out-File -FilePath $TxtReport -Encoding UTF8

# HTML
$statusColor = switch ($Status) {
    "CRITICAL" { "#ff4d4d" }
    "ELEVATED" { "#ffa500" }
    "WATCH"    { "#ffd54f" }
    default    { "#00ffcc" }
}

$rows = foreach ($f in $Findings) {
    $cls = $f.Severity.ToLowerInvariant()
    "<tr class='row-$cls'><td>$(HtmlEncode $f.Time)</td><td><span class='badge $cls'>$($f.Severity)</span></td><td>$($f.Score)</td><td>$(HtmlEncode $f.Title)</td><td><pre>$(HtmlEncode $f.Details)</pre></td></tr>"
}

$html = @"
<!DOCTYPE html>
<html lang="de">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AVA IMMUNE SYSTEM v2</title>
<style>
  body { font-family: 'Segoe UI', Tahoma, Arial, sans-serif; background: #1a1a1a; color: #eee; margin: 0; padding: 20px; }
  h1 { color: #00ffcc; border-bottom: 2px solid #00ffcc; padding-bottom: 10px; }
  .summary { display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 24px; }
  .card { background: #2d2d2d; border-radius: 8px; padding: 16px 24px; flex: 1; min-width: 140px; text-align: center; }
  .card .label { font-size: 12px; color: #aaa; text-transform: uppercase; letter-spacing: 1px; }
  .card .value { font-size: 28px; font-weight: bold; margin-top: 4px; }
  .status-value { color: $statusColor; }
  .critical-value { color: #ff4d4d; }
  .high-value { color: #ffa500; }
  .medium-value { color: #ffd54f; }
  .info-value { color: #81c784; }
  table { width: 100%; border-collapse: collapse; margin-top: 16px; }
  th { background: #333; color: #00ffcc; text-align: left; padding: 10px 12px; font-size: 13px; text-transform: uppercase; letter-spacing: 0.5px; }
  td { padding: 8px 12px; font-size: 13px; border-bottom: 1px solid #333; vertical-align: top; }
  tr:hover td { background: #2a2a2a; }
  pre { margin: 0; white-space: pre-wrap; word-break: break-all; font-size: 11px; color: #ccc; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; text-transform: uppercase; }
  .badge.critical, .row-critical td { background-color: #3d1a1a; }
  .badge.critical { background-color: #ff4d4d; color: #fff; }
  .badge.high { background-color: #ffa500; color: #000; }
  .badge.medium { background-color: #ffd54f; color: #000; }
  .badge.info { background-color: #444; color: #81c784; }
  .row-critical { border-left: 4px solid #ff4d4d; }
  .row-high td:first-child { border-left: 4px solid #ffa500; }
  .row-medium td:first-child { border-left: 4px solid #ffd54f; }
  .tagline { font-style: italic; color: #888; font-size: 13px; margin-bottom: 20px; }
</style>
</head>
<body>
<h1>AVA IMMUNE SYSTEM v2 &#x1F432;&#x1F6E1;&#xFE0F;</h1>
<p class="tagline">Fakten vor Angst. Baseline vor Chaos. Sichtbarkeit vor Kontrolle.</p>

<div class="summary">
  <div class="card"><div class="label">Status</div><div class="value status-value">$($Summary.Status)</div></div>
  <div class="card"><div class="label">Max Risk</div><div class="value status-value">$($Summary.MaxRisk)</div></div>
  <div class="card"><div class="label">Critical</div><div class="value critical-value">$Critical</div></div>
  <div class="card"><div class="label">High</div><div class="value high-value">$High</div></div>
  <div class="card"><div class="label">Medium</div><div class="value medium-value">$Medium</div></div>
  <div class="card"><div class="label">Info</div><div class="value info-value">$Info</div></div>
  <div class="card"><div class="label">Computer</div><div class="value" style="font-size:16px">$(HtmlEncode $Summary.Computer)</div></div>
  <div class="card"><div class="label">Zeit</div><div class="value" style="font-size:14px">$(HtmlEncode $Summary.Time)</div></div>
</div>

<table>
<thead>
<tr>
  <th>Zeit</th>
  <th>Severity</th>
  <th>Score</th>
  <th>Titel</th>
  <th>Details</th>
</tr>
</thead>
<tbody>
$($rows -join "`n")
</tbody>
</table>

</body>
</html>
"@

$html | Out-File -FilePath $HtmlReport -Encoding UTF8

Write-Host ""
Write-Host "AVA IMMUNE SYSTEM v2 fertig." -ForegroundColor Green
Write-Host "Status: $Status | MaxRisk: $MaxScore" -ForegroundColor Cyan
Write-Host "JSON: $JsonReport" -ForegroundColor Cyan
Write-Host "TXT : $TxtReport" -ForegroundColor Cyan
Write-Host "HTML: $HtmlReport" -ForegroundColor Cyan
Write-Host ""

if ($RunOnce -and -not $InstallTask) {
    Start-Process $HtmlReport
}
