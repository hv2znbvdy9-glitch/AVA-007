#requires -RunAsAdministrator
<#
AVA SOC CORE v1
Defensiv / Lokal / Read-Only Monitoring
Keine Angriffe. Keine Exploits. Keine fremden Systeme.
Erstellt Logs, Alerts, Baseline und HTML Dashboard.
#>

[CmdletBinding()]
param(
    [switch]$RunOnce,
    [switch]$InstallTask,
    [switch]$RemoveTask
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Load System.Web once for HtmlEncode usage in the dashboard builder.
Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue

$Root      = "C:\Windows\SecurityGuardian"
$LogDir    = Join-Path $Root "Logs"
$ReportDir = Join-Path $Root "Reports"
$StateDir  = Join-Path $Root "State"
$TaskName  = "AVA_SOC_CORE"

$EventLog     = Join-Path $LogDir "events.jsonl"
$AlertLog     = Join-Path $LogDir "alerts.jsonl"
$BaselinePath = Join-Path $StateDir "baseline.json"
$HtmlReport   = Join-Path $ReportDir "ava_soc_dashboard.html"

$CanaryFiles = @(
    Join-Path $Root "finance_decoy_2026.txt",
    Join-Path $Root "admin_notes_decoy.txt",
    Join-Path $Root "vpn_inventory_decoy.txt"
)

$RiskPorts = @(21,23,135,139,445,3389,5985,5986)
$AllowedAdmins = @(
    "Administrator",
    "$env:USERNAME"
)

function Ensure-Dirs {
    foreach ($d in @($Root,$LogDir,$ReportDir,$StateDir)) {
        if (-not (Test-Path $d)) {
            New-Item -ItemType Directory -Path $d -Force | Out-Null
        }
    }
}

function Write-JsonLine {
    param(
        [string]$Path,
        [object]$Object
    )
    ($Object | ConvertTo-Json -Depth 8 -Compress) | Add-Content -Path $Path -Encoding UTF8
}

function New-Event {
    param(
        [string]$Type,
        [string]$Severity,
        [string]$Summary,
        [object]$Data
    )

    $ev = [ordered]@{
        time     = (Get-Date).ToString("o")
        host     = $env:COMPUTERNAME
        user     = $env:USERNAME
        type     = $Type
        severity = $Severity
        summary  = $Summary
        data     = $Data
    }

    Write-JsonLine -Path $EventLog -Object $ev
    return $ev
}

function New-Alert {
    param(
        [string]$Title,
        [string]$Severity,
        [int]$Score,
        [string]$Reason,
        [object]$Data
    )

    $alert = [ordered]@{
        time     = (Get-Date).ToString("o")
        host     = $env:COMPUTERNAME
        title    = $Title
        severity = $Severity
        score    = $Score
        reason   = $Reason
        data     = $Data
    }

    Write-JsonLine -Path $AlertLog -Object $alert
    return $alert
}

function Initialize-Canaries {
    foreach ($file in $CanaryFiles) {
        if (-not (Test-Path $file)) {
            "AVA CANARY FILE - DO NOT TOUCH - $(Get-Date -Format o)" |
                Set-Content -Path $file -Encoding UTF8
        }
    }
}

function Get-AdminSnapshot {
    try {
        Get-LocalGroupMember -Group "Administrators" |
            Select-Object Name, ObjectClass, PrincipalSource, SID
    } catch {
        @([pscustomobject]@{ Error = $_.Exception.Message })
    }
}

function Get-NetSnapshot {
    $proc = @{}
    Get-Process | ForEach-Object { $proc[$_.Id] = $_.ProcessName }

    Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
        Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess,
        @{Name="ProcessName";Expression={ $proc[$_.OwningProcess] }}
}

function Get-ServiceSnapshot {
    Get-CimInstance Win32_Service |
        Where-Object { $_.StartName -notmatch "LocalSystem|LocalService|NetworkService" } |
        Select-Object Name, DisplayName, State, StartMode, StartName
}

function Get-TaskSnapshot {
    Get-ScheduledTask |
        Where-Object { $_.TaskPath -notlike "\Microsoft\*" } |
        Select-Object TaskName, TaskPath, State
}

function Get-DefenderSnapshot {
    try {
        Get-MpComputerStatus | Select-Object `
            AMServiceEnabled,
            AntivirusEnabled,
            RealTimeProtectionEnabled,
            BehaviorMonitorEnabled,
            IoavProtectionEnabled,
            AntispywareEnabled,
            NISEnabled
    } catch {
        [pscustomobject]@{ Error = $_.Exception.Message }
    }
}

function Save-Baseline {
    $baseline = [ordered]@{
        created   = (Get-Date).ToString("o")
        host      = $env:COMPUTERNAME
        admins    = @(Get-AdminSnapshot)
        tasks     = @(Get-TaskSnapshot)
        services  = @(Get-ServiceSnapshot)
        defender  = Get-DefenderSnapshot
    }

    $baseline | ConvertTo-Json -Depth 10 | Set-Content -Path $BaselinePath -Encoding UTF8
    New-Event -Type "baseline" -Severity "INFO" -Summary "Neue AVA Baseline erstellt" -Data $baseline | Out-Null
}

function Test-AdminDrift {
    if (-not (Test-Path $BaselinePath)) { return }

    $baseline = Get-Content $BaselinePath -Raw | ConvertFrom-Json
    $oldNames = @($baseline.admins.Name)
    $current = @(Get-AdminSnapshot)

    foreach ($admin in $current) {
        if ($oldNames -notcontains $admin.Name) {
            New-Alert `
                -Title "Neue Administrator-Mitgliedschaft erkannt" `
                -Severity "HIGH" `
                -Score 90 `
                -Reason "Ein Admin ist nicht in der Baseline enthalten." `
                -Data $admin | Out-Null
        }
    }
}

function Test-RiskConnections {
    $connections = @(Get-NetSnapshot)

    foreach ($c in $connections) {
        if ($RiskPorts -contains [int]$c.RemotePort -or $RiskPorts -contains [int]$c.LocalPort) {
            New-Alert `
                -Title "Riskanter Netzwerk-Port aktiv" `
                -Severity "MEDIUM" `
                -Score 69 `
                -Reason "Verbindung nutzt typischen Admin-/Remote-/Legacy-Port." `
                -Data $c | Out-Null
        }
    }

    New-Event -Type "network_snapshot" -Severity "INFO" -Summary "Netzwerk-Snapshot erstellt" -Data $connections | Out-Null
}

function Test-Canaries {
    foreach ($file in $CanaryFiles) {
        if (-not (Test-Path $file)) {
            New-Alert `
                -Title "Canary-Datei fehlt" `
                -Severity "CRITICAL" `
                -Score 100 `
                -Reason "Eine AVA Canary-Datei wurde gelöscht oder verschoben." `
                -Data @{ path = $file } | Out-Null
        }
    }
}

function Test-Defender {
    $d = Get-DefenderSnapshot
    New-Event -Type "defender_snapshot" -Severity "INFO" -Summary "Defender Status geprüft" -Data $d | Out-Null

    if ($d.RealTimeProtectionEnabled -eq $false) {
        New-Alert `
            -Title "Defender Echtzeitschutz deaktiviert" `
            -Severity "CRITICAL" `
            -Score 100 `
            -Reason "RealTimeProtectionEnabled ist FALSE." `
            -Data $d | Out-Null
    }
}

function Build-HtmlDashboard {
    $alerts = @()
    if (Test-Path $AlertLog) {
        $alerts = Get-Content $AlertLog -Tail 50 | ForEach-Object {
            try { $_ | ConvertFrom-Json } catch { $null }
        } | Where-Object { $_ }
    }

    $events = @()
    if (Test-Path $EventLog) {
        $events = Get-Content $EventLog -Tail 30 | ForEach-Object {
            try { $_ | ConvertFrom-Json } catch { $null }
        } | Where-Object { $_ }
    }

    $alertRows = foreach ($a in $alerts) {
        "<tr><td>$([System.Web.HttpUtility]::HtmlEncode($a.time))</td><td>$([System.Web.HttpUtility]::HtmlEncode($a.severity))</td><td>$([System.Web.HttpUtility]::HtmlEncode($a.score))</td><td>$([System.Web.HttpUtility]::HtmlEncode($a.title))</td><td>$([System.Web.HttpUtility]::HtmlEncode($a.reason))</td></tr>"
    }

    $eventRows = foreach ($e in $events) {
        "<tr><td>$([System.Web.HttpUtility]::HtmlEncode($e.time))</td><td>$([System.Web.HttpUtility]::HtmlEncode($e.severity))</td><td>$([System.Web.HttpUtility]::HtmlEncode($e.type))</td><td>$([System.Web.HttpUtility]::HtmlEncode($e.summary))</td></tr>"
    }

    $updateTime = [System.Web.HttpUtility]::HtmlEncode((Get-Date).ToString("o"))
    $computerName = [System.Web.HttpUtility]::HtmlEncode($env:COMPUTERNAME)
    $userName = [System.Web.HttpUtility]::HtmlEncode($env:USERNAME)

$html = @"
<!doctype html>
<html lang="de">
<head>
<meta charset="utf-8">
<title>AVA SOC CORE Dashboard</title>
<style>
body { background:#07111f; color:#d8f7ff; font-family:Segoe UI,Arial; margin:30px; }
h1 { color:#79fff2; }
h2 { color:#79fff2; margin-top:0; }
.card { border:1px solid #1f6f80; border-radius:14px; padding:18px; margin:18px 0; background:#0b1d2e; }
table { width:100%; border-collapse:collapse; }
td,th { border-bottom:1px solid #1f6f80; padding:8px; text-align:left; }
th { color:#8dffb0; }
.CRITICAL { color:#ff5f6d; font-weight:bold; }
.HIGH { color:#ffb347; font-weight:bold; }
.MEDIUM { color:#ffe066; }
.LOW { color:#8dffb0; }
.INFO { color:#79d7ff; }
</style>
</head>
<body>
<h1>&#129504; AVA SOC CORE</h1>
<div class="card">
<b>Status:</b> Aktiv / Defensiv / Lokal<br>
<b>Host:</b> $computerName<br>
<b>User:</b> $userName<br>
<b>Update:</b> $updateTime
</div>

<div class="card">
<h2>&#128680; Letzte Alerts (max. 50)</h2>
<table>
<tr><th>Zeit</th><th>Severity</th><th>Score</th><th>Titel</th><th>Grund</th></tr>
$($alertRows -join "`n")
</table>
</div>

<div class="card">
<h2>&#128196; Letzte Events (max. 30)</h2>
<table>
<tr><th>Zeit</th><th>Severity</th><th>Typ</th><th>Zusammenfassung</th></tr>
$($eventRows -join "`n")
</table>
</div>

</body>
</html>
"@

    $html | Set-Content -Path $HtmlReport -Encoding UTF8
    Write-Host "Dashboard gespeichert: $HtmlReport" -ForegroundColor Cyan
}

function Install-MonitoringTask {
    $action  = New-ScheduledTaskAction -Execute "powershell.exe" `
        -Argument "-NonInteractive -WindowStyle Hidden -File `"$PSCommandPath`" -RunOnce"
    $trigger = New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Minutes 15) `
        -Once -At (Get-Date)
    $settings = New-ScheduledTaskSettingsSet `
        -ExecutionTimeLimit (New-TimeSpan -Minutes 5) `
        -RestartCount 2 `
        -RestartInterval (New-TimeSpan -Minutes 1) `
        -StartWhenAvailable

    Register-ScheduledTask `
        -TaskName $TaskName `
        -Action $action `
        -Trigger $trigger `
        -Settings $settings `
        -RunLevel Highest `
        -Force | Out-Null

    Write-Host "Geplante Aufgabe '$TaskName' wurde registriert (alle 15 Min)." -ForegroundColor Green
}

function Remove-MonitoringTask {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Host "Geplante Aufgabe '$TaskName' wurde entfernt." -ForegroundColor Yellow
    } else {
        Write-Host "Geplante Aufgabe '$TaskName' nicht gefunden." -ForegroundColor Gray
    }
}

function Invoke-MonitoringCycle {
    Ensure-Dirs
    Initialize-Canaries

    if (-not (Test-Path $BaselinePath)) {
        Write-Host "Keine Baseline gefunden - erstelle neue Baseline..." -ForegroundColor Yellow
        Save-Baseline
    }

    Test-AdminDrift
    Test-RiskConnections
    Test-Canaries
    Test-Defender
    Build-HtmlDashboard

    New-Event `
        -Type "cycle_complete" `
        -Severity "INFO" `
        -Summary "AVA SOC CORE Überwachungszyklus abgeschlossen" `
        -Data @{ timestamp = (Get-Date).ToString("o") } | Out-Null

    Write-Host "AVA SOC CORE Zyklus abgeschlossen. Dashboard: $HtmlReport" -ForegroundColor Cyan
}

# ------------------------------------------------------------
# EINSTIEGSPUNKT
# ------------------------------------------------------------
if ($InstallTask) {
    Ensure-Dirs
    Install-MonitoringTask
}
elseif ($RemoveTask) {
    Remove-MonitoringTask
}
else {
    # -RunOnce oder direkte Ausführung
    Invoke-MonitoringCycle
}
