#requires -RunAsAdministrator
[CmdletBinding()]
param(
    [switch]$RunOnce,
    [switch]$InstallTask,
    [switch]$RemoveTask,
    [switch]$RollbackFirewall,
    [switch]$HardenRemoteServices
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# =========================
# CONFIG
# =========================
$Root = "C:\Windows\SecurityGuardian"
$LogDir = Join-Path $Root "Logs"
$ReportDir = Join-Path $Root "Reports"
$StateDir = Join-Path $Root "State"
$TaskName = "WindowsSecurityGuardian"

$EventLog = Join-Path $LogDir "events.jsonl"
$AlertLog = Join-Path $LogDir "alerts.jsonl"
$BaselinePath = Join-Path $StateDir "baseline.json"
$HashPath = Join-Path $StateDir "integrity.hash"

$RulePrefix = "AVA_Block_"
$Ports = @(21,23,135,139,445,3389,5985,5986)

$ComputerAdmins = @(
    "Administrator",
    "$env:COMPUTERNAME\$env:USERNAME",
    $env:USERNAME
) | Select-Object -Unique

$CanaryFiles = @(
    (Join-Path $Root "finance_decoy_2026.txt"),
    (Join-Path $Root "admin_notes_decoy.txt"),
    (Join-Path $Root "vpn_inventory_decoy.txt")
)

# =========================
# INIT
# =========================
New-Item -ItemType Directory -Path $Root,$LogDir,$ReportDir,$StateDir -Force | Out-Null

function Write-JsonLine {
    param(
        [Parameter(Mandatory)][object]$Object,
        [Parameter(Mandatory)][string]$Path
    )
    $json = $Object | ConvertTo-Json -Compress -Depth 8
    Add-Content -Path $Path -Value $json -Encoding UTF8
}

function Write-Alert {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('LOW','MEDIUM','HIGH','CRITICAL')]
        [string]$Severity = 'MEDIUM'
    )

    Write-JsonLine -Object @{
        time     = (Get-Date).ToString("s")
        severity = $Severity
        message  = $Message
    } -Path $AlertLog
}

function Write-EventEntry {
    param(
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Message,
        [string]$Severity = 'INFO'
    )

    Write-JsonLine -Object @{
        time     = (Get-Date).ToString("s")
        category = $Category
        severity = $Severity
        message  = $Message
    } -Path $EventLog
}

# =========================
# BASELINE
# =========================
function Save-Baseline {
    $admins = Get-LocalGroupMember -Group "Administrators" |
        Select-Object Name, ObjectClass, PrincipalSource

    $baseline = @{
        created = (Get-Date).ToString("s")
        admins  = $admins
    }

    $baseline | ConvertTo-Json -Depth 6 | Set-Content -Path $BaselinePath -Encoding UTF8
    Write-EventEntry -Category "baseline" -Message "Baseline gespeichert."
}

function Check-Admins {
    $admins = Get-LocalGroupMember -Group "Administrators" |
        Select-Object -ExpandProperty Name

    foreach ($admin in $admins) {
        if ($ComputerAdmins -notcontains $admin) {
            Write-Alert -Message "UNAUTHORIZED ADMIN DETECTED: $admin" -Severity HIGH
        }
    }
}

# =========================
# CANARY SYSTEM
# =========================
function Initialize-Canaries {
    foreach ($file in $CanaryFiles) {
        if (-not (Test-Path -LiteralPath $file)) {
            "DO NOT TOUCH - MONITORED" | Set-Content -Path $file -Encoding UTF8
            Write-EventEntry -Category "canary" -Message "Canary erstellt: $file"
        }
    }
}

function Check-Canaries {
    foreach ($file in $CanaryFiles) {
        if (-not (Test-Path -LiteralPath $file)) {
            Write-Alert -Message "CANARY DELETED OR MISSING: $file" -Severity HIGH
        }
    }
}

# =========================
# INTEGRITY CHECK
# =========================
function Save-ScriptHash {
    if (-not $PSCommandPath) { return }
    $hash = (Get-FileHash -Path $PSCommandPath -Algorithm SHA256).Hash
    Set-Content -Path $HashPath -Value $hash -Encoding ASCII
}

function Check-ScriptHash {
    if (-not $PSCommandPath) { return }
    if (Test-Path -LiteralPath $HashPath) {
        $old = (Get-Content -Path $HashPath -Raw).Trim()
        $new = (Get-FileHash -Path $PSCommandPath -Algorithm SHA256).Hash
        if ($old -and $old -ne $new) {
            Write-Alert -Message "SCRIPT TAMPER DETECTED" -Severity HIGH
        }
    }
}

# =========================
# FIREWALL
# =========================
function Apply-FirewallRules {
    foreach ($port in $Ports) {
        $name = "$RulePrefix$port"
        $existing = Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue
        if (-not $existing) {
            New-NetFirewallRule `
                -DisplayName $name `
                -Direction Inbound `
                -Action Block `
                -Protocol TCP `
                -LocalPort $port | Out-Null

            Write-EventEntry -Category "firewall" -Message "Firewall-Regel erstellt: $name"
        }
    }
}

function Rollback-FirewallRules {
    Get-NetFirewallRule -DisplayName "$RulePrefix*" -ErrorAction SilentlyContinue |
        Remove-NetFirewallRule -ErrorAction SilentlyContinue

    Write-EventEntry -Category "firewall" -Message "AVA-Firewall-Regeln entfernt."
}

# =========================
# REMOTE SERVICES HARDENING
# =========================
function Invoke-RemoteServicesHardening {
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value 1
    Disable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue

    foreach ($svc in @('RemoteRegistry','WinRM')) {
        $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if ($service) {
            if ($service.Status -ne 'Stopped') {
                Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
            }
            Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
        }
    }

    Write-EventEntry -Category "hardening" -Message "Remote Services gehärtet."
}

# =========================
# NETWORK MONITOR
# =========================
function Check-Network {
    $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue

    foreach ($c in $connections) {
        $remote = $c.RemoteAddress

        if (
            $remote -match '^127\.' -or
            $remote -match '^192\.168\.' -or
            $remote -match '^10\.' -or
            $remote -match '^172\.(1[6-9]|2[0-9]|3[0-1])\.'
        ) {
            continue
        }

        $proc = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue
        if (-not $proc) { continue }

        $name = $proc.Name.ToLowerInvariant()
        $path = $null
        try { $path = $proc.Path } catch {}

        if ($name -in @('powershell','pwsh','cmd','python','certutil','bitsadmin')) {
            Write-Alert -Message "SUSPICIOUS CONNECTION: $name -> $remote`:$($c.RemotePort)" -Severity HIGH
        }
        elseif ($path -and $path -like "*\AppData\Local\Temp\*") {
            Write-Alert -Message "TEMP PATH NETWORK PROCESS: $name -> $remote`:$($c.RemotePort) [$path]" -Severity CRITICAL
        }
    }
}

# =========================
# PROCESS CHECK
# =========================
function Scan-SuspiciousProcesses {
    $suspiciousFlags = @("-enc", "encodedcommand", "windowstyle hidden", "bypass", "nop")
    $psProcs = Get-CimInstance Win32_Process | Where-Object {
        $_.Name -in @('powershell.exe','pwsh.exe')
    }

    foreach ($p in $psProcs) {
        $cmdLine = [string]$p.CommandLine
        if ([string]::IsNullOrWhiteSpace($cmdLine)) { continue }

        $cmdLower = $cmdLine.ToLowerInvariant()
        $foundFlags = foreach ($flag in $suspiciousFlags) {
            if ($cmdLower.Contains($flag)) { $flag }
        }

        if (($foundFlags | Measure-Object).Count -ge 2 -or $cmdLower.Contains("-enc")) {
            Write-Alert -Message "SUSPICIOUS PS PROCESS: PID $($p.ProcessId) | Flags: $($foundFlags -join ', ')" -Severity CRITICAL
        }
    }
}

# =========================
# REPORT
# =========================
function Build-HTMLReport {
    $items = @()
    if (Test-Path -LiteralPath $AlertLog) {
        $items = Get-Content -Path $AlertLog -ErrorAction SilentlyContinue |
            Where-Object { $_.Trim() } |
            ForEach-Object {
                try { $_ | ConvertFrom-Json } catch { $null }
            } |
            Where-Object { $_ }
    }

    $style = @"
<style>
body { font-family: Segoe UI, Tahoma, Arial; background: #1a1a1a; color: #eee; padding: 20px; }
h1 { color: #00ffcc; border-bottom: 2px solid #00ffcc; padding-bottom: 10px; }
.card { background: #2d2d2d; margin: 10px 0; padding: 15px; border-radius: 6px; border-left: 5px solid #555; }
.CRITICAL { border-left-color: #ff4d4d; background: #3d1a1a; }
.HIGH { border-left-color: #ffa500; }
.MEDIUM { border-left-color: #ffd54f; background: #3a3520; }
.LOW { border-left-color: #81c784; }
.time { font-size: 12px; color: #aaa; }
.msg { font-weight: bold; display: block; margin-top: 6px; }
</style>
"@

    $body = foreach ($a in $items) {
        $sev = [string]$a.severity
        $msg = [System.Web.HttpUtility]::HtmlEncode([string]$a.message)
        $tim = [System.Web.HttpUtility]::HtmlEncode([string]$a.time)

        "<div class='card $sev'><span class='time'>$tim [$sev]</span><span class='msg'>$msg</span></div>"
    }

    $html = "<html><head>$style</head><body><h1>AVA SECURITY DASHBOARD</h1>$($body -join '')</body></html>"
    Set-Content -Path (Join-Path $ReportDir "report.html") -Value $html -Encoding UTF8
}

# =========================
# TASK
# =========================
function Install-GuardianTask {
    if (-not $PSCommandPath) {
        throw "PSCommandPath ist leer. Script muss als .ps1 Datei gespeichert und per -File ausgefuhrt werden."
    }

    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -RunOnce"
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1)
    $trigger.Repetition = (New-ScheduledTaskRepetitionSettings -Interval (New-TimeSpan -Minutes 5))
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest

    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
    Write-EventEntry -Category "task" -Message "Scheduled Task installiert: $TaskName"
}

function Remove-GuardianTask {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-EventEntry -Category "task" -Message "Scheduled Task entfernt: $TaskName"
    }
}

# =========================
# MAIN
# =========================
if ($RemoveTask) {
    Remove-GuardianTask
    Write-Host "Task entfernt."
    exit
}

if ($RollbackFirewall) {
    Rollback-FirewallRules
}

if ($HardenRemoteServices) {
    Invoke-RemoteServicesHardening
}

if (-not (Test-Path -LiteralPath $BaselinePath)) {
    Save-Baseline
}

Initialize-Canaries
Check-ScriptHash
Check-Admins
Check-Canaries
Apply-FirewallRules
Check-Network
Scan-SuspiciousProcesses
Build-HTMLReport
Save-ScriptHash

if ($InstallTask) {
    Install-GuardianTask
}

Write-Host "AVA SecurityGuardian fertig. Sicherheit aktiv."
