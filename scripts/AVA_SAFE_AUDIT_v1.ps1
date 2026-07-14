[CmdletBinding()]
param(
    [switch]$OpenReport
)

<#
AVA SAFE AUDIT v1

Purpose:
- Collect defensive, local system information.
- Write reports only inside a new Desktop output folder.
- Make no changes to Firewall, Defender, Registry, users, services or tasks.

Scope:
- The current Windows computer only.
- No remote execution, no network scanning, no counterattacks.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$desktop = [Environment]::GetFolderPath('Desktop')
$root = Join-Path $desktop "AVA_SAFE_AUDIT_$stamp"
$dataDir = Join-Path $root 'data'
$logDir = Join-Path $root 'logs'
$transcriptPath = Join-Path $logDir 'transcript.txt'
$htmlPath = Join-Path $root 'AVA_SAFE_AUDIT_REPORT.html'
$zipPath = Join-Path $desktop "AVA_SAFE_AUDIT_$stamp.zip"

New-Item -ItemType Directory -Path $root, $dataDir, $logDir -Force | Out-Null
Start-Transcript -Path $transcriptPath -Force | Out-Null

function Test-IsAdministrator {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [Security.Principal.WindowsPrincipal]::new($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}

function ConvertTo-HtmlSafe {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function Save-Section {
    param(
        [Parameter(Mandatory)][string]$Name,
        [AllowNull()][object]$Value
    )

    $jsonPath = Join-Path $dataDir "$Name.json"
    $textPath = Join-Path $dataDir "$Name.txt"

    $Value | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
    $Value | Out-String -Width 400 | Set-Content -LiteralPath $textPath -Encoding UTF8
}

function Invoke-AuditSection {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$ScriptBlock
    )

    Write-Host "[AVA] Sammle: $Name" -ForegroundColor DarkCyan

    try {
        $result = & $ScriptBlock
    }
    catch {
        $result = [pscustomobject]@{
            section = $Name
            error = $_.Exception.Message
            time = (Get-Date).ToString('o')
        }
    }

    Save-Section -Name $Name -Value $result
    return $result
}

$summary = [ordered]@{
    AVA_Mode = 'SAFE_AUDIT_v1'
    Time = (Get-Date).ToString('o')
    ComputerName = $env:COMPUTERNAME
    UserName = if ($env:USERDOMAIN) { "$env:USERDOMAIN\$env:USERNAME" } else { $env:USERNAME }
    IsAdministrator = Test-IsAdministrator
    OutputRoot = $root
    Safety = 'Local defensive audit. Writes reports only; no security configuration changes.'
}

Save-Section -Name '00_summary' -Value $summary

$systemInfo = Invoke-AuditSection '01_system_info' {
    Get-ComputerInfo | Select-Object \
        CsName,
        WindowsProductName,
        WindowsVersion,
        OsName,
        OsVersion,
        OsBuildNumber,
        OsArchitecture,
        BiosFirmwareType,
        CsManufacturer,
        CsModel,
        CsTotalPhysicalMemory,
        TimeZone,
        LogonServer
}

$defender = Invoke-AuditSection '02_defender_status' {
    if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
        Get-MpComputerStatus | Select-Object \
            AMServiceEnabled,
            AntivirusEnabled,
            AntispywareEnabled,
            RealTimeProtectionEnabled,
            BehaviorMonitorEnabled,
            IoavProtectionEnabled,
            NISEnabled,
            OnAccessProtectionEnabled,
            IsTamperProtected,
            AntivirusSignatureLastUpdated,
            QuickScanEndTime,
            FullScanEndTime
    }
    else {
        [pscustomobject]@{ status = 'Get-MpComputerStatus nicht verfügbar' }
    }
}

$firewallProfiles = Invoke-AuditSection '03_firewall_profiles' {
    if (Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue) {
        Get-NetFirewallProfile | Select-Object \
            Name,
            Enabled,
            DefaultInboundAction,
            DefaultOutboundAction,
            NotifyOnListen
    }
    else {
        [pscustomobject]@{ status = 'Get-NetFirewallProfile nicht verfügbar' }
    }
}

$administrators = Invoke-AuditSection '04_local_administrators' {
    if ((Get-Command Get-LocalGroup -ErrorAction SilentlyContinue) -and
        (Get-Command Get-LocalGroupMember -ErrorAction SilentlyContinue)) {
        $group = Get-LocalGroup -SID 'S-1-5-32-544'
        Get-LocalGroupMember -Group $group.Name |
            Select-Object Name, ObjectClass, PrincipalSource
    }
    else {
        net localgroup administrators
    }
}

$users = Invoke-AuditSection '05_local_users' {
    if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {
        Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordRequired, PasswordLastSet
    }
    else {
        net user
    }
}

$services = Invoke-AuditSection '06_critical_services' {
    $names = @('WinDefend', 'wuauserv', 'RemoteRegistry', 'TermService', 'WinRM', 'BITS', 'EventLog')
    foreach ($name in $names) {
        Get-Service -Name $name -ErrorAction SilentlyContinue |
            Select-Object Name, DisplayName, Status, StartType
    }
}

$networkAdapters = Invoke-AuditSection '07_network_adapters' {
    if (Get-Command Get-NetAdapter -ErrorAction SilentlyContinue) {
        Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, MacAddress, LinkSpeed
    }
    else {
        ipconfig /all
    }
}

$ipConfiguration = Invoke-AuditSection '08_ip_configuration' {
    if (Get-Command Get-NetIPConfiguration -ErrorAction SilentlyContinue) {
        Get-NetIPConfiguration |
            Select-Object InterfaceAlias, IPv4Address, IPv6Address, IPv4DefaultGateway, DNSServer
    }
    else {
        ipconfig /all
    }
}

$connections = Invoke-AuditSection '09_established_connections' {
    if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
        Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
            ForEach-Object {
                $process = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
                [pscustomobject]@{
                    LocalAddress = $_.LocalAddress
                    LocalPort = $_.LocalPort
                    RemoteAddress = $_.RemoteAddress
                    RemotePort = $_.RemotePort
                    State = $_.State
                    OwningProcess = $_.OwningProcess
                    ProcessName = $process.ProcessName
                    ProcessPath = $process.Path
                }
            } |
            Sort-Object ProcessName, RemoteAddress, RemotePort
    }
    else {
        netstat -ano
    }
}

$processes = Invoke-AuditSection '10_processes' {
    Get-Process -ErrorAction SilentlyContinue |
        Select-Object Id, ProcessName, Path, CPU, StartTime |
        Sort-Object ProcessName
}

$interestingProcesses = Invoke-AuditSection '11_interesting_process_names' {
    $pattern = 'powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|python|node|curl|wget'
    Get-Process -ErrorAction SilentlyContinue |
        Where-Object { $_.ProcessName -match $pattern } |
        Select-Object Id, ProcessName, Path, StartTime |
        Sort-Object ProcessName
}

$tasks = Invoke-AuditSection '12_scheduled_tasks_non_microsoft' {
    if (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue) {
        Get-ScheduledTask |
            Where-Object { $_.TaskPath -notlike '\Microsoft\*' } |
            Select-Object TaskName, TaskPath, State, Author, Description
    }
    else {
        schtasks /query /fo LIST /v
    }
}

$autoruns = Invoke-AuditSection '13_registry_autoruns_readonly' {
    $paths = @(
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
    )

    foreach ($path in $paths) {
        if (Test-Path -LiteralPath $path) {
            [pscustomobject]@{
                RegistryPath = $path
                Values = Get-ItemProperty -LiteralPath $path
            }
        }
    }
}

$powerShellEvents = Invoke-AuditSection '14_powershell_suspicious_events_last_7_days' {
    $start = (Get-Date).AddDays(-7)
    $pattern = '-enc|encodedcommand|frombase64string|downloadstring|invoke-expression|\biex\b|-nop|noprofile|windowstyle hidden|-w hidden|executionpolicy bypass|bitsadmin|certutil|mshta|regsvr32|rundll32|wscript|cscript'
    $logs = @('Windows PowerShell', 'Microsoft-Windows-PowerShell/Operational')

    foreach ($log in $logs) {
        try {
            Get-WinEvent -FilterHashtable @{ LogName = $log; StartTime = $start } -MaxEvents 700 |
                Where-Object { $_.Message -match $pattern } |
                Select-Object TimeCreated, ProviderName, Id, LevelDisplayName, Message
        }
        catch {
            [pscustomobject]@{ Log = $log; Status = 'Nicht lesbar oder nicht verfügbar'; Error = $_.Exception.Message }
        }
    }
}

$systemEvents = Invoke-AuditSection '15_system_errors_last_7_days' {
    Get-WinEvent -FilterHashtable @{
        LogName = 'System'
        StartTime = (Get-Date).AddDays(-7)
        Level = 1, 2, 3
    } -MaxEvents 250 -ErrorAction SilentlyContinue |
        Select-Object TimeCreated, ProviderName, Id, LevelDisplayName, Message
}

$defenderEvents = Invoke-AuditSection '16_defender_events_last_14_days' {
    try {
        Get-WinEvent -FilterHashtable @{
            LogName = 'Microsoft-Windows-Windows Defender/Operational'
            StartTime = (Get-Date).AddDays(-14)
        } -MaxEvents 999 |
            Select-Object TimeCreated, ProviderName, Id, LevelDisplayName, Message
    }
    catch {
        [pscustomobject]@{ Status = 'Defender Eventlog nicht lesbar oder nicht verfügbar'; Error = $_.Exception.Message }
    }
}

$downloadHashes = Invoke-AuditSection '17_recent_download_hashes' {
    $downloads = Join-Path $env:USERPROFILE 'Downloads'
    if (Test-Path -LiteralPath $downloads) {
        Get-ChildItem -LiteralPath $downloads -File -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending |
            Select-Object -First 60 |
            ForEach-Object {
                $hash = Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue
                [pscustomobject]@{
                    Name = $_.Name
                    FullName = $_.FullName
                    Length = $_.Length
                    LastWriteTime = $_.LastWriteTime
                    SHA256 = $hash.Hash
                }
            }
    }
    else {
        [pscustomobject]@{ Status = 'Downloads-Ordner nicht gefunden' }
    }
}

$findings = [System.Collections.Generic.List[object]]::new()

function Add-Finding {
    param([string]$Level, [string]$Title, [string]$Detail)
    $findings.Add([pscustomobject]@{ Level = $Level; Title = $Title; Detail = $Detail }) | Out-Null
}

if (-not $summary.IsAdministrator) {
    Add-Finding 'INFO' 'Nicht als Administrator gestartet' 'Einige Bereiche können fehlen.'
}

if ($defender -and $defender.PSObject.Properties.Name -contains 'RealTimeProtectionEnabled' -and
    $defender.RealTimeProtectionEnabled -eq $false) {
    Add-Finding 'HIGH' 'Defender Echtzeitschutz aus' 'RealTimeProtectionEnabled ist false.'
}

foreach ($profile in @($firewallProfiles)) {
    if ($profile.PSObject.Properties.Name -contains 'Enabled' -and $profile.Enabled -eq $false) {
        Add-Finding 'MEDIUM' 'Firewall-Profil deaktiviert' "$($profile.Name) ist deaktiviert."
    }
}

foreach ($service in @($services)) {
    if ($service.Name -in @('RemoteRegistry', 'WinRM', 'TermService') -and $service.Status -eq 'Running') {
        Add-Finding 'INFO' 'Remote-Dienst läuft' "$($service.Name) / $($service.DisplayName) läuft; bewusst prüfen."
    }
}

if (@($interestingProcesses).Count -gt 0) {
    Add-Finding 'INFO' 'Interessante Prozessnamen gefunden' 'Scripting- oder LOLBin-Prozesse gefunden; Kontext im Detailreport prüfen.'
}

Save-Section -Name '18_findings' -Value $findings

$htmlRows = foreach ($finding in $findings) {
    '<tr><td>{0}</td><td>{1}</td><td>{2}</td></tr>' -f \
        (ConvertTo-HtmlSafe $finding.Level),
        (ConvertTo-HtmlSafe $finding.Title),
        (ConvertTo-HtmlSafe $finding.Detail)
}

if (-not $htmlRows) {
    $htmlRows = '<tr><td>OK</td><td>Keine kritischen Sofort-Findings</td><td>Detaildaten trotzdem prüfen.</td></tr>'
}

$html = @"
<!doctype html>
<html lang="de">
<head>
<meta charset="utf-8">
<title>AVA Safe Audit Report</title>
<style>
body { font-family: Segoe UI, Arial, sans-serif; background:#07111d; color:#e8f7ff; margin:24px; }
h1, h2 { color:#79fff2; }
.card { background:#0b1d2e; border:1px solid #1f6f80; border-radius:12px; padding:16px; margin:14px 0; }
table { border-collapse:collapse; width:100%; }
td, th { border:1px solid #315d73; padding:8px; vertical-align:top; }
th { background:#10243a; }
code { background:#07111d; padding:2px 6px; border-radius:6px; }
.ok { color:#8dffb0; }
</style>
</head>
<body>
<h1>AVA Safe Audit Report</h1>
<div class="card">
<h2>Status</h2>
<p><b>Modus:</b> Lokaler defensiver Audit</p>
<p><b>Zeit:</b> $(ConvertTo-HtmlSafe $summary.Time)</p>
<p><b>Computer:</b> $(ConvertTo-HtmlSafe $summary.ComputerName)</p>
<p><b>User:</b> $(ConvertTo-HtmlSafe $summary.UserName)</p>
<p><b>Administrator:</b> $(ConvertTo-HtmlSafe $summary.IsAdministrator)</p>
<p class="ok"><b>Sicherheit:</b> Keine Änderungen an Firewall, Defender, Registry, Benutzern, Services oder Tasks.</p>
</div>
<div class="card">
<h2>Findings</h2>
<table><tr><th>Level</th><th>Titel</th><th>Detail</th></tr>$($htmlRows -join "`n")</table>
</div>
<div class="card">
<h2>Gespeicherte Daten</h2>
<p><code>$(ConvertTo-HtmlSafe $dataDir)</code></p>
<p><code>$(ConvertTo-HtmlSafe $transcriptPath)</code></p>
</div>
<div class="card">
<h2>Leitlinie</h2>
<p>Original sichern. Fakten prüfen. Technik und Symbolik bewusst trennen.</p>
</div>
</body>
</html>
"@

$html | Set-Content -LiteralPath $htmlPath -Encoding UTF8

try { Stop-Transcript | Out-Null } catch {}

try {
    Compress-Archive -LiteralPath $root -DestinationPath $zipPath -Force
}
catch {
    Write-Warning "ZIP konnte nicht erstellt werden: $($_.Exception.Message)"
}

Write-Host ''
Write-Host 'AVA SAFE AUDIT fertig.' -ForegroundColor Green
Write-Host "Report: $htmlPath" -ForegroundColor Cyan
Write-Host "ZIP:    $zipPath" -ForegroundColor Cyan

if ($OpenReport) {
    Start-Process -FilePath $htmlPath
}
