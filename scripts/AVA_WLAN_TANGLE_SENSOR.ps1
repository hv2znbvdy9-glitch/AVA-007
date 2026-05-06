#requires -RunAsAdministrator
<#
AVA WLAN TANGLE SENSOR v1
Defensiv / Lokal / Read-Only

Features:
- Sichtbare WLANs via netsh
- Eigene Adapterdaten
- Eigene LAN-Nachbarn via ARP / Get-NetNeighbor
- JSONL Logs
- Tangle Hash Chain
- HTML Portal

Keine Angriffe / Kein Monitor Mode / Kein Deauth / Kein Cracken

Start einmalig:
  powershell -ExecutionPolicy Bypass -File .\AVA_WLAN_TANGLE_SENSOR.ps1 -RunOnce

Dauerlauf alle 60 Sekunden:
  powershell -ExecutionPolicy Bypass -File .\AVA_WLAN_TANGLE_SENSOR.ps1 -Loop

Scheduled Task installieren (laeuft als SYSTEM alle 60 s):
  powershell -ExecutionPolicy Bypass -File .\AVA_WLAN_TANGLE_SENSOR.ps1 -InstallTask

Scheduled Task entfernen:
  powershell -ExecutionPolicy Bypass -File .\AVA_WLAN_TANGLE_SENSOR.ps1 -RemoveTask
#>

[CmdletBinding()]
param(
    [switch]$RunOnce,
    [switch]$Loop,
    [switch]$InstallTask,
    [switch]$RemoveTask,
    [int]$Interval = 60
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# =========================
# CONFIG
# =========================
$Root       = 'C:\Windows\SecurityGuardian'
$LogDir     = Join-Path $Root 'Logs'
$StateDir   = Join-Path $Root 'State'
$ReportDir  = Join-Path $Root 'Reports'

$TaskName    = 'AVA_WLAN_GUARDIAN_V1'
$EventLog    = Join-Path $LogDir   'wlan_events.jsonl'
$TangleLog   = Join-Path $LogDir   'wlan_tangle.jsonl'
$TangleState = Join-Path $StateDir 'wlan_tangle_state.json'
$PortalHtml  = Join-Path $ReportDir 'ava_wlan.html'

# =========================
# HELPERS
# =========================
function Ensure-Dirs {
    foreach ($d in @($Root, $LogDir, $StateDir, $ReportDir)) {
        if (-not (Test-Path -LiteralPath $d)) {
            New-Item -ItemType Directory -Path $d -Force | Out-Null
        }
    }
}

function Sha256Text {
    param([string]$Text)
    $sha   = [System.Security.Cryptography.SHA256]::Create()
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
    ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) -join ''
}

function Write-JsonLine {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][object]$Object
    )
    $line = $Object | ConvertTo-Json -Depth 20 -Compress
    Add-Content -Path $Path -Value $line -Encoding UTF8
}

# =========================
# TANGLE HASH CHAIN
# =========================
function Write-Tangle {
    param(
        [Parameter(Mandatory)][string]$Type,
        [Parameter(Mandatory)][string]$Summary,
        [object]$Data = $null
    )

    $prev = $null
    if (Test-Path -LiteralPath $TangleState) {
        try {
            $stateRaw = Get-Content -LiteralPath $TangleState -Raw
            $state    = $stateRaw | ConvertFrom-Json
            $prev     = $state.last_hash
        }
        catch { $prev = $null }
    }

    $ev = [ordered]@{
        time          = (Get-Date).ToString('o')
        host          = $env:COMPUTERNAME
        user          = $env:USERNAME
        type          = $Type
        summary       = $Summary
        previous_hash = $prev
        data          = $Data
    }

    $raw  = $ev | ConvertTo-Json -Depth 20 -Compress
    $hash = Sha256Text $raw
    $ev['hash'] = $hash

    Write-JsonLine -Path $TangleLog -Object $ev

    [ordered]@{
        updated   = (Get-Date).ToString('o')
        last_hash = $hash
    } | ConvertTo-Json | Set-Content -Path $TangleState -Encoding UTF8
}

# =========================
# WLAN SCAN
# =========================
function Get-WlanNetworksSafe {
    $raw = ''
    try {
        $raw = netsh wlan show networks mode=bssid 2>&1
    }
    catch {
        return @([pscustomobject]@{ Error = $_.Exception.Message })
    }

    $items          = New-Object System.Collections.Generic.List[object]
    $currentSsid    = $null
    $currentAuth    = $null
    $currentEncrypt = $null

    foreach ($line in ($raw -split '\r?\n')) {
        $l = $line.Trim()

        if ($l -match '^SSID\s+\d+\s*:\s+(.+)') {
            $currentSsid    = $Matches[1].Trim()
            $currentAuth    = $null
            $currentEncrypt = $null
        }
        elseif ($l -match '^Authentication\s*:\s+(.+)') {
            $currentAuth = $Matches[1].Trim()
        }
        elseif ($l -match '^Encryption\s*:\s+(.+)') {
            $currentEncrypt = $Matches[1].Trim()
        }
        elseif ($l -match '^BSSID\s+\d+\s*:\s+(.+)') {
            $bssid = $Matches[1].Trim()
            $items.Add([pscustomobject]@{
                SSID           = $currentSsid
                BSSID          = $bssid
                Authentication = $currentAuth
                Encryption     = $currentEncrypt
                Signal         = $null
                RadioType      = $null
            })
        }
        elseif ($l -match '^Signal\s*:\s+(.+)') {
            if ($items.Count -gt 0) {
                $items[$items.Count - 1].Signal = $Matches[1].Trim()
            }
        }
        elseif ($l -match '^Radio\s+type\s*:\s+(.+)') {
            if ($items.Count -gt 0) {
                $items[$items.Count - 1].RadioType = $Matches[1].Trim()
            }
        }
    }

    return $items.ToArray()
}

# =========================
# LOCAL NETWORK SNAPSHOT
# =========================
function Get-LocalNetworkSnapshot {
    $adapters = @()
    try {
        $adapters = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Select-Object InterfaceAlias, IPAddress, PrefixLength
    }
    catch { $adapters = @() }

    $neighbors = @()
    try {
        $neighbors = Get-NetNeighbor -ErrorAction SilentlyContinue |
            Where-Object { $_.State -ne 'Unreachable' } |
            Select-Object IPAddress, LinkLayerAddress, State, InterfaceAlias
    }
    catch {
        # Fall back to arp -a if Get-NetNeighbor is unavailable
        try {
            $arpRaw = arp -a 2>&1
            $neighbors = foreach ($line in ($arpRaw -split '\r?\n')) {
                if ($line -match '^\s+(\d{1,3}(?:\.\d{1,3}){3})\s+([\da-f-]+)\s+(\S+)') {
                    [pscustomobject]@{
                        IPAddress        = $Matches[1]
                        LinkLayerAddress = $Matches[2]
                        State            = $Matches[3]
                        InterfaceAlias   = $null
                    }
                }
            }
        }
        catch { $neighbors = @() }
    }

    [ordered]@{
        time      = (Get-Date).ToString('o')
        computer  = $env:COMPUTERNAME
        user      = $env:USERNAME
        adapters  = $adapters
        neighbors = $neighbors
    }
}

# =========================
# HTML PORTAL
# =========================
function Build-WlanPortal {
    param([object[]]$Networks, [object]$LocalSnap)

    $style = @'
<style>
  body  { font-family: Segoe UI, Tahoma, Arial; background: #1a1a1a; color: #eee; padding: 24px; }
  h1    { color: #00ffcc; border-bottom: 2px solid #00ffcc; padding-bottom: 10px; }
  h2    { color: #7ecfff; margin-top: 30px; }
  table { border-collapse: collapse; width: 100%; margin-top: 10px; }
  th    { background: #2a2a2a; color: #00ffcc; padding: 8px 12px; text-align: left; border: 1px solid #444; }
  td    { padding: 7px 12px; border: 1px solid #333; font-size: 13px; }
  tr:nth-child(even) { background: #232323; }
  .open { color: #ff6b6b; font-weight: bold; }
  .ts   { font-size: 12px; color: #888; margin-top: 6px; }
</style>
'@

    # WLAN table
    $wlanRows = foreach ($n in $Networks) {
        $authClass = if ([string]$n.Authentication -match 'Open|None') { 'open' } else { '' }
        "<tr>
          <td>$([System.Web.HttpUtility]::HtmlEncode([string]$n.SSID))</td>
          <td>$([System.Web.HttpUtility]::HtmlEncode([string]$n.BSSID))</td>
          <td class='$authClass'>$([System.Web.HttpUtility]::HtmlEncode([string]$n.Authentication))</td>
          <td>$([System.Web.HttpUtility]::HtmlEncode([string]$n.Encryption))</td>
          <td>$([System.Web.HttpUtility]::HtmlEncode([string]$n.Signal))</td>
          <td>$([System.Web.HttpUtility]::HtmlEncode([string]$n.RadioType))</td>
        </tr>"
    }

    $wlanTable = @"
<table>
  <tr><th>SSID</th><th>BSSID</th><th>Auth</th><th>Encryption</th><th>Signal</th><th>Radio</th></tr>
  $($wlanRows -join "`n")
</table>
"@

    # Neighbor table
    $neighborRows = foreach ($nb in $LocalSnap.neighbors) {
        "<tr>
          <td>$([System.Web.HttpUtility]::HtmlEncode([string]$nb.IPAddress))</td>
          <td>$([System.Web.HttpUtility]::HtmlEncode([string]$nb.LinkLayerAddress))</td>
          <td>$([System.Web.HttpUtility]::HtmlEncode([string]$nb.State))</td>
          <td>$([System.Web.HttpUtility]::HtmlEncode([string]$nb.InterfaceAlias))</td>
        </tr>"
    }

    $neighborTable = @"
<table>
  <tr><th>IP-Adresse</th><th>MAC</th><th>Status</th><th>Interface</th></tr>
  $($neighborRows -join "`n")
</table>
"@

    # Adapter table
    $adapterRows = foreach ($ad in $LocalSnap.adapters) {
        "<tr>
          <td>$([System.Web.HttpUtility]::HtmlEncode([string]$ad.InterfaceAlias))</td>
          <td>$([System.Web.HttpUtility]::HtmlEncode([string]$ad.IPAddress))</td>
          <td>$([System.Web.HttpUtility]::HtmlEncode([string]$ad.PrefixLength))</td>
        </tr>"
    }

    $adapterTable = @"
<table>
  <tr><th>Interface</th><th>IPv4-Adresse</th><th>Prefix</th></tr>
  $($adapterRows -join "`n")
</table>
"@

    $ts   = [System.Web.HttpUtility]::HtmlEncode([string]$LocalSnap.time)
    $host = [System.Web.HttpUtility]::HtmlEncode([string]$LocalSnap.computer)
    $user = [System.Web.HttpUtility]::HtmlEncode([string]$LocalSnap.user)

    $html = @"
<html>
<head><meta charset='utf-8'><title>AVA WLAN Portal</title>$style</head>
<body>
  <h1>&#128246; AVA WLAN TANGLE SENSOR</h1>
  <p class='ts'>Host: <b>$host</b> &nbsp;|&nbsp; User: <b>$user</b> &nbsp;|&nbsp; Stand: $ts</p>

  <h2>Sichtbare WLAN-Netze ($($Networks.Count))</h2>
  $wlanTable

  <h2>Eigene Netzwerkadapter</h2>
  $adapterTable

  <h2>LAN-Nachbarn (ARP/Neighbor)</h2>
  $neighborTable
</body>
</html>
"@

    Set-Content -Path $PortalHtml -Value $html -Encoding UTF8
}

# =========================
# MAIN SCAN
# =========================
function Invoke-Scan {
    Ensure-Dirs

    $networks   = Get-WlanNetworksSafe
    $localSnap  = Get-LocalNetworkSnapshot

    # Event log (flat JSONL)
    Write-JsonLine -Path $EventLog -Object ([ordered]@{
        time     = (Get-Date).ToString('o')
        host     = $env:COMPUTERNAME
        user     = $env:USERNAME
        networks = $networks
        local    = $localSnap
    })

    # Tangle chain entry
    $summary = "WLANs sichtbar: $($networks.Count) | Nachbarn: $(([array]$localSnap.neighbors).Count)"
    Write-Tangle -Type 'wlan_scan' -Summary $summary -Data ([ordered]@{
        networks = $networks
        local    = $localSnap
    })

    # HTML portal
    Build-WlanPortal -Networks $networks -LocalSnap $localSnap

    Write-Host "AVA WLAN Scan abgeschlossen. $summary" -ForegroundColor Cyan
    Write-Host "  Portal : $PortalHtml" -ForegroundColor DarkCyan
    Write-Host "  Events : $EventLog"   -ForegroundColor DarkCyan
    Write-Host "  Tangle : $TangleLog"  -ForegroundColor DarkCyan
}

# =========================
# SCHEDULED TASK
# =========================
function Install-WlanTask {
    if (-not $PSCommandPath) {
        throw 'PSCommandPath ist leer. Script muss als .ps1-Datei per -File ausgefuehrt werden.'
    }

    $action    = New-ScheduledTaskAction -Execute 'powershell.exe' `
                     -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -RunOnce"
    $trigger   = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1)
    $trigger.Repetition = New-ScheduledTaskRepetitionSettings `
                              -Interval (New-TimeSpan -Seconds $Interval) `
                              -Duration ([TimeSpan]::MaxValue)
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest

    Register-ScheduledTask -TaskName $TaskName -Action $action `
        -Trigger $trigger -Principal $principal -Force | Out-Null

    Write-Host "Scheduled Task installiert: $TaskName (Intervall: ${Interval}s)" -ForegroundColor Green
}

function Remove-WlanTask {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Host "Scheduled Task entfernt: $TaskName" -ForegroundColor Yellow
    }
    else {
        Write-Host "Kein Task gefunden: $TaskName" -ForegroundColor DarkYellow
    }
}

# =========================
# DISPATCH
# =========================
if ($RemoveTask) {
    Ensure-Dirs
    Remove-WlanTask
    exit
}

if ($InstallTask) {
    Ensure-Dirs
    Install-WlanTask
    exit
}

if ($RunOnce) {
    Invoke-Scan
    exit
}

if ($Loop) {
    Write-Host "AVA WLAN Loop gestartet (Intervall: ${Interval}s). Abbrechen mit Ctrl+C." -ForegroundColor Green
    while ($true) {
        Invoke-Scan
        Start-Sleep -Seconds $Interval
    }
}

# Default: single run
Invoke-Scan
