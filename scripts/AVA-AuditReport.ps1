#requires -RunAsAdministrator
<#
AVA v3 - AUDIT ONLY (Read-Only / Local / Defensive)
- Liest nur lokale Sicherheits-/Systeminformationen aus
- Nimmt KEINE Änderungen am System vor
- Keine Registry-Schreibzugriffe
- Keine Firewall-Regeln
- Keine Dienst-Änderungen
- Erstellt einen Report auf dem Desktop
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Now        = Get-Date -Format "yyyyMMdd_HHmmss"
$ReportDir  = Join-Path ([Environment]::GetFolderPath("Desktop")) "AVA_AUDIT_REPORT_$Now"
$JsonReport = Join-Path $ReportDir "report.json"
$TxtReport  = Join-Path $ReportDir "report.txt"

function Ensure-Dir {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Write-Section {
    param(
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][object]$Data
    )

    $script:Results += [pscustomobject]@{
        Title = $Title
        Data  = $Data
    }
}

function Get-RegistryDwordSafe {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name
    )
    try {
        $item = Get-ItemProperty -Path $Path -ErrorAction Stop
        if ($null -ne $item.$Name) {
            return $item.$Name
        }
        return "NotSet"
    } catch {
        return "PathOrValueNotFound"
    }
}

function Try-GetServiceInfo {
    param([Parameter(Mandatory)][string]$Name)
    if ($Name -notmatch '^[A-Za-z0-9_]+$') {
        return [pscustomobject]@{
            Name      = $Name
            State     = "Unknown"
            StartMode = "Unknown"
            Status    = "InvalidServiceName"
        }
    }
    try {
        $svc = Get-CimInstance Win32_Service -Filter "Name='$Name'" -ErrorAction Stop
        [pscustomobject]@{
            Name      = $svc.Name
            State     = $svc.State
            StartMode = $svc.StartMode
            Status    = "Present"
        }
    } catch {
        [pscustomobject]@{
            Name      = $Name
            State     = "Unknown"
            StartMode = "Unknown"
            Status    = "NotPresentOrUnreadable"
        }
    }
}

function Safe-Run {
    param(
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][scriptblock]$ScriptBlock
    )
    try {
        $data = & $ScriptBlock
        Write-Section -Title $Title -Data $data
    } catch {
        Write-Section -Title $Title -Data "Nicht verfügbar: $($_.Exception.Message)"
    }
}

Ensure-Dir -Path $ReportDir
$Results = @()

Safe-Run -Title "System" -ScriptBlock {
    $computer = $env:COMPUTERNAME
    $userName = "$env:USERDOMAIN\$env:USERNAME"
    $os = Get-CimInstance Win32_OperatingSystem
    $cs = Get-CimInstance Win32_ComputerSystem

    [pscustomobject]@{
        ComputerName = $computer
        User         = $userName
        OS           = $os.Caption
        Version      = $os.Version
        Build        = $os.BuildNumber
        Manufacturer = $cs.Manufacturer
        Model        = $cs.Model
        Time         = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    }
}

Safe-Run -Title "PrivacyAndRemoteStatus" -ScriptBlock {
    $rdpValue = Get-RegistryDwordSafe -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections"

    [pscustomobject]@{
        AllowTelemetry      = Get-RegistryDwordSafe -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry"
        AllowCortana        = Get-RegistryDwordSafe -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana"
        fDenyTSConnections  = $rdpValue
        InterpretedRdpState = switch ($rdpValue) {
            0 { "RDP erlaubt" }
            1 { "RDP blockiert/deaktiviert" }
            default { "Unbekannt" }
        }
    }
}

Safe-Run -Title "Services" -ScriptBlock {
    @(
        Try-GetServiceInfo -Name "RemoteRegistry"
        Try-GetServiceInfo -Name "WinRM"
        Try-GetServiceInfo -Name "TermService"
        Try-GetServiceInfo -Name "wuauserv"
        Try-GetServiceInfo -Name "WinDefend"
    )
}

Safe-Run -Title "FirewallProfiles" -ScriptBlock {
    Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction
}

Safe-Run -Title "FirewallRules_AVA_Block" -ScriptBlock {
    $rules = Get-NetFirewallRule -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -like 'AVA_Block_*' } |
        Select-Object DisplayName, Direction, Action, Enabled, Profile

    if ($null -eq $rules -or $rules.Count -eq 0) {
        "Keine AVA_Block_-Regeln gefunden"
    } else {
        $rules
    }
}

Safe-Run -Title "NetworkAdapters" -ScriptBlock {
    Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, LinkSpeed, MacAddress
}

Safe-Run -Title "IPv4" -ScriptBlock {
    Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -notlike '169.254*' } |
        Select-Object InterfaceAlias, IPAddress, PrefixLength
}

Safe-Run -Title "DNS" -ScriptBlock {
    Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Select-Object InterfaceAlias, ServerAddresses
}

Safe-Run -Title "EstablishedConnections" -ScriptBlock {
    $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
        Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess

    $procMap = @{}
    foreach ($p in Get-Process -ErrorAction SilentlyContinue) {
        $procMap[$p.Id] = $p.ProcessName
    }

    foreach ($c in $connections) {
        [pscustomobject]@{
            LocalAddress  = $c.LocalAddress
            LocalPort     = $c.LocalPort
            RemoteAddress = $c.RemoteAddress
            RemotePort    = $c.RemotePort
            State         = $c.State
            ProcessId     = $c.OwningProcess
            ProcessName   = if ($procMap.ContainsKey($c.OwningProcess)) { $procMap[$c.OwningProcess] } else { "Unknown" }
        }
    }
}

Safe-Run -Title "LocalAdministrators" -ScriptBlock {
    # Use well-known SID S-1-5-32-544 to resolve the Administrators group name
    # regardless of OS locale (e.g. "Administratoren" on German Windows).
    $adminSid   = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
    $adminGroup = $adminSid.Translate([System.Security.Principal.NTAccount]).Value

    Get-LocalGroupMember -Group $adminGroup |
        Select-Object Name, PrincipalSource, ObjectClass
}

Safe-Run -Title "ScheduledTasks_NonMicrosoft" -ScriptBlock {
    Get-ScheduledTask -ErrorAction SilentlyContinue |
        Where-Object { $_.TaskPath -notlike "\Microsoft*" } |
        Select-Object TaskName, TaskPath, State
}

Safe-Run -Title "Defender" -ScriptBlock {
    $mp = Get-MpComputerStatus
    [pscustomobject]@{
        AntivirusEnabled      = $mp.AntivirusEnabled
        RealTimeProtection    = $mp.RealTimeProtectionEnabled
        IoavProtectionEnabled = $mp.IoavProtectionEnabled
        NISEnabled            = $mp.NISEnabled
        AntispywareEnabled    = $mp.AntispywareEnabled
        TamperProtected       = $mp.IsTamperProtected
        QuickScanAgeDays      = $mp.QuickScanAge
        FullScanAgeDays       = $mp.FullScanAge
        SignatureAgeDays      = $mp.AntivirusSignatureAge
    }
}

$mindShield = @"
AVA MIND CHECK-IN

1. Was ist gerade sicher beobachtbar?
2. Was ist Interpretation?
3. Welche 3 Fakten kann ich direkt prüfen?
4. Was brauche ich jetzt: Ruhe, Wasser, Pause, Schlaf, Abstand?

Kernsatz:
Ich bleibe klar.
Ich prüfe erst.
Ich handle bewusst.
"@
Write-Section -Title "MindCheckIn" -Data $mindShield

Safe-Run -Title "Summary" -ScriptBlock {
    [pscustomobject]@{
        CompletedAt = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        Mode        = "ReadOnly"
        ChangesMade = 0
        ReportDir   = $ReportDir
    }
}

$computer = $env:COMPUTERNAME
$userName = "$env:USERDOMAIN\$env:USERNAME"

$reportObject = [pscustomobject]@{
    Meta    = [pscustomobject]@{
        Name      = "AVA AUDIT ONLY"
        Mode      = "Read-Only / Defensive / Local"
        Timestamp = (Get-Date).ToString("o")
        Computer  = $computer
        User      = $userName
    }
    Results = $Results
}

$reportObject | ConvertTo-Json -Depth 8 | Set-Content -Path $JsonReport -Encoding UTF8

$txt = New-Object System.Collections.Generic.List[string]
$txt.Add("AVA AUDIT ONLY")
$txt.Add(("Zeit: {0}" -f (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")))
$txt.Add(("Computer: {0}" -f $computer))
$txt.Add(("User: {0}" -f $userName))
$txt.Add("Modus: Read-Only")
$txt.Add("")

foreach ($entry in $Results) {
    $txt.Add(("==== {0} ====" -f $entry.Title))
    if ($entry.Data -is [string]) {
        $txt.Add($entry.Data)
    } else {
        try {
            $txt.Add(($entry.Data | Format-List | Out-String).Trim())
        } catch {
            $txt.Add(($entry.Data | Out-String).Trim())
        }
    }
    $txt.Add("")
}

$txt -join "`r`n" | Set-Content -Path $TxtReport -Encoding UTF8

Write-Host ""
Write-Host "AVA AUDIT ONLY abgeschlossen." -ForegroundColor Green
Write-Host "Es wurden keine Systemänderungen vorgenommen." -ForegroundColor Green
Write-Host "Report-Ordner: $ReportDir" -ForegroundColor Cyan
Write-Host "TXT-Report : $TxtReport" -ForegroundColor Cyan
Write-Host "JSON-Report: $JsonReport" -ForegroundColor Cyan
Write-Host ""
Write-Host "Kernsatz:" -ForegroundColor Yellow
Write-Host "Ich bleibe klar. Ich prüfe erst. Ich handle bewusst." -ForegroundColor Yellow
