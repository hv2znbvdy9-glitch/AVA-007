#requires -version 5.1
<#
AVA HD READ-ONLY AUDIT
- Start bei Windows-Start
- Wiederholung alle 60 Sekunden
- Aktuelles Administratorkonto, RunLevel Highest
- Kein SYSTEM
- S4U: kein gespeichertes Kennwort, kein Netzwerkzugriff
- Keine Firewall-, Registry-, Dienst- oder Defender-Änderungen
- Hash-Prüfung vor jedem Lauf
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ------------------------------------------------------------
# 1. Voraussetzungen
# ------------------------------------------------------------

if ($env:OS -ne 'Windows_NT') {
    throw 'STOPP: Dieses Installationsskript ist ausschließlich für Windows vorgesehen.'
}

$Identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = New-Object Security.Principal.WindowsPrincipal($Identity)

if (-not $Principal.IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)) {
    throw 'STOPP: Windows PowerShell muss als Administrator geöffnet werden.'
}

Import-Module ScheduledTasks -ErrorAction Stop

$Root          = 'C:\ProgramData\AVA\HD_ReadOnlyAudit'
$LogDirectory  = Join-Path $Root 'Logs'
$AuditScript   = Join-Path $Root 'AVA_HD_ReadOnly_Audit.ps1'
$Launcher      = Join-Path $Root 'AVA_HD_Hash_Launcher.ps1'
$ManifestPath  = Join-Path $Root 'manifest.json'
$IntegrityLog  = Join-Path $LogDirectory 'integrity_alerts.jsonl'
$TaskName      = 'AVA_HD_ReadOnly_Audit_60s'
$CurrentUser   = $Identity.Name
$CurrentSid    = $Identity.User.Value
$PowerShellExe = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"

New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null

# ------------------------------------------------------------
# 2. Eigentliches READ-ONLY-Auditskript
# ------------------------------------------------------------

$AuditTemplate = @'
#requires -version 5.1

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Root         = '__ROOT__'
$LogDirectory = Join-Path $Root 'Logs'

if (-not (Test-Path -LiteralPath $LogDirectory -PathType Container)) {
    throw 'Der geschützte Audit-Logordner fehlt.'
}

function Get-SafeProperty {
    param(
        [AllowNull()]
        [object]$Object,

        [Parameter(Mandatory)]
        [string]$Name
    )

    if (
        $null -ne $Object -and
        $null -ne $Object.PSObject.Properties[$Name]
    ) {
        return $Object.$Name
    }

    return $null
}

try {
    $Now       = Get-Date
    $Identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $Principal = New-Object Security.Principal.WindowsPrincipal($Identity)

    $IsAdministrator = $Principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )

    $IsSystem = $Identity.User.Value -eq 'S-1-5-18'

    # Lokale Betriebssystemdaten
    $OperatingSystem = Get-CimInstance `
        -ClassName Win32_OperatingSystem `
        -ErrorAction Stop

    $LastBoot = [datetime]$OperatingSystem.LastBootUpTime
    $Uptime   = $Now - $LastBoot

    # Lokales Systemlaufwerk
    $SystemDrive = Get-CimInstance `
        -ClassName Win32_LogicalDisk `
        -Filter "DeviceID='C:'" `
        -ErrorAction SilentlyContinue

    $DiskStatus = if ($null -ne $SystemDrive) {
        [ordered]@{
            Drive       = $SystemDrive.DeviceID
            SizeGB      = [math]::Round($SystemDrive.Size / 1GB, 2)
            FreeGB      = [math]::Round($SystemDrive.FreeSpace / 1GB, 2)
            FreePercent = if ($SystemDrive.Size -gt 0) {
                [math]::Round(
                    100 * $SystemDrive.FreeSpace / $SystemDrive.Size,
                    2
                )
            }
            else {
                $null
            }
        }
    }
    else {
        $null
    }

    # Microsoft Defender: ausschließlich Statusabfrage
    $DefenderStatus = [ordered]@{
        Available = $false
    }

    if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
        try {
            $MpStatus = Get-MpComputerStatus -ErrorAction Stop

            $DefenderStatus = [ordered]@{
                Available                   = $true
                AntivirusEnabled            = Get-SafeProperty $MpStatus 'AntivirusEnabled'
                AntispywareEnabled          = Get-SafeProperty $MpStatus 'AntispywareEnabled'
                RealTimeProtectionEnabled   = Get-SafeProperty $MpStatus 'RealTimeProtectionEnabled'
                BehaviorMonitorEnabled      = Get-SafeProperty $MpStatus 'BehaviorMonitorEnabled'
                IoavProtectionEnabled       = Get-SafeProperty $MpStatus 'IoavProtectionEnabled'
                NISEnabled                  = Get-SafeProperty $MpStatus 'NISEnabled'
                TamperProtected             = Get-SafeProperty $MpStatus 'IsTamperProtected'
                AntivirusSignatureAgeDays   = Get-SafeProperty $MpStatus 'AntivirusSignatureAge'
                AntivirusSignatureVersion   = Get-SafeProperty $MpStatus 'AntivirusSignatureVersion'
                QuickScanAgeDays            = Get-SafeProperty $MpStatus 'QuickScanAge'
                FullScanAgeDays             = Get-SafeProperty $MpStatus 'FullScanAge'
            }
        }
        catch {
            $DefenderStatus = [ordered]@{
                Available  = $true
                QueryError = $_.Exception.Message
            }
        }
    }

    # Windows-Firewall: ausschließlich Statusabfrage
    $FirewallProfiles = @()

    if (Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue) {
        $FirewallProfiles = @(
            Get-NetFirewallProfile -ErrorAction Stop |
                Sort-Object Name |
                ForEach-Object {
                    [ordered]@{
                        Name                  = $_.Name
                        Enabled               = $_.Enabled
                        DefaultInboundAction  = [string]$_.DefaultInboundAction
                        DefaultOutboundAction = [string]$_.DefaultOutboundAction
                        NotifyOnListen        = $_.NotifyOnListen
                    }
                }
        )
    }

    # Sicherheitsrelevante Dienste: nur lesen
    $ServiceStatus = @(
        foreach ($ServiceName in 'WinDefend', 'MpsSvc', 'WdNisSvc') {
            try {
                $Service = Get-Service `
                    -Name $ServiceName `
                    -ErrorAction Stop

                [ordered]@{
                    Name        = $Service.Name
                    DisplayName = $Service.DisplayName
                    Status      = [string]$Service.Status
                    Available   = $true
                }
            }
            catch {
                [ordered]@{
                    Name      = $ServiceName
                    Available = $false
                }
            }
        }
    )

    $ProcessCount = @(
        Get-Process -ErrorAction SilentlyContinue
    ).Count

    $Record = [ordered]@{
        SchemaVersion = 'AVA-HD-READONLY-1.0'

        Time = [ordered]@{
            Local = $Now.ToString('o')
            UTC   = $Now.ToUniversalTime().ToString('o')
        }

        Context = [ordered]@{
            Computer             = $env:COMPUTERNAME
            User                 = $Identity.Name
            AdministratorContext = $IsAdministrator
            SystemContext        = $IsSystem

            NetworkCommandsUsed    = $false
            FirewallChangesMade    = $false
            RegistryChangesMade    = $false
            ServiceChangesMade     = $false
            DefenderChangesMade    = $false
            ScheduledTasksModified = $false
            ExternalProcessesRun   = $false
        }

        OperatingSystem = [ordered]@{
            Caption       = $OperatingSystem.Caption
            Version       = $OperatingSystem.Version
            BuildNumber   = $OperatingSystem.BuildNumber
            Architecture  = $OperatingSystem.OSArchitecture
            LastBoot      = $LastBoot.ToString('o')
            UptimeHours   = [math]::Round($Uptime.TotalHours, 2)
        }

        SystemDrive      = $DiskStatus
        ProcessCount     = $ProcessCount
        Defender         = $DefenderStatus
        FirewallProfiles = $FirewallProfiles
        SecurityServices = $ServiceStatus
    }

    $Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    $Json      = $Record | ConvertTo-Json -Depth 8 -Compress

    $LatestPath = Join-Path $LogDirectory 'latest.json'
    $DailyPath  = Join-Path $LogDirectory (
        'audit_{0:yyyyMMdd}.jsonl' -f $Now
    )

    # Ausschließlich kontrollierte Audit-Ausgaben
    [System.IO.File]::WriteAllText(
        $LatestPath,
        $Json,
        $Utf8NoBom
    )

    [System.IO.File]::AppendAllText(
        $DailyPath,
        $Json + [Environment]::NewLine,
        $Utf8NoBom
    )

    exit 0
}
catch {
    try {
        $Utf8NoBom = New-Object System.Text.UTF8Encoding($false)

        $ErrorRecord = [ordered]@{
            TimestampUTC = (Get-Date).ToUniversalTime().ToString('o')
            Type         = $_.Exception.GetType().FullName
            Message      = $_.Exception.Message
        } | ConvertTo-Json -Compress

        [System.IO.File]::AppendAllText(
            (Join-Path $LogDirectory 'errors.jsonl'),
            $ErrorRecord + [Environment]::NewLine,
            $Utf8NoBom
        )
    }
    catch {
        # Keine Ausweichaktion außerhalb des geschützten Ordners
    }

    exit 1
}
'@

$AuditContent = $AuditTemplate.Replace(
    '__ROOT__',
    $Root.Replace("'", "''")
)

[System.IO.File]::WriteAllText(
    $AuditScript,
    $AuditContent,
    (New-Object System.Text.UTF8Encoding($false))
)

$AuditHash = (
    Get-FileHash -LiteralPath $AuditScript -Algorithm SHA256
).Hash

# ------------------------------------------------------------
# 3. Hash-verriegelter Launcher
# ------------------------------------------------------------

$LauncherTemplate = @'
#requires -version 5.1

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$AuditScript  = '__AUDIT_SCRIPT__'
$ExpectedHash = '__EXPECTED_HASH__'
$IntegrityLog = '__INTEGRITY_LOG__'

try {
    $ActualHash = (
        Get-FileHash -LiteralPath $AuditScript -Algorithm SHA256
    ).Hash

    if ($ActualHash -ne $ExpectedHash) {
        $Utf8NoBom = New-Object System.Text.UTF8Encoding($false)

        $Alert = [ordered]@{
            TimestampUTC = (Get-Date).ToUniversalTime().ToString('o')
            Event        = 'AUDIT_SCRIPT_HASH_MISMATCH'
            Expected     = $ExpectedHash
            Actual       = $ActualHash
        } | ConvertTo-Json -Compress

        [System.IO.File]::AppendAllText(
            $IntegrityLog,
            $Alert + [Environment]::NewLine,
            $Utf8NoBom
        )

        exit 23
    }

    & $AuditScript
    exit $LASTEXITCODE
}
catch {
    exit 24
}
'@

$LauncherContent = $LauncherTemplate.
    Replace('__AUDIT_SCRIPT__', $AuditScript.Replace("'", "''")).
    Replace('__EXPECTED_HASH__', $AuditHash).
    Replace('__INTEGRITY_LOG__', $IntegrityLog.Replace("'", "''"))

[System.IO.File]::WriteAllText(
    $Launcher,
    $LauncherContent,
    (New-Object System.Text.UTF8Encoding($false))
)

$LauncherHash = (
    Get-FileHash -LiteralPath $Launcher -Algorithm SHA256
).Hash

# ------------------------------------------------------------
# 4. Statische Parser- und Capability-Prüfung
# ------------------------------------------------------------

function Assert-SafeRuntimeScript {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $Tokens      = $null
    $ParseErrors = $null

    $Ast = [System.Management.Automation.Language.Parser]::ParseFile(
        $Path,
        [ref]$Tokens,
        [ref]$ParseErrors
    )

    if ($ParseErrors.Count -gt 0) {
        $Messages = $ParseErrors |
            ForEach-Object { $_.Message }

        throw "Parserfehler in $Path`n$($Messages -join "`n")"
    }

    $BlockedCommands = @(
        'Invoke-Expression',
        'Invoke-Command',
        'Enter-PSSession',
        'New-PSSession',
        'Start-Process',
        'Invoke-WebRequest',
        'Invoke-RestMethod',
        'Start-BitsTransfer',
        'Resolve-DnsName',
        'Test-NetConnection',
        'New-NetFirewallRule',
        'Set-NetFirewallProfile',
        'Remove-NetFirewallRule',
        'Set-Service',
        'Start-Service',
        'Stop-Service',
        'Restart-Service',
        'Register-ScheduledTask',
        'Unregister-ScheduledTask',
        'Set-ItemProperty',
        'New-ItemProperty',
        'Remove-ItemProperty',
        'Remove-Item',
        'Move-Item',
        'Copy-Item',
        'Add-Type',
        'cmd.exe',
        'netsh.exe',
        'reg.exe',
        'sc.exe',
        'schtasks.exe',
        'certutil.exe',
        'bitsadmin.exe'
    )

    $Commands = @(
        $Ast.FindAll(
            {
                param($Node)

                $Node -is [
                    System.Management.Automation.Language.CommandAst
                ]
            },
            $true
        ) |
            ForEach-Object { $_.GetCommandName() } |
            Where-Object { $_ }
    )

    $BlockedHits = @(
        $Commands |
            Where-Object { $BlockedCommands -contains $_ } |
            Sort-Object -Unique
    )

    if ($BlockedHits.Count -gt 0) {
        throw "Blockierte Befehle in $Path: $($BlockedHits -join ', ')"
    }

    $Content = Get-Content -LiteralPath $Path -Raw

    if ($Content -match '(?i)https?://|ftp://|\\\\[^\\]') {
        throw "Netzwerk- oder UNC-Ziel in $Path erkannt."
    }

    if (
        $Content -match
        '(?i)(api[_-]?key|client[_-]?secret|bearer\s+[a-z0-9._-]+)'
    ) {
        throw "Mögliches Secret in $Path erkannt."
    }
}

Assert-SafeRuntimeScript -Path $AuditScript
Assert-SafeRuntimeScript -Path $Launcher

# ------------------------------------------------------------
# 5. Manifest
# ------------------------------------------------------------

$Manifest = [ordered]@{
    SchemaVersion          = 'AVA-HD-INSTALL-1.0'
    InstalledAtUTC         = (Get-Date).ToUniversalTime().ToString('o')
    InstalledBy            = $CurrentUser
    TaskName               = $TaskName
    IntervalSeconds        = 60
    RunLevel               = 'Highest'
    LogonType              = 'S4U'
    SystemContext          = $false
    PasswordStored         = $false
    NetworkAccessPermitted = $false
    AuditScript            = $AuditScript
    AuditScriptSHA256      = $AuditHash
    LauncherSHA256         = $LauncherHash
    LogDirectory           = $LogDirectory
}

$Manifest |
    ConvertTo-Json -Depth 5 |
    Set-Content -LiteralPath $ManifestPath -Encoding UTF8

# ------------------------------------------------------------
# 6. Ordnerrechte begrenzen
# ------------------------------------------------------------

$Icacls = "$env:SystemRoot\System32\icacls.exe"

& $Icacls $Root '/inheritance:r' '/T' '/C' | Out-Null

if ($LASTEXITCODE -ne 0) {
    throw 'Ordnervererbung konnte nicht sicher entfernt werden.'
}

& $Icacls $Root `
    '/grant:r' `
    "*${CurrentSid}:(OI)(CI)F" `
    '*S-1-5-18:(OI)(CI)F' `
    '*S-1-5-32-544:(OI)(CI)F' `
    '/T' `
    '/C' | Out-Null

if ($LASTEXITCODE -ne 0) {
    throw 'Die geschützten Ordnerrechte konnten nicht gesetzt werden.'
}

# ------------------------------------------------------------
# 7. Geplanten Task erstellen
# ------------------------------------------------------------

$ActionArguments = @(
    '-NoLogo'
    '-NoProfile'
    '-NonInteractive'
    '-ExecutionPolicy RemoteSigned'
    "-File `"$Launcher`""
) -join ' '

$Action = New-ScheduledTaskAction `
    -Execute $PowerShellExe `
    -Argument $ActionArguments `
    -WorkingDirectory $Root

# Sofort beim Windows-Start
$StartupTrigger = New-ScheduledTaskTrigger -AtStartup

# Anschließend alle 60 Sekunden; zehnjährige Laufperiode
$RepeatTrigger = New-ScheduledTaskTrigger `
    -Once `
    -At (Get-Date).AddMinutes(1) `
    -RepetitionInterval (New-TimeSpan -Minutes 1) `
    -RepetitionDuration (New-TimeSpan -Days 3650)

# Höchste Rechte des aktuellen Administratorkontos,
# aber ausdrücklich kein SYSTEM-Konto
$TaskPrincipal = New-ScheduledTaskPrincipal `
    -UserId $CurrentUser `
    -LogonType S4U `
    -RunLevel Highest

$Settings = New-ScheduledTaskSettingsSet `
    -StartWhenAvailable `
    -MultipleInstances IgnoreNew `
    -ExecutionTimeLimit (New-TimeSpan -Seconds 45) `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries

$TaskDefinition = New-ScheduledTask `
    -Action $Action `
    -Trigger @($StartupTrigger, $RepeatTrigger) `
    -Principal $TaskPrincipal `
    -Settings $Settings `
    -Description (
        'AVA HD: lokaler READ-ONLY-Sicherheitsstatus alle 60 Sekunden; ' +
        'hashgeprüft, S4U, kein SYSTEM und kein Netzwerkzugriff.'
    )

Register-ScheduledTask `
    -TaskName $TaskName `
    -InputObject $TaskDefinition `
    -Force | Out-Null

# Erster kontrollierter Lauf
Start-ScheduledTask -TaskName $TaskName
Start-Sleep -Seconds 4

$TaskInfo = Get-ScheduledTaskInfo -TaskName $TaskName
$Task     = Get-ScheduledTask -TaskName $TaskName

Write-Host ''
Write-Host 'AVA HD READ-ONLY AUDIT INSTALLIERT' -ForegroundColor Green
Write-Host "Task:       $TaskName"
Write-Host "Status:     $($Task.State)"
Write-Host "Letzter Lauf: $($TaskInfo.LastRunTime)"
Write-Host "Ergebnis:   $($TaskInfo.LastTaskResult)"
Write-Host "Nächster Lauf: $($TaskInfo.NextRunTime)"
Write-Host "Audit SHA256: $AuditHash"
Write-Host "Logs:       $LogDirectory"
Write-Host ''
Write-Host 'Keine Firewall-, Registry-, Dienst- oder Netzwerkänderungen.' `
    -ForegroundColor Cyan
