#requires -RunAsAdministrator

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ------------------------------------------------------------
# AVA 2.0 - Defensives Sicherungs- und Rückführungssystem
# Rein lokal / defensiv / nur auf autorisierten Systemen nutzen
# ------------------------------------------------------------

# ------------------------------------------------------------
# 1. BASIS-KONFIGURATION
# ------------------------------------------------------------
$script:AvaRoot           = 'C:\AVA'
$script:LogFile           = Join-Path $script:AvaRoot 'ActivityLog.txt'
$script:EncryptedLogFile  = Join-Path $script:AvaRoot 'EncryptedLog.txt'
$script:AlarmFile         = Join-Path $script:AvaRoot 'AlarmLog.txt'
$script:LedgerFile        = Join-Path $script:AvaRoot 'ReturnLedger.json'

$script:ProtectedResources = @('Daten', 'Energie', 'Materialien')
$script:ReturnQueue        = New-Object System.Collections.Generic.List[string]
$script:SecureMode         = $true

# Passwort/Passphrase für lokale Log-Verschlüsselung
# In echt besser aus Secret Store / Windows Credential Manager / DPAPI ziehen
$script:EncryptionPassphrase = 'AVA-2.0-Local-Defensive-Key-2026'

# Optionale E-Mail-Benachrichtigung
$script:NotifyEmail = 'admin@example.com'
$script:SmtpServer  = 'smtp.yourserver.com'
$script:SmtpPort    = 587
$script:SmtpFrom    = 'ava@example.com'
$script:SmtpUser    = ''
$script:SmtpPass    = ''
$script:EnableEmailAlerts = $false

# ------------------------------------------------------------
# 2. C# HILFSKLASSE FÜR AES-VERSCHLÜSSELUNG
# - SHA256 leitet 32-Byte-Key aus Passphrase ab
# - zufälliger IV pro Eintrag
# - Ausgabe = Base64( IV + Ciphertext )
# ------------------------------------------------------------
Add-Type -TypeDefinition @"
using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;

public static class EncryptionHelper
{
    private static byte[] DeriveKey(string passphrase)
    {
        using (SHA256 sha = SHA256.Create())
        {
            return sha.ComputeHash(Encoding.UTF8.GetBytes(passphrase));
        }
    }

    public static string Encrypt(string plainText, string passphrase)
    {
        byte[] key = DeriveKey(passphrase);

        using (Aes aes = Aes.Create())
        {
            aes.Key = key;
            aes.GenerateIV();
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

            using (MemoryStream ms = new MemoryStream())
            {
                ms.Write(aes.IV, 0, aes.IV.Length);

                using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                using (StreamWriter sw = new StreamWriter(cs, Encoding.UTF8))
                {
                    sw.Write(plainText);
                }

                return Convert.ToBase64String(ms.ToArray());
            }
        }
    }

    public static string Decrypt(string cipherText, string passphrase)
    {
        byte[] fullCipher = Convert.FromBase64String(cipherText);
        byte[] key = DeriveKey(passphrase);

        byte[] iv = new byte[16];
        Array.Copy(fullCipher, 0, iv, 0, iv.Length);

        byte[] cipherBytes = new byte[fullCipher.Length - iv.Length];
        Array.Copy(fullCipher, iv.Length, cipherBytes, 0, cipherBytes.Length);

        using (Aes aes = Aes.Create())
        {
            aes.Key = key;
            aes.IV = iv;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

            using (MemoryStream ms = new MemoryStream(cipherBytes))
            using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
            using (StreamReader sr = new StreamReader(cs, Encoding.UTF8))
            {
                return sr.ReadToEnd();
            }
        }
    }
}
"@ -Language CSharp

# ------------------------------------------------------------
# 3. INITIALISIERUNG
# ------------------------------------------------------------
function Initialize-AVAEnvironment {
    if (-not (Test-Path -Path $script:AvaRoot)) {
        New-Item -Path $script:AvaRoot -ItemType Directory -Force | Out-Null
        Write-Host "AVA-Verzeichnis erstellt: $($script:AvaRoot)" -ForegroundColor Cyan
    }

    foreach ($file in @($script:LogFile, $script:EncryptedLogFile, $script:AlarmFile)) {
        if (-not (Test-Path -Path $file)) {
            New-Item -Path $file -ItemType File -Force | Out-Null
        }
    }

    if (-not (Test-Path -Path $script:LedgerFile)) {
        '[]' | Set-Content -Path $script:LedgerFile -Encoding UTF8
    }
}

# ------------------------------------------------------------
# 4. LOGGING
# ------------------------------------------------------------
function Write-PlainLog {
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [ValidateSet('INFO','WARN','ALERT','ERROR')]
        [string]$Level = 'INFO'
    )

    Initialize-AVAEnvironment

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $entry = '{0} [{1}] {2}' -f $timestamp, $Level, $Message
    Add-Content -Path $script:LogFile -Value $entry
    Write-Host $entry
}

function Write-EncryptedLog {
    param(
        [Parameter(Mandatory)]
        [string]$Message
    )

    Initialize-AVAEnvironment

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $entry = '{0} {1}' -f $timestamp, $Message
    $encrypted = [EncryptionHelper]::Encrypt($entry, $script:EncryptionPassphrase)
    Add-Content -Path $script:EncryptedLogFile -Value $encrypted
}

function Log-Activity {
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [ValidateSet('INFO','WARN','ALERT','ERROR')]
        [string]$Level = 'INFO'
    )

    Write-PlainLog -Message $Message -Level $Level
    Write-EncryptedLog -Message "[$Level] $Message"
}

# ------------------------------------------------------------
# 5. ALARMIERUNG
# ------------------------------------------------------------
function Write-Alarm {
    param(
        [Parameter(Mandatory)]
        [string]$Message
    )

    Initialize-AVAEnvironment

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $entry = '{0} [ALARM] {1}' -f $timestamp, $Message
    Add-Content -Path $script:AlarmFile -Value $entry
    Write-Host $entry -ForegroundColor Red
}

function Send-AlertEmail {
    param(
        [Parameter(Mandatory)]
        [string]$Subject,

        [Parameter(Mandatory)]
        [string]$Body
    )

    if (-not $script:EnableEmailAlerts) {
        Log-Activity -Level 'INFO' -Message "E-Mail-Alarm deaktiviert | Betreff=$Subject"
        return
    }

    try {
        if ([string]::IsNullOrWhiteSpace($script:SmtpUser)) {
            Send-MailMessage `
                -To $script:NotifyEmail `
                -From $script:SmtpFrom `
                -Subject $Subject `
                -Body $Body `
                -SmtpServer $script:SmtpServer `
                -Port $script:SmtpPort `
                -UseSsl
        }
        else {
            $securePass = ConvertTo-SecureString $script:SmtpPass -AsPlainText -Force
            $cred = New-Object System.Management.Automation.PSCredential($script:SmtpUser, $securePass)

            Send-MailMessage `
                -To $script:NotifyEmail `
                -From $script:SmtpFrom `
                -Subject $Subject `
                -Body $Body `
                -SmtpServer $script:SmtpServer `
                -Port $script:SmtpPort `
                -UseSsl `
                -Credential $cred
        }

        Log-Activity -Level 'INFO' -Message "E-Mail-Alarm gesendet | Betreff=$Subject"
    }
    catch {
        Log-Activity -Level 'ERROR' -Message "Fehler beim Senden des E-Mail-Alarms: $($_.Exception.Message)"
    }
}

function Invoke-Alarm {
    param(
        [Parameter(Mandatory)]
        [string]$Message
    )

    Write-Alarm -Message $Message
    Log-Activity -Level 'ALERT' -Message $Message
    Send-AlertEmail -Subject 'AVA Alarm' -Body $Message
}

# ------------------------------------------------------------
# 6. RÜCKFÜHRUNGSLISTE
# ------------------------------------------------------------
function Add-ReturnQueue {
    param(
        [Parameter(Mandatory)]
        [string]$ResourceName
    )

    if (-not $script:ReturnQueue.Contains($ResourceName)) {
        $script:ReturnQueue.Add($ResourceName)
        Log-Activity -Level 'WARN' -Message "Ressource zur Rückführungsliste hinzugefügt: $ResourceName"
    }
    else {
        Log-Activity -Level 'INFO' -Message "Ressource bereits in Rückführungsliste: $ResourceName"
    }
}

# ------------------------------------------------------------
# 7. LEDGER-EXPORT
# - Lokaler Nachweis statt echter Blockchain
# ------------------------------------------------------------
function Export-ReturnLedgerEntry {
    param(
        [Parameter(Mandatory)]
        [string]$ResourceName,

        [Parameter(Mandatory)]
        [string]$Action
    )

    Initialize-AVAEnvironment

    $existing = @()
    try {
        $raw = Get-Content -Path $script:LedgerFile -Raw
        if (-not [string]::IsNullOrWhiteSpace($raw)) {
            $parsed = $raw | ConvertFrom-Json
            if ($parsed) {
                $existing = @($parsed)
            }
        }
    }
    catch {
        $existing = @()
    }

    $entry = [pscustomobject]@{
        timestamp    = (Get-Date).ToString('s')
        hostname     = $env:COMPUTERNAME
        resource     = $ResourceName
        action       = $Action
        secureMode   = $script:SecureMode
    }

    $existing += $entry
    $existing | ConvertTo-Json -Depth 5 | Set-Content -Path $script:LedgerFile -Encoding UTF8

    Log-Activity -Level 'INFO' -Message "Ledger-Eintrag geschrieben | Ressource=$ResourceName | Aktion=$Action"
}

# ------------------------------------------------------------
# 8. RESSOURCEN-ÜBERWACHUNG
# DemoMode simuliert
# ForceBreachFor kann gezielt Testalarme auslösen
# ------------------------------------------------------------
function Monitor-Resource {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ResourceName,

        [switch]$DemoMode,
        [switch]$ForceBreach
    )

    Write-Host "AVA überwacht Ressource: $ResourceName ..." -ForegroundColor Cyan
    Log-Activity -Level 'INFO' -Message "Überwachung gestartet: $ResourceName"

    Start-Sleep -Seconds 1

    $breachDetected = $false

    if ($ForceBreach) {
        $breachDetected = $true
    }
    elseif ($DemoMode) {
        $breachDetected = ([bool](Get-Random -Minimum 0 -Maximum 2))
    }

    if ($breachDetected) {
        $msg = "Bedrohung erkannt bei Ressource: $ResourceName"
        Invoke-Alarm -Message $msg
        Add-ReturnQueue -ResourceName $ResourceName
    }
    else {
        Log-Activity -Level 'INFO' -Message "Keine Auffälligkeit erkannt: $ResourceName"
    }
}

# ------------------------------------------------------------
# 9. ENERGIE-MANAGEMENT (LOKALE DEMO-LOGIK)
# ------------------------------------------------------------
function Test-EnergyStatus {
    [CmdletBinding()]
    param(
        [int]$MinimumLevel = 20
    )

    $currentLevel = Get-Random -Minimum 10 -Maximum 101
    Log-Activity -Level 'INFO' -Message "Energiezustand geprüft | Level=$currentLevel%"

    if ($currentLevel -lt $MinimumLevel) {
        Invoke-Alarm -Message "Energielevel kritisch: $currentLevel%"
        return $false
    }

    return $true
}

# ------------------------------------------------------------
# 10. RÜCKFÜHRUNG DURCHFÜHREN
# ------------------------------------------------------------
function Execute-Return {
    if ($script:ReturnQueue.Count -eq 0) {
        Log-Activity -Level 'INFO' -Message 'Keine Ressourcen zur Rückführung vorhanden.'
        return
    }

    Write-Host "Starte Rückführung aller registrierten Ressourcen..." -ForegroundColor Green
    Log-Activity -Level 'WARN' -Message "Rückführung gestartet für $($script:ReturnQueue.Count) Ressource(n)."

    foreach ($resource in $script:ReturnQueue) {
        Write-Host "Rückführung: $resource wird an den Eigentümer zurückgeführt." -ForegroundColor Green
        Log-Activity -Level 'INFO' -Message "Ressource zurückgeführt: $resource"
        Export-ReturnLedgerEntry -ResourceName $resource -Action 'RETURNED'
    }

    $script:ReturnQueue.Clear()
    Log-Activity -Level 'INFO' -Message 'Rückführungsliste geleert.'
}

# ------------------------------------------------------------
# 11. SICHEREN MODUS AKTIVIEREN
# ------------------------------------------------------------
function Enable-SecureMode {
    if ($script:SecureMode) {
        Log-Activity -Level 'INFO' -Message 'Sicherer Modus aktiviert.'
        Write-Host "Sicherer Modus aktiv." -ForegroundColor Magenta
    }
    else {
        Log-Activity -Level 'WARN' -Message 'Sicherer Modus ist deaktiviert.'
        Write-Host "Sicherer Modus deaktiviert." -ForegroundColor Red
    }
}

# ------------------------------------------------------------
# 12. STATUS
# ------------------------------------------------------------
function Get-AVAStatus {
    [pscustomobject]@{
        AvaRoot            = $script:AvaRoot
        LogFile            = $script:LogFile
        EncryptedLogFile   = $script:EncryptedLogFile
        AlarmFile          = $script:AlarmFile
        LedgerFile         = $script:LedgerFile
        SecureMode         = $script:SecureMode
        ProtectedResources = ($script:ProtectedResources -join ', ')
        ReturnQueueCount   = $script:ReturnQueue.Count
        EmailAlertsEnabled = $script:EnableEmailAlerts
    }
}

# ------------------------------------------------------------
# 13. OPTIONAL: ENTSCHLÜSSELN DES ENCRYPTED LOGS
# ------------------------------------------------------------
function Read-EncryptedLog {
    if (-not (Test-Path -Path $script:EncryptedLogFile)) {
        throw "EncryptedLog-Datei nicht gefunden."
    }

    Get-Content -Path $script:EncryptedLogFile | ForEach-Object {
        try {
            [EncryptionHelper]::Decrypt($_, $script:EncryptionPassphrase)
        }
        catch {
            "[FEHLER BEIM ENTSCHLÜSSELN] $_"
        }
    }
}

# ------------------------------------------------------------
# 14. HAUPTLOGIK
# ------------------------------------------------------------
function Start-AVA-System {
    [CmdletBinding()]
    param(
        [switch]$DemoMode,
        [string[]]$ForceBreachFor = @()
    )

    Initialize-AVAEnvironment

    Write-Host "Starte AVA 2.0 ..." -ForegroundColor Green
    Log-Activity -Level 'INFO' -Message 'AVA 2.0 gestartet.'

    Enable-SecureMode
    [void](Test-EnergyStatus -MinimumLevel 20)

    foreach ($resource in $script:ProtectedResources) {
        $forceThis = $ForceBreachFor -contains $resource
        Monitor-Resource -ResourceName $resource -DemoMode:$DemoMode -ForceBreach:$forceThis
    }

    Execute-Return

    Log-Activity -Level 'INFO' -Message 'AVA 2.0 abgeschlossen.'
    Write-Host "AVA 2.0 abgeschlossen. Logs gespeichert unter: $($script:AvaRoot)" -ForegroundColor Cyan
}

# ------------------------------------------------------------
# START
# ------------------------------------------------------------
Start-AVA-System -DemoMode
Get-AVAStatus | Format-List
