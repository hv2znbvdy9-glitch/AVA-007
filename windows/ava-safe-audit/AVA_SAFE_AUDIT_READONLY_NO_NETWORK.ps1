#requires -Version 7.2
<#+
AVA SAFE AUDIT — READ-ONLY / NO NETWORK / NO SYSTEM

This script performs only local, read-only inspection:
- inventories files under a caller-supplied directory
- computes SHA-256 hashes
- statically parses PowerShell files with the PowerShell AST parser
- reports command names that violate the safe execution profile

It does not write files, change permissions, install tasks, alter services,
modify the registry or firewall, access the network, start child processes,
or read environment variables that could contain credentials.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$AuditRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$resolvedRoot = (Resolve-Path -LiteralPath $AuditRoot -ErrorAction Stop).Path

if ($IsWindows) {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if ($identity.IsSystem) {
        throw 'Refusing to run as NT AUTHORITY\SYSTEM.'
    }
}

# Command names are data for AST comparison only. None are invoked.
$blockedCommands = [Collections.Generic.HashSet[string]]::new(
    [StringComparer]::OrdinalIgnoreCase
)

@(
    'Add-Content',
    'Clear-Content',
    'Compress-Archive',
    'Copy-Item',
    'Disable-NetFirewallRule',
    'Enable-NetFirewallRule',
    'Expand-Archive',
    'Export-Csv',
    'Invoke-Command',
    'Invoke-Expression',
    'Invoke-RestMethod',
    'Invoke-WebRequest',
    'Move-Item',
    'New-Item',
    'New-ItemProperty',
    'New-NetFirewallRule',
    'Out-File',
    'Register-ScheduledTask',
    'Remove-Item',
    'Remove-ItemProperty',
    'Remove-NetFirewallRule',
    'Restart-Service',
    'Set-Acl',
    'Set-Content',
    'Set-Item',
    'Set-ItemProperty',
    'Set-NetFirewallProfile',
    'Set-Service',
    'Start-BitsTransfer',
    'Start-Job',
    'Start-Process',
    'Start-Service',
    'Stop-Process',
    'Stop-Service',
    'Unregister-ScheduledTask'
) | ForEach-Object { [void]$blockedCommands.Add($_) }

$networkReadCommands = [Collections.Generic.HashSet[string]]::new(
    [StringComparer]::OrdinalIgnoreCase
)

@(
    'Get-NetAdapter',
    'Get-NetConnectionProfile',
    'Get-NetIPConfiguration',
    'Get-NetIPAddress',
    'Get-NetNeighbor',
    'Get-NetTCPConnection',
    'Resolve-DnsName',
    'Test-NetConnection'
) | ForEach-Object { [void]$networkReadCommands.Add($_) }

$secretNamePattern = '(?i)(password|passwd|pwd|secret|token|api[_-]?key|authorization|bearer|credential)'
$allowedExtensions = [Collections.Generic.HashSet[string]]::new(
    [StringComparer]::OrdinalIgnoreCase
)
@('.ps1', '.psm1', '.psd1', '.json', '.md', '.txt', '.yml', '.yaml', '.js', '.ts', '.py') |
    ForEach-Object { [void]$allowedExtensions.Add($_) }

$results = foreach ($file in Get-ChildItem -LiteralPath $resolvedRoot -File -Recurse -Force) {
    if (-not $allowedExtensions.Contains($file.Extension)) {
        continue
    }

    $relativePath = [IO.Path]::GetRelativePath($resolvedRoot, $file.FullName)
    $sha256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    $parseErrors = @()
    $blockedFound = @()
    $networkFound = @()
    $secretNameFinding = $relativePath -match $secretNamePattern

    if ($file.Extension -in @('.ps1', '.psm1', '.psd1')) {
        $tokens = $null
        $errors = $null
        $ast = [Management.Automation.Language.Parser]::ParseFile(
            $file.FullName,
            [ref]$tokens,
            [ref]$errors
        )

        $parseErrors = @(
            $errors | ForEach-Object {
                [pscustomobject][ordered]@{
                    Message = $_.Message
                    Line = $_.Extent.StartLineNumber
                    Column = $_.Extent.StartColumnNumber
                }
            }
        )

        $commandNames = @(
            $ast.FindAll(
                {
                    param($node)
                    $node -is [Management.Automation.Language.CommandAst]
                },
                $true
            ) | ForEach-Object { $_.GetCommandName() } |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                Sort-Object -Unique
        )

        $blockedFound = @($commandNames | Where-Object { $blockedCommands.Contains($_) })
        $networkFound = @($commandNames | Where-Object { $networkReadCommands.Contains($_) })
    }

    [pscustomobject][ordered]@{
        Path = $relativePath
        Bytes = $file.Length
        SHA256 = $sha256
        PowerShellParseOk = ($parseErrors.Count -eq 0)
        ParseErrors = $parseErrors
        BlockedCommands = $blockedFound
        NetworkCommands = $networkFound
        SecretLikeFileName = $secretNameFinding
    }
}

$summary = [pscustomobject][ordered]@{
    AuditVersion = '1.0'
    Mode = 'READ_ONLY_NO_NETWORK_NO_SYSTEM'
    Root = [IO.Path]::GetFileName($resolvedRoot.TrimEnd([IO.Path]::DirectorySeparatorChar))
    FilesInventoried = @($results).Count
    PowerShellParseFailures = @($results | Where-Object { -not $_.PowerShellParseOk }).Count
    FilesWithBlockedCommands = @($results | Where-Object { $_.BlockedCommands.Count -gt 0 }).Count
    FilesWithNetworkCommands = @($results | Where-Object { $_.NetworkCommands.Count -gt 0 }).Count
    FilesWithSecretLikeNames = @($results | Where-Object { $_.SecretLikeFileName }).Count
    Results = @($results)
}

$summary | ConvertTo-Json -Depth 12
