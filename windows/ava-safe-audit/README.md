# AVA Safe Audit — Read Only / No Network

`AVA_SAFE_AUDIT_READONLY_NO_NETWORK.ps1` inventories a caller-selected folder,
computes SHA-256 hashes and statically parses PowerShell source files. Its only
output is JSON on the success stream.

## Safety properties

- requires PowerShell 7.2 or newer
- refuses `NT AUTHORITY\SYSTEM` on Windows
- does not create, modify or delete files
- does not start child processes
- does not query network state or contact remote systems
- does not change firewall, registry, services, users, permissions or tasks
- reports blocked command names as data; those command names are not invoked

## Example

```powershell
pwsh -NoProfile -File .\AVA_SAFE_AUDIT_READONLY_NO_NETWORK.ps1 `
    -AuditRoot .\path-to-review |
    Set-Content -LiteralPath .\audit-result.json -Encoding utf8
```

The scanner itself does not write `audit-result.json`; the example explicitly
redirects its output. Omit the final pipeline to print JSON to the console only.

## Interpretation

A finding means that a command name appears in a parsed PowerShell file. It is
not proof that the command executed, that a compromise occurred or that a
specific person was responsible. Review the reported file and AST context.

## Privacy

Paths and file names may reveal user names, project names or other local data.
Redact results before uploading them publicly.
