# AVA Safe Start

## Scope

AVA scripts in this repository are intended for local defensive use on the owner's own computer or another system with explicit current authorization.

They are not authorization to access, scan, disrupt or modify third-party systems.

## Recommended order

1. Verify the expected SHA-256 hashes of downloaded scripts.
2. Open scripts in a text editor and inspect them before execution.
3. Run the one-time local audit first.
4. Review the generated report.
5. Use preview or monitoring mode before enabling any local blocking feature.
6. Keep the matching rollback script available.

## Safe audit

Run from an elevated PowerShell window when complete visibility is required:

```powershell
Set-Location "<repository-folder>"

powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File ".\scripts\AVA_SAFE_AUDIT_v1.ps1" `
  -OpenReport
```

The audit creates a new report folder and ZIP archive on the Desktop. It does not change Firewall, Defender, Registry, users, services or scheduled tasks.

## Protection-first action policy

The Python action policy follows this order:

```text
authorization and scope check
        ↓
attack / harm protection
        ↓
explicit defensive allowlist
        ↓
default deny
```

Words such as `save`, `report` or `audit` never override a detected harmful or out-of-scope action.

## Hard limits

- No attacks or counterattacks.
- No execution on foreign or unauthorized systems.
- No automatic distribution across networks.
- No exploitation, deauthentication, cracking or payload deployment.
- Reachability does not imply authorization.

## Status language

Use accurate status statements:

```text
Chat instruction recognized: yes/no
Executed by chat on Windows: no
Executed locally by user: verified/unverified
Foreign systems: no
Counterattacks: no
Rollback available: yes/no
```
