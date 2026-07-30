# AVA HD Safe Start

## Scope

This directory contains a Windows installer for a local defensive status audit.

The generated runtime audit is read-only with respect to firewall, registry,
services and Microsoft Defender. The installer itself is **not** read-only: it
creates files under `C:\ProgramData\AVA\HD_ReadOnlyAudit`, changes ACLs and
registers a scheduled task.

## Runtime model

- Windows PowerShell 5.1
- current administrator account
- `RunLevel Highest`
- `S4U` logon, no stored password
- explicitly not `NT AUTHORITY\SYSTEM`
- one run at startup and one run every 60 seconds
- 45-second execution limit and `IgnoreNew` overlap handling
- SHA-256 verification of the generated audit script before each run

## Collected data

The runtime records local operating-system, disk, Defender, firewall-profile,
service and process-count status. It writes JSON only to:

```text
C:\ProgramData\AVA\HD_ReadOnlyAudit\Logs
```

Reports may contain the Windows user and computer name. Redact those values
before publishing logs or screenshots.

## Important limitations

- The launcher verifies the generated audit script, but the launcher is not
  independently verified before Task Scheduler starts it.
- The installer was statically reviewed in a non-Windows sandbox; it was not
  executed here and no scheduled task was installed during review.
- Do not run unknown PowerShell files directly from GitHub. Review the exact
  commit and file hash first.

## Safe review sequence

1. Read `INSTALL_AND_START_01.ps1` completely.
2. Compare its SHA-256 with a trusted reference.
3. Run it only on a Windows computer you own or administer.
4. Inspect `latest.json`, daily JSONL logs and Task Scheduler results.
5. Stop and investigate any unexpected integrity mismatch.

## Principle

```text
Fakten vor Angst.
Sichtbarkeit vor Kontrolle.
Keine Täterbehauptung ohne Beweis.
Keine Gegenangriffe.
```
