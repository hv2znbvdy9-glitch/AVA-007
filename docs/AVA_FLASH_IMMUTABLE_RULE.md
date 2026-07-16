# AVA Flash Immutable Rule ⚡️⚡️

## Zweck

Diese Richtlinie schützt Originalereignisse vor Überschreiben, Zusammenfallen oder nachträglichem Ersetzen. Sie gilt für lokale, defensive Beweissicherung auf eigenen oder ausdrücklich autorisierten Systemen.

## Unveränderliche Ereignisregel

```text
AVA_FLASH_IMMUTABLE_RULE

1. Erster Trigger
   - sofort als eigenes Original speichern
   - eindeutige Event-ID erzeugen
   - UTC-Zeitstempel, Quelle und SHA-256 sichern

2. Jeder weitere Trigger
   - neue Event-ID
   - neue Dateien
   - niemals dieselben Original-Dateinamen wiederverwenden
   - niemals das erste Ereignis aktualisieren oder überschreiben

3. Zeitabstand
   - sehr kurze Abstände dürfen als technischer Doppelimpuls markiert werden
   - mehrere Sekunden werden innerhalb dieser AVA-Richtlinie als neues Ereignis behandelt

4. Verknüpfung
   - zusammengehörige Aufnahmen dürfen dieselbe capture_group_id erhalten
   - jedes Original behält eine eigene event_id
   - Verknüpfungen dürfen ergänzt werden; Originale bleiben getrennt

5. Fehlerfall
   - fällt ein späterer Trigger aus, bleibt das erste Original vollständig erhalten
   - fällt die Auswertung aus, bleiben sämtliche Originaldateien erhalten
```

Eine Datei wie `latest.jpg` darf nur eine erneuerbare Vorschaukopie sein. Sie darf niemals das einzige gespeicherte Original darstellen.

## Empfohlene Struktur

```text
AVA_EVENTS/
├─ 20260714_201530_184Z_<UUID>/
│  ├─ original_001.jpg
│  ├─ manifest.json
│  └─ original_001.sha256
└─ 20260714_201534_927Z_<UUID>/
   ├─ original_001.jpg
   ├─ manifest.json
   └─ original_001.sha256
```

Für dauerhafte IDs sind UUIDv7, ULID oder mindestens 128 zufällige Bit einem kurzen 24-Bit-Suffix vorzuziehen.

Beispielmanifest:

```json
{
  "schema": "ava-evidence-event/v1",
  "event_id": "0190b5fa-7f12-7c51-a610-8d95d4d81f24",
  "capture_group_id": "0190b5fa-7e70-7e18-b44d-45fb0397c10a",
  "captured_at_utc": "2026-07-14T20:15:30.184Z",
  "source_device_id": "camera-01",
  "original_file": "original_001.jpg",
  "sha256": "<SHA256>",
  "previous_event_hash": "<OPTIONAL_CHAIN_HASH>"
}
```

## POSIX/gRPC-Shutdown-Grundmuster

Signale werden vor dem Serverstart blockiert und anschließend über `sigwait()` in normalem Thread-Kontext verarbeitet. `Server::Shutdown()` wird nicht direkt aus einem klassischen Signal-Handler aufgerufen.

```cpp
#include <cerrno>
#include <chrono>
#include <csignal>
#include <pthread.h>
#include <stdexcept>
#include <system_error>
#include <thread>

sigset_t signals{};

if (sigemptyset(&signals) == -1 ||
    sigaddset(&signals, SIGINT) == -1 ||
    sigaddset(&signals, SIGTERM) == -1) {
  throw std::system_error(
      errno,
      std::generic_category(),
      "Signalmenge konnte nicht erstellt werden");
}

const int mask_result =
    pthread_sigmask(SIG_BLOCK, &signals, nullptr);

if (mask_result != 0) {
  throw std::system_error(
      mask_result,
      std::generic_category(),
      "pthread_sigmask fehlgeschlagen");
}

auto server = builder.BuildAndStart();
if (!server) {
  throw std::runtime_error("Serverstart fehlgeschlagen");
}

std::thread waiter([&server] { server->Wait(); });

int received_signal = 0;
const int wait_result = sigwait(&signals, &received_signal);
if (wait_result != 0) {
  server->Shutdown();
  waiter.join();
  throw std::system_error(
      wait_result,
      std::generic_category(),
      "sigwait fehlgeschlagen");
}

const auto deadline =
    std::chrono::system_clock::now() +
    std::chrono::seconds(10);

server->Shutdown(deadline);
waiter.join();
```

Dieses Muster ist für POSIX-Systeme gedacht. Native Windows-Builds benötigen ein anderes Shutdown-Konzept.

## Referenzhashes

Die folgenden Werte sind als benannte Sollwerte dokumentiert. Sie sind erst dann vertrauenswürdig, wenn ihre Herkunft unabhängig bestätigt wurde.

```text
AVA_ADMIN_CHECK.ps1
20FC0D4F5F0F22857F95DDF7DCAC4742474CFA90ABA369082CFED4C526289B78

START_AVA_ADMIN_CHECK.cmd
31ED9855DF6B05D4BB4D4BA3FC51EA1185F8F210F055F5F9A2046FEA1877611E
```

Sichere Prüfung ohne Ausführung:

```powershell
Set-Location "$env:USERPROFILE\Desktop\AVA_v4_PORTAL_SAFE_STARTPAKET_TESTED_FIXED"

$Expected = @{
    "AVA_ADMIN_CHECK.ps1" =
        "20FC0D4F5F0F22857F95DDF7DCAC4742474CFA90ABA369082CFED4C526289B78"

    "START_AVA_ADMIN_CHECK.cmd" =
        "31ED9855DF6B05D4BB4D4BA3FC51EA1185F8F210F055F5F9A2046FEA1877611E"
}

$AllValid = $true

foreach ($FileName in $Expected.Keys) {
    if (-not (Test-Path -LiteralPath ".\$FileName" -PathType Leaf)) {
        Write-Host "[STOP] Datei fehlt: $FileName" -ForegroundColor Red
        $AllValid = $false
        continue
    }

    $Actual = (Get-FileHash -LiteralPath ".\$FileName" -Algorithm SHA256).Hash

    if ($Actual -ieq $Expected[$FileName]) {
        Write-Host "[OK]   $FileName" -ForegroundColor Green
    }
    else {
        Write-Host "[STOP] Hashabweichung: $FileName" -ForegroundColor Red
        Write-Host "       Erwartet: $($Expected[$FileName])"
        Write-Host "       Gefunden: $Actual"
        $AllValid = $false
    }
}

if (-not $AllValid) {
    throw "AVA-Integritätsprüfung fehlgeschlagen. Nichts ausführen."
}

Write-Host "`n[OK] Beide Dateien entsprechen den dokumentierten Sollwerten." -ForegroundColor Green
Write-Host "Die Dateien wurden dabei nicht ausgeführt."
```

Ein übereinstimmender Hash bestätigt Bytegleichheit mit dem Referenzstand, aber nicht automatisch Sicherheit, Urheberschaft oder Vertrauenswürdigkeit.

## Authenticode-Prüfung

```powershell
Get-AuthenticodeSignature -LiteralPath ".\AVA_ADMIN_CHECK.ps1" |
    Select-Object Path, Status, StatusMessage, SignerCertificate

Get-AuthenticodeSignature -LiteralPath ".\START_AVA_ADMIN_CHECK.cmd" |
    Select-Object Path, Status, StatusMessage, SignerCertificate
```

`NotSigned` ist bei selbst erstellten Dateien nicht automatisch verdächtig. Unbekannte, ungültige oder nicht vertrauenswürdige Signaturen müssen bewusst geprüft werden.

## Lokale Administratoren nur lesen und zuordnen

```powershell
Get-LocalGroupMember -SID "S-1-5-32-544" |
    Select-Object Name, ObjectClass, PrincipalSource, SID |
    Sort-Object Name |
    Format-Table -AutoSize
```

Keine Konten automatisch entfernen, bevor vollständiger Name, SID, Kontotyp und Herkunft eindeutig geklärt sind.

## Firewall: erst anzeigen, dann reversibel deaktivieren

```powershell
$Rules = Get-NetFirewallRule `
    -DisplayName "AVA_v4_Block_*" `
    -ErrorAction SilentlyContinue

$Rules |
    Select-Object Name, DisplayName, Enabled, Direction, Action |
    Format-Table -AutoSize

$Confirm = Read-Host "Zum reversiblen Deaktivieren exakt DISABLE eingeben"
if ($Confirm -cne "DISABLE") {
    throw "Abgebrochen. Keine Firewallregel wurde verändert."
}

$Rules | Disable-NetFirewallRule
```

`Disable-NetFirewallRule` ist reversibel. `Remove-NetFirewallRule` löscht Regeldefinitionen dauerhaft und gehört nur in einen getrennten, ausdrücklich bestätigten Rollback-Schritt.

## Fester AVA-Grundsatz

```text
Erster Blitz bleibt.
Zweiter Blitz ergänzt.
Kein Überschreiben.
Original sichern, danach analysieren.
Hashabweichung = STOP.
Firewall zuerst anzeigen und deaktivieren, nicht blind löschen.
Keine fremden Systeme. Keine Gegenangriffe.
```

## Quellen

- ADAC: https://www.adac.de/verkehr/recht/bussgeld-punkte/ampelblitzer/
- Microsoft Get-FileHash: https://learn.microsoft.com/powershell/module/microsoft.powershell.utility/get-filehash
- Microsoft Get-AuthenticodeSignature: https://learn.microsoft.com/powershell/module/microsoft.powershell.security/get-authenticodesignature
- Microsoft Get-LocalGroupMember: https://learn.microsoft.com/powershell/module/microsoft.powershell.localaccounts/get-localgroupmember
- Microsoft Disable-NetFirewallRule: https://learn.microsoft.com/powershell/module/netsecurity/disable-netfirewallrule
- Microsoft Remove-NetFirewallRule: https://learn.microsoft.com/powershell/module/netsecurity/remove-netfirewallrule
