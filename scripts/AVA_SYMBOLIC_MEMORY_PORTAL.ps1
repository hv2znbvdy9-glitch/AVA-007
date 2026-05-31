#requires -Version 5.1
<#
AVA SYMBOLIC MEMORY PORTAL
Lokal / Privat / Read-Only / Kein Upload / Keine Überwachung

Erstellt:
- Ordnerstruktur
- JSON Memory-Datei
- CSV Export
- HTML Portal
- Symbolische Mindmap
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Root      = Join-Path $env:USERPROFILE 'Desktop\AVA_SYMBOLIC_MEMORY_PORTAL'
$DataDir   = Join-Path $Root 'Daten'
$PortalDir = Join-Path $Root 'Portal'

$JsonPath = Join-Path $DataDir 'symbolic_memory.json'
$CsvPath  = Join-Path $DataDir 'symbolic_memory.csv'
$HtmlPath = Join-Path $PortalDir 'index.html'

function Ensure-Dir {
	param([string]$Path)
	if (-not (Test-Path -LiteralPath $Path)) {
		New-Item -ItemType Directory -Force -Path $Path | Out-Null
	}
}

function H {
	param([AllowNull()][object]$Value)
	if ($null -eq $Value) { return '' }
	return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

Ensure-Dir $Root
Ensure-Dir $DataDir
Ensure-Dir $PortalDir

$Memories = @(
	[pscustomobject]@{
		id = 'sym_001'
		title = 'AI Tools'
		category = 'Technik'
		meaning = 'Werkzeuge, Automatisierung, Assistenz, Kreativität'
		tags = 'AI;Tools;Automation;Coding;Writing;Design'
		note = 'KI-Werkzeuge als praktische Helfer: nicht Magie, sondern strukturierte Unterstützung.'
	},
	[pscustomobject]@{
		id = 'sym_002'
		title = 'Was nicht mein ist'
		category = 'Affirmation'
		meaning = 'Loslassen, Schutz, innere Ordnung'
		tags = 'Schutz;Fokus;Loslassen;Energie;Klarheit'
		note = 'Was nicht mein ist, soll nicht bleiben. Ich löse mich. Energie kehrt zu mir zurück.'
	},
	[pscustomobject]@{
		id = 'sym_003'
		title = 'Alte Kulturen und Pyramiden'
		category = 'Geschichte / Symbolik'
		meaning = 'Architektur, Zivilisation, Erinnerung, Menschheitsgeschichte'
		tags = 'Pyramiden;Kulturen;Zeit;Architektur;Geschichte'
		note = 'Bilder alter Bauwerke als Erinnerung daran, dass Menschen schon immer Muster, Ordnung und Bedeutung gesucht haben.'
	},
	[pscustomobject]@{
		id = 'sym_004'
		title = 'Geometrie und Goldener Schnitt'
		category = 'Mathematik / Symbolik'
		meaning = 'Muster, Verhältnis, Struktur, Form'
		tags = 'Geometrie;Phi;Goldener Schnitt;Muster;Form'
		note = 'Mathematik als echte Sprache von Struktur. Symbolische Bedeutung getrennt von wissenschaftlicher Behauptung betrachten.'
	},
	[pscustomobject]@{
		id = 'sym_005'
		title = 'Klang und Frequenz'
		category = 'Physik / Wahrnehmung'
		meaning = 'Schall, Resonanz, Stimme, Atmosphäre'
		tags = 'Frequenz;Klang;Schall;Resonanz;Stimme'
		note = 'Reale Physik: Schall ist Druckwelle. Symbolisch: Klang kann Erinnerung und Stimmung stark beeinflussen.'
	},
	[pscustomobject]@{
		id = 'sym_006'
		title = 'AVA Memory Core'
		category = 'Systemdenken'
		meaning = 'Daten zu Ereignissen, Ereignisse zu Mustern, Muster zu Verständnis'
		tags = 'AVA;Memory;Graph;Timeline;Baseline;Delta'
		note = 'Fakten vor Angst. Baseline vor Chaos. Sichtbarkeit vor Kontrolle.'
	},
	[pscustomobject]@{
		id = 'sym_007'
		title = 'LaFamilia bleibt LaFamilia'
		category = 'Familie / Erinnerung'
		meaning = 'Verbundenheit, Erinnerung, Schutz, Liebe'
		tags = 'Familie;Erinnerung;Mama;Bruder;Danny;LaFamilia'
		note = 'Erinnerungen vor Vergessen. Familie vor Entfernung. Liebe vor Stolz.'
	}
)

$Memories | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $JsonPath -Encoding UTF8
$Memories | Export-Csv -LiteralPath $CsvPath -NoTypeInformation -Delimiter ';' -Encoding UTF8

$Cards = foreach ($m in $Memories) {
	$TagChips = (
		$m.tags -split ';' |
			ForEach-Object { $_.Trim() } |
			Where-Object { $_ } |
			ForEach-Object { "<span class='tag'>$(H $_)</span>" }
	) -join ''

@"
<article class='card'>
  <div class='meta'>$(H $m.id) · $(H $m.category)</div>
  <h3>$(H $m.title)</h3>
  <p><strong>Bedeutung:</strong> $(H $m.meaning)</p>
  <p><strong>Notiz:</strong> $(H $m.note)</p>
  <div class='tags'>$TagChips</div>
</article>
"@
}

$cx = 360
$cy = 240
$radius = 165
$NodeSvg = for ($i = 0; $i -lt $Memories.Count; $i++) {
	$m = $Memories[$i]
	$angle = (2 * [Math]::PI * $i / $Memories.Count) - ([Math]::PI / 2)
	$x = [Math]::Round($cx + ($radius * [Math]::Cos($angle)))
	$y = [Math]::Round($cy + ($radius * [Math]::Sin($angle)))
	$label = H $m.title
@"
<line x1='$cx' y1='$cy' x2='$x' y2='$y' stroke='#32435d' stroke-width='1.5' />
<circle cx='$x' cy='$y' r='25' fill='#1f2530' stroke='#6aa0ff' />
<text x='$x' y='$($y + 42)' text-anchor='middle' fill='#c9d5ef' font-size='11'>$label</text>
"@
}

$Html = @"
<!doctype html>
<html lang='de'>
<head>
  <meta charset='utf-8' />
  <meta name='viewport' content='width=device-width, initial-scale=1' />
  <title>AVA Symbolic Memory Portal</title>
  <style>
    :root { color-scheme: dark; }
    body { margin: 0; font-family: Segoe UI, Arial, sans-serif; background: #0f1218; color: #eaf0ff; }
    .wrap { max-width: 1100px; margin: 0 auto; padding: 24px; }
    h1 { margin: 0 0 6px; }
    .sub { color: #9db0d0; margin: 0 0 24px; }
    .grid { display: grid; gap: 16px; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); }
    .card { background: #171c25; border: 1px solid #293242; border-radius: 10px; padding: 14px; }
    .card h3 { margin: 8px 0; }
    .card p { margin: 8px 0; color: #d4dff6; line-height: 1.45; }
    .meta { color: #95a8cb; font-size: 12px; text-transform: uppercase; letter-spacing: .4px; }
    .tags { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 12px; }
    .tag { border: 1px solid #39527d; border-radius: 999px; padding: 2px 8px; font-size: 12px; color: #b8cef6; }
    .mindmap { margin-top: 24px; background: #171c25; border: 1px solid #293242; border-radius: 10px; padding: 10px; }
    .mindmap h2 { margin: 8px 10px 0; font-size: 20px; }
    .mindmap svg { width: 100%; height: auto; display: block; }
  </style>
</head>
<body>
  <div class='wrap'>
    <h1>AVA Symbolic Memory Portal</h1>
    <p class='sub'>Lokal · Privat · Read-Only · Kein Upload · Keine Überwachung</p>
    <section class='grid'>
      $($Cards -join [Environment]::NewLine)
    </section>
    <section class='mindmap'>
      <h2>Symbolische Mindmap</h2>
      <svg viewBox='0 0 720 500' role='img' aria-label='Symbolische Mindmap'>
        <circle cx='$cx' cy='$cy' r='36' fill='#263041' stroke='#86b3ff' stroke-width='2' />
        <text x='$cx' y='$($cy + 4)' text-anchor='middle' fill='#ecf3ff' font-size='14' font-weight='700'>AVA Core</text>
        $($NodeSvg -join [Environment]::NewLine)
      </svg>
    </section>
  </div>
</body>
</html>
"@

$Html | Set-Content -LiteralPath $HtmlPath -Encoding UTF8

Write-Host ''
Write-Host 'AVA SYMBOLIC MEMORY PORTAL erstellt.' -ForegroundColor Green
Write-Host "Ordner: $Root" -ForegroundColor Cyan
Write-Host "JSON:   $JsonPath" -ForegroundColor Cyan
Write-Host "CSV:    $CsvPath" -ForegroundColor Cyan
Write-Host "Portal: $HtmlPath" -ForegroundColor Cyan
Write-Host ''

try {
	Start-Process $HtmlPath
}
catch {
	Write-Warning "Portal konnte nicht automatisch geöffnet werden: $($_.Exception.Message)"
}
