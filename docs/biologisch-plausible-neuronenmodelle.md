# Biologisch plausible Neuronenmodelle: von LIF bis aktiven Pyramidenzellen

## Kurzfassung

Zu den anspruchsvollsten biologisch plausiblen **Einzelzellmodellen** gehören morphologisch rekonstruierte, aktive Multi-Kompartiment-Leitfähigkeitsmodelle von Schicht-5-Pyramidenzellen.

Ein klassischer Vertreter ist das **L5b-Pyramidenzellenmodell von Hay et al.** Es bildet eine dreidimensional rekonstruierte Zellmorphologie als viele elektrisch gekoppelte Abschnitte ab und enthält aktive Ionenströme, mit denen unter anderem dendritische Calciumspikes, rücklaufende Aktionspotenziale und komplexe Feuerungsmuster reproduziert werden können.

Ein anderes Spitzenbeispiel ist **DeepDendrite**. Dort wurde ein menschliches Pyramidenzellmodell mit 24.994 explizit angefügten dendritischen Spines simuliert. Diese Spines wurden geometrisch und elektrisch einzeln berücksichtigt, waren jedoch passiv modelliert und stellten keine vollständig biochemisch aktiven Spines dar.

Keines dieser Modelle ist eine vollständige digitale Kopie einer biologischen Nervenzelle.

---

## 1. Leaky Integrate-and-Fire

Ein Leaky-Integrate-and-Fire-Modell reduziert ein Neuron im Wesentlichen auf einen Spannungszustand:

```text
Eingangsstrom
    ↓
Membranspannung steigt oder fällt
    ↓
Schwelle erreicht
    ↓
Spike und Reset
```

Diese Modellklasse ist rechnerisch effizient und für große Netzwerke nützlich, lässt aber viele biologische Mechanismen weg, darunter detaillierte Dendriten, ortsabhängige Ionenkanäle, lokale Calciumereignisse und intrazelluläre Signalwege.

---

## 2. Aktives Multi-Kompartimentmodell einer Schicht-5-Pyramidenzelle

Ein detailliertes Pyramidenzellenmodell arbeitet räumlich verteilt:

```text
Tausende räumlich verteilte Eingänge
        ↓
unterschiedliche Dendritenäste
        ↓
lokale Na⁺-, K⁺-, Ca²⁺-, HCN- und weitere Ionenströme
        ↓
lokale dendritische Nichtlinearitäten und Calciumspikes
        ↓
Wechselwirkung mit rücklaufenden Aktionspotenzialen
        ↓
somatische und axonale Spike-Ausgabe
```

Das Hay-Modell wurde so optimiert, dass es sowohl somatische als auch aktive dendritische Eigenschaften experimenteller Schicht-5b-Zellen nachbildet.

Wichtige Einschränkung: Das Modell besitzt kein vollständig rekonstruiertes und durchgehend detailliertes Axon. Die axonale Spike-Entstehung wurde vereinfacht. Wissenschaftlich sauber ist daher die Bezeichnung:

> Ein detailliertes, aktives, morphologisch rekonstruiertes Multi-Kompartiment-Leitfähigkeitsmodell einer Schicht-5b-Pyramidenzelle.

Quelle:

- Hay et al., *Models of Neocortical Layer 5b Pyramidal Cells Capturing a Wide Range of Dendritic and Perisomatic Active Properties*: https://journals.plos.org/ploscompbiol/article?id=10.1371/journal.pcbi.1002107

---

## 3. DeepDendrite und 24.994 explizite Spines

DeepDendrite demonstrierte ein menschliches Pyramidenzellmodell mit 24.994 explizit an den Dendriten angebrachten Spines. Dadurch konnten verteilte und geclusterte synaptische Eingaben auf sehr großer räumlicher Detailstufe untersucht werden.

Die Spine-Köpfe und Spine-Hälse waren jedoch passive Kabelkompartimente. Das Modell enthielt damit nicht automatisch:

- vollständige aktive Kanalpopulationen in jeder Spine,
- detaillierte Calcium-Biochemie,
- Proteinsynthese,
- umfassende synaptische Plastizität,
- Stoffwechsel und strukturelles Wachstum.

Quelle:

- DeepDendrite, *A GPU-based computational framework that bridges neuron simulation and artificial intelligence*: https://www.nature.com/articles/s41467-023-41553-7

---

## 4. Biologisch detaillierte Netzwerke

Ein bekanntes neokortikales Mikroschaltkreismodell aus dem Blue-Brain-Umfeld enthielt ungefähr:

```text
31.346 biophysikalische Hodgkin-Huxley-Neuronen
7,8 Millionen neuronale Verbindungen
36,4 Millionen Synapsen
55 morphologische Zelltypen
stochastische Vesikelfreisetzung
teilweise stochastische Ionenkanäle
```

Die stochastischen Ionenkanäle wurden nur für einen Teil der Neuronen eingesetzt. Auch dieses Netzwerk war keine vollständige Kopie echten Hirngewebes.

Quelle:

- *Cortical reliability amid noise and chaos*: https://www.nature.com/articles/s41467-019-11633-8

---

## 5. Warum „intelligentestes Neuronenmodell“ kein sauberer Fachbegriff ist

In der Forschung werden Einzelneuronenmodelle eher nach folgenden Kriterien bewertet:

- biologische Detailtiefe,
- experimentelle Validierung,
- dendritische Rechenfähigkeit,
- Lern- und Anpassungsmechanismen,
- Vorhersagekraft,
- Reproduzierbarkeit,
- Unsicherheitsabschätzung,
- Effizienz und Skalierbarkeit.

Ein hochdetailliertes Neuron kann biologisch realistisch sein, ohne selbstständig zu lernen. Umgekehrt kann ein stark vereinfachtes künstliches Neuron Teil eines sehr leistungsfähigen lernenden Systems sein.

---

## 6. Was einem vollständigen digitalen Neuron weiterhin fehlt

Ein maximal umfassendes Modell müsste gleichzeitig integrieren:

```text
3D-Morphologie
+ sämtliche relevanten Ionenkanäle
+ einzelne Synapsen und Spines
+ Neurotransmitterfreisetzung
+ Calcium- und weitere Botenstoffsysteme
+ kurz- und langfristige Plastizität
+ Neuromodulatoren
+ Genexpression und Proteinsynthese
+ Zellstoffwechsel und Energieversorgung
+ strukturelles Wachstum
+ Glia-Interaktion
+ individuelle Entwicklungs- und Lerngeschichte
```

Ein vollständig integriertes und experimentell umfassend validiertes Modell dieser Art existiert derzeit nicht.

Der Ansatz sogenannter *reference-grade neuron models* betont deshalb, dass mehr Parameter nicht automatisch mehr biologische Wahrheit bedeuten. Ebenso wichtig sind Datenherkunft, Unsicherheitsbudgets, Sensitivitätsanalysen, unabhängige Validierung und klar benannte Gültigkeitsbereiche.

Quelle:

- *Toward Reference-Grade neuron models*: https://www.nature.com/articles/s42003-026-10561-w

---

## 7. Präzises Gesamturteil

> Zu den komplexesten biologisch plausiblen Einzelzellmodellen gehören morphologisch rekonstruierte, aktive Multi-Kompartiment-Leitfähigkeitsmodelle von Schicht-5-Pyramidenzellen. Einige Modelle bilden aktive dendritische Ionenkanäle und Calciumspikes besonders detailliert ab, während andere Zehntausende explizite dendritische Spines integrieren. Ein einzelnes umfassend validiertes Modell, das vollständige Elektrophysiologie, sämtliche Spines, biochemische Signalwege, Plastizität, Stoffwechsel, Genexpression und Glia-Interaktion gleichzeitig enthält, existiert bislang nicht.

Gegenüber einem einfachen Leaky-Integrate-and-Fire-Neuron handelt es sich nicht nur um ein kleines Upgrade, sondern um eine grundlegend andere biophysikalische Detailklasse.

Bezogen auf Eon gilt die vorsichtige Formulierung:

> Sofern dort tatsächlich ein einfaches Leaky-Integrate-and-Fire-Modell verwendet wird, liegt ein detailliertes aktives Pyramidenzellenmodell mehrere Ebenen höher in der biophysikalischen Detailtiefe.
