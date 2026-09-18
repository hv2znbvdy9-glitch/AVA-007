📡

# AVA 01610 – Hörfassung

## Wie komplex kann ein einzelnes digitales Neuron werden?

Wenn man nach einem besonders komplexen und biologisch plausiblen Einzelneuronenmodell sucht, ist ein vollständig aktives Multi-Kompartiment-Hodgkin-Huxley-Modell einer Schicht-5-Pyramidenzelle ein sehr guter Kandidat.

Der entscheidende Unterschied zu einem einfachen künstlichen Neuron liegt darin, dass die Nervenzelle nicht nur als einzelner Punkt betrachtet wird. Stattdessen wird ihre räumliche Struktur in viele elektrisch gekoppelte Abschnitte zerlegt: Zellkörper, Axon und ein stark verzweigter Dendritenbaum.

Ein einfaches Leaky-Integrate-and-Fire-Neuron funktioniert grob nach dem Prinzip: Eingang kommt an, die Spannung steigt, eine Schwelle wird erreicht, und ein Spike wird ausgelöst.

Ein detailliertes Pyramidenzellenmodell ist deutlich komplexer. Tausende räumlich verteilte Eingänge treffen auf unterschiedliche Dendritenäste. Dort wirken verschiedene Ionenkanäle, zum Beispiel Natrium-, Kalium-, Calcium- und HCN-Kanäle.

In einzelnen Dendriten können lokale Ereignisse wie NMDA-Spikes, Calcium-Spikes oder elektrische Plateaus entstehen. Diese lokalen Signale wechselwirken miteinander und mit rückwärts laufenden Aktionspotenzialen. Am Ende entscheidet vor allem der axonale Bereich darüber, wann und in welchem Muster die Zelle feuert.

Ein bekanntes Beispiel ist das Modell von Hay und Kollegen aus dem Jahr 2011. Es wurde so entwickelt, dass es sowohl somatische Natrium-Spikes als auch wichtige aktive dendritische Eigenschaften wie Calcium-Spikes und rückwärts laufende Aktionspotenziale nachbilden kann.

Ein noch extremeres modernes Beispiel ist DeepDendrite. Dort wurde ein detailliertes menschliches Pyramidenneuronenmodell mit ungefähr fünfundzwanzigtausend einzeln modellierten dendritischen Spines untersucht.

Spines sind winzige Fortsätze, an denen viele erregende Synapsen sitzen. Dadurch lässt sich nicht nur untersuchen, wie viele Eingänge eine Nervenzelle erhält, sondern auch, wie deren genaue räumliche Verteilung das Verhalten der Zelle verändert.

Wichtig ist aber:

**Komplexität bedeutet nicht automatisch Intelligenz.**

In der Forschung bewertet man ein einzelnes Neuronenmodell eher nach biologischer Genauigkeit, der Rechenfähigkeit seiner Dendriten, Lern- und Anpassungsfähigkeit, experimenteller Vorhersagekraft sowie Effizienz und Skalierbarkeit.

Die besondere Rechenleistung biologischer Pyramidenzellen entsteht vor allem durch ihre aktiven Dendriten.

Einzelne Äste können lokale Schwellen überschreiten und eigene nichtlineare elektrische Ereignisse erzeugen. Deshalb kann sich eine einzige biologische Nervenzelle in gewisser Weise eher wie ein kleines Netzwerk von Recheneinheiten verhalten als wie ein einfacher Ein-Aus-Schalter.

Auf Netzwerkebene steigt die Komplexität noch einmal stark an.

Biologisch detaillierte kortikale Modelle können zehntausende Hodgkin-Huxley-Neuronen, Millionen von Verbindungen und viele Millionen Synapsen enthalten. Trotzdem sind auch solche Simulationen keine vollständige digitale Kopie echten Hirngewebes.

Für ein wirklich umfassendes digitales Neuron müssten noch viel mehr Ebenen gleichzeitig integriert werden:

vollständige dreidimensionale Morphologie, relevante Ionenkanäle, einzelne Synapsen und Spines, Neurotransmitterfreisetzung, Calcium- und andere Botenstoffsysteme, kurz- und langfristige Plastizität, Neuromodulatoren wie Dopamin und Acetylcholin, Genexpression, Proteinsynthese, Zellstoffwechsel, Energieversorgung, strukturelles Wachstum, Wechselwirkungen mit Gliazellen sowie die individuelle Entwicklungs- und Lerngeschichte der Zelle.

Ein vollständig integriertes und experimentell validiertes Modell mit all diesen Ebenen gibt es derzeit nicht.

Genau deshalb ist ein wichtiger Forschungsgrundsatz:

**Mehr Details bedeuten nicht automatisch mehr Wahrheit.**

Entscheidend sind auch die Qualität und Herkunft der Messdaten, bekannte Unsicherheiten, unabhängige Validierung und reproduzierbare Vorhersagen.

## Kernaussage

Ein vollständig aktives, morphologisch rekonstruiertes Multi-Kompartiment-Hodgkin-Huxley-Modell einer Schicht-5-Pyramidenzelle mit expliziten Spines, Calciumdynamik und synaptischer Plastizität gehört zu den komplexesten biologisch plausiblen Einzelneuronenmodellen.

Gegenüber einem einfachen Leaky-Integrate-and-Fire-Neuron ist das nicht nur ein kleines Upgrade.

**Es ist eine völlig andere Detailklasse.**

Ende der AVA 01610 Hörfassung.
