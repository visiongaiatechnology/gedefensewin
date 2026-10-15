# Kinetic GeoIP/ASN — lokale Daten und Betrieb

Die Karte ordnet tatsächlich beobachtete WFP-Kinetic- und Threat-IP-Ereignisse lokal zu. Quell-IP-Adressen werden nicht an externe GeoIP-Dienste gesendet. Die Zuordnung beschreibt eine ungefähre Netzwerk-/Registrierungsherkunft, keinen physischen Standort einer Person. Land und ASN verleihen keine Enforcement-Autorität.

## Installation und eigene Builds

Der veröffentlichte Installer 4.1.3 enthält die lokale CSV und ihren SHA-256-Sidecar neben der Service-EXE. Die Daten sind nicht in die Service-Binärdatei einkompiliert. Das öffentliche Git enthält statt der großen CSV diese Anleitung.

Für eigene Builds: `data/geoip.csv` und `data/geoip.csv.sha256` vor dem Payload-Build bereitstellen. Bei bestehender Installation beide Dateien neben `gedefense-windows.exe` ablegen; alternativ `GEDEFENSE_GEOIP_CSV` als absoluten Pfad in der Umgebung des **Dienstprozesses** setzen. Anschließend den Dienst neu starten.

CSV-Spalten: `network,country_code,country_name,latitude,longitude,asn,as_name`. Der Sidecar enthält den hexadezimalen SHA-256 der CSV, optional gefolgt von zwei Leerzeichen und dem Dateinamen. Der Loader prüft reguläre Datei, SHA-256, maximal 128 MiB, maximal 1.000.000 Einträge und öffentliche IP-Netze. Eigene Datensätze müssen dem vom Resolver getesteten Format entsprechen.

Bei fehlenden oder inkonsistenten Daten meldet die Karte den nicht geladenen Bestand. Es gibt keine erfundenen Host-Pins oder Angriffsverläufe. Die erste authentifizierte Geo-Abfrage lädt die Daten; sie bleiben bis zum Dienstneustart gecacht. Ausgabegrenzen: 150 betrachtete eindeutige IPs, 96 ausgegebene Einträge, 64 Länderaggregate. Nur `verifiedWfpBlock` kennzeichnet verifizierte WFP-Blockevidenz.

## Herkunft des in 4.1.3 gebündelten Bestands

Die kombinierte CSV stammt aus der bestehenden, bereitgestellten GeDefense-Linux-Integration. Die Windows-Portierung verwendet Longest-Prefix-Match und schließt private sowie besondere Adressbereiche aus.

- Tatsächliche CSV: **69.876.579 Bytes**.
- SHA-256: `cee2d19cfcc44926c0cefffe0ba47b1d3ceb7b6c16f39dff715837f82844123c`.
- Der ursprünglich mitgelieferte Linux-Sidecar nannte abweichend `60907affe213f513d0198e0f892562a6c40dfe5a84146e7b02c6311f9134f8a7`.
- Der Windows-Sidecar wurde auf die tatsächlichen Bytes berichtigt. Das bestätigt Bytekonsistenz, keine unabhängig geprüfte Authentizität oder Aktualität. Datum und genaue Version der Ausgangsdaten sind nicht belegt.

Für einen unabhängig qualifizierten Datenstand muss die kombinierte Datei aus nachvollziehbar datierten, lizenzierten Quellen neu erzeugt und mit kontrollierten WFP-/TI-Ereignissen in einer isolierten Windows-Umgebung geprüft werden.

## Attribution

- Geolocation: **DB-IP Lite**, [DB-IP](https://db-ip.com), [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).
- ASN: **sapics/ip-location-db**, PDDL laut übernommener Linux-Integration; [Quelle](https://github.com/sapics/ip-location-db), [Lizenz](https://opendatacommons.org/licenses/pddl/1-0/).
- Lokale Kartengeometrie: **jsVectorMap world-merc**, MIT, Copyright © 2020 Mustafa Omar; vollständiger Text in [LICENSES/jsVectorMap-LICENSE](LICENSES/jsVectorMap-LICENSE).

Die kombinierte CSV ist eine übernommene Zusammenführung dieser Daten. Der Sidecar wurde für die Windows-Integration korrigiert. Weitere Hinweise: [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
