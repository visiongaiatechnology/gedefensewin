# Third-Party Notices

## Go und Microsoft Windows

GeDefense Windows 4 verwendet keine externen Go-Module. Die Go-Standardbibliothek unterliegt der Go-Lizenz. Windows, Defender, Firewall/WFP, App Control und der lokal installierte Browser sind eigene Plattformkomponenten; ihre Binärdateien werden nicht mitgeliefert.

## Lokale Kartengeometrie

`src/GeDefense/windows/internal/server/web/world-merc.js` enthält lokal eingebundene jsVectorMap-Weltkartengeometrie, Copyright © 2020 Mustafa Omar, **MIT**. Der Wrapper wurde für einen lokalen ES-Modul-Export angepasst. Der vollständige Lizenztext steht in `LICENSES/jsVectorMap-LICENSE` und wird im Installer-Payload mitgeliefert. Die jsVectorMap-Laufzeitbibliothek wird nicht verwendet.

## Optionale GeoIP/ASN-Daten

Geolocation-Daten: **DB-IP Lite**, bereitgestellt von [DB-IP](https://db-ip.com), **Creative Commons Attribution 4.0**: https://creativecommons.org/licenses/by/4.0/ .

ASN-Daten: **sapics/ip-location-db**, Datenbankzuordnung laut übernommener Linux-Integration **PDDL**: https://github.com/sapics/ip-location-db und https://opendatacommons.org/licenses/pddl/1-0/ .

Die bereitgestellte kombinierte CSV wurde aus der bestehenden GeDefense-Linux-Integration übernommen; ihr SHA-256 wurde anhand der tatsächlichen Bytes korrigiert. Der genaue Ausgangssnapshot und sein Aktualitätsstand sind nicht unabhängig bestätigt. Herkunft, Transformation und Prüfsumme sind in `GEOIP_LICENSE_AND_DEPLOYMENT.md` dokumentiert. Die große CSV ist nicht im öffentlichen Git enthalten, wird aber im 4.1.3-Installer als lokale Datenressource mitgeliefert.

## Threat Intelligence

Zur Laufzeit werden Feodo Tracker, Spamhaus DROP IPv4/IPv6, FireHOL Level 1, CINS Army, blocklist.de, Emerging Threats, IPsum und Tor Exit Nodes gemäß Feed-Katalog verwendet. Es gelten die Bedingungen der jeweiligen Anbieter; Feed-Snapshots werden nicht im Quellrepository gebündelt. Aktionsklassen und Sicherheitsgrenzen: `docs/THREAT-INTELLIGENCE.md`.

## Abdeckung der Komponentenliste

`sbom/gedefense-windows.cdx.json` dokumentiert die Anwendung und den leeren externen Go-Modulgraphen. Diese leere Modulliste bedeutet nicht, dass Kartendaten, optionale Datenbanken, Toolchain oder Plattformkomponenten keine eigenen Lizenzen und Vertrauensgrenzen besitzen. Für diese Ressourcen gelten die Hinweise oben und die Lizenzmatrix.
