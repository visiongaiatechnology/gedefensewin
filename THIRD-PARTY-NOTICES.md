# Third-Party Notices

## Go und Microsoft Windows

GeDefense Windows 5.2 verwendet keine externen Go-Module. Die Go-Standardbibliothek unterliegt der Go-Lizenz. Windows, Defender, Firewall/WFP, App Control und der lokal installierte Browser sind eigene Plattformkomponenten; ihre Binärdateien werden nicht mitgeliefert.

## Lokale Kartengeometrie

`src/GeDefense/windows/internal/server/web/world-merc.js` enthält lokal eingebundene jsVectorMap-Weltkartengeometrie (`world-merc.js`, Upstream-Version **1.7.0**), Copyright © 2020 Mustafa Omar, **MIT**. Quelle: https://github.com/themustafaomar/jsvectormap · Kartendatei: https://cdn.jsdelivr.net/npm/jsvectormap@1.7.0/dist/maps/world-merc.js · Lizenz: https://github.com/themustafaomar/jsvectormap/blob/main/LICENSE . Der Wrapper wurde für einen lokalen ES-Modul-Export angepasst. Der vollständige Lizenztext steht in `LICENSES/jsVectorMap-LICENSE` und wird im Installer-Payload mitgeliefert. Die jsVectorMap-Laufzeitbibliothek wird nicht verwendet.

## Optionale GeoIP/ASN-Daten

Geolocation-Daten: **DB-IP Lite**, bereitgestellt von [DB-IP](https://db-ip.com), **Creative Commons Attribution 4.0**: https://creativecommons.org/licenses/by/4.0/ .

ASN-Daten: **iplocate/ip-address-databases**, öffentliche IP-to-Country-/IP-to-ASN-Datenbanken unter **CC BY-SA 4.0**: https://github.com/iplocate/ip-address-databases . Die Attribution ist für Weitergabe und Bearbeitung der abgeleiteten CSV erforderlich; die abgeleitete `data/geoip.csv` wird im Installer-Payload als lokale Ressource mitgeliefert.

Die bereitgestellte kombinierte CSV wurde aus der bestehenden GeDefense-Linux-Integration übernommen; ihr SHA-256 wurde anhand der tatsächlichen Bytes korrigiert. Der genaue Ausgangssnapshot und sein Aktualitätsstand sind nicht unabhängig bestätigt. Herkunft, Transformation und Prüfsumme sind in `GEOIP_LICENSE_AND_DEPLOYMENT.md` dokumentiert. Die große CSV ist nicht im öffentlichen Git enthalten, wird aber im Installer-Payload als lokale Datenressource mitgeliefert. Attributionen: DB-IP Lite (CC BY 4.0) für Geolocation; iplocate/ip-address-databases (CC BY-SA 4.0) für ASN-Daten; Quellen-URLs jeweils oben.

## Threat Intelligence

Zur Laufzeit werden Feodo Tracker, Spamhaus DROP IPv4/IPv6, FireHOL Level 1, CINS Army, blocklist.de, Emerging Threats, IPsum und Tor Exit Nodes gemäß Feed-Katalog verwendet. Es gelten die Bedingungen der jeweiligen Anbieter; Feed-Snapshots werden nicht im Quellrepository gebündelt. Aktionsklassen und Sicherheitsgrenzen: `docs/THREAT-INTELLIGENCE.md`.

## Abdeckung der Komponentenliste (CycloneDX-SBOM)

Die CycloneDX-1.5-Komponentenliste wird im Release-Build als `sbom/gedefense-windows.cdx.json` erzeugt (gitignoriert) und erfasst mit Version, Lieferant, Lizenz und SHA-256:

- die Anwendung und alle First-Party-Assets (`engine/`, `audit/`, `xdr/`, `installer/*.ps1`/`*.psm1`, Branding, Lizenztexte, Root-Notices),
- die vendored jsVectorMap-Weltkartengeometrie (MIT),
- den optionalen GeoIP/ASN-Datensatz (DB-IP Lite CC BY 4.0 / PDDL) mit ehrlichem "nicht unabhängig bestätigt"-Vermerk,
- die gepinnte Go-Toolchain (Version und Archiv-Hash aus `TOOLCHAINS.lock`) und die Windows-PowerShell-5.1-Laufzeit,
- im `-ArtifactMode` zusätzlich jedes Payload-Artefakt inklusive `manifest.json`, `vgt-payload.cat` und `vgt-release.cer`.

Erzeugung und Prüfung:

```powershell
& .\tools\New-VgtSbom.ps1 -ArtifactMode -PayloadRoot .\payload\VGT\GeDefense
& .\tools\Test-VgtSbom.ps1 -ArtifactMode
```

Das Release-Gate startet mit einem **nicht-leeren** Inventar; eine leere oder veraltete SBOM bricht den Build ab. Die SBOM ist eine Inventarliste, kein Schwachstellen-Scan — für CVEs gilt `govulncheck -mode=binary` im Gate. Externe Vertrauensanker (öffentliche CA, RFC3161-Zeitstempel, Revocation, extern verankerter Anti-Rollback-Kanal) stehen ausdrücklich als externe Blocker in der SBOM und in `README.md`/`SECURITY.md`; sie werden nicht behauptet.
