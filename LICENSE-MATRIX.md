# Lizenzmatrix

| Bereich | Pfade beziehungsweise Komponente | Lizenz / Status |
|---|---|---|
| GeDefense-Quellcode | `src/`, `audit/`, `engine/`, `xdr/`, `installer/`, `build/`, `tools/` | AGPL-3.0-only |
| Projektdokumentation | `README.md`, `docs/`, Richtlinien und Metadaten | AGPL-3.0-only, soweit nicht anders markiert |
| VGT-Markenmaterial | `branding/`, Namen und Produktaufmachung | Nicht unter AGPL; Nutzung gemäß `TRADEMARKS.md` |
| Go Toolchain / Standardbibliothek | externe Build-Abhängigkeit | jeweilige Go-/BSD-Lizenz, nicht vendored |
| Microsoft Windows | Betriebssystem und Systembibliotheken | Microsoft-Lizenz; nicht Bestandteil des Repositorys |
| Microsoft Defender / WFP / App Control | Betriebssystemfunktionen | Microsoft-Lizenz |
| abuse.ch Feodo Tracker | Laufzeit-Feed | Bedingungen des Anbieters; nicht gebündelt |
| Spamhaus DROP | Laufzeit-Feed | Spamhaus-Nutzungsbedingungen; nicht gebündelt |
| Kartengeometrie | src/GeDefense/windows/internal/server/web/world-merc.js | MIT; LICENSES/jsVectorMap-LICENSE |
| Optionale GeoIP/ASN-Daten | lokale geoip.csv im Installer; nicht in Git | DB-IP Lite / CC BY 4.0, ASN / PDDL laut importierter Integration; siehe THIRD-PARTY-NOTICES.md |

GeDefense Windows 4.1.4 besitzt keine externen Go-Module.
