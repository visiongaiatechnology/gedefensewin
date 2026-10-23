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
| Kartengeometrie | src/GeDefense/windows/internal/server/web/world-merc.js (jsVectorMap world-merc 1.7.0) | MIT; LICENSES/jsVectorMap-LICENSE |
| Optionale GeoIP/ASN-Daten | lokale geoip.csv im Installer; nicht in Git | Geolocation: DB-IP Lite / CC BY 4.0; ASN: iplocate/ip-address-databases / CC BY-SA 4.0; siehe THIRD-PARTY-NOTICES.md |
| Go-Toolchain (Build) | `TOOLCHAINS.lock` Pin + Archiv-SHA-256 | Go-/BSD-Lizenz, nicht redistribuiert |
| Windows PowerShell 5.1 (Laufzeit) | Plattformkomponente | Microsoft-EULA, nicht redistribuiert |
| Build-/Supply-Chain-Tools | `tools/New-VgtSbom.ps1`, `tools/Test-VgtSbom.ps1`, `tools/New-VgtProvenance.ps1`, `tools/Test-VgtProvenance.ps1`, `build/PublishVerification.psm1` | AGPL-3.0-only |

GeDefense Windows 5.2.0 besitzt keine externen Go-Module. Die maschinenlesbare Komponenten-/Lizenzzuordnung wird im Build als CycloneDX-SBOM (`sbom/gedefense-windows.cdx.json`, gitignoriert) erzeugt.
