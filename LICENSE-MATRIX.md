# Lizenzmatrix

Diese Matrix definiert die Lizenzzuordnung innerhalb dieses Repositorys. Sie ersetzt keine Lizenztexte; maßgeblich sind `LICENSE`, die Dateien unter `LICENSES/` und die jeweiligen Upstream-Lizenzen.

| Bereich | Pfade beziehungsweise Komponente | Lizenz / Status |
|---|---|---|
| GeDefense-Quellcode | `src/`, `audit/`, `engine/`, `xdr/`, `installer/`, `build/`, `tools/` | AGPL-3.0-only |
| Projektdokumentation | `README.md`, `docs/`, Richtlinien und Metadaten | AGPL-3.0-only, soweit nicht ausdrücklich anders markiert |
| VGT-Markenmaterial | `branding/`, `src/**/gedefense-logo.png`, Namen und Produktaufmachung | Nicht unter AGPL; begrenzte Nutzung gemäß `TRADEMARKS.md` |
| fyne.io/systray | Go-Modul `fyne.io/systray` | Apache-2.0 |
| go-webview2 | Go-Modul `github.com/jchv/go-webview2` | MIT |
| golang.org/x/sys | Go-Modul `golang.org/x/sys` | BSD-3-Clause |
| godbus/dbus | indirektes Go-Modul `github.com/godbus/dbus/v5` | BSD-2-Clause |
| go-winloader | indirektes Go-Modul `github.com/jchv/go-winloader` | ISC |
| Go Toolchain / Standardbibliothek | externe Build-Abhängigkeit | jeweilige Go-/BSD-Lizenz, nicht in diesem Repository vendored |
| Microsoft Windows | Betriebssystem und Systembibliotheken | Microsoft-Lizenz; nicht Bestandteil dieses Repositorys |
| Microsoft Defender / WFP / App Control | Betriebssystemfunktionen | Microsoft-Lizenz; nur über öffentliche Windows-Schnittstellen angesprochen |
| Microsoft WebView2 Runtime | externe Laufzeit | Microsoft-Lizenz; nicht mit dem Quellcode relizenziert |
| abuse.ch Feodo Tracker | zur Laufzeit abgerufener Feed | CC0 laut Feed-Zuordnung; Daten werden nicht im Repository gebündelt |
| Spamhaus DROP | zur Laufzeit abgerufener Feed | Spamhaus-Nutzungsbedingungen und Quellenangabe; Daten werden nicht im Repository gebündelt |
| offizielle VGT-Binärreleases | separat veröffentlichte, VGT-signierte Installer | AGPL-Quellcodepflicht plus VGT-Signatur- und Markenrichtlinie |

## Abgrenzung

Die AGPL-Lizenz für GeDefense verändert nicht die Lizenz von Windows, WebView2 oder anderen Systemkomponenten. Dieses Repository enthält keine Windows-ISO, keine Microsoft-Binärdateien, keine WebView2-Runtime und keine Threat-Feed-Snapshots.

Community-Builds müssen ihre eigene Signatur verwenden und dürfen ohne ausdrückliche Freigabe nicht als offizielles VGT-Release auftreten.

