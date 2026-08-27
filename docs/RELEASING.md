# Release-Prozess

## Community-Release

1. Versionsnummer in allen vier Go-Binaries und Installer-Metadaten aktualisieren.
2. `VERSION`, `CHANGELOG.md`, SBOM und Dokumentation synchronisieren.
3. vollständige Race-, Vet-, JavaScript- und PowerShell-Prüfung durchführen.
4. sauberen Standalone-Build erstellen.
5. Manifest, SHA-256 und Authenticode-Status dokumentieren.
6. Artefakt klar als Community-Build kennzeichnen.

## Offizielles VGT-Release

Ein offizielles Release benötigt zusätzlich:

- kontrollierten, gehärteten Release-Runner
- ausschließlich durch VGT kontrollierten Codesigning-Schlüssel
- Vier-Augen-Freigabe des Source-Commits und der SBOM
- unabhängige Prüfung von Hash und Signatur
- signiertes Git-Tag
- veröffentlichte Corresponding Source für exakt dieses Artefakt
- bestätigte Threat-Feed- und Drittanbieterlizenzen

Offizielle Schlüssel werden niemals in Repository, CI-Log, Build-ZIP oder Supportpaket gespeichert.

## AGPL-Quellangebot

Zu jedem veröffentlichten Binärartefakt muss der vollständige bevorzugte Quellstand einschließlich Buildskripten verfügbar sein. Der Release-Eintrag verlinkt auf das unveränderliche Tag und dokumentiert den SHA-256 des Installers.

