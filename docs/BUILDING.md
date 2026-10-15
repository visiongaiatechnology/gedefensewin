# Build-Anleitung

## Umgebung

- Windows 11 x64, Windows PowerShell 5.1 x64 und Git.
- Exakt Go **1.26.9** gemäß `TOOLCHAINS.lock`; `go 1.23.0` im Modul ist die minimale Sprachkompatibilität.
- Ein für den Go-Race-Detector geeigneter C-Compiler im Build-PATH.
- Für das Center zur Laufzeit: lokal installiertes Edge, Chrome oder Brave.

## Verifikation und Installer

```powershell
# STATUS: GOLD — vollständige VM-Qualifikation separat durchführen
$env:GOTOOLCHAIN = 'go1.26.9'
& .\build\Test-GeDefenseRelease.ps1
& .\build\Build-GeDefenseStandalone.ps1
```

Der Gate prüft Versionskonsistenz, keine externen Go-Module, gofmt, Race-Tests, Vet, vier Windows-Builds, Frontend-Sicherheitsinvarianten und PowerShell-Parsing. Der Standalone-Build signiert Payload und Installer und schreibt ein JSON-Manifest nach `release/`.

Die Signieridentität muss im Zertifikatsspeicher des Buildkontos mit privatem Schlüssel und Code-Signing-EKU vorliegen. `certificates/release-thumbprint.txt` enthält ausschließlich ihren Thumbprint. Der Build exportiert nur das öffentliche Zertifikat. Private Schlüssel niemals ins Repository kopieren.

`-TrustDevelopmentCertificate` ist ausschließlich für isolierte Entwicklungsmaschinen vorgesehen: Die Option erzeugt gegebenenfalls ein Entwicklungszertifikat und importiert es in den lokalen Benutzer-Vertrauensspeicher. Sie ist kein Ersatz für die öffentlich vertrauenswürdige Signieridentität einer allgemeinen Distribution.

## Optionale GeoIP/ASN-Daten

Das öffentliche Git enthält die große CSV nicht. Vor dem Build können lizenzierte Daten im dokumentierten Format unter `data/geoip.csv` mit passender `data/geoip.csv.sha256` bereitgestellt werden. Der Payload-Builder kopiert beide neben die Service-EXE; ohne Daten funktioniert der restliche Dienst weiter und die Karte meldet den fehlenden Bestand. Siehe [Datenformat, Herkunft und Grenzen](../GEOIP_LICENSE_AND_DEPLOYMENT.md).

## Zusätzliche Regressionen

Aus `src/GeDefense/windows/`: `go test -race ./...`, `go vet ./...` und optional `go test -shuffle=on -count=10 ./...`. Der Release-Scan verwendete golangci-lint 2.14.0 mit `--max-issues-per-linter=0 --max-same-issues=0` und Staticcheck 0.8.2.

`node --test test/telemetry-ui.test.mjs` prüft die Traffic-Darstellung. `node test/startup-health.browser.cjs` benötigt separat installiertes Playwright und Chrome. Playwright wird normal über Node aufgelöst; alternativ kann `CODEX_NODE_MODULES` auf dessen absolutes Modulverzeichnis zeigen. Diese Testwerkzeuge sind keine Produktionsabhängigkeiten.

Native Tests mit echten Browserfenstern sowie Tests, die Windows-Schutzrichtlinien ändern, gehören auf isolierte Testsysteme. Umfang und Grenzen der durchgeführten Tests: [4.1.4](VERIFICATION-4.1.4.md).

## Sauberes Source-Release

Den Source-Builder aus einem sauberen Checkout ausführen:

```powershell
# STATUS: GOLD
& .\build\Build-SourceRelease.ps1
```

Er erzeugt ein geordnetes ZIP mit festen Zeitstempeln und `SOURCE-MANIFEST.sha256`. Das Manifest hasht die ausgelieferten Bytes außer sich selbst. Das verifizierte Release-ZIP ist für die Byteprüfung maßgeblich; Git kann beim Checkout Zeilenenden anpassen.

Nicht veröffentlichen: private Signierdaten, `certificates/`, `payload/`, `work/`, Laufzeit-Tokens, Logs, Evidenz- oder Feed-Snapshots. Installer und Source-ZIP gehören als Assets ins GitHub-Release.
