# Build-Anleitung

## Umgebung

- Windows 11 x64, Windows PowerShell 5.1 x64 und Git.\n\nDer Quellbaum enthält ausschließlich Quellcode, Tests, Build-Skripte, Produktdokumentation und Lizenztexte. Generierte Artefakte (`release/`, `payload/`, `work/`, `sbom/`, `SOURCE-MANIFEST.sha256`) sowie Agenten-/Handoff-Dateien sind gitignoriert und werden vom Release-Gate bei Auftauchen abgelehnt. Das Release-Datum für reproduzierbare Builds steht in `SOURCE_DATE_EPOCH`.
- Exakt Go **1.26.10** gemäß `TOOLCHAINS.lock` (inklusive Go-Archiv-SHA-256); `go 1.23.0` im Modul ist die minimale Sprachkompatibilität.
- Ein für den Go-Race-Detector geeigneter C-Compiler im Build-PATH.
- Für das Center zur Laufzeit: lokal installiertes Edge, Chrome oder Brave.

## Verifikation und Installer

```powershell
# STATUS: GOLD — vollständige VM-Qualifikation separat durchführen
# Verbindliche Reihenfolge (SC-FIND-005/SC-FIND-003): Source-Archiv zuerst,
# dann der Standalone-Build (er führt das Release-Gate aus und bindet die
# finale Source-ZIP in die Provenance), zuletzt die Offline-Publish-Prüfung.
$env:GOTOOLCHAIN = 'go1.26.10'
& .\build\Build-SourceRelease.ps1
& .\build\Build-GeDefenseStandalone.ps1
# Ohne .git/Tag nur als ausdrücklicher Dry-Run:
& .\build\Publish-GitHubRelease.ps1 -VerifyOnly -AllowMissingVcs
```

`Build-GeDefenseStandalone.ps1` führt den Gate aus: Versionskonsistenz, keine externen Go-Module, gofmt, Race-Tests, Vet, vier Windows-Builds, Frontend-Sicherheitsinvarianten, PowerShell-Parsing, `govulncheck -mode=binary` (Go ≥ 1.26.10), SBOM/Provenance/Hygiene/Kanal/Publish-Gates. Anschließend signiert er Payload und Installer und erzeugt SBOM, Provenance, JSON-Sidecar und SHA256SUMS in der festen Reihenfolge.

Die Signieridentität muss im Zertifikatsspeicher des Buildkontos mit privatem Schlüssel und Code-Signing-EKU vorliegen. Der Build referenziert sie über `certificates/release-thumbprint.txt` (nur Thumbprint); Signierzertifikat, Thumbprint-Datei und exportieres öffentliches Zertifikat sind gitignoriert und gehören nicht in den sauberen Quellbaum. Private Schlüssel niemals ins Repository kopieren. Für lokale Testbuilds kann `-TrustDevelopmentCertificate` ein Entwicklungszertifikat erzeugen; das ist kein Release-Trust.

`-TrustDevelopmentCertificate` ist ausschließlich für isolierte Entwicklungsmaschinen vorgesehen: Die Option erzeugt gegebenenfalls ein Entwicklungszertifikat und importiert es in den lokalen Benutzer-Vertrauensspeicher. Sie ist kein Ersatz für die öffentlich vertrauenswürdige Signieridentität einer allgemeinen Distribution.

## Supply-Chain-Nachweise (SBOM, Provenance, Hygiene)

Vor dem Release-Gate regeneriert `Build-GeDefenseStandalone.ps1` die SBOM und `SOURCE-MANIFEST.sha256` deterministisch; danach erzeugt es mit dem signierten Payload die Release-Artefakte:

```powershell
# SBOM aus dem Arbeitsbaum (Source-Modus).
& .\tools\New-VgtSbom.ps1
& .\tools\Test-VgtSbom.ps1

# Payload-vollständige SBOM als Release-Asset.
& .\tools\New-VgtSbom.ps1 -ArtifactMode -PayloadRoot .\payload\VGT\GeDefense -OutputPath .\release\GeDefense-SBOM-v5.2.0.cdx.json
& .\tools\Test-VgtSbom.ps1 -ArtifactMode -Path .\release\GeDefense-SBOM-v5.2.0.cdx.json

# Offline verifizierbare, bewusst unsignierte Build-Provenance.
& .\tools\New-VgtProvenance.ps1 -RequireSourceManifest
& .\tools\Test-VgtProvenance.ps1 -Path .\release\GeDefense-Provenance-v5.2.0.json -RequireSourceManifest

# Verteilungs-/Key-Hygiene und Installer-Härtungsregressionen.
& .\tools\Test-DistributionHygiene.ps1
& .\tools\Test-InstallerSafety.ps1
& .\tools\Test-InstallerHardening.ps1
& .\tools\Test-PublishGates.ps1
```

SBOM und Source-Manifest sind generierte Build-Artefakte und werden nicht im Repository versioniert; `Build-SourceRelease.ps1` und `Build-GeDefenseStandalone.ps1` erzeugen sie deterministisch neu. Die SBOM ist eine Inventarliste, kein CVE-Scan; Schwachstellen prüft `govulncheck -mode=binary` im Gate. Externe Blocker (öffentliche CA, RFC3161, Revocation, extern verankerter Anti-Rollback-Kanal) sind in `README.md` und `SECURITY.md` dokumentiert und werden nicht als PASS gewertet.

## Optionale GeoIP/ASN-Daten

Das öffentliche Git enthält die große CSV nicht. Vor dem Build können lizenzierte Daten im dokumentierten Format unter `data/geoip.csv` mit passender `data/geoip.csv.sha256` bereitgestellt werden. Der Payload-Builder kopiert beide neben die Service-EXE; ohne Daten funktioniert der restliche Dienst weiter und die Karte meldet den fehlenden Bestand. Siehe [Datenformat, Herkunft und Grenzen](../GEOIP_LICENSE_AND_DEPLOYMENT.md).

## Zusätzliche Regressionen

Aus `src/GeDefense/windows/`: `go test -race ./...`, `go vet ./...` und optional `go test -shuffle=on -count=10 ./...`. Der Release-Scan verwendete golangci-lint 2.14.0 mit `--max-issues-per-linter=0 --max-same-issues=0` und Staticcheck 0.8.2.

`node --test test/telemetry-ui.test.mjs` prüft die Traffic-Darstellung. `node test/startup-health.browser.cjs` benötigt separat installiertes Playwright und Chrome. Playwright wird normal über Node aufgelöst; alternativ kann `CODEX_NODE_MODULES` auf dessen absolutes Modulverzeichnis zeigen. Diese Testwerkzeuge sind keine Produktionsabhängigkeiten.

Native Tests mit echten Browserfenstern sowie Tests, die Windows-Schutzrichtlinien ändern, gehören auf isolierte Testsysteme. Umfang und Grenzen der verifizierten Tests stehen im Release-Gate-Ergebnis des jeweiligen Builds.

## Sauberes Source-Release

Den Source-Builder aus einem sauberen Checkout ausführen:

```powershell
# STATUS: GOLD
& .\build\Build-SourceRelease.ps1
```

Er erzeugt ein geordnetes ZIP mit festen Zeitstempeln, ausschließlich unkomprimierten (stored) Einträgen und `SOURCE-MANIFEST.sha256`. Der Builder verifiziert das entstandene Archiv wieder (Eintragszahl, Reihenfolge, unkomprimierte Speicherung, fixer Zeitstempel) und bindet anschließend die Provenance an Arbeitsbaum und Archiv (`-RequireSourceManifest`). Das Manifest hasht die ausgelieferten Bytes außer sich selbst. Das verifizierte Release-ZIP ist für die Byteprüfung maßgeblich; Git kann beim Checkout Zeilenenden anpassen.

`FULL_SOURCE_SHA256.txt` ist entfernt und wird vom Builder aktiv abgelehnt: `SOURCE-MANIFEST.sha256` ist das einzige autoritative Integritätsmanifest.

Nicht veröffentlichen: private Signierdaten, `certificates/`, `payload/`, `work/`, Laufzeit-Tokens, Logs, Evidenz- oder Feed-Snapshots. Installer, Source-ZIP, SBOM, Provenance und `SHA256SUMS.txt` gehören als Assets ins GitHub-Release.
