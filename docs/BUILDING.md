# Build-Anleitung

## Unterstützte Build-Umgebung

- Windows 11 x64
- Go 1.27.1 für offizielle VGT-Releases (`TOOLCHAINS.lock`)
- Windows PowerShell 5.1
- Race-Detector-fähige Windows-x64-Buildumgebung für den vollständigen Gate
- Git

GeDefense Windows 4 verwendet keine externen Go-Module und benötigt keine separate UI-Runtime. `go.mod` bleibt aus Quellkompatibilitätsgründen bei `go 1.23.0`; der offizielle Release-Compiler ist unabhängig davon exakt gepinnt.

## Vollständiger Release-Gate

```powershell
& .\build\Test-GeDefenseRelease.ps1
```

Der Gate prüft Versionskonsistenz, Zero-Go-Dependency, Formatierung, Race-Tests, Vet, Builds aller Windows-Binaries, Frontend-Sicherheitsinvarianten und verbotene Legacy-Referenzen.

## Standalone-Build

```powershell
& .\build\Build-GeDefenseStandalone.ps1
```

Der Build führt zuerst den Release-Gate aus, signiert Payload und Installer und erzeugt Manifest sowie SHA-256.

## Verbotene Build-Inhalte

- private Schlüssel und PFX/P12-Dateien
- `certificates/release-thumbprint.txt`
- `payload/`, `release/`, `work/` und eingebettete ZIP-Dateien
- ProgramData-Laufzeitdaten, Tokens, Evidenz oder Feed-Snapshots

## Native Windows-Integrationstests

Produktive Systeme sind kein CI-Testziel. Tests, die Prozessüberwachung oder Schutzrichtlinien tatsächlich aktivieren, laufen ausschließlich auf isolierten Windows-Testmaschinen.


## Source-Release

```powershell
& .\build\Build-SourceRelease.ps1
```

Das Source-Archiv schließt Buildausgaben, Signiermaterial, Laufzeitdaten und eingebettete Payload-ZIPs aus. `SOURCE-MANIFEST.sha256` deckt alle ausgelieferten Quelldateien außer sich selbst ab.
