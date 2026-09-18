# Release-Prozess

## Pflicht-Gates

1. `VERSION` aktualisieren.
2. `CHANGELOG.md`, SBOM, NOTICE und Dokumentation synchronisieren.
3. `build/Test-GeDefenseRelease.ps1` vollständig bestehen.
4. erhöhte Windows-Integrationstests auf isoliertem Testsystem ausführen.
5. sauberen Standalone-Build erstellen.
6. Manifest, SHA-256 und Authenticode-Status dokumentieren.
7. Source-Archiv deterministisch mit `build/Build-SourceRelease.ps1` erzeugen und gegen `SOURCE-MANIFEST.sha256` verifizieren.

## Zero-Dependency-Vertrag

Ein Release wird abgelehnt, wenn `go.mod` einen `require`-Block enthält, `go.sum` nicht leer ist, `go list -m all` mehr als das GeDefense-Modul liefert oder externe Frontend-Runtimes/CDNs eingeführt werden.

## Community-Release

Community-Builds müssen klar als solche gekennzeichnet sein und ihre eigene Codesigning-Identität verwenden.

## Offizielles VGT-Release

Zusätzlich erforderlich: kontrollierter Release-Runner, VGT-Codesigning-Schlüssel, Vier-Augen-Freigabe, unabhängige Hash-/Signaturprüfung, signiertes Git-Tag und veröffentlichte Corresponding Source.


## Release-Toolchain

Offizielle VGT-Artefakte werden ausschließlich mit den in `TOOLCHAINS.lock` gepinnten Werkzeugen gebaut. Der Release-Gate bricht bei abweichender Go- oder PowerShell-Version ab. Das `go 1.23.0` in `go.mod` bleibt ausschließlich die minimale Quellkompatibilitätsgrenze.

## Reproduzierbarer Source-Release

```powershell
& .\build\Build-SourceRelease.ps1
```

Der Source-Builder leitet den ZIP-Zeitstempel aus dem aktuellen Changelog-Release-Datum ab, verwendet eine stabile Dateireihenfolge, speichert Einträge ohne kompressorabhängige Variabilität und erzeugt zusätzlich `SOURCE-MANIFEST.sha256` sowie eine SHA-256-Sidecar-Datei für das Archiv.
