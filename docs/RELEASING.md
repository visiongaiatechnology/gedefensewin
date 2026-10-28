# Release-Prozess

## Pflicht-Gates

1. `VERSION` aktualisieren.
2. README-Version, Release-Version, NOTICE und Dokumentation synchronisieren.
3. `build/Test-GeDefenseRelease.ps1` vollständig bestehen (inkl. SBOM-, Provenance-, Hygiene-, Installer- und Publish-Gates sowie `govulncheck -mode=binary`).
4. erhöhte Windows-Integrationstests auf isoliertem Testsystem ausführen.
5. Source-Archiv deterministisch mit `build/Build-SourceRelease.ps1` erzeugen und gegen `SOURCE-MANIFEST.sha256` verifizieren.
6. Standalone-Build mit `build/Build-GeDefenseStandalone.ps1` erstellen; er führt das Release-Gate aus und erzeugt SBOM, signed Installer, finale Provenance (bindet die Source-ZIP), Sidecar und SHA256SUMS in dieser Reihenfolge.
7. Manifest, SHA-256, Authenticode-Status **gemessen** dokumentieren.
8. Publish nur über `build/Publish-GitHubRelease.ps1 -VerifyOnly` (offline) und danach den eigentlichen Publish als Draft; Veröffentlichung erst nach Vier-Augen-Freigabe über `-PublishImmediately` und erneuter Upload-Digest-Prüfung.

## Zero-Dependency-Vertrag

Ein Release wird abgelehnt, wenn `go.mod` einen `require`-Block enthält, `go.sum` nicht leer ist, `go list -m all` mehr als das GeDefense-Modul liefert oder externe Frontend-Runtimes/CDNs eingeführt werden.

## Community-Release

Community-Builds müssen klar als solche gekennzeichnet sein und ihre eigene Codesigning-Identität verwenden.

## Offizielles VGT-Release

Zusätzlich erforderlich: kontrollierter Release-Runner, VGT-Codesigning-Schlüssel, Vier-Augen-Freigabe, unabhängige Hash-/Signaturprüfung, signiertes Git-Tag und veröffentlichte Corresponding Source.

## Release-Toolchain

Offizielle VGT-Artefakte werden ausschließlich mit den in `TOOLCHAINS.lock` gepinnten Werkzeugen gebaut. Der Release-Gate bricht bei abweichender Go- oder PowerShell-Version ab und erzwingt Go ≥ 1.26.10 (GO-2026-6809 / CVE-2026-111943 in `crypto/x509` ist in älteren Toolchains enthalten). Das `go 1.23.0` in `go.mod` bleibt ausschließlich die minimale Quellkompatibilitätsgrenze.

## Reproduzierbarer Source-Release

```powershell
& .\build\Build-SourceRelease.ps1
```

Der Source-Builder leitet den ZIP-Zeitstempel aus dem `SOURCE_DATE_EPOCH`-Metadatenwert ab, verwendet eine ordinale Dateireihenfolge, speichert Einträge ohne kompression (stored) und verifiziert das erzeugte Archiv erneut (Eintragszahl, Pfad/Reihenfolge, unkomprimiert, fixer Zeitstempel). Er erzeugt zusätzlich `SOURCE-MANIFEST.sha256`, eine SHA-256-Sidecar-Datei für das Archiv und eine source-gebundene Provenance. `FULL_SOURCE_SHA256.txt` ist entfernt; nur `SOURCE-MANIFEST.sha256` ist autoritativ.

## Publikationsprüfung (fail-closed)

```powershell
# Offline: Hashes, Signatur, Tag/Clean-Tree, SBOM, Provenance und SHA256SUMS prüfen — ohne Token/Netz.
& .\build\Publish-GitHubRelease.ps1 -VerifyOnly
# Danach (falls alle Checks bestehen): Draft-Release erzeugen und Digests erneut prüfen.
& .\build\Publish-GitHubRelease.ps1
# Veröffentlichung erst nach Vier-Augen-Freigabe:
& .\build\Publish-GitHubRelease.ps1 -PublishImmediately
```

Der Publish-Pfad enthält keine fest eingetragenen Signatur-/Thumbprint-Behauptungen mehr; alle Werte werden gemessen. Ohne `.git`/clean Tag bricht er fail-closed ab (explizite, dokumentierte Ausnahme: `-AllowMissingVcs` nur für nicht-offizielle Dry-Runs).

## Publikationsstand 5.3.0

Repository: https://github.com/visiongaiatechnology/gedefensewin . Das Release dokumentiert die tatsächlich bestandenen Build-, Analyse-, Fenster- und Fixture-Prüfungen. Die separate vollständige VM-Neuinstallation/Upgrade-Qualifikation und eine unabhängige Vier-Augen-Freigabe sind damit nicht nachgewiesen; die README dokumentiert den Verifikationsstand und die Grenzen des Release-Gates. Die Veröffentlichung behauptet keine darüber hinausgehende Qualifikation.

Sources und Commit-Tag werden vor dem Release gepusht. Assets zunächst in einen Entwurf hochladen, Größe und SHA-256 prüfen und erst danach veröffentlichen. Private Schlüssel und lokale Laufzeitdaten bleiben ausgeschlossen.

## Externe Blocker (kein PASS)

Folgende Punkte sind ohne externe Infrastruktur nicht lokal lösbar und werden ausdrücklich NICHT als bestanden gezählt:

- öffentlich vertrauenswürdige Code-Signing-Identität (CA/EV) statt self-signed Zertifikat,
- RFC3161-Zeitstempel an Installer/Payload,
- CRL/OCSP-Revocationspfad,
- extern verankerter, manipulationsfester Anti-Rollback-Kanal,
- Clean-Host-Trust-Provisioning für Neuinstallationen.

Details und verbleibende Risiken stehen in `README.md` und `SECURITY.md`; Rotation von Evidence-/Vault-Keys ist dort beschrieben.
