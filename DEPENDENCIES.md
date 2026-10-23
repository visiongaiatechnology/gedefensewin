# Abhängigkeiten

## Go-Module

GeDefense Windows 5.2 verwendet **keine externen Go-Module**. `src/GeDefense/windows/go.mod` enthält ausschließlich Modulpfad, Go-Sprachversion und gepinnte Build-Toolchain; `go.sum` ist absichtlich leer.

Windows-spezifische Funktionen werden über kleine interne Wrapper gegen öffentliche Win32-APIs umgesetzt. Es entstehen keine transitiven Go-Abhängigkeiten und keine zusätzliche UI-Runtime.

## Laufzeit

- Microsoft Windows 11 x64
- Microsoft Defender Antivirus und verfügbare Windows-Sicherheitsfunktionen
- Windows PowerShell 5.1 für signierte Hardening-/Systemtransaktionen
- Lokal installierter Chromium-Browser (Edge, Chrome oder Brave) als externer Renderer im eigenen Win32-Fensterhost (kein eingebetteter Renderer/WebView2)

## Build

- Offizielle VGT-Release-Toolchain: Go 1.26.10 (siehe `TOOLCHAINS.lock`, inklusive Go-Archiv-SHA-256)
- Windows PowerShell 5.1
- ein für den Go-Race-Detector geeignetes Windows-x64-Buildsystem für den vollständigen Release-Gate

## Supply-Chain-Nachweise

- `sbom/gedefense-windows.cdx.json` — echte CycloneDX-1.5-Komponentenliste; Erzeugung/Prüfung über `tools/New-VgtSbom.ps1` und `tools/Test-VgtSbom.ps1`.
- `release/GeDefense-Provenance-v<version>.json` — unsignierter, offline verifizierbarer Build-/Reproduzierbarkeitsnachweis (Quellbaum-Digest, Toolchain-Pin, Build-Flags, Artefakt-Hashes); Erzeugung/Prüfung über `tools/New-VgtProvenance.ps1` und `tools/Test-VgtProvenance.ps1`.
- `release/SHA256SUMS.txt` — vollständige Hash-Abdeckung aller veröffentlichten Assets, erzwungen durch `build/Publish-GitHubRelease.ps1`.

Die Provenance ist bewusst unsigniert: Identität/Authentizität benötigen eine öffentlich vertrauenswürdige Signatur mit RFC3161-Zeitstempel; das ist ein externer Blocker, kein PASS (siehe `README.md` und `SECURITY.md`).

## Dependency-Gate

Ein Release wird abgelehnt, wenn `go.mod` einen `require`-Block enthält, `go.sum` nicht leer ist, `go list -m all` mehr als das GeDefense-Modul ausgibt oder Frontend/Go-Code externe CDN- bzw. Script-Runtimes einführt.


Der `go 1.23.0`-Eintrag in `go.mod` beschreibt die minimale Sprach-/Modulkompatibilität. Offizielle VGT-Artefakte werden ausschließlich mit der in `TOOLCHAINS.lock` gepinnten, unterstützten Go-Version gebaut.
