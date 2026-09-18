# Abhängigkeiten

## Go-Module

GeDefense Windows 4 verwendet **keine externen Go-Module**. `src/GeDefense/windows/go.mod` enthält ausschließlich Modulpfad und Go-Version; `go.sum` ist absichtlich leer.

Windows-spezifische Funktionen werden über kleine interne Wrapper gegen öffentliche Win32-APIs umgesetzt. Es entstehen keine transitiven Go-Abhängigkeiten und keine zusätzliche UI-Runtime.

## Laufzeit

- Microsoft Windows 11 x64
- Microsoft Defender Antivirus und verfügbare Windows-Sicherheitsfunktionen
- Windows PowerShell 5.1 für signierte Hardening-/Systemtransaktionen

## Build

- Offizielle VGT-Release-Toolchain: Go 1.27.1 (siehe `TOOLCHAINS.lock`)
- Windows PowerShell 5.1
- ein für den Go-Race-Detector geeignetes Windows-x64-Buildsystem für den vollständigen Release-Gate

## Dependency-Gate

Ein Release wird abgelehnt, wenn `go.mod` einen `require`-Block enthält, `go.sum` nicht leer ist, `go list -m all` mehr als das GeDefense-Modul ausgibt oder Frontend/Go-Code externe CDN- bzw. Script-Runtimes einführt.


Der `go 1.23.0`-Eintrag in `go.mod` beschreibt die minimale Sprach-/Modulkompatibilität. Offizielle VGT-Artefakte werden ausschließlich mit der in `TOOLCHAINS.lock` gepinnten, unterstützten Go-Version gebaut.
