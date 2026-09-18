# VGT GeDefense Windows 4.0.0-beta.1

Release-Datum: 2026-09-18

## Generation 4

GeDefense Windows 4 hebt den Windows-Agent auf dieselbe Architekturphilosophie wie GeDefense Linux V4: minimale Abhängigkeiten, getrennte Detection-/Response-Autorität, bounded State, nachvollziehbare Attack Stories und ein modernes lokales Protection Center.

### Kernänderungen

- externe Go-Module vollständig entfernt
- eigene schlanke Win32-Wrapper für Service, Tray, Handles, Shell und Netzwerk
- native TCP → Owning PID → Prozessidentität-Korrelation
- PID-Reuse-sichere Prozessreaktion
- Threat-Intel-Prefix-Index mit harten Feed- und Netzgrenzen
- Attack Stories aus Prozess-, Netzwerk- und Threat-Intel-Signalen
- Host-Response nur mit expliziter ResponseAuthority und erneuter Identitätsprüfung
- XDR-Datenminimierung: verdächtige Command Lines und Scriptmaterial werden als Hash/Metadaten statt Rohpayload persistiert
- gehärteter Integrity-Lifecycle mit Reparse- und Mutationserkennung
- modularisierte lokale Control Plane mit bounded Replay-/Session-/Rate-State
- Guided Protection Activation: Monitor → Guarded → Sovereign
- komplett modernisierte Ice-Blue-Glassmorphism-UI ohne CDN oder Framework
- signierter Installerpfad mit expliziter Catalog- und Zielskript-Signerprüfung
- global serialisierte Windows-Policy-Mutationen mit verifiziertem Protection-Health-State
- Threat-Intel-Status fällt bei fehlgeschlagener Firewall-Verifikation fail-closed auf `STALE`
- Bootstrap und erhöhte Skripttransaktionen laufen ausschließlich unter `ExecutionPolicy AllSigned`
- offizielle Release-Toolchain auf Go 1.27.1 gepinnt
- privilegierte PowerShell-Prozesse werden ausschließlich über den validierten System32-Pfad gestartet, niemals über `PATH`
- Sovereign-Allow-Transaktionen gelten erst nach bestätigter App-Control-Kernelverifikation als gesund
- deterministischer Source-Release-Pfad mit internem SHA-256-Manifest und festen ZIP-Zeitstempeln

## Dependency-Vertrag

`go.mod` besitzt keinen `require`-Block, `go.sum` ist leer und `go list -m all` liefert ausschließlich das GeDefense-Modul.

## Verifikation in der Source-Release-Umgebung

Bestanden:

- `gofmt` vollständig sauber
- Cross-Windows-Testkompilierung aller Go-Packages und Tests
- Cross-Windows `go vet ./...`
- Cross-Windows-Build von Service, Center, Tray und Installer
- Race Detector für plattformunabhängige Core-Packages
- JavaScript-Syntaxprüfung aller UI-Module
- Zero-Go-Dependency-Graph
- SBOM-/Versionskonsistenz
- Frontend-Scan auf externe URLs, eval, dynamische Function-Konstruktion, Web Storage und Debug-Ausgaben
- produktiver Baum frei von den entfernten Legacy-Go-/UI-Abhängigkeiten

## Windows-native Final-Gates

Der Repository-Gate `build/Test-GeDefenseRelease.ps1` führt auf Windows zusätzlich vollständige `go test -race ./...`, PowerShell-AST-Parsing und native Windows-Buildverifikation aus. Erhöhte Integrationstests für reale Prozess-, Defender-, App-Control- und Policy-Pfade bleiben absichtlich auf isolierte Windows-Testsysteme beschränkt.
