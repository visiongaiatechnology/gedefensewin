# VGT GeDefense Windows

![Status](https://img.shields.io/badge/status-production--tested-54d39a)
![Platform](https://img.shields.io/badge/platform-Windows%2011%20Enterprise-0078d4)
![License](https://img.shields.io/badge/license-AGPL--3.0--only-d3aa46)
![Go](https://img.shields.io/badge/Go-1.23%2B-00add8)

GeDefense Windows ist ein lokales, überprüfbares Windows-Sicherheitszentrum von VisionGaia Technology. Es verbindet Microsoft Defender, Windows Firewall, Attack Surface Reduction, Windows App Control, Systemhärtung, SafetySys Audit, MHX XDR und dateibasierte Integritätsüberwachung in einer nativen Anwendung.

Der Dienst arbeitet ausschließlich über den Loopback-Endpunkt `127.0.0.1:17831`. Die Benutzeroberfläche läuft in einem eigenen WebView2-Fenster ohne CDN, Remote-UI oder Cloud-Control-Plane.

## Funktionen

- Live-Security-Dashboard mit Schutzwert, Schutzdomänen und MHX-Zählern
- Defender-, Firewall-, Secure-Boot-, TPM-, BitLocker-, VBS- und Update-Posture
- MHX-XDR-Realtimeanalyse für PowerShell, Script Hosts und Windows LOLBins
- Base64- und UTF-16LE-Dekodierung von PowerShell EncodedCommand
- Payload-, Signatur-, Parent- und Prozesskettenanalyse
- Guarded-Prozessterminierung nach kontextueller Bewertung
- optionaler Sovereign-Modus mit ausgehendem Default-Deny
- Feodo- und Spamhaus-Threat-Intelligence mit 12-Stunden-Aktualisierung
- atomare Windows-Firewall-Regeln für eingehende und ausgehende IOC-Netze
- SafetySys-Auto-Audit mit 31 Windows-Sicherheitsprüfungen
- zwölf einzeln mess- und ausführbare Windows-Härtungskomponenten
- optionaler SHA-256-Integrity-Scanner im 12- oder 24-Stunden-Zyklus
- HMAC-SHA-256-verkettete lokale Evidenz
- Windows-Dienst, natives Security Center und Systemtray

## Technische Einordnung

MHX enthält keinen eigenen Kernel-Treiber. Die Prozessaufnahme erfolgt über Windows-CIM-Ereignisse. Kernelnahe Durchsetzung wird an die von Microsoft vorgesehenen Schutzschichten delegiert: Defender, ASR, Windows Filtering Platform über Windows Firewall und Windows App Control. Dadurch bleibt die Angriffsfläche kleiner als bei einem nicht erforderlichen eigenen Kernel-Hook.

Threat-Intelligence-IP-Adressen werden auf Netzwerkebene blockiert. Eine Realtime-Korrelation von Remote-IP zu Owning PID mit anschließender Prozessbaum-Terminierung ist noch nicht Bestandteil von Version 2.3.2.

## Repository-Struktur

```text
src/GeDefense/windows/   Go-Dienst, Center, Tray, API, MHX und Integrity
audit/                   SafetySys-Audit
engine/                  Windows-Härtungsprofile und PowerShell-Module
xdr/                     MHX-, Firewall- und XDR-Transaktionen
installer/               Installation, Bootstrap und Deinstallation
build/                   reproduzierbarer Standalone-Build
branding/                VGT-Markenmaterial unter separater Markenrichtlinie
tools/                   erhöhte Integrationsdiagnosen
docs/                    Architektur, Build, Betrieb und Sicherheitsmodell
LICENSES/                AGPL- und Drittanbieterlizenztexte
sbom/                    CycloneDX-Komponentenverzeichnis
```

## Voraussetzungen

- Windows 11 Enterprise, Enterprise LTSC oder IoT Enterprise LTSC x64
- Go 1.23 oder neuer
- Windows PowerShell 5.1
- Microsoft WebView2 Runtime
- GNU `windres.exe`, beispielsweise aus MinGW-w64
- Administratorrechte für Installation und systemweite Schutzrichtlinien

## Entwicklung und Tests

```powershell
Set-Location .\src\GeDefense\windows
gofmt -w .\cmd .\internal
go test -race ./...
go vet ./...
node --check .\internal\server\web\app.js
```

Erhöhte Windows-Integrationstests sind opt-in und verändern keine dauerhaften Schutzrichtlinien:

```powershell
& .\tools\Test-MhxWatcherIntegration.ps1
```

Weitere Details: [Build-Anleitung](docs/BUILDING.md), [Architektur](docs/ARCHITECTURE.md), [Threat Model](docs/THREAT-MODEL.md).

## Standalone-Installer bauen

```powershell
& .\build\Build-GeDefenseStandalone.ps1
```

Der Build erzeugt lokal ein Codesigning-Zertifikat, signiert den Payload und schreibt die Artefakte nach `release\`. Zertifikate, private Schlüssel und Release-Dateien sind durch `.gitignore` vom Repository ausgeschlossen. Community-Builds sind keine offiziellen VGT-Releases.

## Sicherheitsrelevante Voreinstellungen

- Standardmodus: `Guarded`
- Sovereign Default-Deny: ausschließlich nach exakter Operator-Bestätigung
- Integrity-Vollscan: standardmäßig deaktiviert
- USB-Sperre und Controlled Folder Access: nicht ungefragt aktiviert
- API-Bindung: ausschließlich Loopback
- zustandsändernde API-Anfragen: Bearer-Sitzung plus Replay-geschützte Request-ID

## Lizenz

Der Programmcode und die Projekt-Dokumentation stehen unter **GNU Affero General Public License v3.0 only**, SPDX `AGPL-3.0-only`.

VGT-, VisionGaia- und GeDefense-Namen, Logos und Produktaufmachungen sind nicht pauschal unter AGPL lizenziert. Sie unterliegen [TRADEMARKS.md](TRADEMARKS.md). Drittanbieter- und Microsoft-Komponenten werden in [LICENSE-MATRIX.md](LICENSE-MATRIX.md) und [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md) getrennt ausgewiesen.

Copyright © 2026 VisionGaia Technology, Cologne, Germany.

## Sicherheit melden

Bitte keine ausnutzbaren Schwachstellen als öffentliches Issue veröffentlichen. Das koordinierte Verfahren steht in [SECURITY.md](SECURITY.md).

