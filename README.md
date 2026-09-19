# VGT GeDefense Windows 4

[![Status](https://img.shields.io/badge/status-v4.1.0--beta.1-4cc9ff?style=for-the-badge)](https://github.com/visiongaiatechnology/gedefensewin/releases)
[![Platform](https://img.shields.io/badge/platform-Windows%2011%20x64-168bff?style=for-the-badge)](https://github.com/visiongaiatechnology/gedefensewin)
[![License](https://img.shields.io/badge/license-AGPL--3.0--only-31d0aa?style=for-the-badge)](LICENSE)
[![Security Standard](https://img.shields.io/badge/security-VGT-blueviolet?style=for-the-badge)](ARCHITECTURE.md)
[![Dependencies](https://img.shields.io/badge/dependencies-0%20Go%20Modules%20%7C%200%20CDNs-success?style=for-the-badge)](DEPENDENCIES.md)

GeDefense Windows 4 ist die souveräne, lokal überprüfbare Endpoint-Defense- und Orchestrierungsplattform von VisionGaia Technology. Sie vereint Microsoft Defender Antivirus, Windows Filtering Platform (WFP), Attack Surface Reduction (ASR), Windows App Control (WDAC), Baseline-Systemhärtung, SafetySys Compliance Audit, MHX EDR/XDR, native TCP-zu-Prozess-Korrelation und dateibasierte Integritätsüberwachung in einer gemeinsamen, vollständig entkoppelten lokalen Control Plane.

---

## 🛡️ Für Security Researcher & System Architects

> **Vollständige technische Systemspezifikation:**  
> Die gesamte Architektur, alle Bedrohungsmodelle, Trust Boundaries, Win32-Syscalls, IPC-Verträge und State-Machines sind detailliert und erschöpfend in der [**ARCHITECTURE.md**](ARCHITECTURE.md) dokumentiert.

### Kern-Architektur-Prinzipien & Invarianten

1. **Zero External Go Dependencies (Zero-Supply-Chain-Risk)**:  
   Das Backend verzichtet vollständig auf externe Go-Module (`go.sum` hat exakt 0 Bytes, kein `require`-Block in `go.mod`). Sämtliche Interaktionen mit dem Betriebssystem erfolgen direkt über die Go-Standardbibliothek und native Windows-APIs (`kernel32.dll`, `advapi32.dll`, `user32.dll`, `shell32.dll`, `iphlpapi.dll`).
2. **Zero External Frontend Dependencies (No Remote Ingestion)**:  
   Die Benutzeroberfläche bindet keinerlei Remote-CDNs, externe Web-Fonts oder Drittanbieter-JavaScript-Bibliotheken ein. Sämtliche Assets sind nativ per `embed.FS` in die Binärdatei einkompiliert. Web Storage (`localStorage`, `sessionStorage`) sowie `eval()` sind strikt untersagt.
3. **Loopback-Only Control Plane (`127.0.0.1:17831`)**:  
   Der Dienst lauscht ausschließlich auf dem lokalen Loopback-Interface. Anfragen werden serverseitig über Client-Token-Authentifizierung (`dashboard.token`), Host-Header-, Origin- und RemoteAddr-Validierung sowie zeitbegrenzte, kryptografisch zufällige HttpOnly-/SameSite-Cookies verifiziert.
4. **Kein proprietärer Kernel-Treiber (Delegierte Durchsetzung)**:  
   Zur Vermeidung von Instabilitäten und Privilege-Escalation-Gefahren nutzt GeDefense keinen eigenen Third-Party-Kernel-Treiber. Tiefgreifende Durchsetzung (Process Block, Network Deny, Code Integrity) wird transaktional an die verifizierten Kernel-Subsysteme von Windows delegiert: Defender Antivirus, ASR, Windows Filtering Platform / Firewall und Windows App Control (WDAC).
5. **Anti-PID-Reuse Host-Response-Autorität**:  
   Reine Netzwerk-IOC-Matches besitzen niemals autonome Host-Kill-Rechte. Eine Prozessterminierung erfordert zwingend ein eigenständiges MHX-Verdikt sowie eine atomare Revalidierung des Prozess-Tripels `(PID, CreationTime, BinaryPath)`.
6. **Kryptografisch verkettetes Evidence-Ledger (HMAC-SHA-256)**:  
   Jede Konfigurationsänderung, jeder Audit-Befund, jede EDR-Blockade und jede Regelsynchronisation wird in einem manipulationssicheren, sequenziell verketteten JSONL-Ledger (`evidence.jsonl`) mit lokalem Authentifizierungsschlüssel verankert.
7. **Privilegientrennung (Least Privilege)**:  
   - Core Security Service (`gedefense-windows.exe`): Läuft als `LocalSystem` im Windows Service Control Manager (SCM).
   - Operator UI Launcher (`GeDefenseCenter.exe`) & Tray (`GeDefenseTray.exe`): Laufen mit den Standardrechten des angemeldeten Benutzers.
   - Wartungs- und Installationsskripte: Laufen strikt unter PowerShell mit `ExecutionPolicy AllSigned`.

---

## 🚀 Was hat sich in GeDefense Windows 4 geändert? (Delta zu V2 / V3)

GeDefense Windows 4 ist eine vollständige Neugestaltung des Windows-Sicherheitsagenten auf der V4-Architekturphilosophie:

| Bereich | Legacy (GeDefense Windows 2.3.2) | GeDefense Windows 4.1.0-beta.1 |
| :--- | :--- | :--- |
| **Go-Abhängigkeiten** | Externe Go-Module für Tray, Webview und Syscalls | **Zero Go Modules**. Reine Standardbibliothek + native WinAPI-Syscalls |
| **Frontend Runtime** | Eingebettete Webview-Komponenten mit externen Bindings | **Native Browser-Orchestrierung** via Loopback-Server (`127.0.0.1:17831`) mit Strict CSP Nonce |
| **Prozessreaktion** | Einfache PID-basierte Terminierung | **Anti-PID-Reuse-Engine**: Validierung von `PID`, `CreationTime` und `ExecutablePath` vor Terminierung |
| **Netzwerk-Telemetrie** | Zeitverzögerte Netstat-Abfragen | **Native TCP Extended Table** (`iphlpapi.dll`) mit atomarer Owning-PID-Zuordnung in Echtzeit |
| **XDR / Threat Intel** | Rohe Speicherung von Command-Lines | **Datensparsame Attack Stories**: Hash-basierte Evidenz, Base64/UTF-16LE EncodedCommand-Dekodierung |
| **Threat-Intel-Feeds** | Einfache IP-Listen | **Präfix-Indexierte CIDR-Radix-Bäume**, harte Feed-Grenzen, Filterung privater/reservierter IP-Bereiche |
| **Schutzstufen** | Statische Modi | **Guided Protection Lifecycle**: `Monitor` ➔ `Guarded` ➔ `Sovereign` mit serverseitiger Readiness-Gate |
| **App Control** | Basale Software-Einschränkungen | **Windows App Control (WDAC / CiTool)** mit Kernel-Validierung und transaktionalen Audit-/Enforce-Regeln |
| **Firewall-Kopplung** | Unabhängige Firewall-Skripte | **Atomare Synchronisation**; fehlgeschlagene Firewall-Verifikation versetzt den Feed-Status in `STALE` |
| **Integritätsüberwachung** | Klassischer periodischer SHA-256-Scan | **Resilienter Fabric-Scanner**: Bounded Queue, Reparse-Point-Schutz, Mutation-during-hash-Erkennung |
| **Installer & Trust** | Extern generierte Setup-Pakete | **Autarker Standalone-Installer** mit signiertem embedded Payload-Zip, Catalog-Prüfung (`vgt-payload.cat`) und `AllSigned`-Policy |
| **UI-Design** | Früheres Dashboard | **Modernes VGT Ice-Blue Glassmorphism UI**, zustandsgetriebene Komponenten, Micro-Interactions |

---

## 🌐 Sovereign Threat Intelligence 4.1

GeDefense Windows 4.1 trennt Feed-Vertrauen strikt von Enforcement-Autorität. Feodo Tracker und Spamhaus DROP IPv4/IPv6 dürfen Windows Firewall/WFP-Blockregeln erzeugen; CINS Army, blocklist.de, Emerging Threats, IPsum und FireHOL werden ausschließlich für Korrelation verwendet; Tor Exit Nodes bleiben strikt `ANNOTATE_ONLY`. Ein Treffer aus Netzwerk-Telemetrie allein erzeugt weiterhin keine Prozess-Termination-Autorität.

Jeder Feed besitzt eine unabhängige Last-Known-Good-Generation. Erst nach Input-Härtung, Größen-/Shrink-Gates, Canonicalisierung und SHA-256-Fingerprinting wird ein neuer immutable Gesamtindex veröffentlicht. Das BLOCK-Projektionsset erhält eine separate Enforcement-Generation, die gegen die tatsächlich installierte Windows-Firewall-Generation verifiziert wird. Auf unterstützten Windows-11-Systemen werden Dynamic Keyword Addresses genutzt; andernfalls greift ein bounded Static-Rule-Fallback. WFP Event 5157 liefert anschließend blockierte Verbindungsevidenz inklusive PID zurück in MHX/XDR.

Für Management-Strecken existiert zusätzlich eine **Protected-Network Safety Plane**. Explizit freigegebene öffentliche IP/CIDR werden durch einen CIDR-Subtraction-Compiler aus dem WFP-BLOCK-Set entfernt, statt ein überlappendes Threat-Subnetz komplett freizuschalten. Die Threat-Attribution bleibt im XDR sichtbar; ein Protected-Network-Treffer kann jedoch keine Threat-Intel-abgeleitete Host-Response-Eskalation auslösen. Die Policy ist HMAC-authentifiziert, generationiert und über das lokale Dashboard verwaltbar.

Die vollständigen Invarianten und Datenpfade stehen in [docs/THREAT-INTELLIGENCE.md](docs/THREAT-INTELLIGENCE.md).

---

## 🏗️ Systemkomponenten & Repository-Struktur

```text
GeDefense-Windows-4/
├── ARCHITECTURE.md          # Umfassende technische System- & Architekturspezifikation
├── README.md                # Projektübersicht & Schnellstart
├── VERSION                  # Offizielle Release-Version (4.1.0-beta.1)
├── TOOLCHAINS.lock          # Exakt gepinnte Toolchains (Go 1.26.4 / Go 1.27.1, PowerShell 5.1)
├── src/GeDefense/windows/   # Go-Quellcode (Zero External Dependencies)
│   ├── cmd/
│   │   ├── gedefense-windows/   # Windows Service Daemon (LocalSystem Background Host)
│   │   ├── gedefense-center/    # Desktop-Launcher & Mutex-Client
│   │   ├── gedefense-tray/      # Windows System-Tray-Daemon
│   │   └── gedefense-installer/ # Autarker Standalone-Installer
│   └── internal/
│       ├── mhx/                 # EDR-Realtime-Heuristik, WFP-Korrelation & EncodedCommand Unpacker
│       ├── threatintel/         # 9-Feed TI Core, LKG-Generationen & immutable Prefix-Index
│       ├── server/              # Lokale HTTP Control Plane & Session-Exchange
│       ├── hardening/           # Schnittstelle zur Windows-Sicherheitsbaseline
│       ├── integrity/           # Dateisystem-Integrität & Reparse-Detektion
│       ├── evidence/            # HMAC-SHA-256 verkettetes Audit-Ledger
│       ├── winapi/              # Direkte Win32 DLL-Syscall-Bindungen
│       ├── monitor/             # Telemetrie- und Heartbeat-Aggregator
│       └── winexec/             # Gehärteter Executor für signierte PowerShell-Transaktionen
├── engine/                  # PowerShell-Härtungs-Engine & Sicherheits-Module
│   ├── Invoke-VgtHardening.ps1
│   └── Modules/                 # Vgt.Common, Vgt.Defender, Vgt.Identity, Vgt.Network, Vgt.System
├── xdr/                     # EDR/XDR-Transaktionen & Firewall-Synchronisation
│   ├── Invoke-VgtXdrScan.ps1
│   ├── Set-VgtMhxProtection.ps1
│   ├── Set-VgtMhxAppControl.ps1
│   └── Sync-VgtMhxFirewall.ps1
├── audit/                   # SafetySys Compliance-Audit Engine
├── installer/               # Bootstrap-, Installations- und Bereinigungsskripte
├── build/                   # Release-Gates, Build-Skripte & Standalone-Packager
├── branding/                # Offizielle VGT-Design-Assets (Icons, Logos, Lockscreen)
├── sbom/                    # CycloneDX SBOM (Nachweis: 0 Third-Party-Komponenten)
└── tools/                   # Erweiterte Diagnose- & Tracing-Werkzeuge
```

---

## ⚙️ Voraussetzungen

### Zielsystem (Laufzeit)
- **Betriebssystem**: Windows 11 x64 (22H2 / 23H2 / 24H2 / LTSC)
- **PowerShell**: Windows PowerShell 5.1 (integriert in Windows)
- **Antivirus**: Microsoft Defender Antivirus (aktiviert)
- **Rechte**: Administratorrechte für Erstinstallation und Aktivierung der Systemhärtung

### Build-Umgebung
- **Go-Compiler**: Go 1.26.4 oder Go 1.27.1 (64-Bit)
- **PowerShell**: Windows PowerShell 5.1 (x64)
- **Code-Signing**: Lokales oder Unternehmens-Code-Signing-Zertifikat mit Enhanced Key Usage (EKU) `1.3.6.1.5.5.7.3.3` (Code Signing)

---

## 🔨 Build & Verifikation

Das gesamte Release wird über automatisierte PowerShell-Gates validiert und gebaut.

### 1. Release-Verifikation ausführen (Gate-Prüfung)
```powershell
& .\build\Test-GeDefenseRelease.ps1
```
Dieser Gate verifiziert:
- Go Code Formatting (`gofmt -l`)
- Vollständige Race-Condition-Tests (`go test -race ./...`)
- Statische Go-Code-Analyse (`go vet ./...`)
- Zero-Go-Dependency-Garantie (`go list -m all` enthält ausschließlich GeDefense)
- Frontend-Sicherheitsinvarianten (keine externen URLs, kein eval, kein Web Storage)
- PowerShell AST-Parsing aller Skripte
- Test-Kompilierung aller vier Windows-Binaries

### 2. Standalone-Installer kompilieren & signieren
```powershell
& .\build\Build-GeDefenseStandalone.ps1
```
Dieser Befehl:
1. Durchläuft alle Release-Gates.
2. Kompiliert Service, Center und Tray in das Payload-Verzeichnis.
3. Signiert alle Binärdateien und PowerShell-Module digital mit Authenticode (SHA-256).
4. Erzeugt den signierten Windows-Katalog `vgt-payload.cat`.
5. Bettet den Payload komprimiert in `cmd/gedefense-installer` ein.
6. Kompiliert die autarke Setup-Datei `release\GeDefense-Setup-x64-v4.1.0-beta.1.exe` und signiert diese.

---

## 📦 Installation & Inbetriebnahme

### Neuinstallation oder Upgrade von V2.x
1. Starte die erstellte Datei als Administrator:
   ```powershell
   Start-Process .\release\GeDefense-Setup-x64-v4.1.0-beta.1.exe -Verb RunAs
   ```
2. Der Installer führt vollautomatisch folgende Schritte durch:
   - Sauberes Beenden und Entfernen früherer GeDefense-Versionen (Dienst `VGTGeDefense` und Tray `GeDefenseTray`).
   - Installation der V4-Binärdateien nach `C:\Program Files\VGT\GeDefense`.
   - Konfiguration der Benutzergruppe `VGT GeDefense Operators` und Absicherung der Dateisystem-ACLs (`icacls`).
   - Registrierung des Windows-Systemdienstes `VGTGeDefense` mit Starttyp `Automatic` (**startet direkt bei jedem Windows-Boot**).
   - Eintrag in `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` zur automatischen Initialisierung des Tray-Icons beim Benutzer-Login.
   - Starten des V4-Dienstes und Aktivierung der `Guarded`-Schutzrichtlinie.

---

## 🔒 Sicherheitsrichtlinien & Verantwortungsbewusste Offenlegung

Sicherheitsrelevante Schwachstellen, Design-Bugs oder kryptografische Feststellungen können gemäß unserer [SECURITY.md](SECURITY.md) direkt an das Security-Team von VisionGaia Technology gemeldet werden.

---

## 📄 Lizenz & Markenschutz

- **Quellcode & Dokumentation**: Lizenziert unter der **GNU Affero General Public License v3.0 only** (SPDX: `AGPL-3.0-only`). Siehe [LICENSE](LICENSE).
- **Marken & Produktaufmachung**: Die Bezeichnungen „VGT“, „VisionGaia Technology“, „GeDefense“ sowie alle zugehörigen Logos unterliegen der gesonderten [TRADEMARKS.md](TRADEMARKS.md).

Copyright © 2026 VisionGaia Technology. Alle Rechte vorbehalten.
