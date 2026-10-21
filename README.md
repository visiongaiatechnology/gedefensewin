<div align="center">

<img width="256" height="256" alt="GeDefense Windows" src="https://github.com/user-attachments/assets/978d2835-c915-473d-9995-d315efaa869c" />

# VGT GeDefense Windows
### Sovereign Endpoint Security Center & Kinetic Threat Fabric

[![License](https://img.shields.io/badge/License-AGPL--3.0--only-blue?style=for-the-badge)](https://www.gnu.org/licenses/agpl-3.0)
[![Version](https://img.shields.io/badge/Version-4.1.4-orange?style=for-the-badge)](#)
[![Status](https://img.shields.io/badge/Status-Public_Beta-yellow?style=for-the-badge)](#-public-beta-advisory--betriebshinweise)
[![Platform](https://img.shields.io/badge/Platform-Windows_11_x64-lightgrey?style=for-the-badge&logo=windows)](#-systemvoraussetzungen)
[![Control Plane](https://img.shields.io/badge/Control_Plane-Local%2FSovereign-brightgreen?style=for-the-badge)](#-schutzarchitektur--souveränität)
[![Architecture](https://img.shields.io/badge/Architecture-Zero_Go_Dependencies-blue?style=for-the-badge)](#-schutzarchitektur--souveränität)
[![Evidence](https://img.shields.io/badge/Evidence-HMAC--SHA256_Ledger-gold?style=for-the-badge)](#-schutzarchitektur--souveränität)
[![Signing](https://img.shields.io/badge/Signing-Authenticode_Signed-success?style=for-the-badge&logo=windows)](#-authenticode-signatur--vertrauen)
[![VGT](https://img.shields.io/badge/VGT-VisionGaiaTechnology-cyan?style=for-the-badge)](https://visiongaiatechnology.de)

**DEFENDER · WFP FIREWALL · ASR · APP CONTROL · KINETIC DEFENSE · MHX EDR/XDR · NATIVE TRAFFIC · GEOIP/ASN**

<br />

[Installer und Release](https://github.com/visiongaiatechnology/gedefensewin/releases/tag/v4.1.4) · [Changelog](CHANGELOG.md) · [Architektur](ARCHITECTURE.md) · [Verifikationsbericht 4.1.4](docs/VERIFICATION-4.1.4.md) · [Sicherheitsrichtlinie](SECURITY.md)

</div>

---

<img width="2364" height="1240" alt="GeDefense Windows Center Dashboard" src="https://github.com/user-attachments/assets/8bbb85f0-65be-42c9-b9ff-f78b3a401a5e" />

---

## ⚠️ PUBLIC BETA ADVISORY & BETRIEBSHINWEISE

> [!IMPORTANT]
> **Status: Öffentliche Beta-Phase (Public Beta — Version 4.1.4)**
> 
> VGT GeDefense Windows befindet sich in aktiver Weiterentwicklung. Die Kernarchitektur — lokale Sovereign Control Plane, Defender/WFP-Koordination, ASR-Härtung, Windows App Control, HMAC-SHA256-Evidenzlogging, Kinetic-Burst-Erkennung, nativer Traffic-Monitor sowie lokale GeoIP/ASN-Netzwerkverortung — ist vollständig funktional und durch automatisierte Release-Gates (Go Race, Go Vet, Static Security, Authenticode) verifiziert.
>
> **Wichtige Betriebshinweise für Administratoren & Tester:**
> 1. **100 % Lokale Hoheit ohne Cloud-Zwang:** GeDefense kommuniziert standardmäßig ausschließlich über Loopback (`127.0.0.1:17831`). Es existiert keine externe Cloud-Control-Plane und keine stille Telemetrieübertragung an Drittanbieter.
> 2. **Defensiver Standardmodus (`OBSERVE_ONLY`):** Kinetic Defense startet defensiv im reinen Beobachtungsmodus. Die scharfe TI-Korrelation (`ARMED_TI_CORRELATION`) erfordert eine bewusste Bestätigung durch den Administrator im Center.
> 3. **Windows Audit-Richtlinien (Event ID 5157):** Zur Erfassung eingehender WFP-Blockaden muss die Windows-Überwachungsrichtlinie (*Filtering Platform Connection / Packet Drop*) im Betriebssystem aktiv sein.
> 4. **Feedback & Fehlerberichte:** Als Beta-Tester hilfst du uns, die Stabilität auf diversen Windows-11-Hardware- und Treiberkonfigurationen zu perfektionieren. Reiche Beobachtungen, Logs oder Feature-Wünsche über die [GitHub Issues](https://github.com/visiongaiatechnology/gedefensewin/issues) ein.

---

## 🛡️ Überblick & Kernarchitektur

GeDefense Windows ist das souveräne Windows Security Center von **VisionGaia Technology**. Es führt die verteilten Microsoft-Windows-Sicherheitsmechanismen, native Netzwerktelemetrie und Threat Intelligence in einer einheitlichen, hochperformanten Oberfläche zusammen:

| Schutzbereich | Funktion & Wirkungsweise |
|---|---|
| **Microsoft Defender** | Echtzeitschutz, Signaturstatus, Scan-Trigger und koordinierte Steuerung ohne Cloud-Zwang. |
| **Windows Filtering Platform (WFP)** | Native Paketfilterung, Ingress-/Egress-Regelsynchronisation und dynamische Feed-Durchsetzung. |
| **Attack Surface Reduction (ASR)** | 16 native Windows ASR-Regeln zur Eliminierung gängiger Angriffs- und Exploit-Vektoren. |
| **Windows App Control (WDAC)** | Whitelisting und Ausführungsschutz für verifizierte, kryptografisch signierte Anwendungen. |
| **Kinetic Defense** | Echtzeit-Burst-Erkennung bei Port-Scans und Brute-Force-Angriffen aus WFP-Sicherheitsereignissen (Event 5157). |
| **Netzwerk-Traffic** | Echte RX/TX-Durchsatzmessung via native Windows-Interface-Zähler (`GetIfTable2`) ohne TLS-Bruch. |
| **Echtzeit-Threat-Karte & GeoIP** | Lokale, datenschutzkonforme Herkunftszuordnung (ASN, Land, Koordinaten) für beobachtete Vorfälle. |
| **MHX EDR/XDR & Evidence Ledger** | Verifizierte Prozessidentitäten, manipulationssicheres HMAC-SHA-256 Ledger und reversible Systemhärtung. |

---

## 🚀 Highlights & Neuerungen in Version 4.1.4

Version 4.1.4 optimiert die Betriebsstabilität der WFP-Telemetrie und erweitert das Dashboard um eine direkte Verortung des souveränen Host-Systems:

- **WFP-Sensor Auto-Recovery & Watchdog:** Die Windows-Ereignisbrücke startet bei Unterbrechungen automatisch neu. Ein dedizierter Watchdog erkennt hängende API-Abfragen und verhindert Blockaden.
- **Sensor-Health anhand des Empfangszeitpunkts:** Der Start-Healthcheck unterscheidet zuverlässig zwischen einem aktiven Sensor und veralteten historischen Ereignissen.
- **Souveräne Host- und LAN-Erkennung:**
  - **RFC 1918 Klassifizierung:** Lokale IPs (z. B. `192.168.x.x`, `10.x.x.x`) werden als *Lokales Heim-/Unternehmensnetz (LAN)* deklariert und verbleiben strukturiert in der Detailtabelle.
  - **Dual Host Hub:** GeDefense erkennt sowohl die interne Netzwerk-IP als auch die externe WAN-IP des Hosts und platziert den sovereignen Host-Marker präzise auf der Weltkarte.
- **Optimierte Benutzeroberfläche:** Die *Echtzeit Threat-Karte & Globale Angriffsvektoren* ist direkt über dem Traffic-Dashboard positioniert, um Angriffsvektoren im Kontext des Bandbreitenverlaufs sichtbar zu machen.
- **Zero-Dependency Release Gate:** Alle 92 Lint-Prüfungen bestehen mit 0 Meldungen; Go Race Detector und Go Vet passieren ohne Beanstandung.

---

<img width="2281" height="1240" alt="GeDefense Detailansicht & Kinetic Threat Map" src="https://github.com/user-attachments/assets/52f1fffe-4dba-4025-8712-7b470f6728b2" />

---

## 📦 Installation und Schnelleinstieg

### Systemvoraussetzungen

- **Betriebssystem:** Windows 11 x64 (Build 22621 oder neuer empfohlen).
- **Berechtigungen:** Lokale Administratorrechte für Installation und Richtlinienkonfiguration (Center und Tray laufen im unprivilegierten Benutzerkontext).
- **Plattform:** Windows PowerShell 5.1 x64.
- **Laufzeitumgebung:** Ein lokaler Chromium-Browser (Edge, Chrome oder Brave) zur Ausführung der Benutzeroberfläche im nativen Win32-Fensterhost.

### Installationsschritte

1. **Release herunterladen:** Lade `GeDefense-Setup-x64-v4.1.4.exe` aus dem [offiziellen Release](https://github.com/visiongaiatechnology/gedefensewin/releases/tag/v4.1.4) herunter.
2. **Integrität prüfen:**
   ```powershell
   Get-FileHash -Algorithm SHA256 .\GeDefense-Setup-x64-v4.1.4.exe
   Get-AuthenticodeSignature .\GeDefense-Setup-x64-v4.1.4.exe
   ```
3. **Setup ausführen:** Starte den Installer mit Administratorrechten. Er installiert den Hintergrunddienst (`GeDefenseService`), das Tray-Modul und das GeDefense Center.
4. **Erster Start & Healthcheck:** Öffne das GeDefense Center. Der integrierte Startcheck prüft automatisch:
   - Policy-Integrität und Ledger-Verkettung
   - Microsoft Defender Echtzeitschutz
   - Windows Firewall & WFP-Filterregeln
   - Prozess- und Netzwerktelemetrie
   - Threat Intelligence Feed-Generationen
   - Sensor-Status der WFP-Ereignisbrücke

---

## ⚡ Kinetic Defense, Traffic & GeoIP

### Kinetic Defense (WFP-Burst-Erkennung)
Kinetic analysiert reale eingehende **Windows Security Events 5157** (blockierte Verbindungen).
- **Erkennungslogik:** Ein Burst-Kandidat benötigt mindestens 12 Block-Ereignisse innerhalb eines 10-Sekunden-Fensters an mindestens 3 unterschiedlichen lokalen Zielports.
- **Ressourcenschutz:** Der lokale Speicherring ist fest limitiert auf 2.048 Quellen und maximal 32 Samples pro Quelle.
- **Betriebsmodi:** Standard ist `OBSERVE_ONLY`. Die Aktivierung von `ARMED_TI_CORRELATION` erfordert eine verifizierte Threat-IP-Generation und muss nach jedem Dienstneustart explizit autorisiert werden.

### Netzwerk-Traffic-Monitoring
Die RX/TX-Messwerte werden ohne Paketinspektion direkt über native Windows-Netzwerkschnittstellen abgefragt (`GetIfTable2` mit `GetIfTable`-Fallback).
- Abtastintervall: Alle 2 Sekunden.
- Bis zu 60 Datenpunkte bilden den Live-Verlauf.
- Zählerüberläufe und Schnittstellenwechsel werden visuell transparent behandelt.

### Lokale GeoIP- und ASN-Verortung
Die Zuordnung von IP-Adressen zu Autonomen Systemen (ASN) und geografischen Koordinaten erfolgt **vollständig lokal** über eine optionale CSV-Datenbank mit kryptografisch geprüftem SHA-256-Sidecar:
- **Keine Cloud-Abfragen:** Keine DNS- oder HTTP-Lecks für beobachtete Angreifer-IPs.
- **Lokale Netzwerke:** RFC 1918 Adressen (LAN) werden nicht fälschlich im Ozean oder im Ausland platziert, sondern bleiben übersichtlich in der Netzwerktabelle.
- Details siehe [GeoIP-Betrieb und Herkunft](GEOIP_LICENSE_AND_DEPLOYMENT.md).

---

## 🔒 Schutzarchitektur & Souveränität

```
┌────────────────────────────────────────────────────────────────────────┐
│                   VGT GeDefense Win32 Center Host                      │
│        (Isolierter Renderer · Lokale Assets · Strikte CSP)             │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Authentifizierte Loopback-API
                                    │ (127.0.0.1:17831 · Bootstrap Token)
┌───────────────────────────────────▼────────────────────────────────────┐
│                    GeDefense Windows Service                           │
│                     (LocalSystem Berechtigung)                         │
├───────────────────────────────────┬────────────────────────────────────┤
│  • WFP-Eventlog-Brücke (5157)     │  • Zero External Go Dependencies   │
│  • MHX EDR/XDR Engine             │  • HMAC-SHA256 Evidence Ledger     │
│  • Feed-Pipeline (LKG Gates)      │  • GetIfTable2 Traffic-Monitor     │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Signierte PowerShell-Transaktionen
                                    │ (ExecutionPolicy: AllSigned)
┌───────────────────────────────────▼────────────────────────────────────┐
│                  Windows 11 Sicherheitsarchitektur                     │
│    [Microsoft Defender]   [WFP / Firewall]   [ASR]   [App Control]     │
└────────────────────────────────────────────────────────────────────────┘
```

- **Zero External Go Dependencies:** Ausschließlich Go-Standardbibliothek und interne Win32-API-Wrapper. Keine externen Pakete im Modulbaum (`go list -m all` = 1).
- **Lokale Control Plane:** `127.0.0.1:17831` mit strikter Host-, Origin- und Session-Token-Prüfung.
- **Embedded Web Assets:** Sämtliche HTML-, CSS- und JS-Ressourcen sind fest in das Binary eingebunden; kein Laden externer Schriftarten oder CDNs.
- **Delegierte Durchsetzung:** Kein unsicherer Third-Party Kernel-Treiber. Alle Blockaden und Isolationen erfolgen über die bewährten Kernel-Komponenten von Microsoft Windows.
- **HMAC-SHA256 Evidenzkette:** Sicherheitsentscheidungen und Audit-Logs werden fortlaufend kryptografisch verkettet.
- **Privilegientrennung:** Der Dienst läuft unter `LocalSystem`; Center und Tray laufen strikt im unprivilegierten Benutzerkontext.

---

## 🌐 Threat Intelligence & Feed-Architektur

GeDefense verarbeitet globale Bedrohungsdaten in drei klar definierten Aktionsklassen:

| Aktionsklasse | Feed-Quellen | Durchsetzung |
|---|---|---|
| `BLOCK` | Feodo Tracker, Spamhaus DROP IPv4/IPv6, **FireHOL Level 1** | Aktive WFP-Firewallsperrung (Inbound & Outbound) |
| `CORRELATE_ONLY` | CINS Army, blocklist.de, Emerging Threats, IPsum | Vorfallskorrelation in Kinetic Defense |
| `ANNOTATE_ONLY` | Tor Exit Nodes | Kontext- und Attributionsanzeige |

- **Last-Known-Good (LKG) Sicherheit:** Schlägt ein Feed-Download oder die Validierung fehl, bleibt die bisherige verifizierte Regelsammlung aktiv.
- **Shrink- & Input-Gates:** Drastische Listenverkleinerungen oder fehlerhafte Zeilenformate werden automatisch verworfen.
- **Protected Networks:** Lokale und unternehmenseigene IP-Bereiche werden deterministisch aus Blocklisten ausgeklammert, um versehentliche Sperrungen zu verhindern.
- Details siehe [Threat Intelligence Spezifikation](docs/THREAT-INTELLIGENCE.md).

---

## 🛠️ Quellcode und Build-Verifikation

### Projektstruktur

| Verzeichnis | Modul & Verantwortung |
|---|---|
| `src/GeDefense/windows/cmd/` | Dienst (`gedefense-windows`), Center, Tray und Standalone-Installer |
| `internal/kinetic` | WFP-Burst-Beobachtung und Vorfallserkennung |
| `internal/traffic` | Native RX/TX-Netzwerkdurchsatzmessung |
| `internal/geoip` | Lokale Offline-Zuordnung für ASN und Koordinaten |
| `internal/mhx` | EDR/XDR Engine, WFP-Recovery und Watchdog |
| `internal/threatintel` | Threat Feed Lifecycle und Firewall-Regelgeneration |
| `internal/server` | Authentifizierte Loopback-API, UI-Routen und Startcheck |
| `internal/winframe`, `internal/wintray` | Nativer Win32-Fensterhost und System-Tray-Integration |
| `internal/integrity`, `internal/evidence` | Dateiintegritätsprüfung und HMAC-SHA256 Ledger |
| `engine/`, `audit/`, `installer/` | Signierte Windows-Systemtransaktionen |
| `build/`, `docs/`, `sbom/` | Automatisierte Release-Gates, Spezifikationen und SBOM |

### Reproduzierbarer Build

Offizielle Toolchain: **Go 1.26.9**, Windows PowerShell 5.1 x64 und Windows SDK.

```powershell
# 1. Release-Gates & Tests ausführen (Go Race, Vet, Static Security)
$env:GOTOOLCHAIN = 'go1.26.9'
& .\build\Test-GeDefenseRelease.ps1

# 2. Standalone-Installer kompilieren und signieren
& .\build\Build-GeDefenseStandalone.ps1
```

Der vollständige Buildprozess erfordert ein gültiges Code-Signing-Zertifikat. Siehe [Build-Anleitung](docs/BUILDING.md).

---

## 📜 Lizenz und Trademarks

- **Quellcode und Dokumentation:** Lizenziert unter der [GNU Affero General Public License v3.0 (AGPL-3.0-only)](LICENSE).
- **Marken & Branding:** Name, Logo und visuelle Kennzeichen unterliegen der [Markenrichtlinie](TRADEMARKS.md).
- **Drittanbieter-Komponenten:** jsVectorMap (MIT). Siehe [Third-Party Notices](THIRD-PARTY-NOTICES.md) und [Lizenzmatrix](LICENSE-MATRIX.md).
- **Sicherheitsmeldungen:** Verantwortungsbewusste Offenlegung von Sicherheitslücken via [SECURITY.md](SECURITY.md).

<div align="center">
  <sub>Copyright © 2026 VisionGaia Technology. Alle Rechte vorbehalten.</sub>
</div>
