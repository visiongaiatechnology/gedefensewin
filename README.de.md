<div align="center">

<img width="256" height="256" alt="GeDefense Windows" src="https://github.com/user-attachments/assets/978d2835-c915-473d-9995-d315efaa869c" />

# VGT GeDefense Titan

### Souveränes Endpoint-Sicherheitscenter &amp; Kinetic Threat Fabric

[English](README.md) · **Deutsch** · [Русский](README.ru.md) · [中文](README.zh.md)

[![License](https://img.shields.io/badge/License-AGPL--3.0--only-blue?style=for-the-badge)](LICENSE)
[![Version](https://img.shields.io/badge/Version-5.3.0-orange?style=for-the-badge)](https://github.com/visiongaiatechnology/gedefensewin/releases)
[![Status](https://img.shields.io/badge/Status-Public_Beta-yellow?style=for-the-badge)](#public-beta-advisory)
[![Platform](https://img.shields.io/badge/Platform-Windows_11_x64-lightgrey?style=for-the-badge&logo=windows)](#system-requirements)
[![Control Plane](https://img.shields.io/badge/Control_Plane-Local%2FSovereign-brightgreen?style=for-the-badge)](#local-sovereignty-and-privacy)
[![Architecture](https://img.shields.io/badge/Architecture-Zero_Go_Dependencies-blue?style=for-the-badge)](#architecture)
[![Evidence](https://img.shields.io/badge/Evidence-HMAC--SHA256_Ledger-gold?style=for-the-badge)](#what-is-geodefense-titan)
[![Signing](https://img.shields.io/badge/Signing-Self--Signed_Beta_Only-lightgrey?style=for-the-badge)](#verification-and-trust)
[![VGT](https://img.shields.io/badge/VGT-VisionGaiaTechnology-cyan?style=for-the-badge)](https://visiongaiatechnology.de)

**DEFENDER · WFP FIREWALL · ASR · APP CONTROL · KINETIC DEFENSE · MHX EDR/XDR · TITAN INTEGRITY · NATIVE TRAFFIC · GEOIP/ASN**

<br />

[Installation und Releases](https://github.com/visiongaiatechnology/gedefensewin/releases) · [Architektur](ARCHITECTURE.md) · [Titan-Konzept](docs/TITAN.md) · [Build-Anleitung](docs/BUILDING.md) · [Betrieb](docs/OPERATIONS.md) · [Sicherheitsrichtlinie](SECURITY.md)

</div>

---

<img width="1536" height="1024" alt="GeDefense_ Real Security, Many Feathers" src="https://github.com/user-attachments/assets/68406427-a185-4fa5-b06a-af874a747dcb" />

> [!IMPORTANT]
> **Installer-Update (5.3.0):** Der bisherige selbstsignierte PowerShell-Bootstrap konnte auf frischen Windows-Installationen fehlschlagen, weil das VGT-Zertifikat nicht vertraut war. Das Release verwendet jetzt einen gebrandeten **Inno-Setup-Installer**, der das Beta-Zertifikat nach Annahme der Lizenz automatisch importiert — manuelle Zertifikatsschritte sind nicht mehr nötig.
>
> **[GeDefense Windows 5.3.0 Installer herunterladen](https://github.com/visiongaiatechnology/gedefensewin/releases/download/v5.3.0/GeDefense-Setup-x64-v5.3.0.exe)**

## 🌐 Das GeDefense-Universum

GeDefense ist eine lokal-first Security-Fabric – für Linux, Windows, Android und WordPress. Alle Schwesterprojekte teilen dieselbe Philosophie: lokale Kontrolle, ehrliche Sichtbarkeit, keine stille Telemetrie.

| Projekt | Schwerpunkt |
| --- | --- |
| [![Android TV](https://img.shields.io/badge/Android_TV-3DDC84?style=flat-square&logo=android&logoColor=0B1220)](https://github.com/visiongaiatechnology/gedefense_androidtv) **GeDefense TV** | Sicherheitskonsole für Android TV / Google TV: Loopback-VPN, Traffic-Map, XDR-Light und reversibles Kinetic-Lite-Containment. |
| [![Linux](https://img.shields.io/badge/Linux-D4AF37?style=flat-square&logo=linux&logoColor=0B1220)](https://github.com/visiongaiatechnology/gedefense) **GeDefense Linux** | Kernel-nahe Netzwerkverteidigung: eBPF/XDP-Durchsetzung, L7-WAF, Host-XDR mit signierter Evidenz und reversible Härtung (Rust/Go, vollständig lokal). |
| [![Windows](https://img.shields.io/badge/Windows-8B5CF6?style=flat-square&logo=windows&logoColor=ffffff)](https://github.com/visiongaiatechnology/gedefensewin) **GeDefense Windows** *(dieses Repository)* | Lokale, souveräne Windows-11-Sicherheitskonsole: Defender/ASR/WFP/App Control, Härtung, MHX EDR/XDR, lokale Threat Intelligence und HMAC-verkettete Evidenz. |
| [![Android](https://img.shields.io/badge/Android-22D3EE?style=flat-square&logo=android&logoColor=0B1220)](https://github.com/visiongaiatechnology/gedefenseandroid) **GeDefense Android** | Native Android-Sicherheitsplattform: lokale VPN-Durchsetzung, Endpoint-Telemetrie, XDR/EDR-Korrelation, Threat Intelligence, App-Risikoanalyse und verschlüsselte Evidenz. |
| [![WordPress](https://img.shields.io/badge/WordPress-1F8FFF?style=flat-square&logo=wordpress&logoColor=ffffff)](https://github.com/visiongaiatechnology/gedefensewp) **GeDefense WordPress** | AGPL-3.0-Open-Core-Suite für WordPress: ZEUS-WAF, AEGIS-Deep-Packet-Inspection, TRINITY-XDR, ThroneGuard-Lockdown und HADES-Admin-Cloaking. |


<a id="public-beta-advisory"></a>

## ⚠️ Hinweis zur öffentlichen Beta

> [!IMPORTANT]
> **Status: Öffentliche Beta — GeDefense Windows 5.3.0.**
>
> GeDefense Titan befindet sich in aktiver Entwicklung. **Diese Beta kann Fehler enthalten — auch Sicherheitsdefekte.** Wir arbeiten kontinuierlich an Härtung, Tests und Korrekturen und freuen uns über jeden reproduzierbaren Bericht.
>
> - Bitte setzen Sie die Beta zunächst auf Testsystemen ein, halten Sie Backups bereit und verlassen Sie sich nicht darauf als einzige Sicherheitskontrolle einer Produktivumgebung.
> - Melden Sie Fehler, Sicherheitsprobleme und Funktionswünsche über [GitHub Issues](https://github.com/visiongaiatechnology/gedefensewin/issues) oder verantwortungsvoll über [SECURITY.md](SECURITY.md).
> - Dieses Release ist **selbstsigniert** und genießt **kein Vertrauen öffentlicher CAs**; es gibt noch keinen RFC-3161-Zeitstempel, keinen CRL/OCSP-Widerrufspfad und keinen extern verankerten Anti-Rollback-Kanal. Aus diesen Gründen ist 5.3.0 **kein öffentlich vertrauenswürdiges Release**. Siehe [Verifikation und Vertrauen](#verification-and-trust).
> - Die Kernarchitektur wird durch automatisierte Release-Gates verifiziert (Go Race, Go Vet, govulncheck, SBOM, Provenienz, Installer- und Publish-Gates). Live-Installation und Änderungen an Sicherheitsrichtlinien gehören weiterhin auf eine isolierte Test-VM.

---

<a id="what-is-geodefense-titan"></a>

## Was ist GeDefense Titan?

GeDefense Titan ist eine lokale, souveräne Sicherheitskonsole für Windows 11. Sie vereint die Sicherheitsschichten von Windows in einer einzigen Bedieneroberfläche und ergänzt eine eigene Autorisierungs-, Nachweis- und Integritätsschicht:

- **Windows-Kontrollgefüge:** Defender, ASR, Windows-Firewall/WFP, App Control, Überwachungsrichtlinie, SMB-/RDP-/LSA-/UAC-Einstellungen und Härtungskomponenten werden gemessen, mit einer Baseline verglichen und können idempotent mit Nachweis angewendet werden.
- **MHX EDR/XDR:** native Prozess-, Defender- und Netzwerkkorrelation, Prozessabstammung, Ermittlung der besitzenden PID, Erkennung kodierter Befehle und abgesicherte Reaktionsaktionen.
- **Threat Intelligence:** kuratierte Feeds, validierte Autorität pro Feed, WFP-Block-Generierung und strenge Lebenszyklusgrenzen.
- **Kinetic Defense:** Burst-Korrelation für echte eingehende WFP-Block-Ereignisse (standardmäßig OBSERVE_ONLY; ARMED erfordert eine ausdrückliche Bestätigung durch den Bediener und verifizierte aktive Telemetrie).
- **Native Netzwerktelemetrie und lokale GeoIP/ASN-Karte:** RX/TX-Schnittstellenzähler und lokale, CSV-basierte Länder-/ASN-Zuordnung für tatsächlich beobachtete Quellen — keine externe IP-Abfrage, keine erfundenen Hostpositionen.
- **Titan:** die weiter unten beschriebene Integritäts-, Autorisierungs- und Nachweisschicht.
- **Ausschließlich lokale Kontrollebene:** Der Dienst lauscht auf Loopback (`127.0.0.1:17831`). Es gibt keine Cloud-Kontrollebene und keine stille Telemetrie an Dritte.

### Titan — Souveräne Endpoint-Integrität

Titan beantwortet eine Frage, die klassische Antivirenwerkzeuge oft verwischen: *Wurde diese Änderung vom Eigentümer autorisiert?* Jede Änderung wird als `AUTHORIZED`, `TOLERATED`, `UNEXPECTED` oder `COMPROMISED` klassifiziert — auf Grundlage der gespeicherten Eigentümerrichtlinie und nicht allein deshalb, weil ein Prozess signiert ist oder ein Administrator ihn gestartet hat.

Titan kombiniert:

- einen nativen Windows-Sensor (`ReadDirectoryChangesW` mit Overlapped-I/O) für geschützte System-, Start-, Treiber-, Aufgaben- und Benutzereingangspfade;
- SHA-256-Nachweise, Zonenkennungen, native Prozesslisten, TCP-Kontext und zeitliche Prozess-/Netzwerkkorrelation — ohne erfundene Datei-zu-PID-Zuordnung;
- ein Persistenz- und Sicherheitsinventar (Dienste, Run-/RunOnce-Schlüssel, Defender-/Firewall-/LSA-/UAC-/SMB-/RDP-/PowerShell-Protokollierungssteuerungen, Secure-Boot-Status) mit Baselines, die erst vorgerückt werden, nachdem der Nachweis erfolgreich geschrieben wurde;
- ein ausschließlich fortschreibbares, HMAC-/SHA-256-verkettetes Nachweisjournal mit Ed25519-signierten Checkpoints, Integritätsprüfung und signierten Aufbewahrungsarchiven;
- einen AES-256-GCM-Quarantänetresor mit begrenzter Dateigröße, SHA-256-Verifikation, Rückverfolgbarkeit des Originalpfads und kontrollierter Wiederherstellung, die ein vorhandenes Ziel niemals überschreibt;
- Eigentümerrichtlinie (`OBSERVE`, `CONTAIN`, `STRICT`), Eigentümerfreigaben, Entwicklungsbaum-Marker, Prüfentscheidungen und native Windows-Block-Toasts.

**Ehrliche Grenzen:** kein Anspruch auf vollständige Zuordnung, kein Schutz gegen eine vollständige Kompromittierung von Kernel/Firmware, keine TPM-basierte Measured-Boot-Attestierung und in dieser Phase keine minifilterbasierte Ausführungsblockierung. Diese Grenzen sind in der UI und in [`docs/TITAN.md`](docs/TITAN.md) dokumentiert.

---


## Neu in 5.3.0

- **Sentinel-/Killerdom-Ausführungsebene:** Echtzeit-Signatur- und Verhaltensreaktion, strikte Parent-Child-Lineage, kanonische System32-Pfadprüfung, AMSI-Scan-Buffer-Integritätsüberwachung und Default-Deny-Paranoia-Gate.
- **Ausführungs-Provenance statt Freifahrtschein:** kuratierte System-Apps und Allowlist-Einträge werden über Pfad, PE-OriginalFilename, Authenticode-Signer/Publisher und optionalen SHA-256-Pin geprüft; die Allowlist unterdrückt nie einen Kill mit hoher Konfidenz.
- **Titan→Killerdom-Brücke:** Titan-Integritätsbrüche neutralisieren bösartige Persistenz über verifizierte PID-Terminierung; jede Aktion und jeder Fehler landen in der HMAC-verketteten Evidenz.
- **Ghost Mode mit echter Durchsetzung:** ausgehende Telemetrie-Programme und -Dienste werden über WFP-gestützte Windows-Firewall-Regeln blockiert, Microsoft-Telemetrie-Hosts gesinkholed, der Status beim Boot abgeglichen und ehrlich gemeldet (`applied` / `lastError`).
- **False-Positive-Härtung:** Signaturen für PowerShell-Obfuskation, Base64-Blobs und destruktive `cmd /c`-Muster wurden präzisiert; der Encoded-Command-Parser gilt nur noch für PowerShell-Hosts. Admin-/Testbefehle und `govulncheck` werden nicht mehr getötet.
- **Härtung und Lieferkette:** gescopte Sessions, typisierte Bestätigung plus Begründung bei Schutzreduktion, SHA-256-/Signer-gepinnte Allowlist, unveränderlicher Selbstschutz, v5-API-Aliase, signierter Installer, SBOM/Provenance, null Go-Fremdabhängigkeiten und `govulncheck` 0.
- **UI und Lokalisierung:** Sentinel-/Killerdom-Tabellen rendern unabhängig mit Empty-States; alle vier UI-Sprachen (Deutsch, Englisch, Russisch, Vereinfachtes Chinesisch) decken die neue Seite ab; Abstände und Glass-2100-Layout wurden korrigiert.

## Für kritische Szenarien gebaut

GeDefense Windows 5.3.0 ist für Windows-11-Endpunkte gedacht, bei denen der Betreiber in isolierten, regulierten oder Offline-Umgebungen die Kontrolle behalten muss: lokale Control Plane, keine Cloud-Abhängigkeit, prüfbare Evidenz, begrenzte Ressourcen und explizite Antwortgrenzen. Es ist **keine** Behauptung vollständigen Schutzes: Kernel-/Firmware-Kompromittierung, ein bösartiger lokaler Administrator und eine vollständige Supply-Chain-Kompromittierung liegen außerhalb der Produktgrenze; der Build ist selbstsigniert und weiterhin Public Beta.

## Architektur

```text
GeDefenseCenter.exe / GeDefenseTray.exe        operator surfaces (unprivileged)
        │  operator broker session (Windows process token verified)
        ▼
127.0.0.1:17831                                authenticated loopback API
        │
        ▼
VGTGeDefense Windows Service (LocalSystem)     sovereign control plane
        ├── Defender / ASR / Firewall / WFP / App Control / Hardening
        ├── MHX EDR/XDR process and network correlation
        ├── Threat Intelligence feeds and WFP generation
        ├── Kinetic Defense burst correlation
        ├── Native traffic + local GeoIP/ASN map
        ├── Titan sensor, quarantine, owner policy and signed evidence
        └── HMAC/SHA-256 evidence ledger + Ed25519 checkpoints
```

- **Keine externen Go-Module.** Nur die Go-Standardbibliothek und kleine interne Win32-Wrapper.
- **Lokale Host-UI.** Die eingebettete Web-UI wird lokal ausgeliefert; der native Win32-Host startet einen installierten Chromium-Browser im Kioskmodus (externer Renderer, kein eingebettetes WebView2).
- **Keine CDNs zur Laufzeit.** Alle UI-Assets, die Kartengeometrie und die GeoIP/ASN-CSV sind lokal.

---

<a id="system-requirements"></a>

## Systemanforderungen

- Windows 11 x64 (Build 22621 oder neuer empfohlen).
- Lokale Administratorrechte für Installation und Richtlinienkonfiguration. Center und Tray laufen im unprivilegierten Benutzerkontext des Bedieners.
- Windows PowerShell 5.1 x64.
- Ein lokal installierter Chromium-Browser (Edge, Chrome oder Brave) für die Center-UI.
- Optional: lokale GeoIP/ASN-CSV (`data/geoip.csv` plus `.sha256`) für die Karte; ohne sie meldet die Karte „nicht geladen“, und der Rest des Produkts funktioniert weiter.

<a id="installation"></a>

## Installation

1. Laden Sie `GeDefense-Setup-x64-v5.3.0.exe` von der [Releases-Seite](https://github.com/visiongaiatechnology/gedefensewin/releases) herunter.
2. Messen und prüfen Sie das Artefakt:

   ```powershell
   Get-FileHash -Algorithm SHA256 .\GeDefense-Setup-x64-v5.3.0.exe
   Get-AuthenticodeSignature .\GeDefense-Setup-x64-v5.3.0.exe
   ```

   Der Installer ist derzeit **selbstsigniert**. `Get-AuthenticodeSignature` meldet `Valid` nur auf Hosts, die dem VGT-Zertifikat bereits vertrauen; für alle anderen ist der erwartete Zustand `NotTrusted`/`UnknownError`. Der gemessene SHA-256 muss mit `SHA256SUMS.txt` und der `.sha256`-Sidecar-Datei des Releases übereinstimmen.
3. Führen Sie den Installer als Administrator aus. Er installiert den Dienst, Center, Tray, Härtungs-/XDR-Assets und das Laufzeit-Datenstammverzeichnis für Nachweise/Titan.
4. Starten Sie das Center. Center und Tray beziehen kurzlebige Bedienersitzungen über den Loopback-Broker; das langlebige Master-Token ist eine Break-Glass-Anmeldeinformation, die ausschließlich SYSTEM/Administratoren vorbehalten ist.
5. Öffnen Sie das **Schutzcenter** und folgen Sie der Bereitschaftsanleitung. Der defensive Standard ist `OBSERVE_ONLY`; die scharfe Kinetic-Korrelation (`ARMED_TI_CORRELATION`) erfordert eine ausdrückliche Bestätigung durch den Bediener.


### Ersteinrichtung (First-Run-Assistent)

Beim ersten Start des Centers nach Installation oder Update öffnet sich der
**Ersteinrichtungsassistent**, solange die Einrichtung nicht serverseitig
abgeschlossen wurde. Er führt in vier Schritten durch Einsatzgebiet,
Empfehlung, Aktivierung und Verifikation:

1. **Einsatzgebiet:** persönlicher PC, Unternehmen/Büro, Server/Hochrisiko oder
   Entwickler/Build.
2. **Empfehlung:** Das Profil **Enterprise Balanced** ist der Standard für
   Privat und Büro; **Isolation** ergänzt deaktivierten USB-Speicher und RDP und
   ist nur für passende Server-/Hochrisiko-Umgebungen gedacht. Die
   Schutzstufen-Tabelle erklärt ausdrücklich, was `OBSERVE`, `BALANCED` und
   `ISOLATION` bedeuten.
3. **Aktivierung:** Härtungsprofil, Integritätsmonitor, Titan-Richtlinie und
   MHX-Policy-Abgleich werden über die vorhandenen Operator-APIs angewendet.
   Der Assistent zeigt Fehler und ablehnende Voraussetzungen an; er täuscht
   keinen Erfolg vor.
4. **Verifikation:** Erst wenn Defender, ASR (11/11 blockierend), Controlled
   Folder Access, Firewall, Schutzrichtlinie und Integritätsmonitor tatsächlich
   verifiziert sind, kann die Einrichtung abgeschlossen werden.

Die Abschlussmarkierung wird serverseitig authentifiziert gespeichert. Ein
Browserwechsel, ein anderer Rechner oder eine neue Sitzung setzt den Assistenten
nicht zurück; eine neue Programmversion kann ihn erneut anfordern. Der
Assistent ersetzt keine Operator-Berechtigung: Änderungen bleiben an die lokale
Bedienersitzung und die serverseitige Bestätigungsphrase gebunden.

### Wichtige Betriebshinweise

1. **Lokale Souveränität:** Die Kontrollebene läuft ausschließlich auf Loopback; keine Cloud-Kontrollebene und keine stille Telemetrie an Dritte.
2. **Defensiver Standard:** Kinetic Defense startet im Observe-only-Modus.
3. **Windows-Überwachungsrichtlinie:** Die Telemetrie eingehender WFP-Blocks (Ereignis-ID 5157) erfordert, dass die Überwachungsrichtlinie der Windows Filtering Platform aktiviert ist.
4. **Deinstallation:** exportiert zuerst relevante Nachweise und entfernt anschließend die verwalteten Schutzrichtlinien, soweit konfiguriert.

### UI-Sprachen

Die Center-UI ist in **Deutsch, Englisch, Russisch und vereinfachtem Chinesisch** verfügbar. Die Sprache wird automatisch anhand der System-/Browsersprache erkannt und kann jederzeit über den Sprachumschalter im Header geändert werden. Die Auswahl wird lokal gespeichert (Cookie, kein externer Dienst). Das README ist in denselben vier Sprachen verfügbar.

---

<a id="local-sovereignty-and-privacy"></a>

## Lokale Souveränität und Datenschutz

- Keine externe Cloud-Kontrollebene.
- Keine stille Telemetrie an Dritte.
- Threat-Intel-Feeds werden von ihren dokumentierten Upstream-Quellen abgerufen; Feed-Inhalte werden nirgendwo sonst hingeschickt.
- Die GeoIP-/ASN-Zuordnung erfolgt lokal auf CSV-Basis; IP-Adressen werden nicht an externe Geo-Dienste gesendet.
- Nachweis- und Quarantänedaten verbleiben auf dem lokalen Host und sind durch ACLs geschützt; Nachweisexporte sind ausdrückliche Aktionen des Bedieners.

---

<a id="verification-and-trust"></a>

## Verifikation und Vertrauen

- **Release-Gates:** Go-Race-Suite (einschließlich `vgt_bundle`), Go Vet, `govulncheck -mode=binary` (0 erreichbare Schwachstellen), vier Windows-Builds, PowerShell-5.1-Parsing, Sicherheitsinvarianten des Frontends, CycloneDX-SBOM, deterministisches Quellarchiv, unsignierte lokale Provenienz, Distributionshygiene, Installer-Sicherheit, Hygiene des Release-Kanals, Sidecar-Bindung und Offline-Publish-Verifikation.
- **Artefakte:** signierter Installer, `.sha256`-Sidecar, JSON-Release-Sidecar (gemessene Bytes/Hash/Signer plus SBOM-/Provenienz-Bindungen), Artefakt-SBOM, Provenienz und `SHA256SUMS.txt`.
- **Signaturstatus:** Der aktuelle Installer ist mit einer **lokalen selbstsignierten Identität** signiert (keine öffentliche CA, kein RFC-3161-Zeitstempel, keine Online-Widerrufsprüfung). Dies ist eine Beta-Einschränkung und ein dokumentierter externer Blocker — **es wird kein öffentliches Vertrauen beansprucht**.
- **Provenienz:** bewusst unsigniert-lokal; sie belegt Build-Eingaben/-Hashes und die Reproduzierbarkeit des Quellarchivs, nicht eine Remote-Attestierung.
- **CI:** `.github/workflows/security-gate.yml` führt das Release-Gate auf einem Windows-Runner aus, wenn das Repository mit einem Tag versehen ist und CI verfügbar ist.

---

<a id="licenses-and-attribution"></a>

## Lizenzen und Attribution

### Softwarelizenz

Quellcode und Dokumentation von GeDefense Windows stehen unter der **GNU Affero General Public License v3.0 only (AGPL-3.0-only)** — siehe [LICENSE](LICENSE). Namen, Logos und visuelle Markenassets sind durch [TRADEMARKS.md](TRADEMARKS.md) abgedeckt; Drittanbieterkomponenten sind unten sowie in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md), [LICENSE-MATRIX.md](LICENSE-MATRIX.md) und [DEPENDENCIES.md](DEPENDENCIES.md) aufgeführt.

### Weltkartengeometrie — jsVectorMap (MIT)

Die mitgelieferte lokale Weltkartengeometrie (`src/GeDefense/windows/internal/server/web/world-merc.js`, `world-merc.js`) stammt aus dem Open-Source-Projekt **jsVectorMap** und entspricht dessen Mercator-Weltkarte in Version **1.7.0**:

- Projekt: [themustafaomar/jsvectormap](https://github.com/themustafaomar/jsvectormap)
- Kartendatei: [world-merc.js 1.7.0](https://cdn.jsdelivr.net/npm/jsvectormap@1.7.0/dist/maps/world-merc.js)
- Lizenz: [MIT License](https://github.com/themustafaomar/jsvectormap/blob/main/LICENSE) · Copyright © 2020 Mustafa Omar
- Vollständiger Lizenztext: [LICENSES/jsVectorMap-LICENSE](LICENSES/jsVectorMap-LICENSE)

Die lokale Datei ist als ES-Modul verpackt; die jsVectorMap-Laufzeitbibliothek selbst wird nicht verwendet.

### GeoIP/ASN-Daten — iplocate und DB-IP (Attribution erforderlich)

Die optionale lokale CSV (`data/geoip.csv`, im Installer-Payload enthalten, nicht im öffentlichen Git) führt öffentliche IP-zu-Land- und IP-zu-ASN-Daten zusammen. Bei Weitergabe und abgeleiteten Werken ist eine Attribution erforderlich:

- **ASN-Daten:** [iplocate/ip-address-databases](https://github.com/iplocate/ip-address-databases) — öffentliche IP-zu-Land- und IP-zu-ASN-Datenbanken, lizenziert unter **CC BY-SA 4.0** ([Lizenz](https://creativecommons.org/licenses/by-sa/4.0/)). Ein konkretes Beispiel: Das Netz `1.0.4.0/22` ist mit ASN `38803` und der Organisation `Gtelecom Pty Ltd` aufgeführt, passend zur mitgelieferten CSV. Quellenangabe: © iplocate/ip-address-databases contributors, CC BY-SA 4.0.
- **Geolokalisierungsdaten (vorherige/kombinierte Basis):** DB-IP Lite — [DB-IP](https://db-ip.com), **CC BY 4.0** ([Lizenz](https://creativecommons.org/licenses/by/4.0/)).
- **Status:** Das genaue Upstream-Snapshot-Datum und die Vollständigkeit der mitgelieferten CSV sind nicht unabhängig bestätigt; die SHA-256-Sidecar-Datei wurde an den tatsächlichen Bytes korrigiert. Details: [GEOIP_LICENSE_AND_DEPLOYMENT.md](GEOIP_LICENSE_AND_DEPLOYMENT.md).
- Die Daten begründen keine Durchsetzungsbefugnis; Land/ASN beschreiben den ungefähren Registrierungsursprung eines Netzwerks, nicht den physischen Standort einer Person.

### Weiteres Drittmaterial

- Go-Standardbibliothek und -Toolchain: Go-/BSD-Lizenz; fixierter Toolchain-Hash in [TOOLCHAINS.lock](TOOLCHAINS.lock), nicht weitergegeben.
- Microsoft Windows, Defender, Firewall/WFP und App Control: Microsoft-Lizenz; nicht Teil des Repositories.
- Threat-Intelligence-Feeds (Feodo Tracker, Spamhaus DROP, FireHOL, CINS, blocklist.de, Emerging Threats, IPsum, Tor-Exit-Nodes): Es gelten die Bedingungen der Anbieter; Snapshots werden nicht mitgeliefert. Siehe [docs/THREAT-INTELLIGENCE.md](docs/THREAT-INTELLIGENCE.md).
- Windows PowerShell 5.1: Microsoft-Plattformkomponente, nicht weitergegeben.

---

## Aus dem Quellcode bauen

Voraussetzungen: Windows 11 x64, Windows PowerShell 5.1 x64, Go **1.26.10** (siehe `TOOLCHAINS.lock`) und ein C-Compiler, der für den Go-Race-Detektor geeignet ist.

```powershell
$env:GOTOOLCHAIN = 'go1.26.10'
# 1) deterministic source archive + SOURCE-MANIFEST
& .\build\Build-SourceRelease.ps1
# 2) full release gate + signed payload/installer + SBOM/provenance/sidecar/SHA256SUMS
& .\build\Build-GeDefenseStandalone.ps1
# 3) offline publish verification (no Git/VCS required with the explicit override)
& .\build\Publish-GitHubRelease.ps1 -VerifyOnly -AllowMissingVcs
```

Die Signaturidentität muss im Zertifikatspeicher des Build-Kontos bereitgestellt werden (privater Schlüssel, Code-Signing-EKU); `certificates/release-thumbprint.txt` referenziert sie ausschließlich über den Thumbprint. Private Schlüssel werden niemals eingecheckt. Siehe [docs/BUILDING.md](docs/BUILDING.md).

---

## Feedback und Mitwirkung

- Fehlerberichte, Meldungen zu Falschmeldungen und Funktionswünsche: [GitHub Issues](https://github.com/visiongaiatechnology/gedefensewin/issues).
- Sicherheitsmeldungen: Bitte folgen Sie [SECURITY.md](SECURITY.md) — veröffentlichen Sie keine ausnutzbaren Details, bevor eine Korrektur verfügbar ist.
- Beiträge: Siehe [CONTRIBUTING.md](CONTRIBUTING.md) und [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Es gilt ein [Contributor License Agreement](CONTRIBUTOR-LICENSE-AGREEMENT.md).

**Vielen Dank, dass Sie die GeDefense Titan Beta testen.** Reproduzierbares Feedback — einschließlich ehrlicher Fehlerberichte — macht das nächste Release besser.
