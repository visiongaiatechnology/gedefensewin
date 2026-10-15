# GeDefense Windows 4.1.4

<img width="2364" height="1240" alt="image_2026-10-15_10-50-03" src="https://github.com/user-attachments/assets/8bbb85f0-65be-42c9-b9ff-f78b3a401a5e" />


Lokales Windows Security Center von **VisionGaia Technology**. GeDefense führt Defender, Firewall/WFP, ASR, Windows App Control, Systemhärtung, MHX EDR/XDR, Threat Intelligence und Dateiintegrität in einer gemeinsamen Oberfläche zusammen.

[Installer und Release](https://github.com/visiongaiatechnology/gedefensewin/releases/tag/v4.1.4) · [Changelog](CHANGELOG.md) · [Architektur](ARCHITECTURE.md) · [Sicherheit](SECURITY.md)

## WFP-Hotfix 4.1.4

Die WFP-Ereignisbrücke startet nach Abbruch automatisch neu; ein Watchdog beendet hängende Abfragen. Der Sensor meldet den Empfangszeitpunkt als Healthcheck und behält den Originalzeitpunkt für die Ereigniskorrelation. Der Startcheck erkennt einen ausgefallenen WFP-Leser auch dann, wenn historische Blockereignisse vorliegen. Nach Installation von 4.1.4 meldet der lokale Leser wieder aktuelle Ereignisse; die effektive Windows-Audit-Richtlinie bleibt ausdrücklich unbestätigt.

## Letzte öffentliche Veröffentlichung: 4.1.4

4.1.4 ergänzt die automatische Wiederherstellung des WFP-Lesers und eine Health-Prüfung, die historische Blockereignisse nicht mit einem aktiven Sensor verwechselt. Die Version 4.1.3 bündelt Fenster- und Startkorrekturen aus 4.1.2 sowie Kinetic Defense, Traffic und GeoIP/ASN.

| Bereich | Änderung |
|---|---|
| **Kinetic Defense** | Eigene Ansicht für eingehende WFP-Blockereignisse, Burst-Erkennung, Threat-IP-Korrelation und nachvollziehbare Vorfälle. |
| **Netzwerk-Traffic** | Native RX/TX-Zähler mit Verlauf, tatsächlichen Messwerten und explizitem Zustand bei fehlenden Daten. |
| **GeoIP und ASN** | Lokale Karte für beobachtete Kinetic-/Threat-IP-Ereignisse; keine externe IP-Abfrage und keine erfundenen Standortmarkierungen. |
| **Start-Healthcheck** | Automatische Synchronisierung der vorhandenen Policy sowie bei Bedarf der Threat-Feeds und ihrer Firewallregeln. Sieben Bereiche werden anhand aktueller Backend-Daten bewertet. |
| **Eigenes Fenster** | Eigener Win32-Host mit genau einer Fenstersteuerung. Die Befehle wirken auf das GeDefense-Fenster; eine Suche nach fremden Fenstertiteln entfällt. |
| **Größe und Darstellung** | Maximierter Start, dunkle native Randfläche und Wiederherstellen auf 92 % Breite und 90 % Höhe der Monitor-Arbeitsfläche. |
| **Codequalität** | Alle 92 Befunde des unbegrenzten Lint-Scans bereinigt; Ergebnis: **0 Meldungen**, ohne neue Ausnahmen oder Unterdrückungen. |
| **Robustheit** | Korrekte Win32-Fehlerverträge, erhaltene Close-/Cleanup-Fehler und geordneter Abbruch des Tray-Ereignis-Workers. Go-Toolchain 1.26.9. |

| **WFP-Sensor** | Automatischer Neustart der Eventlog-Brücke, Watchdog für hängende Abfragen und Health anhand des Empfangszeitpunkts. Das Release bestätigt keine effektive Audit-Richtlinie oder vollständige Ingress-Abdeckung. |
Details: [Release Notes](RELEASE-NOTES.md), [Verifikationsbericht 4.1.4](docs/VERIFICATION-4.1.4.md).

<img width="2281" height="1240" alt="image_2026-10-15_10-50-21" src="https://github.com/user-attachments/assets/52f1fffe-4dba-4025-8712-7b470f6728b2" />


## Installation und erster Start

1. `GeDefense-Setup-x64-v4.1.4.exe` aus dem [Release](https://github.com/visiongaiatechnology/gedefensewin/releases/tag/v4.1.4) herunterladen. SHA-256 mit `SHA256SUMS.txt` vergleichen und die Authenticode-Signatur prüfen.
2. Installer als Administrator starten. Er installiert Dienst, Center und Tray und richtet die lokalen Zugriffsrechte ein.
3. GeDefense Center öffnen. Der Startdialog gleicht die konfigurierte Schutzlage ab und prüft **Policy, Defender, Firewall, Prozess-/Netzwerk-Telemetrie, Threat Intelligence, aktive Threat-IP-Firewallgeneration und Evidenzkette**.
4. Hinweise im Dialog bearbeiten oder den Check im Hintergrund fortsetzen. Bei Problemen ist eine erneute Prüfung möglich. Grün erscheint erst nach erfolgreicher Verifikation; der Check schaltet optionale Schutzfunktionen nicht pauschal ein.

Voraussetzungen: **Windows 11 x64**, Windows PowerShell 5.1, verfügbare Windows-Sicherheitsfunktionen und ein lokal installierter Chromium-Browser wie Edge, Chrome oder Brave. Der Renderer läuft im eigenen Win32-Fensterhost. Administratorrechte sind für Installation und Systemänderungen nötig; Center und Tray laufen im Benutzerkontext.

Die Signatur bestätigt die Integrität unter der jeweiligen Zertifikats-Vertrauenskette. Eine lokal gültige Signatur bedeutet keine allgemeine SmartScreen-Reputation. Build- und Testumfang einschließlich der noch offenen separaten VM-Neuinstallation/Upgrade-Prüfung stehen im [Verifikationsbericht](docs/VERIFICATION-4.1.4.md).

## Kinetic Defense, Traffic und Karte

Kinetic verarbeitet reale eingehende **Windows Security Events 5157** für blockierte Verbindungen. Ein Burst-Kandidat benötigt mindestens zwölf Ereignisse innerhalb von zehn Sekunden an mindestens drei lokalen Ports. Die Erfassung ist begrenzt auf 2.048 Quellen und 32 Samples pro Quelle.

Standard ist `OBSERVE_ONLY`. Die ausdrücklich bestätigte Aktivierung `ARMED_TI_CORRELATION` verlangt verfügbare Telemetrie und eine verifizierte aktive Threat-IP-WFP-Generation. Sie korreliert Vorfälle mit der vorhandenen Durchsetzung. Kinetic installiert keine eigenen dynamischen Sperrregeln und ist kein eigenständiger Paketfilter oder DDoS-Schutz. Eine IP-Beobachtung berechtigt nicht zur Prozessterminierung. Nach einem Dienstneustart muss die Aktivierung erneut bestätigt werden.

RX/TX-Werte stammen aus nativen Windows-Interface-Zählern (`GetIfTable2`, mit `GetIfTable`-Fallback). Die Abtastung erfolgt alle zwei Sekunden; bis zu 60 Samples bilden den Verlauf. Zählerwechsel und fehlende Messwerte werden sichtbar behandelt. Virtuelle/VPN-Interfaces können die Summen beeinflussen; Paketinhalt oder TLS-Inhalte werden dabei nicht erfasst.

Die GeoIP/ASN-Karte zeigt Kontext für tatsächlich beobachtete Kinetic- und Threat-IP-Ereignisse. Die Zuordnung erfolgt lokal aus einer optionalen CSV mit geprüftem SHA-256-Sidecar. Ohne passende Daten meldet die Oberfläche den fehlenden Datenbestand. GeoIP beschreibt eine ungefähre Netzwerkzuordnung, keinen Standort einer Person. Der veröffentlichte Installer enthält den dokumentierten Datenstand; die Git-Quellen enthalten Anleitung und Lizenzhinweise statt der großen CSV. Siehe [GeoIP-Betrieb und Herkunft](GEOIP_LICENSE_AND_DEPLOYMENT.md).

## Schutzarchitektur

- **Keine externen Go-Module:** Standardbibliothek und interne Wrapper um öffentliche Windows-APIs. Das reduziert Abhängigkeiten; Windows, Browser, Toolchain und Datenquellen bleiben eigene Vertrauensgrenzen.
- **Lokale Control Plane:** `127.0.0.1:17831`, Bootstrap-/Session-Authentifizierung, Host-/Origin-/RemoteAddr-Prüfung und begrenzter Anfragezustand.
- **Lokale Oberfläche:** Assets sind eingebettet, ohne Remote-CDN oder externe Fonts. CSP begrenzt Skripte und Styles auf den eigenen Ursprung. Die lokale Kartengeometrie stammt aus jsVectorMap und ist unter MIT lizenziert.
- **Delegierte Durchsetzung:** Defender, ASR, Windows Firewall/WFP und App Control übernehmen die jeweiligen Windows-Schutzfunktionen; kein eigener Kernel-Treiber.
- **Prozessidentität:** Eine Host-Reaktion benötigt ein eigenständiges MHX-Verdikt und die erneute Prüfung von PID, Erstellungszeit und Programmpfad.
- **Nachvollziehbare Evidenz:** HMAC-SHA-256-verkettetes Ledger macht Veränderungen unter dem lokalen Schlüsselmodell erkennbar.
- **Privilegientrennung:** Dienst als LocalSystem; Center und Tray im Benutzerkontext; signierte Systemtransaktionen mit Windows PowerShell und `AllSigned`.

### Threat Intelligence

| Aktionsklasse | Quellen |
|---|---|
| `BLOCK` | Feodo Tracker, Spamhaus DROP IPv4/IPv6, **FireHOL Level 1** |
| `CORRELATE_ONLY` | CINS Army, blocklist.de, Emerging Threats, IPsum |
| `ANNOTATE_ONLY` | Tor Exit Nodes |

Feeds erhalten unabhängige Last-Known-Good-Generationen. Größen-, Eingabe- und Shrink-Gates schützen die Übernahme; gewünschte und tatsächlich aktive Firewallgeneration werden getrennt verifiziert. Protected Networks werden exakt aus der Blockprojektion entfernt, während die Attribution erhalten bleibt. Details: [Threat Intelligence](docs/THREAT-INTELLIGENCE.md).

## Quellcode und Build

| Pfad | Verantwortung |
|---|---|
| `src/GeDefense/windows/cmd/` | Dienst, Center, Tray und Standalone-Installer |
| `internal/kinetic`, `internal/traffic`, `internal/geoip` | WFP-Burst-Beobachtung, Traffic-Messung und lokale Herkunftszuordnung |
| `internal/mhx`, `internal/threatintel` | EDR/XDR, Policy-Lifecycle und Feed-/Firewallgenerationen |
| `internal/server` | Authentifizierte lokale API, Oberfläche und Startcheck |
| `internal/winframe`, `internal/wintray`, `internal/winapi` | Nativer Fensterhost, Tray und Windows-Verträge |
| `internal/integrity`, `internal/evidence`, `internal/cleanup` | Dateiprüfung, Evidenzkette und Fehlererhalt beim Ressourcenabbau |
| `engine/`, `audit/`, `xdr/`, `installer/` | Signierte Windows-Systemtransaktionen |
| `build/`, `test/`, `diagnostics/` | Release-Gates, Regressionen und Diagnose |
| `docs/`, `LICENSES/`, `sbom/` | Architektur, Verifikation und Lizenz-/Komponentenhinweise |

Die `internal/`-Pfade liegen unter `src/GeDefense/windows/`.

Offizielle Buildbasis: **Go 1.26.9**, Windows PowerShell 5.1 x64 und eine Race-Detector-fähige Windows-Buildumgebung. Die minimale Go-Sprachversion im Modul ist von der Release-Toolchain getrennt.

```powershell
# STATUS: GOLD — Releasequalifikation siehe docs/VERIFICATION-4.1.4.md
$env:GOTOOLCHAIN = 'go1.26.9'
& .\build\Test-GeDefenseRelease.ps1
& .\build\Build-GeDefenseStandalone.ps1
```

Der Standalone-Build benötigt eine provisionierte Code-Signing-Identität. Private Schlüssel und lokale Vertrauenskonfiguration gehören nicht ins Repository. Vollständige Einrichtung, optionale GeoIP-Daten und zusätzliche Tests: [Build-Anleitung](docs/BUILDING.md).

## Lizenz und Meldungen

Quellcode und Projektdokumentation: **AGPL-3.0-only**, siehe [LICENSE](LICENSE). Namen und Logos: [Markenrichtlinie](TRADEMARKS.md). Kartengeometrie und optionale GeoIP/ASN-Daten: [Third-Party Notices](THIRD-PARTY-NOTICES.md), [Lizenzmatrix](LICENSE-MATRIX.md).

Sicherheitsmeldungen: [SECURITY.md](SECURITY.md). Beiträge: [CONTRIBUTING.md](CONTRIBUTING.md).

Copyright © 2026 VisionGaia Technology.
