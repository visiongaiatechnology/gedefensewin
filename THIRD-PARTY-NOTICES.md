# Third-Party Notices

GeDefense Windows verwendet die folgenden direkten und indirekten Go-Abhängigkeiten. Die vollständigen Lizenztexte liegen unter `LICENSES/`.

| Modul | Version | Lizenz | Lizenzdatei |
|---|---:|---|---|
| `fyne.io/systray` | 1.12.2 | Apache-2.0 | `LICENSES/Apache-2.0-fyne-systray.txt` |
| `github.com/jchv/go-webview2` | 56598839c808 | MIT | `LICENSES/MIT-go-webview2.txt` |
| `golang.org/x/sys` | 0.35.0 | BSD-3-Clause | `LICENSES/BSD-3-Clause-golang-x-sys.txt` |
| `github.com/godbus/dbus/v5` | 5.1.0 | BSD-2-Clause | `LICENSES/BSD-2-Clause-godbus-dbus.txt` |
| `github.com/jchv/go-winloader` | c1995be93bd1 | ISC | `LICENSES/ISC-go-winloader.md` |

## Microsoft-Komponenten

GeDefense ruft Betriebssystemfunktionen von Microsoft Windows auf, darunter Defender, Windows Firewall, CIM/WMI, Windows App Control und WebView2. Diese Komponenten werden nicht unter AGPL relizenziert und sind nicht als Microsoft-Binärdateien in diesem Repository enthalten.

## Threat-Intelligence-Quellen

Die Anwendung lädt Feodo Tracker sowie Spamhaus DROP IPv4/IPv6 zur Laufzeit direkt von den jeweiligen Anbietern. Snapshots und abgeleitete Feed-Dateien werden nicht im Repository ausgeliefert. Betreiber sind für die Einhaltung der jeweils aktuellen Quellenbedingungen verantwortlich.

## Aktualisierung

Bei jeder Änderung von `go.mod` oder `go.sum` müssen diese Datei, `DEPENDENCIES.md`, die SBOM und gegebenenfalls die Lizenztexte gemeinsam aktualisiert werden.

