# Abhängigkeiten

## Go-Module

Die kanonischen Versionen stehen in `src/GeDefense/windows/go.mod` und `go.sum`.

| Modul | Verwendung | Version | Lizenz |
|---|---|---:|---|
| `fyne.io/systray` | Windows-Systemtray | 1.12.2 | Apache-2.0 |
| `github.com/jchv/go-webview2` | natives Security-Center-Fenster | 56598839c808 | MIT |
| `golang.org/x/sys` | Windows-Dienst, Handles und Sicherheits-APIs | 0.35.0 | BSD-3-Clause |
| `github.com/godbus/dbus/v5` | indirekte Systray-Abhängigkeit | 5.1.0 | BSD-2-Clause |
| `github.com/jchv/go-winloader` | indirekter Windows-Loader | c1995be93bd1 | ISC |

## Externe Laufzeiten

- Microsoft Windows 11
- Microsoft Defender Antivirus
- Microsoft WebView2 Runtime
- Windows PowerShell 5.1
- Go Toolchain für Builds
- MinGW-w64 `windres.exe` für Windows-Ressourcen

Diese Laufzeiten werden nicht unter AGPL relizenziert und nicht in diesem Repository gebündelt.

## Update-Regel

Ein Dependency-Update erfordert gemeinsam:

1. Upstream-Release- und Security-Prüfung,
2. Lizenzprüfung,
3. Aktualisierung von `go.mod` und `go.sum`,
4. Race-Tests und Vet,
5. Aktualisierung von `THIRD-PARTY-NOTICES.md` und SBOM,
6. Prüfung des finalen Binärimports und der Authenticode-Signatur.

