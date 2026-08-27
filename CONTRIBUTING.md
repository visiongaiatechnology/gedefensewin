# Contributing

Beiträge sind willkommen, sofern sie die Sicherheits-, Lizenz- und Qualitätsgrenzen dieses Projekts einhalten.

## Entwicklungsablauf

1. Fork erstellen und einen fachlich begrenzten Branch verwenden.
2. Änderungen modular halten; UI-Tabs, Schutzdomänen und Transaktionen bleiben voneinander isoliert.
3. Tests für jeden neuen Sicherheitsentscheidungszweig ergänzen.
4. `gofmt`, Race-Tests, `go vet`, JavaScript-Syntaxprüfung und PowerShell-Parser ausführen.
5. Keine Binärdateien, Zertifikate, Feed-Snapshots oder Laufzeitdaten committen.
6. Pull Request mit Bedrohungsmodell, Blast Radius, Rollback und Testnachweis einreichen.

## Erforderliche Prüfungen

```powershell
Set-Location .\src\GeDefense\windows
gofmt -w .\cmd .\internal
go test -race ./...
go vet ./...
node --check .\internal\server\web\app.js
```

PowerShell-Dateien müssen mit `System.Management.Automation.Language.Parser` ohne Parserfehler geprüft werden.

## Sicherheitsregeln

- Kein `TODO`, Dummy-Code oder Fail-open-Verhalten in Schutzpfaden.
- Keine dynamische Ausführung unvalidierter Eingaben.
- Keine externen CDN-Abhängigkeiten im Security Center.
- Alle Dateipfade werden kanonisiert und innerhalb eines definierten Jails geprüft.
- Zustandsändernde APIs benötigen Authentifizierung und Replay-Schutz.
- Riskante Systemprofile bleiben Opt-in und benötigen eine eindeutige Operator-Bestätigung.
- Tests dürfen keine realen Schadprogramme benötigen.

## Lizenz und Beiträge

Beiträge werden unter `AGPL-3.0-only` angenommen. Jeder Commit muss einen Developer Certificate of Origin Sign-off enthalten:

```text
Signed-off-by: Vorname Nachname <adresse@example.invalid>
```

Für Beiträge, die in offizielle dual lizenzierte VGT-Ausgaben übernommen werden sollen, ist zusätzlich die Zustimmung zum `CONTRIBUTOR-LICENSE-AGREEMENT.md` erforderlich. Der Contributor behält sein Urheberrecht.

## Marken

Pull Requests dürfen VGT-Markenmaterial für die offizielle Codebasis bearbeiten. Öffentliche Drittanbieter-Builds unterliegen weiterhin `TRADEMARKS.md`.

