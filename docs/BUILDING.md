# Build-Anleitung

## Unterstützte Build-Umgebung

- Windows 11 x64
- Go 1.23 oder neuer
- Windows PowerShell 5.1
- Git
- MinGW-w64 `windres.exe`
- Microsoft WebView2 Runtime für die Ausführung des Centers

Der Build lädt Go-Abhängigkeiten gemäß `go.sum`. Für reproduzierbare oder abgeschottete Umgebungen sollte ein kontrollierter Go Module Proxy oder ein vorab validierter Modulcache verwendet werden.

## Quellcode prüfen

```powershell
$source = Resolve-Path '.\src\GeDefense\windows'
Push-Location $source
try {
    gofmt -w .\cmd .\internal
    if ($LASTEXITCODE -ne 0) { throw 'gofmt failed' }
    go test -race ./...
    if ($LASTEXITCODE -ne 0) { throw 'tests failed' }
    go vet ./...
    if ($LASTEXITCODE -ne 0) { throw 'go vet failed' }
    node --check .\internal\server\web\app.js
    if ($LASTEXITCODE -ne 0) { throw 'JavaScript validation failed' }
} finally {
    Pop-Location
}
```

## PowerShell statisch prüfen

```powershell
$scripts = Get-ChildItem .\audit,.\engine,.\xdr,.\installer,.\build,.\tools -Recurse -File -Include *.ps1,*.psm1
foreach ($script in $scripts) {
    $tokens = $null
    $errors = $null
    [void][Management.Automation.Language.Parser]::ParseFile($script.FullName, [ref]$tokens, [ref]$errors)
    if (@($errors).Count -gt 0) { throw ($errors | Out-String) }
}
```

## Standalone-Build

```powershell
& .\build\Build-GeDefenseStandalone.ps1
```

Der Standard-Build signiert mit einem lokal erzeugten, nicht exportierbaren
Entwicklungszertifikat, verändert den Windows-Truststore jedoch nicht. Ein expliziter
lokaler Integrationstest kann das Zertifikat in einer interaktiven Sitzung importieren:

```powershell
& .\build\Build-GeDefenseStandalone.ps1 -TrustDevelopmentCertificate
```

Dieser Schalter ist nur für isolierte Testsysteme bestimmt. Offizielle Releases
verwenden das kontrollierte VGT-Releasezertifikat der Release-Pipeline.

Der Build:

1. führt Race-Tests aus,
2. erzeugt Dienst, Center und Tray,
3. signiert PowerShell- und EXE-Artefakte,
4. erstellt einen signierten Dateikatalog,
5. bettet den Payload in den Installer ein,
6. schreibt Manifest und SHA-256 nach `release\`.

Beim ersten lokalen Build wird ein nicht exportierbares Codesigning-Zertifikat im Zertifikatsspeicher des aktuellen Benutzers erzeugt. Dieses Zertifikat ist ausschließlich ein lokales Community-Build-Zertifikat und macht das Artefakt nicht zu einem offiziellen VGT-Release.

## Verbotene Build-Inhalte

Folgende Dateien dürfen nicht eingecheckt werden:

- private Schlüssel und PFX/P12-Dateien
- `certificates/release-thumbprint.txt`
- `payload/`, `release/`, `work/` und eingebettete ZIP-Dateien
- Windows-ISO-, WIM- oder ESD-Dateien
- ProgramData-Laufzeitdaten, Tokens, Evidenz oder Feed-Snapshots

## Installationsprüfung

Eine Installationsprüfung erfolgt auf einer isolierten Windows-Testmaschine. Produktive Systeme sind kein CI-Testziel. Vor der Ausführung von Sovereign, USB-Sperre, Controlled Folder Access oder vollständiger Isolation ist ein Snapshot erforderlich.
