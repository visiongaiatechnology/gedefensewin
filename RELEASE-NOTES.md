# VGT GeDefense Windows 4.1.1

Release-Datum: 2026-09-25

## Generation 4.1.1: Dedicated Application Window & Sovereign Resilience

GeDefense Windows 4.1.1 liefert ein dediziertes, isoliertes Anwendungsfenster für das Windows Security Center, beseitigt Policy-Synchronisationslücken in Windows App Control (WDAC), führt den neuen VGT Ice-Blue Glassmorphism Setup Wizard ein und optimiert die Härtungs- und Dienstresilienz unter Windows 11.

### Kernänderungen in 4.1.1

- **Dediziertes Anwendungsfenster (Standalone Window Experience)**:
  - Automatischer Start des GeDefense Security Centers in einem eigenständigen, tab- und adressleistenfreien Fenster via Chromium Application Mode (`--app`).
  - Native Farbkopplung der Windows-Fensterleiste via Dark-Mode `<meta name="theme-color" content="#050b14">`.
  - Isoliertes Benutzerprofil unter `%LocalAppData%\VGT\GeDefense\WebWindow`, um Cache-Konflikte mit normalen Browser-Sessions auszuschließen.
  - Native Erkennungskette für Edge, Chrome, Brave und EdgeCore über Standardpfade und Windows-Registry.
- **Windows App Control (WDAC / MHX) & Policy-Reconciliation**:
  - Resiliente Fehlerbehandlung in `Set-VgtMhxAppControl.ps1`: Graceful Tolerance von `0x80070002` (`ERROR_FILE_NOT_FOUND`) beim Entfernen nicht mehr vorhandener Richtlinien-GUIDs.
  - Aktive Policy-Cache-Prüfung in `CiPolicies\Active`, um redundante 30-Sekunden-Vollscans zu verhindern.
  - Neuer Endpoint `POST /api/v1/mhx/policy/reconcile` zur direkten, manuellen Policy-Neusynchronisation bei Status `DEGRADED`.
  - Dedizierte Synchronisierungs-Buttons im Protection Center und der Übersichts-Kachel mit Live-Feedback.
- **VGT Glassmorphism Setup Wizard**:
  - Moderner, transparenter Glassmorphism-Look mit feinen Ice-Blue-Akzenten und flüssigen Micro-Transitions.
  - Resiliente Administrator-Elevation und transaktionale Installationsüberwachung.
- **Dienst- und Härtungs-Resilienz**:
  - Getestete und signierte PowerShell-Module unter `ExecutionPolicy AllSigned`.
  - Aktualisierte Versionierung und SBOM nach CycloneDX 1.6.

---

# VGT GeDefense Windows 4.1.0-beta.1

Release-Datum: 2026-09-19

## Generation 4.1: Sovereign Threat Intelligence

GeDefense Windows 4.1 erweitert MHX/XDR um eine action-aware 9-Feed-Threat-Intelligence-Schicht und koppelt sie verifiziert an Windows Filtering Platform / Windows Firewall, ohne einen proprietären Kernel-Treiber einzuführen.

### Kernänderungen

- neun Threat-Intelligence-Feeds mit expliziter Autorität: `BLOCK`, `CORRELATE_ONLY`, `ANNOTATE_ONLY`
- nur Feodo Tracker und Spamhaus DROP IPv4/IPv6 dürfen Firewall-Blockgenerationen erzeugen
- CINS Army, blocklist.de, Emerging Threats, IPsum und FireHOL bleiben reine Korrelationsquellen
- Tor Exit Nodes bleiben strikt `ANNOTATE_ONLY`
- unabhängige Last-Known-Good-Generationen pro Feed mit SHA-256-Fingerprints
- TLS-gehärteter Fetcher mit Redirect-Verbot, DNS/SSRF-Adressfilter, Header-/Body-Grenzen und HTML-Rejection
- strikte IP/CIDR-Canonicalisierung und Filterung privater, reservierter, Link-Local-, Multicast-, Metadata- und überbreiter Präfixe
- Catastrophic-Shrink-Gate gegen fehlerhafte oder manipulierte Feed-Leerläufe
- immutable, lock-free ThreatIndex-Snapshots für MHX/XDR
- separate SHA-256-Enforcement-Generation ausschließlich für `BLOCK`-Vektoren
- Protected-Network-Safety-Plane: öffentliche Management-IP/CIDR werden vor der Firewall-Publikation exakt aus BLOCK-Prefixen subtrahiert, ohne Threat-Attribution aus XDR zu entfernen
- HMAC-SHA-256-authentifizierte Protected-Network-Policy mit eigener Generation, expliziter Operator-Bestätigung und Evidence-Preflight
- Windows Firewall Dynamic Keyword Address Sharding mit transaktionaler Generation-Promotion
- verifizierter statischer Firewall-Fallback auf Systemen ohne Dynamic Keyword Address Support; hartes 25.000-Indicator-Limit verhindert Firewall-Regel-Explosion
- gewünschte und tatsächlich aktive Firewall-Generation werden getrennt geführt und für Sovereign Readiness abgeglichen
- WFP Security Event 5157 wird als Block-Telemetrie mit PID, Richtung, Ziel, Port, Filter-ID und FilterOrigin in MHX korreliert
- GeDefense-Firewallregeln erhalten deterministische `VGT-GeDefense-TI-*` Rule-IDs für Filter-Origin-Zuordnung
- blockierte und zugelassene Verbindungen fließen gemeinsam in Attack Stories und das Evidence Ledger
- Netzwerk-IOC-Treffer behalten die bestehende Invariante: keine Prozess-Termination ohne unabhängige MHX ResponseAuthority plus PID/CreationTime/Image-Revalidierung
- XDR-/Network-UI zeigt Feed-Matrix, Aktionsklasse, LKG-Zustand, WFP-Events sowie Desired/Active Generation
- Protected-Network-Editor im lokalen XDR-Dashboard; Änderungen werden CIDR-validiert, bounded kompiliert und unmittelbar gegen WFP reconciled
- Threat-Intel-Laufzeitdaten erhalten eine eigene SYSTEM/Administrators-only ACL
- MHX Engine auf 7.1 angehoben

## Dependency-Vertrag

`go.mod` besitzt weiterhin keinen `require`-Block. Der neue Threat-Intelligence-Core verwendet ausschließlich die Go-Standardbibliothek und vorhandene Windows-/PowerShell-Systemkomponenten. Es wurden keine externen Go- oder Frontend-Abhängigkeiten ergänzt.

## In dieser Source-Release-Umgebung verifiziert

- `go test ./internal/threatintel`
- Cross-Windows-Testkompilierung aller Go-Packages und Tests
- Cross-Windows `go vet ./...`
- JavaScript-Syntaxprüfung des aktualisierten Frontends
- Source-Manifest nach allen Änderungen neu erzeugt

## Windows-native Final-Gates

Vor einem produktiven Release müssen auf Windows zusätzlich `build/Test-GeDefenseRelease.ps1`, PowerShell-AST-Parsing, `go test -race ./...`, reale Dynamic-Keyword- und Static-Fallback-Transaktionen, Security-Event-5157-Ingestion sowie installierter Service-/Firewall-Reconcile gegen ein isoliertes Testsystem ausgeführt werden. Der Beta-Status bleibt bestehen, bis diese Windows-native Laufzeitverifikation abgeschlossen ist.

Technische Details: [docs/THREAT-INTELLIGENCE.md](docs/THREAT-INTELLIGENCE.md)
