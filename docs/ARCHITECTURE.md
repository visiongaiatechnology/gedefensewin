# Architektur

## Sicherheitsgrenzen

```text
Operator
  │
  ▼
GeDefenseCenter.exe / GeDefenseTray.exe
  │  lokaler Bootstrap / authentifizierte Loopback-Session
  ▼
127.0.0.1:17831
  │
  ▼
VGTGeDefense Windows Service (LocalSystem)
  ├─ Hardening Engine ── signierte PowerShell-Transaktionen
  ├─ SafetySys Audit ─── read-only Windows-Posture
  ├─ MHX Engine ──────── Prozess-, Defender- und Netzwerk-Ereignisse
  ├─ Native Network ──── TCP-Tabelle → Owning PID
  ├─ Feed Manager ────── Threat Intel → bounded Prefix Index → Firewall
  ├─ Integrity Engine ── SHA-256-Snapshot-Generationen
  └─ Evidence Ledger ─── HMAC-SHA-256-Kette
```

Die UI besitzt keine Administratorrechte. Zustandsänderungen laufen ausschließlich über die authentifizierte Loopback-API und den LocalSystem-Dienst.

## Zero-Go-Dependency

Die Windows-Integration verwendet Go-Standardbibliothek und interne Win32-Wrapper. Tray, Service Control Manager, Prozesshandles, Netzwerk-Telemetrie, Shell-Launch und Dateisystemprimitive benötigen keine externen Go-Module.

## Control Plane

- Bindung ausschließlich an `127.0.0.1:17831`
- RemoteAddr-, Host- und Origin-Prüfung
- geschütztes Master-Token unter ProgramData
- einmaliger Bootstrap-Code
- HttpOnly/SameSite-Session
- replay-geschützte Request-ID für Mutationen
- bounded Replay-, Session-, Bootstrap- und Rate-State
- strikte JSON-Größen- und Schema-Grenzen
- keine externen UI-Ressourcen

## MHX / XDR

Prozessereignisse werden mit Authenticode, SHA-256, Parent und begrenzter Ancestry angereichert. PowerShell EncodedCommand wird bounded dekodiert; persistente Evidenz erhält Hash und Metadaten statt den dekodierten Inhalt.

Native TCP-Telemetrie ordnet Remote-Verbindungen dem Owning PID zu. Eine Korrelation wird nur akzeptiert, wenn PID, Creation Time und Image des beobachteten Prozesses weiterhin übereinstimmen.

```text
Process signal
   +
Threat network destination
   +
stable process identity
   ↓
Attack Story
```

Netzwerkevidenz allein verleiht keine Host-Kill-Autorität.

## Protection Modes

- `monitor`: Analyse und Evidenz ohne MHX-Prozessterminierung
- `guarded`: kontextuelle Response nach unabhängiger Blockentscheidung
- `sovereign`: Guarded plus App-Control-Enforcement und restriktive Netzwerkpolitik

Die UI führt durch Monitor → Guarded → Sovereign. Die Readiness-Entscheidung bleibt serverseitig.

## Integrity

Der Scanner enumeriert feste Laufwerke, öffnet Dateien reparse-sicher, verwendet bounded Worker/Channels, erkennt Änderungen während des Hashings, schreibt partitionierte Manifeste und aktiviert Generationen atomar.

## Persistenz

Laufzeitdaten liegen unter `%ProgramData%\VGT\GeDefense` mit restriktiven ACLs. Programmdateien liegen unter `%ProgramFiles%\VGT\GeDefense`.

## Fail-closed- und Fail-safe-Grenzen

- ungültige Feed-Generationen werden nicht ausgerollt
- gefährlich breite, private, lokale und reservierte Threat-Intel-Netze werden abgelehnt
- Sovereign benötigt serverseitige Readiness und explizite Bestätigung
- Telemetrie ohne Heartbeat wird `DEGRADED`
- ein Blockzähler steigt erst nach erfolgreicher, identitätsvalidierter Prozessbeendigung
- PID-Reuse verhindert Korrelation und Response
