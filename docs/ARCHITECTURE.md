# Architektur

## Sicherheitsgrenzen

```text
Operator
  │
  ▼
GeDefenseCenter.exe / GeDefenseTray.exe
  │  kurzlebiger Bootstrap, Loopback HTTP
  ▼
127.0.0.1:17831
  │
  ▼
VGTGeDefense Windows Service (LocalSystem)
  ├─ Hardening Engine ── signierte PowerShell-Transaktionen
  ├─ SafetySys Audit ─── read-only Windows-Posture
  ├─ MHX Engine ──────── Prozess- und Defender-Ereignisse
  ├─ Feed Manager ────── Feodo/Spamhaus → Firewall-Regeln
  ├─ Integrity Engine ── SHA-256-Snapshot-Generationen
  └─ Evidence Ledger ─── HMAC-SHA-256-Kette
```

Die UI besitzt keine direkten Administratorrechte. Zustandsänderungen laufen ausschließlich über die authentifizierte Loopback-API und den als LocalSystem gestarteten Dienst.

## Control Plane

- Bindung ausschließlich an `127.0.0.1:17831`
- Host- und Origin-Prüfung
- zufälliges Dashboard-Token im geschützten ProgramData-Verzeichnis
- einmaliger Bootstrap-Code für das native Center
- Bearer-Sitzung und eindeutige Request-ID für zustandsändernde Operationen
- keine externen UI-Ressourcen oder CDNs

## MHX

Der Windows-CIM-Provider beobachtet ausgewählte Script Hosts und LOLBins. Ereignisse enthalten Prozesspfad, Befehlszeile, Signaturstatus, Parent-Identität und begrenzte Prozesskette. EncodedCommand wird vor der effektiven Entscheidung dekodiert und inhaltlich bewertet.

Die Modi sind:

- `monitor`: Analyse und Evidenz ohne MHX-Prozessterminierung
- `guarded`: kontextuelle Blockade und Terminierung
- `sovereign`: Guarded plus restriktive Netzwerk- und App-Control-Politik

Windows App Control steht in Monitor und Guarded auf Audit. Sovereign kann nach expliziter Bestätigung Kernel-Enforcement aktivieren.

## Integrity

Der Scanner enumeriert feste Laufwerke, überspringt Reparse Points und systemkritische Verwaltungsverzeichnisse und schreibt 256 nach Pfad-Hash partitionierte Manifeste. Generationen werden erst nach vollständigem Schreiben atomar aktiviert. Vergleiche werden bucketweise gestreamt, um den Arbeitsspeicherbedarf zu begrenzen.

## Persistenz

Laufzeitdaten liegen unter `%ProgramData%\VGT\GeDefense` mit restriktiven ACLs. Programmdateien liegen unter `%ProgramFiles%\VGT\GeDefense`. Benutzer erhalten ausschließlich die für UI und Tray erforderlichen Leserechte.

## Fail-closed- und Fail-safe-Grenzen

- ungültige Feed-Generationen werden nicht ausgerollt; die letzte gültige Generation bleibt aktiv
- Sovereign benötigt eine exakte Bestätigungsphrase
- nicht unterstützte Hardening-Komponenten werden abgelehnt
- Integrity wird nicht automatisch aktiviert
- Telemetrie ohne Heartbeat wird als `DEGRADED` gemeldet
- eine Klassifikation `BLOCK` erhöht den Blockzähler erst nach erfolgreicher Prozessbeendigung

