# GeDefense Windows — Security Incident Response Runbook

**Version:** 1.0 | **Gültig für:** GeDefense Windows 5.3.0 | **Owner:** VGT Security
**Klassifikation:** intern | **Letzte Übung:** 2026-10-28 (Session-Containment-Drill)

## 1. Sofortmaßnahmen (erste 15 Minuten)

1. **Beweise sichern:** `C:\ProgramData\VGT\GeDefense\evidence.jsonl` und `evidence.jsonl.checkpoints.jsonl` kopieren (MAC-Kette nicht verändern). Titan-Journal unter `titan\evidence\` mitnehmen.
2. **Scope bestimmen:** betroffene Komponente (Service, UI-Session, Installer, Threat-Feed, Quarantäne, Signing-Key) und Zeitfenster anhand der Ledger-Sequenz eingrenzen.
3. **Kein stilles Abschalten:** Schutz nicht deaktivieren, um „Ruhe“ zu erzeugen. Änderungen nur mit Reason + Confirmation über die vorgesehenen Gates.
4. **Kommunikation:** Incident-ID `VGT-IR-YYYYMMDD-NNN`, Entscheider und Uhrzeit im Ledger/Notiz festhalten.

## 2. Break-Glass-Zugriff

- Master-Credential: `C:\ProgramData\VGT\GeDefense\dashboard.token` (nur Administratoren/SYSTEM/Operator-Gruppe).
- Master-Header: `Authorization: Bearer <token>`; Mutationen benötigen zusätzlich `X-VGT-Request-ID` (UUID, einmalig) und — bei schutzreduzierenden Aktionen — typisierte Bestätigung + Begründung.
- Token-Rotation: `POST /api/v1/admin/token/rotate` (Master). Danach alle Sessions serverseitig widerrufen; neue Sessions nur über Peer-gebundenen Browser-Exchange.
- Nach Nutzung: Incident-Token sofort rotieren, alte Kopien vernichten.

## 3. Szenarien

### 3.1 Verdächtige UI-/Operator-Session
1. Session-Token nicht mehr vertrauen.
2. `POST /api/v1/session/logout` mit betroffener Session (oder `POST /api/v1/admin/sessions/revoke-all` bei unklarem Umfang).
3. Neues Peer-gebundenes Browser-Fenster über den Launcher öffnen.
4. Ledger auf `session.lifecycle`, `authorization.policy` und `killerdom.*` prüfen.
5. Drill (2026-10-28): gemintete Session → Status 200; Logout; erneuter Zugriff → 401.

### 3.2 Kompromittierter Service-/Agent-Prozess
1. Keine manuelle `taskkill`-Orgie; Killerdom/Paranoia antworten auf verifizierte Signale.
2. Bei begründetem Verdacht Service stoppen (`sc stop VGTGeDefense`), Speicher-/Prozess-Artefakte sichern, Binary-Hash gegen Release-SHA prüfen.
3. Signierter Neuinstaller aus dem Release-Kanal; Downgrade ist blockiert.
4. Nach Neustart: Titan/Evidenz-Verify ausführen, offene Findings triagieren.

### 3.3 Signing-Key/Kompromittierung der Supply Chain
1. Release-Kanal einfrieren; keine neuen Artefakte mit dem alten Zertifikat.
2. Neuen Signaturschlüssel im kontrollierten Store erzeugen, öffentlichen Teil verteilen.
3. Probelauf: Testbinär mit neuem Zertifikat signieren, Signatur prüfen (Rehearsal 2026-10-28 erfolgreich).
4. Alle Release-Artefakte mit neuem Key neu bauen/signieren; `SHA256SUMS`, SBOM und Provenance neu binden.
5. Alten Key widerrufen, Kunden über neuen Thumbprint/Verify-Anleitung informieren.

### 3.4 Threat-Feed- oder Update-Kompromittierung
1. Feed-Generation/Signatur prüfen; bei Mismatch Last-known-good aktivieren (Feed-Policy-Rollback).
2. Update nicht installieren; Installer-Signatur und Source-Provenance gegen Release-Manifest prüfen.
3. Betroffene Generation im Ledger markieren; Neubewertung aller in diesem Zeitraum blockierten/erlaubten Objekte.

### 3.5 Quarantäne-Fehlentscheidung
1. Objekt-ID/Hash im Quarantäne-Metadatensatz prüfen; Wiederherstellung nur nach Review.
2. False-Positive dokumentieren und Signatur/Regel zentral korrigieren (nicht pro Host).
3. Regressionstest ergänzen, damit dieselbe Klasse nicht erneut fehlklassifiziert.

## 4. Wiederherstellung und Nachbereitung

- Dienststatus, Loopback-API, Schutzmodus, Feed-Generation und Evidenz-Verify nach jedem Eingriff prüfen.
- `POST /api/v1/titan/verify` / Titan-Verifikation und Evidenz-Checkpoint ausführen.
- Root Cause im `Next.md`-Checkpoint festhalten: Zeit, Scope, Beweise, Fix, Tests, Restrisiko.
- Innerhalb von 24 h: Findings/Regressionstests, Kommunikation, ggf. Risk Acceptance mit Ablaufdatum.

## 5. Nachweise / Befehle

```powershell
# Dienststatus
Get-CimInstance Win32_Service -Filter "Name='VGTGeDefense'" | Select State,ProcessId,StartName
# Loopback-Status (Master-Token)
$t=(Get-Content 'C:\ProgramData\VGT\GeDefense\dashboard.token' -Raw).Trim()
Invoke-RestMethod 'http://127.0.0.1:17831/api/v1/titan/status' -Headers @{Authorization="Bearer $t"}
# Evidenz-/Signaturprüfung
Get-AuthenticodeSignature 'C:\Program Files\VGT\GeDefense\bin\gedefense-windows.exe'
Get-FileHash 'C:\Program Files\VGT\GeDefense\bin\gedefense-windows.exe' -Algorithm SHA256
```

## 6. Kontakte / Eskalation

- **Incident Commander:** Operator mit Master-Zugriff.
- **Security Owner:** VGT Security (Freigabe für RISK ACCEPTANCE und Key-Rotation).
- **Release Owner:** VGT Release (signierte Artefakte, Provenance, Rollback).
