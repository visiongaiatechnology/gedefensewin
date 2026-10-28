# Betrieb

## Windows-Dienst

- Dienstname: `VGTGeDefense`
- Identität: `LocalSystem`
- Starttyp: `Automatic`
- API: `127.0.0.1:17831`
- Programm: `%ProgramFiles%\VGT\GeDefense`
- Daten: `%ProgramData%\VGT\GeDefense`

## Empfohlener Standard

- MHX: Guarded
- App Control: Audit
- Hardening: Enterprise Balanced
- Integrity: erst nach Wartungsfenster aktivieren
- Feed-Synchronisation: alle 12 Stunden

## Wartungsfenster für Integrity

Der erste Scan hasht alle regulären Dateien auf festen Laufwerken und kann erhebliche I/O-Last erzeugen. Auf Servern, Entwicklungsmaschinen und großen Datenträgern muss er in einem Wartungsfenster gestartet werden. Nach der Baseline zeigen Folgescans neue, veränderte und gelöschte Dateien.

## Riskante Schutzprofile

Sovereign, Isolation, USB-Sperre und Controlled Folder Access können legitime Anwendungen oder Administration beeinträchtigen. Vor Aktivierung sind Systemabbild, Wiederherstellungszugang und eine dokumentierte Freigabeliste erforderlich.

## Diagnose

Statusdaten werden über das Security Center gelesen. Schutzwürdige Dateien unter ProgramData besitzen absichtlich keine allgemeinen Leserechte. ACLs sollen nicht zur bequemeren Diagnose abgeschwächt werden; Diagnosen erfolgen über die authentifizierte API oder einen explizit erhöhten, administrativen Prozess. Center und Tray lesen den Dashboard-Token nicht mehr; sie erhalten kurzlebige, per Windows-Prozesstoken verifizierte Operator-Sessions vom Dienst.

## Center-/Tray-Start und Diagnose

Center und Tray sollen immer im Kontext des angemeldeten Standardbenutzers starten. Wird eine
der Anwendungen erhöht gestartet (z. B. Tray-Start durch den UAC-auto-elevierten Installer),
startet sie sich über das Shell-Prozesstoken automatisch unprivilegiert neu; der
Relaunch-Marker `VGT_UI_LAUNCHED_UNELEVATED` verhindert eine Relaunch-Schleife. Schlägt die
De-Elevation fehl, wird dies protokolliert und der erhöhte Weiterlauf bleibt ein
dokumentierter Fallback.

Startfehler des Centers werden kategorisiert (Broker, Browser, Host, Start, Profil,
Elevation) und pro Benutzer protokolliert:

- Log: `%LocalAppData%\VGT\GeDefense\logs\center-launch.log`
- Verzeichnis 0700, Datei 0600, Rotation bei 256 KiB nach `center-launch.log.1`
- Inhalt: UTC-Zeitstempel, Kategorie, Fehlertext, Elevated-Flag, Browser-Pfad — keine
  Token, Session-IDs, Secrets oder vollständigen Kommandozeilen.

Die im Fehlerdialog genannte Ursache und der Logpfad sind für die Diagnose maßgeblich; die
authentifizierte API bleibt der primäre Statusweg. Transiente Brokerfehler (Transport,
HTTP 429/502/503/504) werden automatisch bis zu dreimal mit kurzem Backoff wiederholt;
400/401/403/409 gelten als endgültig und werden nicht wiederholt.

**Erstinstallation:** Der Installer legt die lokale Gruppe `VGT GeDefense Operators` an bzw.
verwendet sie und fügt den installierenden Benutzer hinzu. Center und Tray authentifizieren
sich danach sofort — ohne Ab- und Anmeldung. Der Operator-Broker prüft dafür die autoritative
SAM-Mitgliedschaft der Peer-User-SID, wenn die Gruppe im Anmeldetoken noch fehlt; ein
Widerruf der Gruppenmitgliedschaft wirkt auf neue Broker-Anfragen sofort.

## Titan-Listen und Live-Aktualisierung

Die Titan-Ansicht (Ingress-Timeline, Quarantäne, Checkpoints, Sensoren, Watch-Roots,
Security-Controls, Entwicklungsbäume, Permits und Policy-Regeln) wird im 6-Sekunden-Takt
live aktualisiert. Die Listen-Position bleibt dabei erhalten: eine offene Belegzeile behält
ihre Bildschirmposition, eine am Anfang stehende Liste bleibt am Anfang, und unveränderte
Listen werden nicht neu aufgebaut. Filter-, Tab- oder Seitenwechsel setzen die Position
bewusst zurück. Geöffnete Belege und der Tastaturfokus bleiben bei der Aktualisierung
erhalten; neue Ereignisse werden gebündelt gemeldet, statt die große Ereignisliste erneut
vorlesen zu lassen. Ungespeicherte Änderungen der Owner-Policy werden durch den
Live-Refresh nicht überschrieben.

Sollte sich die Ansicht wider Erwarten zurücksetzen, ist zu prüfen, ob der Dienst in der
erwarteten Version läuft (`GET /api/v1/status`) und die eingebettete UI nach einem
Browser-Neuladen verwendet wird; die Web-Assets sind in die Dienst-Binärdatei eingebettet
und werden nicht separat ausgeliefert.

## Externer Evidenz-Witness (optional)

Das Evidenz-Ledger kann einen externen Witness-Tip auf einem vom Host getrennten Speicherort (z. B. verschreibbares Netzlaufwerk, Wechselmedium) führen:

```powershell
# Maschinenweit für den Dienst setzen (Beispielpfad außerhalb von %ProgramData%\VGT\GeDefense):
[Environment]::SetEnvironmentVariable('VGT_EVIDENCE_WITNESS', '\\witness-host\vgt\gedefense-witness.json', 'Machine')
```

- Der Pfad muss absolut und außerhalb des Datenverzeichnisses liegen; relative Pfade und Pfade im dataRoot werden abgelehnt.
- Der Witness enthält nur Sequenz, letzten MAC, Signatur und Public-Key-Fingerprint — keine Secrets.
- Beim Start wird ein Witness-Tip vor dem lokalen Ledger als Truncation/Rollback erkannt und **fail-closed** abgewiesen; ein fehlendes/nicht erreichbares Medium führt zu einem dokumentierten `DEGRADED`-Status (Verfügbarkeit), nicht zu stillem Ignorieren.
- Nach einem autorisierten Reset des dataRoot mit neuem Evidenz-Key muss der alte Witness entfernt werden, sonst verweigert der Start den „different evidence key“-Zustand.

## Deinstallation

Die Deinstallation verwendet den installierten Setup-Broker und stellt von GeDefense verwaltete Schutzrichtlinien soweit vorgesehen zurück. Vor der Entfernung müssen relevante Evidenz und Integrity-Berichte exportiert werden, wenn sie aufbewahrt werden sollen.

