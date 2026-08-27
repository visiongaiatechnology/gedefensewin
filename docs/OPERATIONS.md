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

Statusdaten werden über das Security Center gelesen. Schutzwürdige Dateien unter ProgramData besitzen absichtlich keine allgemeinen Leserechte. ACLs sollen nicht zur bequemeren Diagnose abgeschwächt werden; Diagnosen erfolgen über die authentifizierte API oder einen explizit erhöhten, administrativen Prozess.

## Deinstallation

Die Deinstallation verwendet den installierten Setup-Broker und stellt von GeDefense verwaltete Schutzrichtlinien soweit vorgesehen zurück. Vor der Entfernung müssen relevante Evidenz und Integrity-Berichte exportiert werden, wenn sie aufbewahrt werden sollen.

