# Security Policy

## Unterstützte Versionen

| Version | Sicherheitsupdates |
|---|---|
| 2.3.x | Ja |
| kleiner als 2.3 | Nein |

## Vertrauliche Meldung

Sicherheitslücken dürfen nicht zusammen mit Exploit-Code, Zugangsdaten oder personenbezogenen Diagnosedaten als öffentliches GitHub-Issue veröffentlicht werden.

Verwende GitHub Private Vulnerability Reporting im Bereich **Security → Report a vulnerability** des Repositorys. Falls diese Funktion nicht verfügbar ist, veröffentliche zunächst ausschließlich eine kontaktfreie Ankündigung ohne technische Details im Issue-Tracker und bitte die Maintainer um einen privaten Kanal.

Eine Meldung sollte enthalten:

- betroffene Version und Windows-Build
- betroffene Schutzschicht
- reproduzierbare Schritte mit harmloser Demonstration
- erwartetes und tatsächliches Verhalten
- Sicherheitsauswirkung und benötigte Berechtigungen
- bekannte Gegenmaßnahmen
- Hashes relevanter Testartefakte, aber keine Malware-Binaries

## Reaktionsziel

- Eingangsbestätigung: innerhalb von 3 Werktagen
- erste technische Einstufung: innerhalb von 7 Werktagen
- koordinierter Zeitplan nach Auswirkung und Patch-Komplexität

## Geltungsbereich

Im Scope liegen Dienst, Loopback-API, Bootstrap, Security Center, Tray, Installer, MHX, Integrity, Hardening, SafetySys, Evidenzkette und Update-/Feed-Validierung.

Nicht im Scope liegen Schwachstellen in unveränderten Microsoft-Komponenten oder Drittanbieter-Abhängigkeiten; entsprechende Meldungen werden an den jeweiligen Upstream weitergeleitet.

## Safe Harbor

Autorisierte Forschung muss auf eigenen Systemen oder mit ausdrücklicher Zustimmung erfolgen, Datenminimierung einhalten und darf keine fremden Systeme, Konten oder Netzwerke beeinträchtigen. VGT verfolgt keine gutgläubige Forschung, die diese Bedingungen und das koordinierte Verfahren einhält.

