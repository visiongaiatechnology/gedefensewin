# Threat Model

## Schutzobjekte

- Integrität des GeDefense-Diensts und seiner Richtlinien
- Operator-Sitzung und Dashboard-Token
- Windows-Defender- und Firewall-Konfiguration
- MHX-Entscheidungen, Feed-Generationen und Allow-Regeln
- Integrity-Snapshots und Evidenzkette
- offizielle Release-Signaturen und Markenvertrauen

## Angreifermodelle

1. nicht privilegierter lokaler Benutzer
2. kompromittierter Benutzerprozess
3. Malware mit Benutzerrechten
4. lokaler Administrator
5. manipulierter Feed- oder Netzwerkpfad
6. kompromittierte Build- oder Abhängigkeitskette

Ein lokaler Administrator und Kernel-Code liegen außerhalb einer absoluten Schutzgarantie: Beide können letztlich Dienst, Dateien oder Betriebssystemkontrollen verändern. GeDefense soll solche Änderungen sichtbar machen, erschweren und beweissicher protokollieren, kann aber keinen vertrauenswürdigen Hypervisor außerhalb des kompromittierten Hosts ersetzen.

## Primäre Gegenmaßnahmen

| Bedrohung | Gegenmaßnahme |
|---|---|
| unautorisierter API-Zugriff | Loopback-Bindung, Host/Origin-Prüfung, Token und One-Time-Bootstrap |
| Replay zustandsändernder Anfragen | kryptografische Request-ID und begrenztes Replay-Fenster |
| Pfadmanipulation | absolute Pfade, Lstat, Reparse-Prüfung und definierte Jails |
| Feed-Manipulation | TLS 1.2+, Größenlimits, Parser-Validierung, Attribution und atomare Generation |
| EncodedCommand-Umgehung | Dekodierung, Inhaltsanalyse, Signatur- und Parent-Korrelation |
| falsche Known-good-Freigabe | Zweck-, Payload-, Signatur- und Parent-Prüfung; Herkunft allein reicht nicht |
| Evidenzmanipulation | sequenzielle HMAC-SHA-256-Kette und geschützte ACLs |
| Ressourcenerschöpfung | Größenlimits, begrenzte Kanäle, partitionierte Integrity-Manifeste |
| gefährliche Bedienhandlung | explizite Bestätigungsphrasen und Opt-in für destruktive Profile |
| Supply Chain | `go.sum`, SBOM, Drittanbieterlizenzen, signierter Payload und reproduzierbare Tests |

## Bekannte Grenzen

- kein eigener Kernel-Sensor oder ETW-Minifilter
- keine garantierte Prozessattribution allein durch Firewall-Blockereignisse
- kein Cloud-SIEM oder zentrales Flottenmanagement
- keine Malware-Sandbox
- selbst signierte Community-Builds besitzen nicht das Vertrauensniveau offizieller Releases
- Full-Disk-Integrity misst Veränderungen, bewertet aber nicht automatisch deren Legitimität

## Sicherheitsentscheidung

Eine Erkennung und eine Durchsetzung sind getrennte Zustände. Die UI darf „blockiert“ nur ausweisen, wenn die Durchsetzungsoperation erfolgreich war. Fehler werden in der Evidenz sichtbar und dürfen nicht als Erfolg maskiert werden.

