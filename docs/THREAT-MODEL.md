# Threat Model

## Schutzobjekte

- Integrität des GeDefense-Diensts und seiner Richtlinien
- Operator-Sitzung und Dashboard-Token
- Defender-, Firewall- und App-Control-Konfiguration
- MHX-Entscheidungen und Prozessidentitäten
- Threat-Intel-Generationen und Netzwerk-Korrelation
- Integrity-Snapshots und Evidenzkette
- Release-Signaturen und Markenvertrauen

## Angreifermodelle

1. nicht privilegierter lokaler Benutzer
2. kompromittierter Benutzerprozess
3. Malware mit Benutzerrechten
4. lokaler Administrator
5. manipulierter Feed- oder Netzwerkpfad
6. kompromittierte Buildkette

Ein lokaler Administrator und Kernel-Code liegen außerhalb einer absoluten Schutzgarantie. GeDefense kann keinen externen vertrauenswürdigen Hypervisor ersetzen.

## Primäre Gegenmaßnahmen

| Bedrohung | Gegenmaßnahme |
|---|---|
| unautorisierter API-Zugriff | Loopback, RemoteAddr/Host/Origin, Master-Token, One-Time-Bootstrap |
| Replay | kryptografische Request-ID und bounded Replay-Fenster |
| Session-/Cardinality-Flood | feste Obergrenzen für Sessions, Bootstrap, Replay und Rate-State |
| PID-Reuse | Creation-Time- und Image-Revalidierung vor Korrelation und Termination |
| Feed-Manipulation | TLS, Größen-/Indikatorlimits, Prefix-Validierung, atomare Generation |
| Feed verursacht Selbstsperre | private/lokale/reservierte und gefährlich breite Netze werden abgelehnt |
| EncodedCommand-Umgehung | bounded Decode, Inhaltsanalyse, Provenance und Hash-Evidenz |
| falsche Known-good-Freigabe | Zweck-, Payload-, Signatur- und Parent-Prüfung |
| Evidenzmanipulation | HMAC-SHA-256-Kette und geschützte ACLs |
| File-Race/Reparse | handlebasierte Prüfung, Reparse-Reject, Vor-/Nach-Metadaten |
| Ressourcenerschöpfung | bounded Channels, State, Feeds, API-Bodies und Integrity-Manifeste |
| gefährliche Bedienhandlung | Guided Activation mit serverseitiger Readiness |
| Supply Chain | Zero-Go-Dependency, SBOM, signierter Payload, Release-Gates |

## Datenschutz / Datenminimierung

Verdächtige PowerShell- oder XDR-Command-Lines werden nicht als Rohpayload in Findings persistiert. Stattdessen werden SHA-256, Länge und notwendige Metadaten verwendet. Secrets und vollständige Scriptinhalte sind kein UI-Telemetrieziel.

## Bekannte Grenzen

- kein eigener Kernel-Sensor oder Minifilter
- kein Cloud-SIEM oder Flottenmanagement
- keine Malware-Sandbox
- lokale Administratoren können Host-Sicherheitsmechanismen letztlich verändern
- Full-Disk-Integrity bewertet Veränderungen nicht automatisch als legitim oder bösartig

## Sicherheitsentscheidung

Erkennung und Durchsetzung sind getrennte Zustände. Die UI darf „blockiert“ nur ausweisen, wenn die Durchsetzungsoperation erfolgreich und die Zielprozessidentität erneut validiert wurde.
