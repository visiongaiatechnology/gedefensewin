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
| unautorisierter API-Zugriff | Loopback, RemoteAddr/Host/Origin, Master-Token (Break-Glass, SYSTEM/Administratoren-only) oder per Windows-Prozesstoken verifizierte Operator-Broker-Session mit Scopes; One-Time-Bootstrap nur noch als administrativer Kompatibilitätspfad |
| Rollen-/Client-Verwechslung | getrennte Scopes (read/operate/policy/window), OS-Konto-Attribution der Broker-Session, widerrufbare Sessions; Center/Tray lesen den Master-Token nicht mehr |
| Stale Operator-Token nach Gruppenänderung | SAM-Mitgliedschaft der Peer-User-SID ist für neue Broker-Anfragen autoritativ (exakter SID-Vergleich, begrenzte Abfrage, fail-closed bei SAM-Fehler); Administrators bleibt tokenbasiert. Widerruf wirkt auf neue Anfragen sofort; ein altes Token kann die Gruppe bis zur Abmeldung weiterführen (dokumentierte Restlaufzeit) |
| Erhöhte Bedienoberfläche | Center, Tray und Installer-Tray starten grundsätzlich als Standardbenutzer; bei erhöhtem Start erfolgt eine De-Elevation über das Shell-Prozesstoken (marker-geschützt, kein Endlos-Relaunch). Ein Fehlschlag wird protokolliert; der erhöhte Weiterlauf ist ein dokumentierter Fallback, kein stiller Zustand |
| Nicht diagnostizierbare Startfehler | Kategorisierte Diagnose (broker/browser/host/startup/profile/elevation) nach `%LocalAppData%\VGT\GeDefense\logs\center-launch.log` (Verzeichnis 0700, Datei 0600, 256 KiB Rotation, keine Token/Secrets); Meldung nennt Ursache und Logpfad |
| Replay | kryptografische Request-ID und bounded Replay-Fenster, verpflichtend für jede Mutation |
| Session-/Cardinality-Flood | feste Obergrenzen für Sessions, Bootstrap, Replay und Rate-State |
| PID-Reuse | Creation-Time- und Image-Revalidierung vor Korrelation und Termination |
| Feed-Manipulation | TLS, Größen-/Indikatorlimits, Prefix-Validierung, atomare Generation |
| Feed verursacht Selbstsperre | private/lokale/reservierte und gefährlich breite Netze werden abgelehnt |
| EncodedCommand-Umgehung | bounded Decode, Inhaltsanalyse, Provenance und Hash-Evidenz; angehängte `-EncodedCommand:<base64>`-Schalter werden ebenfalls zerlegt |
| Telemetrie-Blindheit durch fehlende Audit-Richtlinie | Audit-Vorbedingungen (`Audit Process Creation`, `ProcessCreationIncludeCmdLine_Enabled`, WFP-Audit) werden durch die Härtung gesetzt; fehlende Voraussetzungen werden als Sensorverlust/-degradation ausgewiesen, nicht als „keine Ereignisse“ |
| Umbenannte Systembinärdateien | PE-`OriginalFilename`-/Relocation-Prüfung ergänzt Pfad- und Namensprüfung des Prozesssensors |
| falsche Known-good-Freigabe | Zweck-, Payload-, Signatur- und Parent-Prüfung |
| Evidenzmanipulation | HMAC-SHA-256-Kette, SIGNIERTE Checkpoints, geschützte SYSTEM-/Administratoren-ACLs und optionaler externer Witness mit Truncation-Erkennung |
| File-Race/Reparse | handlebasierte Prüfung, Reparse-Reject, Vor-/Nach-Metadaten |
| Ressourcenerschöpfung | bounded Channels, State, Feeds, API-Bodies und Integrity-Manifeste |
| gefährliche Bedienhandlung | Guided Activation mit serverseitiger Readiness |
| Ereignisflut/Ablenkung im Live-UI | 6-Sekunden-Polling ersetzt unveränderte Listen nicht (Signatur-No-Op), erhält Scrollposition, Fokus und offene Belege und meldet neue Ereignisse gebündelt; die große Ereignisliste ist keine Live-Region mehr; bestehende Listen-, Queue- und Exportgrenzen begrenzen die Ereigniszahl weiterhin |
| Supply Chain | Zero-Go-Dependency, SBOM, signierter Payload, Release-Gates |

## Telemetrie-Sensoren (5.2.1)

MHX bezieht Telemetrie aus nativen Windows-Ereignisabonnements über `wevtapi.dll` (`EvtSubscribe`) statt aus persistenten PowerShell-Telemetrieprozessen:

- **Security 4688 — Prozesserstellung:** Prozess-ID, Image, CommandLine und Parent-PID. Setzt `Audit Process Creation` und `ProcessCreationIncludeCmdLine_Enabled` voraus; die GeDefense-Härtung aktiviert beides.
- **Microsoft-Windows-Windows Defender/Operational:** 1116, 1117, 5001, 5010, 5012 (nur lesend).
- **Security 5157 — WFP-Blocks:** `FilterOrigin` und GeDefense-Regelpräfixe bleiben für die Korrelation erhalten; setzt die WFP-Audit-Richtlinie voraus.

Der Dienst hält dadurch keine persistenten `powershell.exe`-Telemetrieprozesse mehr. Prozess-, Defender- und WFP-Sensor laufen unter begrenzten Backoff-Supervisoren. Fehlt eine Audit-Voraussetzung, wird die betroffene Quelle als eingeschränkt/degradiert behandelt; es werden weder Ereignisse noch Attributionen erfunden. Der Prozesssensor prüft zusätzlich die PE-`OriginalFilename`-/Relocation-Informationen erkannter Systembinärdateien, damit umbenannte Systemwerkzeuge nicht allein anhand des Dateinamens beurteilt werden.

## Operator-Authentifizierung und UI-Start (5.2.2)

Der Operator-Broker autorisiert lokale Center-/Tray-Aufrufe fail-closed und gebunden an die
verifizierte Peer-Identität:

- **Token-Pfad:** Der Windows-Prozesstoken des Loopback-Aufrufers muss die lokale Gruppe
  `VGT GeDefense Operators` (enable-only; deny-only wird verworfen) oder Administrators
  enthalten. Administrators-Autorität wird nicht auf SAM ausgeweitet.
- **SAM-Fallback:** Fehlt die Operatorengruppe im Token (typisch direkt nach der
  Erstinstallation, wenn `Add-LocalGroupMember` erst mit der nächsten Anmeldung im Token
  erscheint), prüft der Dienst die Mitgliedschaft der Peer-User-SID über
  `netapi32!NetLocalGroupGetMembers` gegen die per Registry gepinnte Gruppen-SID
  (`OperatorGroupSid`). Es werden exakt SIDs verglichen, nie Namen oder Client-Angaben; die
  Abfrage ist begrenzt (max. 8192 Mitglieder, 1 MiB Puffer, 8 Resume-Aufrufe) und scheitert
  fail-closed. Eine deny-only- oder deaktivierte Token-Gruppe ist eine bewusste Einschränkung und wird vom SAM-Fallback nicht überschrieben. SAM ist damit die autoritative Quelle für neue Anfragen: Ein Widerruf wirkt
  auf die nächste Broker-Anfrage; ein bereits ausgestelltes Token kann die alte Gruppe bis
  zur Abmeldung weiterführen (dokumentierte Restlaufzeit).
- **UI-Integrität:** Center, Tray und der vom Installer gestartete Tray sollen als
  Standardbenutzer laufen. Eine erhöht gestartete Instanz startet sich über den
  Shell-Prozesstoken unprivilegiert neu (`CreateProcessWithTokenW`, Marker
  `VGT_UI_LAUNCHED_UNELEVATED`); Argumente sind validiert und begrenzt, der Fallback ohne
  Argumente nutzt `explorer.exe` mit validiertem absolutem Pfad. Ein Fehlschlag wird
  diagnostiziert; der erhöhte Weiterlauf ist ein dokumentierter Fallback.
- **Diagnose ohne Secrets:** Der Center-Launch-Log enthält UTC-Zeitstempel, Fehlerkategorie,
  Fehlertext, Elevated-Flag und Browser-Pfad — keine Token, Session-IDs, Secrets oder
  vollständigen Kommandozeilen. Transiente Brokerfehler werden begrenzt wiederholt
  (Transport/HTTP 429/502/503/504, max. 3 Versuche, 300/600 ms Backoff); 400/401/403/409
  gelten als endgültig.

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
