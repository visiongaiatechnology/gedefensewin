# GeDefense Titan — Sovereign Endpoint Integrity & Ingress Defense

**Version:** 5.3.0 · **Platform scope:** Windows 11 x64 (Linux adapter follows separately)  
**Product promise:** Detect. Verify. Contain. Preserve.

## 1. Positionierung

Titan ist kein Dateiscanner mit zusätzlichen Alarmen. Titan verbindet fünf Fragen:

1. Was hat sich verändert?
2. Wie ist die Veränderung zustande gekommen, soweit die Plattform das belegen kann?
3. War sie durch die Richtlinie des Besitzers autorisiert?
4. Was hat Titan dagegen getan — und was konnte es nicht tun?
5. Ist der Nachweis auch dann noch prüfbar, wenn der Host selbst nicht mehr vertrauenswürdig ist?

Titan bewertet **Autorisierung, nicht Urheberschaft**. Es behauptet nicht, eine Behörde, Organisation oder Person erkannt zu haben. Die Vertrauensstufen sind:

| Stufe | Bedeutung |
|---|---|
| `AUTHORIZED` | Eine gültige, begrenzte Besitzerfreigabe deckt die Änderung. |
| `TOLERATED` | Beobachtet, aber kein akutes Hochrisikosignal. Kein Freibrief. |
| `UNEXPECTED` | Die Änderung passt nicht zur Owner-Policy. Prüfung erforderlich. |
| `COMPROMISED` | Mehrere belastbare Hochrisikosignale oder eine Sicherheitsabschwächung. |

## 2. Architektur

```text
Platform Sensors (Windows)
  ├─ ReadDirectoryChangesW / SHA-256 / Zone Identifier
  ├─ Service-, Run-, Benutzer-Hive-Inventar
  ├─ Defender/Firewall/LSA/UAC/SMB/RDP/Logging-Messung
  ├─ Secure-Boot-Registry
  ├─ Toolhelp32-Prozessliste + TcpTable
  └─ WFP/Netz-Kontext (nur beobachtend)
            │
            ▼
Event Collector + Provenance
  ├─ normalisiertes Event
  ├─ beobachtete vs. temporale Korrelation
  └─ Telemetrie-/Sensorzustand inkl. Verlust
            │
            ▼
Owner Policy + Trust Engine
  ├─ Risikoklasse, Score, NeedsReview
  ├─ Permits (Pfad + Hash + Aktion + Ablauf)
  └─ Auto-Quarantäne nur bei CONTAIN/STRICT + Opt-in
            │
            ▼
Response
  ├─ ALERT / OBSERVE
  ├─ verschlüsselte Quarantäne
  └─ Restore nur mit Hash- und Zielprüfung
            │
            ▼
Evidence & Witness surface
  ├─ SHA-256-Journalkette
  ├─ Ed25519-signierte Checkpoints
  ├─ Verifikation und begrenzter Export
  └─ lokaler Signaturanker (externer Witness noch nicht konfiguriert)
```

### Kerneigenschaften

- Ereignisgesteuerte native Dateisensoren, ergänzt durch periodische Persistenz-/Sicherheitsmessung.
- Ein gemeinsames Event-Modell mit ausdrücklicher `correlationQuality` (`OBSERVED`, `TEMPORAL`, `NONE`).
- Begrenzte Warteschlangen, Dateigrößen, Eventfenster und Exportgrenzen.
- Keine automatische Löschung von Beweisen, keine erfundene Attribution.

## 3. Windows-Sensoren

### Datei- und Ingress-Sensor

`ReadDirectoryChangesW` läuft als overlapped Read mit Completion-Event, CancelIoEx beim Stoppen und kontrolliertem Overflow-Neustart. Beobachtet werden unter anderem:

- `C:\Windows\System32\Tasks`
- `C:\Windows\System32\GroupPolicy`
- `C:\Windows\System32\drivers`
- `C:\Windows\System32\CodeIntegrity`
- `C:\Windows\Temp`
- Startmenü-Startup-Ordner
- `C:\Users\Public`
- pro Benutzer: Desktop, Downloads, lokaler Temp, Startup-Ordner

Änderungen werden nach einer kurzen Beruhigungsphase gehasht; die Datei wird während des Hashings auf Stabilität geprüft. Der Zone-Identifier wird, sofern vorhanden, als Herkunftshinweis gespeichert. Ein Prozesskontext wird nur dann angehängt, wenn ein Prozessstart innerhalb eines engen Zeitfensters beobachtet wurde; die UI kennzeichnet das als **temporal**, nicht als bewiesene Datei-zu-PID-Zuordnung.

Bekanntes OS-/Treiberrauschen wird nicht als Ingress-Ereignis gespeichert: transiente `__PSScriptPolicyTest_*`-Dateien der PowerShell-ExecutionPolicy-Prüfung, AMD-Treiberdump-Logs unter `System32\drivers\DriverData` sowie nicht-ausführbare/Archiv-Artefakte in `AppData\Local\Temp` und `Windows\Temp`. Ausführbare Dateien und Skripte in Temp bleiben ausdrücklich Beobachtungskandidaten.

### Persistenz- und Sicherheitsinventar

Gemessen werden:

- Dienste unter `HKLM\SYSTEM\CurrentControlSet\Services` (ImagePath, Start, Type, ObjectName)
- Run/RunOnce für HKLM, WOW6432Node und geladene Benutzer-Hives
- Defender-Policy, Echtzeitschutz-Policy, Firewallprofile, LSA-Schutz, UAC, SMBv1, RDP, PowerShell ScriptBlock-Logging
- Secure-Boot-Registryzustand

Die erste Messung erzeugt eine Baseline ohne Alarmierung. Erst spätere Abweichungen werden zu Persistenz- oder Sicherheitsereignissen. Die Baseline wird nur fortgeschrieben, wenn alle zugehörigen Ereignisse erfolgreich in die Evidenzkette geschrieben wurden.

### Prozess- und Netzwerkkontext

Toolhelp32 liefert die Prozessliste; neue PIDs werden über `OpenProcess`/`QueryFullProcessImageNameW` angereichert. Die TCP-Tabelle wird ausschließlich für Kontext genutzt. Es gibt **keine** Behauptung, dass eine Verbindung eine bestimmte Datei übertragen hat.

## 4. Owner Policy

Gespeichert unter `%ProgramData%\VGT\GeDefense\titan\policy.json`, atomar mit 0600.

- **OBSERVE:** nur erfassen und bewerten.
- **CONTAIN:** automatische Quarantäne für neue ausführbare/scriptfähige Hochrisiko-Objekte, wenn der Owner sie aktiviert.
- **STRICT:** zusätzlich strenge Besitzerprüfung; keine automatische Freigabe durch Adminrechte.

Der Modus allein ist keine Freigabe. Hochriskante Objekte benötigen eine konkrete, kurzlebige Freigabe (Pfad, optional Hash, Aktion, Ablauf, Einmaligkeit). Die Owner-UI verwaltet diese **Permits** und protokolliert Erteilung wie Widerruf.

Zusätzlich kann der Owner einen absoluten Source-/Build-Baum als **Entwicklungsbaum** markieren. Dateiereignisse darin bleiben vollständig in der Evidenz, werden aber nicht als Ingress-Hochrisiko eskaliert. System-, Persistenz-, Sicherheits- und Boot-Änderungen bleiben davon unberührt; geschützte Systempfade können nicht markiert werden.

## 5. Quarantäne

`%ProgramData%\VGT\GeDefense\titan\quarantine` enthält:

- `<id>.bin` — AES-256-GCM-verschlüsselter Inhalt mit Nonce und ID als Associated Data
- `<id>.json` — Originalpfad, Name, SHA-256, Größe, Dateityp, Ereignis-ID, Begründung, Zustand
- `vault.key` — 32-Byte-Schlüssel, dateibasiert mit restriktiven Rechten; TPM/DPAPI-Versiegelung ist noch nicht behauptet

Ablauf:

1. Quelle muss eine reguläre Datei ohne Reparse-Punkt sein und innerhalb des Größenlimits liegen.
2. Inhalt lesen, hashen, verschlüsseln, verschlüsselte Kopie durabel schreiben.
3. Metadaten durabel schreiben.
4. Original erst danach entfernen. Schlägt das Entfernen fehl, wird das als `originalGone=false` ausgewiesen.
5. Restore prüft Hash, verweigert das Überschreiben eines vorhandenen Ziels und verwendet einen atomaren Move ohne Replace.

## 6. Evidenz

`%ProgramData%\VGT\GeDefense\titan\evidence` enthält:

- `events.jsonl` — append-only Ereignisse mit Sequenz, Prev-Hash und Event-Hash
- `checkpoints.jsonl` — regelmäßige Ed25519-signierte Checkpoints
- `signing.key` — 32-Byte-Ed25519-Seed, 0600

Die Verifikation prüft:

- lückenlose Sequenz und Prev-Hash-Verkettung
- Hash jedes Ereignisses
- Signatur jedes Checkpoints
- dass jeder Checkpoint auf einen tatsächlich vorhandenen Journal-Hash verweist

Ein beschädigtes Journal wird nicht stillschweigend weiterverwendet: Titan benennt es als Forensikkopie um, startet einen neuen lokalen Epoch und bleibt im Zustand `DEGRADED`, bis ein Operator eingreift.

Ein lokaler Checkpoint ist **tamper-evident**, aber nicht tamper-proof. Der externe Witness ist noch nicht konfiguriert; die UI sagt das ausdrücklich.

## 7. HTTP-API (authentifiziert, Loopback)

| Methode | Pfad | Zweck |
|---|---|---|
| GET | `/api/v1/titan/status` | Gesamtlage, Sensoren, Policy, Boot, Witness, Evidenzstatus |
| GET | `/api/v1/titan/events?limit=&offset=&filter=` | Ingress-Timeline, serverpaginiert |
| GET | `/api/v1/titan/quarantine` | Quarantäneobjekte |
| POST | `/api/v1/titan/events/{id}/quarantine` | Objekt isolieren (Begründung) |
| POST | `/api/v1/titan/events/{id}/acknowledge` | Befund prüfen (Begründung) |
| POST | `/api/v1/titan/quarantine/{id}/restore` | hashgeprüft wiederherstellen |
| POST | `/api/v1/titan/quarantine/{id}/review` | Quarantäne prüfen |
| GET/POST | `/api/v1/titan/policy` | Owner Policy lesen/ändern |
| GET/POST | `/api/v1/titan/permits` | Owner Permits lesen/erzeugen |
| POST | `/api/v1/titan/permits/{id}/revoke` | Owner Permit widerrufen |
| POST | `/api/v1/titan/development-roots` | Entwicklungsbaum markieren |
| POST | `/api/v1/titan/development-roots/remove` | Markierung entfernen |
| GET | `/api/v1/titan/checkpoints` | signierte Checkpoints |
| POST | `/api/v1/titan/verify` | Journal und Signaturen prüfen |
| GET | `/api/v1/titan/export?limit=` | begrenztes Evidenzpaket |

Alle Endpunkte laufen durch die bestehende Authorization-, Origin-, Rate-Limit-, CSP- und Request-ID-Middleware.

## 8. UI

Die Titan-Seite ist in die bestehende Glass-2100-Shell integriert. Seit 5.1.2 nutzt sie dieselbe Material-, Abstands- und Typografiesprache wie der Host: eisblaues Signal als Primärachse, Bronze nur noch als Evidenzakzent, eine kompakte Control-Stage, segmentierte Tabs, dichte Sensorzeilen und Glas-Rail-Karten. Alle sichtbaren Schriftfarben sind weiß; Zustände bleiben über getönte Flächen, Rahmen und Punkte erkennbar. Fünf Bereiche:

- **Lage:** Vertrauenslage, Sensoren, Security Controls, Boot, Witness, Watch-Roots
- **Ingress-Timeline:** Filter, Eventzeilen, Belegdetails, klare Trennung von Fakten und temporalen Hypothesen
- **Quarantäne:** Objekte, Hash, Zustand, Restore und Review
- **Owner Policy:** Modus, Auto-Quarantäne, Regeln und Grenzen
- **Evidenz:** Checkpoints, Verifikation und Export

Keine dekorativen Hintergrundgitter, keine erfundenen KPIs, keine Attribution.

**Live-Aktualisierung und Lesbarkeit:** Die Titan-Listen — insbesondere die
Ingress-Timeline — werden alle 6 Sekunden aktualisiert, ohne die Ansicht nach oben zu
reißen. Eine offene Belegzeile bleibt an derselben Bildschirmposition, eine am Anfang
stehende Liste bleibt am Anfang, und unveränderte Listen werden nicht neu aufgebaut;
Filter-, Tab- und Seitenwechsel springen weiterhin bewusst an den Anfang. Geöffnete
Belege (`<details>`) und der Fokus überstehen die Aktualisierung. Neue Ereignisse werden
gebündelt über die bestehende Live-Region gemeldet; die große Ereignisliste ist keine
Live-Region mehr und wird nicht alle 6 Sekunden vorgelesen. Ungespeicherte
Owner-Policy-Änderungen werden durch den Live-Refresh nicht überschrieben.

## 9. Bewusste Grenzen

- Kein Schutz gegen einen Angreifer mit vollständiger Kernel-, Bootkit- oder Firmware-Kontrolle ohne externen Witness.
- Keine TPM-/Measured-Boot-Attestation in dieser Phase; nur Secure-Boot-Registrystatus.
- Keine aktive Ausführungsblockade per Windows-Minifilter. Quarantäne entfernt die Datei, beendet aber keinen bereits laufenden Prozess.
- Keine universelle Datei-zu-Prozess-Zuordnung; temporale Korrelation wird als solche angezeigt.
- Keine automatische Attribution und keine rechtliche Entlastungsbehauptung.
- Löschen ist kein Standard; die verschlüsselte Beweiskopie bleibt erhalten.
- Linux-Adapter, externer Witness, TPM-Quote und Minifilter sind Folgephasen.

## 10. Tests

- Go-Unit-/Contract-Tests für Policy, Permits, Trust-Mapping, Quarantäne-Roundtrip, Journal-Tampering, Checkpoints, Baseline und SensorLifecycle.
- Native WinAPI-Tests für `ReadDirectoryChangesW`-Erstellung, Sensor-Lifecycle/Stopp und Prozessliste.
- Browser-Fixture für alle fünf Titan-Bereiche, Aktionen, Filter, Restore, Policy-Wechsel, Evidenzprüfung, Desktop und Mobile; 22 Checks inklusive vollständiger Weiß-Typografie und begrenzter Sammelprüfung.
- Startup-Gate prüft den gecachten Monitor-Zustand (`GET /api/v1/health/status`) und blockiert nicht auf Netzwerk-Synchronisation; die vollständige Neumessung bleibt `POST /api/v1/health/refresh`.
- Release-Gate: Go Race, Vet, `gofmt`, vier Windows-Builds, PowerShell-Parser, Frontend-Security, SBOM.

## 11. Nächste Ausbaustufen

1. TPM-Quote/Measured-Boot und Secure-Boot-Attestation mit unabhängiger Prüfung.
2. Externer Witness (Companion/NAS/self-hosted) mit Heartbeat und fehlendem Nachweis als eigener Zustand.
3. Signierter Windows-Minifilter für echte Pre-Write-/Execute-Prävention.
4. Permit-Verwaltung und Wartungsfenster in der UI — Permits sind in 5.1.1 umgesetzt; Wartungsfenster bleiben offen.
5. Linux-Adapter (fanotify, auditd, IMA, TPM2) mit demselben Eventmodell.

## 12. Owner-Toolchain-Prozessketten

Titan speichert zu einem Ereignis eine begrenzte, ausschlieÃŸlich aus der realen
Prozessliste gelesene `processChain` (Leaf first, maximal acht EintrÃ¤ge). Der
Konsolenhost `conhost.exe` wird nicht mehr als Datei-Actor ausgegeben; er ist kein
Schreiber und war die grÃ¶ÃŸte Einzelquelle irrefÃ¼hrender Zuordnungen.

Die Owner-Policy kann mit `ownerProcessImages` explizite, absolute Image-Pfade
freigeben, zum Beispiel den lokalen DeepSeek-Harness-Pfad. Ein Treffer in der
Prozesskette darf **nur** Ingress-/User-Content-Ereignisse auf `TOLERATED`
herabstufen; System-, Persistenz- und SicherheitsÃ¤nderungen bleiben unabhÃ¤ngig
davon prÃ¼fpflichtig. Eine Freigabe ist damit keine AusfÃ¼hrungs- oder
Systemautorisierung und erzeugt weiterhin vollstÃ¤ndige Evidenz.

API: `POST /api/v1/titan/owner-process-images` mit
`{"images":["C:\\Tools\\DeepSeek Harness.exe"],"reason":"...","confirmation":"UPDATE OWNER PROCESS IMAGES"}`.
Die Route ist eine bestÃ¤tigungspflichtige Policy-Mutation; sie ist nicht als
allgemeine Prozess-Allowlist gedacht.
