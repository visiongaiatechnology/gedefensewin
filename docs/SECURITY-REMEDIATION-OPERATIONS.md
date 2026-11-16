# GeDefense Windows — Security Remediation Operations (5.3.1)

**Scope:** operative Verfahren für die in `VGT-SEC-GEDEFENSE-WIN-520-20261116`
behobenen Integritäts- und Fail-Closed-Pfade. Dieses Dokument beschreibt, was ein
Betreiber tun muss, wenn eine dieser Grenzen auslöst. Es enthält keine erfundenen
Tool-Aufrufe; alle Pfade und Funktionen verweisen auf den tatsächlichen Code.

---

## 1. Evidence-Anker: Fail-Closed nach Upgrade (`FIND-WIN-016`)

**Verhalten:** Ist `evidence.jsonl` nicht leer, aber die signierten Checkpoints
fehlen oder sind beschädigt, verweigert der Ledger den Start mit
`ErrEvidenceCheckpointAnchorMissing` bzw. `ErrEvidenceHighWaterRollback`. Das ist
gewollt: eine stillschweigend neu signierte, verkürzte Kette wäre ein
Tail-Truncation-Bypass.

**Diagnose**

1. Dienststatus und Ledger-Fehler aus dem Diagnoseprotokoll lesen
   (`%ProgramData%\VGT\GeDefense\...`, Kategorie Titan/Service).
2. Prüfen, ob `evidence.jsonl` Einträge enthält, aber `checkpoints.jsonl` /
   `evidence.jsonl.highwater.json` fehlen (Dateisystembeleg, kein Raten).

**Wiederherstellung (nur durch autorisierten Operator, einmalig)**

- `evidence.RecoverCheckpointAnchors(evidencePath, keyPath, options, reason)`
  aufrufen (Paket `internal/evidence`, Datei `recovery.go`). Der Aufruf
  verlangt einen begründeten Operator-Reason, verifiziert HMAC-Kette und
  optionalen Witness, archiviert die alten Anker unverändert als
  `.recovery-<stamp>` und schreibt einen auditierbaren
  `evidence.recovery/checkpoint-reanchor`-Record, **bevor** neue Tip-Checkpoints
  und der High-Water-Anker entstehen.
- Rotation, Append oder ein normaler Neustart lösen diese Recovery **nie**
  automatisch aus.
- Nach der Recovery: Dienst neu starten und `Verify()`-Status prüfen
  (`journalVerified=true`, kein `journalError`).

**Restrisiko:** Ein konsistenter Full-Rollback von Evidence + Checkpoints +
High-Water ist ohne externen Witness (`VGT_EVIDENCE_WITNESS`) nicht erkennbar.

---

## 2. Quarantäne-Metadaten-Integrität (`FIND-WIN-012` / `FIND-WIN-021`)

**Verhalten:** Ein `<id>.json` im Quarantäne-Vault, dessen authentifizierter
MAC nicht mehr verifiziert, wird **nicht** neu signiert. Der Dienst startet
weiter (Schutz bleibt aktiv), der Zustand ist `DEGRADED`, der Eintrag ist für
Restore/Review gesperrt, und `Status.QuarantineIntegrity` listet ID + Detail.
Ein manipuliertes `originalPath` kann dadurch nicht beim Neustart „abgesegnet"
werden.

**Betreiberverfahren**

1. `GET /api/v1/titan/status` → `quarantineIntegrity` prüfen (nur IDs/Details,
   keine Secrets).
2. Betroffene Einträge **nicht** über die UI wiederherstellen; sie sind
   serverseitig gesperrt.
3. Forensik: die Datei byte-identisch sichern (sie wurde nicht neu geschrieben),
   Herkunft/Änderungszeit prüfen.
4. Einzelne Einträge bewusst aufgeben (löschen) oder nach dokumentierter
   Prüfung den Vault-Eintrag durch einen sauberen Neu-Import ersetzen — kein
   Re-Signieren alter, ungeprüfter Metadaten.

**Mark-of-the-Web:** Restore schreibt `:Zone.Identifier` aus dem
authentifizierten Sidecar `<id>.zone` zurück. Fehlt er (Legacy-Eintrag) oder
schlägt das ADS-Schreiben fehl, lautet der Zustand `RESTORED_DEGRADED` mit
`restoreReason`; die UI zeigt „Wiederhergestellt · eingeschränkt" statt
fälschlich „isoliert".

---

## 3. Threat-Intelligence-Autorität (`FIND-WIN-015`)

**Verhalten:** Ohne konfigurierte, verifizierte Ed25519-Autorität
(`keys/feed-authority.pubkeys.json` unterhalb des MHX-Intelligence-Roots) werden
Feeds nur **angezeigt und auditiert** (`FeedAuthenticity=UNVERIFIED`,
`FeedEnforcement=DISABLED_UNAUTHORIZED`). Es gibt kein stilles
Enforcement auf unsignierten Listen. `ANNOTATE_ONLY`-Feeds können zentral nicht
zu Blocking hochgestuft werden.

**Provisionierung**

1. Signierten Autoritätsdatensatz (`feed-authority.json`) und den zugehörigen
   öffentlichen Schlüsselring (`keys/feed-authority.pubkeys.json`, nur
   Public Keys) durch VGT-Release bzw. den Feed-Anbieter bereitstellen.
2. Schlüsselring-Datei restriktiv ablegen (SYSTEM/Administrators), Größe ≤ 64 KiB
   gemäß Code-Grenze.
3. Nach Neustart Status prüfen: `feedEnforcement` muss von
   `DISABLED_UNAUTHORIZED` auf den verifizierten Zustand wechseln; erst dann
   wirken signierte Feed-Aktionen.

**Clock-High-Water:** `clock-high-water.json` ist HMAC-geschützt und fail-closed.
Eine unauthentische oder unplausible Datei wird nicht als Wahrheit übernommen;
Status zeigt `feedClockError`.

**Selbst-Lockout-Schutz:** Blockierbare Präfixe müssen mindestens IPv4 `/16`
bzw. IPv6 `/32` breit sein. Loopback, Link-Local/IMDS, Multicast und
konfigurierte DNS-Resolver werden zentral vetoed und aus Compiler-Ausgaben
herausgeschnitten.

---

## 4. V6-Witness (Phase 1)

Der Witness startet nur mit explizit provisionierter Settings-Datei
(`witness/settings.json` unter dem Datenserver-Verzeichnis). Fehlt sie, lautet
der Status `DISABLED`; eine ungültige Datei führt zu `FAULT`, nicht zu einem
stillen Default. Private Schlüssel (Ed25519 + Outbox-Key) werden nur bei
bewusster Aktivierung erzeugt und über die gehärtete Dateiablage geschützt.
Ein Audit-Token für Air-Gap-Export hat das Format `vgtw1:<base64url>` (≤ 2 KiB)
und enthält keine privaten Schlüssel.

---

## 5. Verifikationsbefehle nach Wartung

```powershell
# Dienst läuft und lauscht nur auf Loopback
Get-Service VGTGeDefense | Select-Object Status
Get-NetTCPConnection -LocalPort 17831 -State Listen | Select-Object LocalAddress,OwningProcess

# Evidenz-/Titan-Status (Master-Token erforderlich, siehe OPERATIONS.md)
# GET /api/v1/titan/status → journalVerified, quarantineIntegrity, state
# GET /api/v1/mhx/status   → feedEnforcement, feedClockError, threat intelligence

# Lokale Integritätsprüfung ohne Dienst
cd src\GeDefense\windows
go test -count=1 ./internal/evidence/... ./internal/threatintel/... ./internal/titan/...
```

Alle Aussagen in diesem Runbook sind an den genannten Code gebunden. Wo ein
Nachweis nur mit installiertem Dienst/Administratorrechten möglich ist, ist das
im jeweiligen Abschnitt als Restrisiko benannt.
