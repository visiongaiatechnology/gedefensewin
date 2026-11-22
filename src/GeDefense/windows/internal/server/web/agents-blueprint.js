// STATUS: DIAMANT VGT SUPREME
'use strict';
/**
 * GeDefense Windows 6.1.0 — Offline AGENTS.md & Starter-Prompt Generator.
 *
 * Security invariant (vgt-security-master / user constraint):
 *   - NEVER exposes, contacts, or simulates any central/remote AI API.
 *   - NEVER embeds tokens, secrets, or unvalidated operator text as executable code.
 *   - All host adaptation is performed locally by the user's own AI coding agent
 *     (Codex, Antigravity, Claude Code, etc.) via read-only Windows discovery
 *     followed by authenticated local control-plane API calls (127.0.0.1:17831).
 */

export const AGENT_DEFAULT_VERSION = '6.1.0';
const MAX_CUSTOM_LINES = 32;
const MAX_LINE_LEN = 260;

function localControlOrigin() {
  if (typeof globalThis.location?.origin === 'string' && globalThis.location.origin !== 'null') {
    return globalThis.location.origin;
  }
  return ['http', '127.0.0.1:17831'].join('://');
}

export function sanitizeAgentLines(raw) {
  const source = Array.isArray(raw) ? raw.map(v => String(v ?? '')) : String(raw || '').split(/\r?\n/);
  const cleaned = [];
  const seen = new Set();
  for (const entry of source) {
    const line = entry
      .replace(/[\r\n\t\x00-\x1f\x7f]/g, ' ')
      .replace(/[`]/g, '')
      .trim()
      .slice(0, MAX_LINE_LEN);
    if (!line || seen.has(line)) continue;
    seen.add(line);
    cleaned.push(line);
    if (cleaned.length >= MAX_CUSTOM_LINES) break;
  }
  return cleaned;
}

export function buildAgentStarterPrompt(options = {}) {
  const profile = String(options.profile || 'personal').toLowerCase();
  const profileTitle = String(options.profileTitle || profile);
  const version = sanitizeAgentLines([options.version || AGENT_DEFAULT_VERSION])[0] || AGENT_DEFAULT_VERSION;
  return [
    `Lies AGENTS.md im Detail (GeDefense Windows ${version}, Zielprofil: ${profile} / ${profileTitle}).`,
    `Analysiere dieses Windows-System ZUERST strikt read-only (Windows-Edition, Defender/ASR/CFA, installierte Programme, Entwickler-Toolchains wie Go/Node/Python/Rust/Visual Studio/Docker, laufende Dienste, offene Ports, WDAC/App Control sowie den lokalen Control-Plane-Status unter ${localControlOrigin()}).`,
    'Bewerte jedes Modul (Hardening-Profil, Defender Symbiosis, CFA-Freigaben, App Control Allowlist/Deny, Titan Development Roots & Owner-Prozessketten, Sentinel Signer/SHA-256 Whitelist, StyX Egress) anhand der real genutzten Software und Toolchains.',
    'Schlage deinen konkreten Konfigurationsplan zur Bestätigung vor, wende nach Freigabe die Mutationen mit X-VGT-Request-ID, Begründung und Confirmation-Phrase lokal an und verifiziere abschließend live gegen /api/v1/status, /api/v1/mhx/symbiosis und /api/v1/protection/readiness.',
  ].join(' ');
}

export function buildWindowsAgentsMarkdown(options = {}) {
  const profile = String(options.profile || 'personal').toLowerCase();
  const profileTitle = sanitizeAgentLines([options.profileLabel || profile])[0] || profile;
  const targetProfile = options.targetProfile === 'Isolation' ? 'Isolation' : 'EnterpriseBalanced';
  const titanMode = sanitizeAgentLines([options.titanMode || 'STRICT'])[0] || 'STRICT';
  const autoQuarantine = Boolean(options.autoQuarantine);
  const version = sanitizeAgentLines([options.version || AGENT_DEFAULT_VERSION])[0] || AGENT_DEFAULT_VERSION;
  const platform = sanitizeAgentLines([options.platform || 'Windows 11 / Server x64'])[0] || 'Windows 11 / Server x64';
  const devRoots = sanitizeAgentLines(options.devRoots);
  const ownerProcesses = sanitizeAgentLines(options.ownerProcesses);
  const posture = options.posture && typeof options.posture === 'object' ? options.posture : {};

  const devRootsSection = devRoots.length
    ? devRoots.map(p => `- \`${p}\``).join('\n')
    : '- *(keine vorab eingetragen — in Phase 1 lokal per Toolchain-Scan ermitteln)*';
  const ownerProcSection = ownerProcesses.length
    ? ownerProcesses.map(p => `- \`${p}\``).join('\n')
    : '- *(keine vorab eingetragen — in Phase 1 installierte IDEs/Compiler/SDKs prüfen)*';

  const postureLines = [
    `- **GeDefense Version:** \`${version}\``,
    `- **Erkannte Windows-Plattform:** \`${platform}\``,
    `- **Gewähltes Setup-Profil:** \`${profile}\` (${profileTitle}) → Härtungsprofil \`${targetProfile}\`, Titan \`${titanMode}\`, Auto-Quarantäne \`${autoQuarantine ? 'AN' : 'AUS'}\``,
  ];
  if (posture.protectionMode || posture.protectionHealth) {
    postureLines.push(
      `- **Aktueller Live-Status bei Export:** Schutzmodus \`${sanitizeAgentLines([posture.protectionMode || 'unbekannt'])[0]}\`, Policy \`${sanitizeAgentLines([posture.protectionHealth || 'unbekannt'])[0]}\`, Defender \`${posture.defender ? 'aktiv' : 'prüfen'}\`, CFA \`${posture.cfa ? 'aktiv' : 'prüfen'}\``
    );
  }

  return `# AGENTS.md — Lokale Host-Einrichtung & Härtung für GeDefense Windows ${version}

> **Sicherheitsmodell (Zero Remote AI API):** GeDefense öffnet bewusst **KEINE** zentrale oder entfernte KI-API und sendet keine Prompt-/Systemdaten an Drittserver.
> Du wirst als lokaler Coding-/Admin-Agent direkt auf diesem Windows-System ausgeführt, analysierst Windows-Edition, installierte Programme, Entwickler-Toolchains und Dienste **zuerst strikt read-only**, wägst jede Härtung gegen echte Workloads ab, konfigurierst ausschließlich über die lokale Control Plane (\`${localControlOrigin()}\`) und verifizierst danach live.

---

## 0. Vorgemerkter Host- & Profilkontext

${postureLines.join('\n')}

### Vorgemerkte Entwicklungsbäume (\`titan/development-roots\`)
${devRootsSection}

### Vorgemerkte Owner-Prozessketten (\`titan/owner-process-images\`)
${ownerProcSection}

### Authentifizierungs- & Secret-Hygiene (VERBINDLICH)
1. **Kein Secret-Dump:** Gib den Inhalt von \`%ProgramData%\\VGT\\GeDefense\\dashboard.token\` niemals im Chat aus, speichere ihn in keinen Repository-Dateien, Skripten oder Logs.
2. **Scoped Session bevorzugen:** Nutze im laufenden PowerShell-Prozess ein kurzes Operator-Token (z. B. über \`\$env:VGT_SESSION_TOKEN\` in Memory, nur für die aktuelle Sitzung) und lösche die Variable am Ende wieder (\`Remove-Item Env:VGT_SESSION_TOKEN\`).
3. **Mutationspflichten der Control Plane:** Jede schreibende Anfrage (\`POST\`) benötigt:
   - \`Authorization: Bearer <token>\`
   - \`X-VGT-Request-ID: <UUIDv4>\` (frisch pro Request, Replay-Schutz)
   - aussagekräftiges \`reason\`-Feld (mindestens 8 Zeichen)
   - exakte \`confirmation\`-Phrase (siehe Phase 3), wo serverseitig gefordert.

---

## Phase 1 · Read-Only Windows-, Software- & Toolchain-Analyse

Führe zuerst **nur lesende** PowerShell-Befehle aus. Verändere in Phase 1 noch **keine** Firewall-, Defender-, AppControl- oder Dienstzustände:

\`\`\`powershell
# 1) Windows-Version, Edition & Sicherheitsbasis
Get-ComputerInfo OSName,OSDisplayVersion,OsBuildNumber,CsSystemType
Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled,AMRunningMode
Get-MpPreference | Select-Object EnableControlledFolderAccess,ControlledFolderAccessAllowedApplications,AttackSurfaceReductionRules_Ids,AttackSurfaceReductionRules_Actions
Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction

# 2) Installierte klassische Programme (64-Bit & 32-Bit) + Appx
Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*','HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*','HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*' -ErrorAction SilentlyContinue |
  Where-Object { \$_.DisplayName } |
  Sort-Object DisplayName |
  Select-Object DisplayName,DisplayVersion,Publisher,InstallLocation

# 3) Entwickler-Toolchains, SDKs, Container & IDEs lokalisieren
foreach (\$cmd in @('go','git','node','npm','pnpm','python','py','rustc','cargo','dotnet','cl','msbuild','cmake','ninja','docker','podman','wsl','code')) {
  Get-Command \$cmd -ErrorAction SilentlyContinue | Select-Object Name,Source
}
Get-ChildItem -Path "\$env:ProgramFiles\\Microsoft Visual Studio","\$env:LOCALAPPDATA\\Programs" -Depth 2 -Directory -ErrorAction SilentlyContinue | Select-Object FullName
if (Test-Path 'C:\\Windows\\System32\\citool.exe') { citool.exe --list-policies }

# 4) Laufende Dienste & lauschende TCP-Ports
Get-Service | Where-Object { \$_.Status -eq 'Running' } | Select-Object Name,DisplayName,StartType | Sort-Object Name
Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
  Select-Object LocalAddress,LocalPort,OwningProcess,@{N='Proc';E={(Get-Process -Id \$_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} |
  Sort-Object LocalPort
\`\`\`

---

## Phase 2 · Live-Zustand der lokalen GeDefense-6.1.0-Control-Plane (Read-Only)

Lies vor jeder Änderung den tatsächlichen Zustand aller Engine-Schichten aus \`${localControlOrigin()}\`:

- \`GET /api/v1/status\` — Gesamtstatus (Defender, ASR, CFA, Firewall, \`mhx.protectionHealth\`, Integritätsmonitor)
- \`GET /api/v1/setup/status\` — Serverseitiger Ersteinrichtungs-Status
- \`GET /api/v1/protection/readiness?target=guarded\` & \`?target=sovereign\` — Konkrete Blocker vor Moduswechsel
- \`GET /api/v1/mhx/symbiosis\` — Defender Deep Symbiosis (16 Operational-Event-IDs, FairScorer-Korrelation, Containment-Anzahl, AppControl)
- \`GET /api/v1/mhx/containments\` — Aktive reversible \`NtSuspendProcess\`-Baum-Containments
- \`GET /api/v1/titan/status\` — Titan-Modus (\`OBSERVE\`/\`CONTAIN\`/\`STRICT\`), \`developmentRoots\`, \`ownerProcessImages\`, Quarantäne
- \`GET /api/v1/mhx/applications\` & \`GET /api/v1/mhx/application-denies\` — App Control Allowlist & Sovereign Firewall Denies
- \`GET /api/v1/sentinel/status\` — Sentinel Signaturen, System-Apps & Provenance-Whitelist
- \`GET /api/v1/v6/status\` & \`GET /api/v1/v6/styx/whitelist\` — V6 Anti-Spyware-Sensoren, Witness, StyX Egress

---

## Phase 3 · Entscheidungsmatrix angepasst an Windows-Installation & Programme

Wäge jede Regel anhand der real erkannten Software und Nutzerrolle ab. Frage den Betreiber bei eingreifenden Schritten kurz um Bestätigung:

### 1. Härtungsprofil (\`POST /api/v1/hardening/enforce\`)
- Nutze \`"profile": "${targetProfile}"\` mit \`"confirmation": "APPLY HARDENING PROFILE"\`.
- **Schutz-Hinweis bei Server (\`Isolation\`):** \`Isolation\` deaktiviert zusätzlich USB-Massenspeicher und RDP! Prüfe bei Remote-Servern **VORHER**, dass SSH/Out-of-Band/VPN-Management nicht über RDP läuft.
- **Controlled Folder Access (CFA):** Deaktiviere CFA niemals global (\`EnableControlledFolderAccess = 0\`). Wenn legitime Desktop-/Office-/IDE-/Backup-Programme beim Schreiben in geschützte Benutzerordner blockiert werden (Event 1123/1124), trage gezielt deren signierte Haupt-Executable als CFA-Ausnahme nach.

### 2. Entwickler-Toolchains & Build-Workspaces (\`developer\` / Build-PCs)
- **Titan Policy (\`POST /api/v1/titan/policy\`):** \`"mode": "${titanMode}"\`, \`"autoQuarantine": ${autoQuarantine ? 'true' : 'false'}\`, \`"confirmation": "CHANGE TITAN POLICY"\`. Auf aktiven Entwicklungsrechnern \`autoQuarantine: false\` belassen, damit frische Compiler-Artefakte (\`go build\`, \`cargo build\`, \`msbuild\`) nicht mitten im Build verschoben werden.
- **Development Roots (\`POST /api/v1/titan/development-roots\`):**
  - Body: \`{"path": "C:\\\\Pfad\\\\zum\\\\Workspace", "reason": "...", "confirmation": "ADD DEVELOPMENT ROOT"}\`
  - Registriere ausschließlich echte Projekt-/Build-Stammverzeichnisse (z. B. Repo-Roots, \`%GOPATH%\`, \`.cargo\`, \`.venv\`), niemals breite Root-Pfade wie \`C:\\\\\`, \`C:\\\\Users\` oder \`%TEMP%\`.
- **Owner Process Images (\`POST /api/v1/titan/owner-process-images\`):**
  - Body: \`{"images": ["C:\\\\Program Files\\\\Go\\\\bin\\\\go.exe", ...], "reason": "...", "confirmation": "UPDATE OWNER PROCESS IMAGES"}\`
  - Trage die in Phase 1 gefundenen verifizierten Compiler/IDE/Paketmanager-Binaries ein. Persistenz- und Systemänderungen durch diese Prozesse bleiben dennoch prüfpflichtig!

### 3. App Control Allowlist & Firewall-Deny (MHX)
- **App Control Allowlist (\`POST /api/v1/mhx/applications\`):** Erfordert \`"confirmation": "UPDATE APPLICATION ALLOWLIST"\`. Nur vom Betreiber genutzte, **Authenticode-signierte oder Hash-geprüfte** Programme aufnehmen — keine unsignierten Temp-Skripte und keine Wildcard-Ordner.
- **Firewall Deny (\`POST /api/v1/mhx/application-denies\`):** Telemetrie-lastige oder unerwünschte Binaries aus dem Inventar sauber blockieren, ohne Windows Update/Systemdienste abzuschneiden.

### 4. Sentinel Provenance-Whitelist (\`POST /api/v1/sentinel/whitelist/add\`)
- \`FIND-WIN-009\` erzwingt mindestens ein **SHA-256-Pin** oder einen **Authenticode-Signer-Pin** (reine Dateinamen ohne Krypto-Pinning werden serverseitig abgewiesen).
- Halte alle Sentinel-Signaturen und System-App-Prüfungen aktiv; nimm nur reproduzierbare False-Positives mit Hash/Signer auf die Whitelist.

### 5. Defender Deep Symbiosis & Reversible Containment (\`6.1.0\`)
- Prüfe \`GET /api/v1/mhx/symbiosis\`: Defender Symbiosis verknüpft 16 Defender-Event-IDs mit dem \`FairScorer\` und dem Titan-Artifact-Oracle. Synchronisiere bei Bedarf über \`POST /api/v1/mhx/defender/reconcile\` oder triggere gezielte Einzelprüfung mit \`POST /api/v1/mhx/defender/scan-file\`.
- Falls MHX einen verdächtigen Prozessbaum per \`NtSuspendProcess\` eingefroren hat (\`GET /api/v1/mhx/containments\`): **NIEMALS automatisch fortsetzen!** Prüfe zuerst den Korrelations-/Defender-Befund und hole explizite menschliche Freigabe vor \`POST /api/v1/mhx/containments/{id}/resume\` (\`"confirmation": "RESUME CONTAINED PROCESS"\`).

### 6. Integrität, Threat Intel & Moduswechsel
- Aktiviere den Integritätsmonitor: \`POST /api/v1/integrity/configuration\` (\`"enabled": true, "intervalHours": 24, "confirmation": "CHANGE INTEGRITY MONITORING"\`).
- Gleiche Schutzrichtlinie und Feeds ab: \`POST /api/v1/mhx/policy/reconcile\` und \`POST /api/v1/mhx/feeds/sync\`.
- Vor einem Wechsel nach \`sovereign\` über \`POST /api/v1/mhx/mode\` zuerst \`GET /api/v1/protection/readiness?target=sovereign\` und legitim nötige StyX-Egress-Ziele (\`POST /api/v1/v6/styx/whitelist\`) prüfen.

---

## Phase 4 · Verbotene Aktionen (Harte Sicherheitsleitplanken)

- **NIEMALS** Defender Echtzeitschutz, Behavior Monitoring, ASR-Blockregeln, Controlled Folder Access, Windows Firewall, TLS oder die Control-Plane-Authentifizierung deaktivieren.
- **NIEMALS** pauschale Ausschlüsse für \`C:\\\\Users\\*\`, \`C:\\\\Temp\\*\`, \`%APPDATA%\` oder \`%LOCALAPPDATA%\` setzen.
- **NIEMALS** ein Containment ohne menschliche Prüfung per Skript blind aufheben.
- **NIEMALS** das Master-Token auslesen und in Konfigurationsdateien, Skripte oder Logs schreiben.

---

## Phase 5 · Live-Verifikation & Einrichtung abschließen

Nach den abgestimmten Anpassungen verpflichtend ausführen:
1. \`POST /api/v1/mhx/policy/reconcile\` und \`POST /api/v1/health/refresh\`
2. \`GET /api/v1/status\` → Defender, 11/11 ASR-Blockregeln, CFA, Firewall, \`mhx.protectionHealth == "VERIFIED"\` und \`integrity.state != "DEGRADED"\` prüfen
3. \`GET /api/v1/mhx/symbiosis\` & \`GET /api/v1/protection/readiness?target=guarded\` → keine offenen Blocker für legitime Workloads
4. Wenn der Ersteinrichtungs-Status noch offen ist (\`setup/status\` \`complete == false\`): \`POST /api/v1/setup/complete\` mit \`{"profile":"${profile}","reason":"Verified host-adapted onboarding completed","confirmation":"COMPLETE SETUP"}\`
`;
}
