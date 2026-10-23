// STATUS: DIAMANT VGT SUPREME
// Isolated Titan control-center fixture. It never contacts an installed service.
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const http = require('node:http');
const { createRequire } = require('node:module');
const runtimeRequire = process.env.CODEX_NODE_MODULES
  ? createRequire(path.join(path.resolve(process.env.CODEX_NODE_MODULES), 'package.json'))
  : require;
const { chromium } = runtimeRequire('playwright');

const root = path.resolve(__dirname, '../src/GeDefense/windows/internal/server/web');
const output = path.resolve(__dirname, '../work/verification/titan');
const now = new Date().toISOString();
const hash = (char) => char.repeat(64);

const sensors = [
  { id: 'boot', label: 'Boot- und Vertrauenskette', state: 'HEALTHY', detail: 'Secure Boot gemessen; TPM nicht behauptet.', events: 1, errors: 0 },
  { id: 'files', label: 'Datei- und Ingress-Sensoren', state: 'HEALTHY', detail: '7 Watch-Roots aktiv.', events: 18, errors: 0 },
  { id: 'persistence', label: 'Persistenz-Inventar', state: 'HEALTHY', detail: 'Dienste, Run-Keys und Sicherheitsvertrag erfasst.', events: 4, errors: 0 },
  { id: 'process', label: 'Prozesskontext', state: 'HEALTHY', detail: 'Temporale Prozesskontexte verfügbar.', events: 12, errors: 0 },
  { id: 'security', label: 'Sicherheitskonfiguration', state: 'DEGRADED', detail: 'Zwei Kontrollen weichen vom erwarteten Zustand ab.', events: 2, errors: 1 },
];

const events = [
  {
    sequence: 4, id: 'evt-planted', bootId: 'boot-fixture', timestampUtc: now, timeSource: 'SYSTEM_UTC',
    eventType: 'FILE_CREATED', severity: 'HIGH',
    object: { kind: 'FILE', path: 'C:\\Users\\Operator\\Downloads\\update.exe', name: 'update.exe', sha256: hash('a'), size: 245760, fileType: 'EXECUTABLE' },
    actor: { pid: 0, correlationQuality: 'NONE', correlationNote: 'Keine Datei-zu-PID-Zuordnung beobachtet.' },
    network: { correlationQuality: 'TEMPORAL', remoteAddress: '203.0.113.42', remotePort: 443, localPort: 51234, image: 'msedge.exe', detail: 'Fernverbindung zeitlich korreliert, Datenfluss nicht belegt.' },
    authorization: { status: 'UNEXPECTED', riskClass: 'INGRESS', policyMode: 'CONTAIN', reason: 'Benutzerbeschreibbarer Ingress-Pfad; ausführbarer Dateityp; keine Freigabe.', riskScore: 82, needsReview: true, autoQuarantine: true },
    response: { action: 'ALERT', state: 'RECORDED' },
    collection: { source: 'titan-file-watch', telemetryHealth: 'HEALTHY' },
    previousHash: hash('1'), hash: hash('2'),
  },
  {
    sequence: 3, id: 'evt-service', bootId: 'boot-fixture', timestampUtc: new Date(Date.now() - 60000).toISOString(), timeSource: 'SYSTEM_UTC',
    eventType: 'PERSISTENCE_ADDED', severity: 'HIGH',
    object: { kind: 'SERVICE', path: 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\RemoteHelper', name: 'RemoteHelper', fileType: 'SERVICE' },
    actor: { pid: 0, correlationQuality: 'NONE' },
    network: { correlationQuality: 'NONE' },
    authorization: { status: 'COMPROMISED', riskClass: 'PERSISTENCE', policyMode: 'CONTAIN', reason: 'Neue Persistenz ohne Freigabe nach einer Sicherheitsabschwächung.', riskScore: 91, needsReview: true, autoQuarantine: false },
    response: { action: 'ALERT', state: 'RECORDED' },
    collection: { source: 'titan-persistence', telemetryHealth: 'HEALTHY' },
    previousHash: hash('3'), hash: hash('4'),
  },
  {
    sequence: 2, id: 'evt-signed', bootId: 'boot-fixture', timestampUtc: new Date(Date.now() - 120000).toISOString(), timeSource: 'SYSTEM_UTC',
    eventType: 'FILE_MODIFIED', severity: 'LOW',
    object: { kind: 'FILE', path: 'C:\\Windows\\System32\\drivers\\signed.sys', name: 'signed.sys', sha256: hash('b'), size: 4096, fileType: 'DRIVER' },
    actor: { pid: 4420, image: 'TrustedInstaller.exe', correlationQuality: 'TEMPORAL', correlationNote: 'Prozessstart zeitlich nahe; nicht als Urheber bewiesen.' },
    network: { correlationQuality: 'NONE' },
    authorization: { status: 'AUTHORIZED', riskClass: 'SYSTEM_COMPONENT', policyMode: 'CONTAIN', matchedGrant: 'permit-signed-driver', reason: 'Gültige, begrenzte Besitzer-Freigabe angewendet.', riskScore: 36, needsReview: false, autoQuarantine: false },
    response: { action: 'OBSERVE', state: 'RECORDED' },
    collection: { source: 'titan-file-watch', telemetryHealth: 'HEALTHY' },
    previousHash: hash('5'), hash: hash('6'),
  },
  {
    sequence: 1, id: 'evt-doc', bootId: 'boot-fixture', timestampUtc: new Date(Date.now() - 180000).toISOString(), timeSource: 'SYSTEM_UTC',
    eventType: 'FILE_CREATED', severity: 'LOW',
    object: { kind: 'FILE', path: 'C:\\Users\\Operator\\Documents\\report.pdf', name: 'report.pdf', sha256: hash('c'), size: 8192, fileType: 'OTHER' },
    actor: { pid: 0, correlationQuality: 'NONE' },
    network: { correlationQuality: 'NONE' },
    authorization: { status: 'TOLERATED', riskClass: 'USER_CONTENT', policyMode: 'CONTAIN', reason: 'Benutzerinhalt ohne Hochrisikosignal.', riskScore: 12, needsReview: false, autoQuarantine: false },
    response: { action: 'OBSERVE', state: 'RECORDED' },
    collection: { source: 'titan-file-watch', telemetryHealth: 'HEALTHY' },
    previousHash: '', hash: hash('7'),
  },
];

let quarantine = [
  { id: '0123456789abcdef0123456789abcdef', createdUtc: now, originalPath: 'C:\\Users\\Operator\\Downloads\\update.exe', originalName: 'update.exe', sha256: hash('a'), size: 245760, fileType: 'EXECUTABLE', eventId: 'evt-planted', reason: 'Automatische Quarantäne nach Titan-Richtlinie.', originalGone: true, state: 'QUARANTINED', reviewed: false },
  { id: 'fedcba9876543210fedcba9876543210', createdUtc: new Date(Date.now() - 900000).toISOString(), originalPath: 'C:\\Windows\\Temp\\old.DLL', originalName: 'old.DLL', sha256: hash('d'), size: 1024, fileType: 'DRIVER', reason: 'Besitzerentscheidung nach unerwarteter Ablage.', originalGone: true, state: 'RESTORED', reviewed: true },
];

let policy = { schemaVersion: 1, mode: 'CONTAIN', autoQuarantine: true, permits: [], developmentRoots: [], updatedUtc: now, reason: 'Fixture-Richtlinie' };
let verification = { verified: true, events: 4, checkpoints: 2, checkedUtc: now, firstSequence: 1, lastSequence: 4, detail: 'Journal-Kette und alle Checkpoint-Signaturen sind gültig.' };

function status() {
  return {
    version: '5.1.0', state: 'PROTECTING', trustPosture: 'TOLERATED', mode: policy.mode,
    startedUtc: now, uptimeSeconds: 742, sensors, eventCount: 4, openFindings: 2, quarantineCount: quarantine.length,
    lastEventUtc: now,
    lastCheckpoint: { sequence: 4, createdUtc: now, publicKeySha256: hash('e'), signature: 'fixture-signature', verified: true, detail: '' },
    journalVerified: true, journalError: '', policy,
    watchRoots: [
      { path: 'C:\\Windows\\System32\\Tasks', class: 'PERSISTENCE', active: true },
      { path: 'C:\\Windows\\System32\\drivers', class: 'SYSTEM_COMPONENT', active: true },
      { path: 'C:\\Users\\Operator\\Downloads', class: 'INGRESS', active: true },
      { path: 'C:\\Users\\Operator\\AppData\\Local\\Temp', class: 'INGRESS', active: true },
    ],
    securityControls: [
      { id: 'firewall-domain', label: 'Windows Firewall Domainprofil aktiv', value: '1', expected: '1', secure: true, severity: 'CRITICAL' },
      { id: 'defender-disable-realtime', label: 'Defender Echtzeitschutz nicht per Policy deaktiviert', value: '0', expected: '0 oder nicht gesetzt', secure: true, severity: 'CRITICAL' },
      { id: 'rdp-disabled', label: 'Remote Desktop nicht unnötig freigegeben', value: '0', expected: '1', secure: false, severity: 'HIGH' },
    ],
    boot: { secureBoot: true, tpm: null, measuredBoot: false, checkedUtc: now, detail: 'Secure Boot aktiv; TPM-Attestation nicht behauptet.' },
    witness: { configured: false, reachable: false, detail: 'Kein unabhängiger Witness konfiguriert. Lokale Checkpoints sind manipulationsanzeigend, aber kein externer Vertrauensanker.' },
    eventsDropped: 0, watcherOverflows: 0, quarantineBytes: quarantine.reduce((sum, entry) => sum + entry.size, 0),
    canQuarantine: true, limits: { maxEventsPerPage: 100, maxQuarantineMb: 64, maxPermits: 128 },
  };
}

function json(response, value) {
  response.setHeader('Content-Type', 'application/json');
  response.end(JSON.stringify(value));
}

function readJSON(request) {
  return new Promise((resolve) => {
    let body = '';
    request.on('data', (chunk) => { body += chunk; });
    request.on('end', () => { try { resolve(JSON.parse(body || '{}')); } catch { resolve({}); } });
  });
}

async function main() {
  await fs.mkdir(output, { recursive: true });
  const server = http.createServer(async (request, response) => {
    const url = new URL(request.url, 'http://localhost');
    try {
      if (url.pathname.startsWith('/api/')) {
        if (url.pathname === '/api/v1/mhx/status') return json(response, { protectionMode: 'guarded', protectionHealth: 'VERIFIED', realtime: true });
        if (url.pathname === '/api/v1/status') return json(response, { version: '5.1.0', platform: 'Windows Test', protection: { Defender: true }, mhx: { protectionMode: 'guarded', protectionHealth: 'VERIFIED', realtime: true } });
        if (url.pathname === '/api/v1/startup/state') return json(response, { required: false, reason: '', version: '5.1.0', currentVersion: '5.1.0' });
        if (url.pathname === '/api/v1/startup/ack') return json(response, { required: false });
        if (url.pathname === '/api/v1/health/refresh' || url.pathname === '/api/v1/health/status') return json(response, { healthy: true, checkedUtc: now, checks: [] });
        if (url.pathname === '/api/v1/notifications') return json(response, []);
        if (url.pathname === '/api/v1/overview/threat-map') return json(response, { sources: [], recent: [], origin: { known: false }, geo: { loaded: false }, totals: {} });
        if (url.pathname === '/api/v1/mhx/geo') return json(response, { database: { loaded: false, entries: 0 }, sources: [] });
        if (url.pathname === '/api/v1/mhx/stories') return json(response, []);
        if (url.pathname === '/api/v1/mhx/analyses') return json(response, []);
        if (url.pathname === '/api/v1/xdr/findings') return json(response, { Findings: [], Items: [] });
        if (url.pathname === '/api/v1/window/state') return json(response, { handled: false, state: 'normal' });
        if (url.pathname === '/api/v1/titan/status' && request.method === 'GET') return json(response, status());
        if (url.pathname === '/api/v1/titan/events' && request.method === 'GET') {
          const filter = url.searchParams.get('filter') || 'all';
          const filtered = filter === 'unexpected' ? events.filter((event) => ['UNEXPECTED', 'COMPROMISED'].includes(event.authorization.status)) : filter === 'quarantine' ? [] : events;
          return json(response, { events: filtered, total: filtered.length, limit: 20, offset: 0, filter });
        }
        if (url.pathname === '/api/v1/titan/quarantine' && request.method === 'GET') return json(response, { entries: quarantine, total: quarantine.length, bytes: quarantine.reduce((sum, entry) => sum + entry.size, 0) });
        if (url.pathname === '/api/v1/titan/checkpoints' && request.method === 'GET') return json(response, { checkpoints: [
          { sequence: 4, lastHash: hash('2'), createdUtc: now, bootId: 'boot-fixture', publicKeySha256: hash('e'), signature: 'fixture' },
          { sequence: 2, lastHash: hash('6'), createdUtc: new Date(Date.now() - 60000).toISOString(), bootId: 'boot-fixture', publicKeySha256: hash('e'), signature: 'fixture' },
        ] });
        if (url.pathname === '/api/v1/titan/policy' && request.method === 'GET') return json(response, policy);
        if (url.pathname === '/api/v1/titan/policy' && request.method === 'POST') {
          const body = await readJSON(request);
          policy = { ...policy, mode: body.mode || policy.mode, autoQuarantine: Boolean(body.autoQuarantine), updatedUtc: new Date().toISOString(), reason: body.reason || policy.reason };
          return json(response, policy);
        }
        if (url.pathname === '/api/v1/titan/permits' && request.method === 'GET') return json(response, { permits: policy.permits || [] });
        if (url.pathname === '/api/v1/titan/permits' && request.method === 'POST') {
          const body = await readJSON(request);
          const permit = { id: 'permit-fixture', path: body.path, sha256: body.sha256 || '', action: body.action, createdUtc: new Date().toISOString(), expiresUtc: new Date(Date.now() + Number(body.ttlMinutes || 60) * 60000).toISOString(), singleUse: Boolean(body.singleUse), used: false, reason: body.reason };
          policy = { ...policy, permits: [...(policy.permits || []), permit] };
          return json(response, { permit });
        }
        if (url.pathname.startsWith('/api/v1/titan/permits/') && url.pathname.endsWith('/revoke')) {
          const id = url.pathname.split('/').at(-2);
          policy = { ...policy, permits: (policy.permits || []).filter((permit) => permit.id !== id) };
          return json(response, policy);
        }
        if (url.pathname === '/api/v1/titan/development-roots' && request.method === 'POST') {
          const body = await readJSON(request);
          policy = { ...policy, developmentRoots: [...(policy.developmentRoots || []), body.path] };
          return json(response, policy);
        }
        if (url.pathname === '/api/v1/titan/development-roots/remove' && request.method === 'POST') {
          const body = await readJSON(request);
          policy = { ...policy, developmentRoots: (policy.developmentRoots || []).filter((root) => root !== body.path) };
          return json(response, policy);
        }
        if (url.pathname === '/api/v1/titan/verify' && request.method === 'POST') return json(response, verification);
        if (url.pathname === '/api/v1/titan/export' && request.method === 'GET') return json(response, { schemaVersion: 1, generatedUtc: now, version: '5.1.0', bootId: 'boot-fixture', events, checkpoints: [], verification, publicKeySha256: hash('e'), limitations: ['Fixture'] });
        if (url.pathname === '/api/v1/titan/events/acknowledge' && request.method === 'POST') {
          await readJSON(request);
          return json(response, { reviewed: 2 });
        }
        if (url.pathname.includes('/api/v1/titan/events/') && url.pathname.endsWith('/quarantine')) {
          return json(response, { entry: quarantine[0] });
        }
        if (url.pathname.includes('/api/v1/titan/quarantine/') && (url.pathname.endsWith('/restore') || url.pathname.endsWith('/review'))) {
          const id = url.pathname.split('/').at(-2);
          const entry = quarantine.find((item) => item.id === id) || quarantine[0];
          if (url.pathname.endsWith('/restore')) { entry.state = 'RESTORED'; entry.originalGone = true; }
          else entry.reviewed = true;
          return json(response, { entry });
        }
        response.statusCode = 404;
        return json(response, { error: 'fixture route missing' });
      }
      const name = url.pathname === '/' ? 'index.html' : url.pathname.replace(/^\/assets\//, '');
      const resolved = path.resolve(root, name);
      if (!resolved.startsWith(root + path.sep)) { response.statusCode = 403; return response.end(); }
      response.setHeader('Content-Type', name.endsWith('.js') ? 'text/javascript' : name.endsWith('.css') ? 'text/css' : name.endsWith('.png') ? 'image/png' : 'text/html; charset=utf-8');
      response.end(await fs.readFile(resolved));
    } catch (error) {
      response.statusCode = 500;
      response.end(String(error));
    }
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const browser = await chromium.launch({ executablePath: path.join(process.env.ProgramFiles, 'Google/Chrome/Application/chrome.exe'), headless: true });
  const checks = [];
  const errors = [];
  const check = async (name, fn) => { assert.ok(await fn(), name); checks.push(name); };
  try {
    const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
    page.on('pageerror', (error) => errors.push(error.message));
    page.on('console', (message) => { if (message.type() === 'error') errors.push('console: ' + message.text()); });
    page.on('response', (response) => { if (response.status() === 404) errors.push('404: ' + response.url()); });
    await page.goto('http://127.0.0.1:' + server.address().port);
    await page.waitForTimeout(700);
    await page.locator('[data-view="titan"]').click();
    await page.locator('#titanPosture').waitFor();
    await check('white legibility layer applies to primary and secondary copy', async () => {
      const details = await page.evaluate(() => {
        const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, { acceptNode(node) {
          if (!node.nodeValue.trim()) return NodeFilter.FILTER_REJECT;
          const parent = node.parentElement;
          return parent && parent.offsetParent !== null ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_REJECT;
        } });
        const nonWhite = [];
        while (walker.nextNode()) {
          const parent = walker.currentNode.parentElement;
          const color = parent ? getComputedStyle(parent).color : '';
          if (parent && color !== 'rgb(255, 255, 255)') nonWhite.push({ tag: parent.tagName, cls: parent.className || '', text: walker.currentNode.nodeValue.trim().slice(0, 60), color });
        }
        return nonWhite;
      });
      if (details.length) process.stdout.write('titan-non-white ' + JSON.stringify(details.slice(0, 12)) + '\n');
      return details.length === 0;
    });
    await check('Titan page is reachable from primary navigation', async () => (await page.locator('#viewTitle').textContent()).includes('Titan'));
    await check('trust posture is rendered from server status', async () => (await page.locator('#titanPosture').textContent()).trim() === 'GEDULDET');
    await check('all five sensors are visible', async () => await page.locator('.titan-sensor-row').count() === 5);
    await check('security controls are rendered', async () => await page.locator('.titan-control').count() === 3);
    await check('desktop has no document overflow', async () => await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
    await page.screenshot({ path: path.join(output, 'titan-desktop.png'), fullPage: false });

    await page.locator('[data-titan-tab="ingress"]').click();
    await page.waitForTimeout(300);
    await check('ingress timeline renders real-shaped events', async () => await page.locator('.titan-event-row').count() === 4);
    await check('temporal network correlation is explicitly labelled', async () => (await page.locator('.titan-event-row').first().textContent()).includes('TEMPORAL'));
    await page.locator('#titanAcknowledgeOpen').click();
    await page.locator('#reasonDialogReason').fill('Sichtbare Testbefunde nach Prüfung als Entwicklungsvorgang bestätigt');
    await page.locator('#reasonDialogConfirm').click();
    await page.waitForTimeout(500);
    await check('open findings can be reviewed as a bounded page', async () => (await page.locator('#titanReviewStatus').textContent()).includes('Befund'));
    await page.locator('[data-titan-filter="unexpected"]').click();
    await page.waitForTimeout(300);
    await check('unexpected filter hides tolerated events', async () => await page.locator('.titan-event-row').count() === 2);

    await page.locator('[data-titan-tab="quarantine"]').click();
    await page.waitForTimeout(300);
    await check('quarantine list renders encrypted objects', async () => await page.locator('.titan-quarantine-row').count() === 2);
    await page.locator('.titan-quarantine-row').first().locator('[data-titan-action="restore"]').click();
    await page.locator('#reasonDialogReason').fill('Besitzer stellt das Objekt nach Prüfung wieder her');
    await page.locator('#reasonDialogConfirm').click();
    await page.waitForTimeout(500);
    await check('restore action is sent and acknowledged', async () => await page.locator('#titanQuarantineStatus').textContent() !== '');
    await page.locator('[data-titan-tab="policy"]').click();
    await page.locator('#titanPolicyMode').selectOption('STRICT');
    await page.locator('#titanAutoQuarantine').check();
    await page.locator('#titanPolicySave').click();
    await page.locator('#reasonDialogReason').fill('Verschärfte Titan-Richtlinie nach Vorfallprüfung');
    await page.locator('#reasonDialogConfirm').click();
    await page.waitForTimeout(600);
    await check('owner policy mutation is accepted', async () => (await page.locator('#titanPolicyBadge').textContent()).includes('STRICT'));
    await page.locator('#titanPermitPath').fill('C:\\Users\\Operator\\Downloads\\approved.exe');
    await page.locator('#titanPermitAction').selectOption('FILE_CREATED');
    await page.locator('#titanPermitCreate').click();
    await page.locator('#reasonDialogReason').fill('Besitzer genehmigt genau diesen Installerpfad');
    await page.locator('#reasonDialogConfirm').click();
    await page.waitForTimeout(600);
    await check('owner permit is created and visible', async () => await page.locator('.titan-permit-row').count() === 1);
    await page.locator('.titan-permit-row [data-titan-action="revoke-permit"]').click();
    await page.locator('#reasonDialogReason').fill('Freigabe nach Abschluss des Installers widerrufen');
    await page.locator('#reasonDialogConfirm').click();
    await page.waitForTimeout(600);
    await check('owner permit can be revoked', async () => await page.locator('.titan-permit-row').count() === 0);
    await page.locator('#titanDevRootPath').fill('C:\\Users\\Operator\\Projects\\MyApp');
    await page.locator('#titanDevRootAdd').click();
    await page.locator('#reasonDialogReason').fill('Projektbaum fuer kontrollierte Entwicklungsartefakte');
    await page.locator('#reasonDialogConfirm').click();
    await page.waitForTimeout(600);
    await check('development root can be marked', async () => await page.locator('#titanDevRootsList .titan-permit-row').count() === 1);
    await page.locator('#titanDevRootsList [data-titan-action="remove-dev-root"]').click();
    await page.locator('#reasonDialogReason').fill('Entwicklungsbaum-Markierung nach Test entfernt');
    await page.locator('#reasonDialogConfirm').click();
    await page.waitForTimeout(600);
    await check('development root can be removed', async () => await page.locator('#titanDevRootsList .titan-permit-row').count() === 0);

    await page.locator('[data-titan-tab="evidence"]').click();
    await page.waitForTimeout(300);
    await check('signed checkpoints are visible', async () => await page.locator('.titan-checkpoint-row').count() === 2);
    await page.locator('#titanVerifyInline').click();
    await page.waitForTimeout(500);
    await check('evidence verification reports a verified journal', async () => (await page.locator('#titanEvidenceStatus').textContent()).includes('Verifiziert'));
    await page.screenshot({ path: path.join(output, 'titan-evidence.png'), fullPage: false });

    await page.setViewportSize({ width: 390, height: 844 });
    await page.waitForTimeout(400);
    await check('mobile has no document overflow', async () => await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
    await check('mobile tabs remain reachable', async () => await page.locator('[data-titan-tab="lage"]').isVisible());
    await page.screenshot({ path: path.join(output, 'titan-mobile.png'), fullPage: false });
    if (errors.length) console.log('browser errors:', errors);
    await check('no page or console errors', async () => errors.length === 0);
    if (errors.length) console.log('browser errors:', errors);
    console.log('PASS:', checks.length, 'Titan browser checks');
  } finally {
    await browser.close();
    server.close();
  }
}

main().catch((error) => { console.error(error); process.exit(1); });
