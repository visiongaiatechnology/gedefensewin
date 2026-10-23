// Isolated fixture test for slow protection-mode transitions.
// Verifies that the operator sees progress immediately instead of a silent button.
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
const output = path.resolve(__dirname, '../work/verification/protection-transition');
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const protection = {
  Defender: true, DefenderService: true, RealTimeProtection: true, BehaviorProtection: true,
  IOAVProtection: true, CloudProtection: true, NetworkProtection: true, TamperProtection: true,
  Firewall: true, SecureBoot: true, Tpm: true, BitLocker: true, Vbs: true, CredentialGuard: true,
  MemoryIntegrity: true, LsaProtection: true, SmbHardening: true, PowerShellLogging: true,
  UsbStorageBlocked: true, RemoteDesktopDisabled: true, WindowsUpdate: true,
};

let currentMode = 'monitor';
let modePosts = [];

function status() {
  return {
    version: '5.0.0',
    platform: 'Windows 11 Enterprise LTSC 2024',
    protection,
    mhx: {
      protectionMode: currentMode,
      protectionHealth: 'VERIFIED',
      protectionVerifiedUtc: '2026-10-22T08:54:43Z',
      realtime: true,
      realtimeProtection: true,
      telemetry: 'WMI_PROCESS_START_TRACE',
      telemetryHeartbeatUtc: new Date().toISOString(),
      networkRealtime: true,
      wfpRealtime: true,
      appControl: 'AUDIT',
      kernelEnforcement: false,
      eventsEvaluated: 12453,
      eventsBlocked: 3,
      wfpBlockedEvents: 133916,
      networkTelemetry: 'NATIVE_TCP_OWNER_PID',
      wfpBlockTelemetry: 'SECURITY_5157_OBSERVED',
      threatNetworkHits: 128,
      attackStories: 4,
      threatIntelligence: {
        state: 'CURRENT', indicators: 133916, blockingIndicators: 52840,
        blockingFeedsReady: 4, blockingFeedsTotal: 4,
        enforcementGenerationSha256: 'b1b2c3d4e5f6', lastSuccessUtc: '2026-10-22T08:50:00Z',
        nextSyncUtc: '2026-10-22T20:50:00Z', feeds: [],
      },
      threatEnforcement: { state: 'VERIFIED', activeGenerationSha256: 'b1b2c3d4e5f6', indicators: 52840, rules: 52840 },
      traffic: { state: 'LIVE', receivedBytesPerSec: 128430, sentBytesPerSec: 84210, observedUtc: new Date().toISOString() },
      kineticArmed: false,
      kineticReadiness: { threatRules: 'GENERATION_VERIFIED', wfpAudit: 'BLOCK_EVENTS_OBSERVED', mode: 'OBSERVE_ONLY' },
      kinetic: { mode: 'OBSERVE_ONLY', burstCandidates: 2, trackedSources: 9, capacity: 2048, blocksObserved: 133916 },
      kineticSources: [], kineticIncidents: [], kineticThreatCorrelations: 2, kineticBlockedCorrelations: 1,
      uncorrelatedThreatHits: 0,
    },
    integrity: { healthy: true },
  };
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
        response.setHeader('Content-Type', 'application/json');
        if (url.pathname === '/api/v1/startup/state') { return response.end('{"required":false,"reason":"","version":"5.0.0","currentVersion":"5.0.0"}'); }
        if (url.pathname === '/api/v1/startup/ack') { return response.end('{"required":false,"reason":"","version":"5.0.0","currentVersion":"5.0.0"}'); }
        if (url.pathname === '/api/v1/status') { return response.end(JSON.stringify(status())); }
        if (url.pathname === '/api/v1/mhx/status') { return response.end(JSON.stringify(status().mhx)); }
        if (url.pathname === '/api/v1/protection/readiness') {
          return response.end(JSON.stringify({ target: url.searchParams.get('target'), currentMode, ready: true, blockers: [], consequences: ['Kontextuelle Response nach erneuter Identitätsprüfung.'] }));
        }
        if (url.pathname === '/api/v1/mhx/mode' && request.method === 'POST') {
          modePosts.push(await readJSON(request));
          await sleep(4200);
          currentMode = 'guarded';
          return response.end(JSON.stringify(status()));
        }
        if (url.pathname === '/api/v1/hardening/components') { return response.end('[]'); }
        if (url.pathname === '/api/v1/settings') {
          return response.end('{"schemaVersion":1,"values":{},"settings":{},"profiles":[],"levels":[],"activeProfileId":"monitor","activeLevel":"monitor","protectionLevel":"monitor","state":"READY","applierReady":true}');
        }
        if (url.pathname === '/api/v1/settings/catalog') {
          return response.end('{"schemaVersion":1,"controls":[],"sections":[],"levels":[]}');
        }
        if (url.pathname === '/api/v1/settings/profiles') {
          return response.end('{"profiles":[],"levels":[],"activeProfileId":"monitor","activeLevel":"monitor","protectionLevel":"monitor","state":"READY","applierReady":true}');
        }
        if (url.pathname === '/api/v1/defender/telemetry') {
          return response.end(JSON.stringify({ Available: false, Reason: 'Fixture ohne Defender-Messung' }));
        }
        if (url.pathname === '/api/v1/health/refresh' || url.pathname === '/api/v1/health/status') {
          return response.end(JSON.stringify({ healthy: true, checkedUtc: new Date().toISOString(), checks: [] }));
        }
        if (url.pathname === '/api/v1/notifications') { return response.end('[]'); }
        if (url.pathname === '/api/v1/window/state') { return response.end('{"handled":false,"state":"normal"}'); }
        if (url.pathname === '/api/v1/mhx/stories') { return response.end('[]'); }
        if (url.pathname === '/api/v1/overview/threat-map') {
          return response.end('{"sources":[],"recent":[],"origin":{"known":false},"geo":{"loaded":false},"totals":{}}');
        }
        response.statusCode = 404;
        return response.end('{"error":"fixture route missing"}');
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
    await page.waitForTimeout(1000);
    await page.evaluate(() => document.querySelector('[data-view="protection"]').click());
    await page.locator('[data-protection="guarded"]').waitFor();
    await page.locator('[data-protection="guarded"]').click();
    await page.locator('#protectionDialog[open]').waitFor();
    await page.locator('#protectionReason').fill('Operator bestaetigt Guarded nach Readiness-Pruefung');

    await page.locator('#protectionConfirm').evaluate((button) => {
      button.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      button.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    });
    await page.locator('#protectionProgress:not([hidden])').waitFor();
    await check('progress panel appears immediately', async () => await page.locator('#protectionProgress').isVisible());
    await check('confirmation button is disabled during transition', async () => await page.locator('#protectionConfirm').isDisabled());
    await check('dialog is marked busy', async () => await page.locator('#protectionDialog').evaluate((dialog) => dialog.dataset.busy === 'true' && dialog.getAttribute('aria-busy') === 'true'));
    await check('first progress phase is visible', async () => (await page.locator('#protectionProgressTitle').textContent()).includes('angewendet'));
    await page.waitForTimeout(1200);
    await page.screenshot({ path: path.join(output, 'protection-transition-progress.png') });
    await page.waitForTimeout(1900);
    await check('elapsed time advances while waiting', async () => Number.parseFloat(await page.locator('#protectionProgressElapsed').textContent()) >= 2.5);
    await check('verification phase replaces the first phase', async () => (await page.locator('#protectionProgressTitle').textContent()).includes('verifiziert'));
    await page.locator('#protectionProgress[data-tone="good"]').waitFor({ timeout: 15000 });
    await check('success state is shown before the dialog closes', async () => (await page.locator('#protectionProgressTitle').textContent()).includes('aktiv und verifiziert'));
    await page.waitForTimeout(1500);
    await check('dialog closes after the verified transition', async () => !(await page.locator('#protectionDialog').evaluate((dialog) => dialog.open)));
    await check('only one mode request was sent', async () => modePosts.length === 1);
    await check('mode request carries target, confirmation and reason', async () => modePosts[0].mode === 'guarded' && modePosts[0].confirmation === 'ACTIVATE GUARDED' && modePosts[0].reason.length >= 8);
    await check('protection view reflects the new mode', async () => (await page.locator('#currentMode').textContent()).toLowerCase().includes('guarded'));
    if (errors.length) console.log('browser errors:', errors);
    await check('no page or console errors', async () => errors.length === 0);
    await page.screenshot({ path: path.join(output, 'protection-transition.png') });
    console.log('PASS: ' + checks.length + ' protection-transition checks');
  } finally {
    await browser.close();
    server.close();
  }
}

main().catch((error) => { console.error(error); process.exit(1); });
