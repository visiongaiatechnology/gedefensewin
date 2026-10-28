#!/usr/bin/env node
// STATUS: DIAMANT VGT SUPREME
// Independent real-DOM regression test for the Titan 6 s refresh scroll jump.
//
// Loads the REAL web\titan.js module from a configurable --web-root through a
// local loopback Python http.server, mocks globalThis.fetch for /api/v1/titan/*
// before the module import, drives the exported loadTitan()/selectTitanTab()
// and asserts in a real Chromium layout:
//
//   (a) after a refresh with one prepended event the previously first visible
//       row keeps its viewport position (+/- 2 px) and scrollTop stays > 0,
//   (b) a refresh with unchanged data performs no DOM replacement (same row
//       element references) and keeps scrollTop unchanged,
//   (c) a refresh while at scrollTop=0 keeps the list at the top (live feed),
//   (d) an open <details> evidence block stays open after a refresh,
//   (e) the real index.html no longer marks #titanEventList aria-live="polite",
//   (f) deep-scroll anchor stability: near the end of the list the previously
//       first visible row keeps its viewport position (+/- 2 px) after a
//       prepend refresh (regression guard for the content-relative anchor fix).
//
// No external dependencies (Node standard library only), no network except
// 127.0.0.1. Exit code 0 only when every assertion passes. A failing assertion
// is never retried; only a broken harness run (e.g. headless Chrome failed to
// produce a DOM dump / hit the process timeout) is retried once, because that
// is an infrastructure failure and not evidence about the fix.
//
// Usage:
//   node test/titan-scroll.browser.cjs --web-root <web dir>
//   node test/titan-scroll.browser.cjs --baseline
//       -> uses %TEMP%\vgt-web-baseline (pre-fix snapshot), expected to FAIL
//
// Optional: --label <name>, --keep-temp, --chrome <exe>, --python <exe>,
//           --timeout <ms> (headless Chrome process timeout, default 60000),
//           --evidence-dir <dir>.

'use strict';

const { spawn, spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const TEST_DIR = __dirname;
const REPO_ROOT = path.resolve(TEST_DIR, '..');
const HARNESS_PAGE = path.join(TEST_DIR, 'helpers', 'titan-scroll-harness.html');
const SERVER_SCRIPT = path.join(TEST_DIR, 'helpers', 'titan_scroll_server.py');
const DEFAULT_WEB_ROOT = path.join(REPO_ROOT, 'src', 'GeDefense', 'windows', 'internal', 'server', 'web');
const BASELINE_WEB_ROOT = path.join(os.tmpdir(), 'vgt-web-baseline');
const EVIDENCE_DIR = path.join(os.tmpdir(), 'vgt-ui-scroll-evidence');
const CHROME_CANDIDATES = [
  process.env.CHROME_PATH,
  'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
  'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
  path.join(process.env.LOCALAPPDATA || '', 'Google', 'Chrome', 'Application', 'chrome.exe'),
].filter(Boolean);

/* ------------------------------------------------------------------ */
/* CLI                                                                 */
/* ------------------------------------------------------------------ */
function parseArgs(argv) {
  const options = {
    webRoot: '',
    baseline: false,
    label: '',
    chrome: '',
    python: '',
    timeout: 60000,
    keepTemp: false,
    evidenceDir: EVIDENCE_DIR,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    const takeValue = (name) => {
      if (token.includes('=')) return token.slice(token.indexOf('=') + 1);
      index += 1;
      if (index >= argv.length) throw new Error(name + ' needs a value');
      return argv[index];
    };
    if (token === '--web-root' || token.startsWith('--web-root=')) options.webRoot = takeValue('--web-root');
    else if (token === '--baseline') options.baseline = true;
    else if (token === '--label' || token.startsWith('--label=')) options.label = takeValue('--label');
    else if (token === '--chrome' || token.startsWith('--chrome=')) options.chrome = takeValue('--chrome');
    else if (token === '--python' || token.startsWith('--python=')) options.python = takeValue('--python');
    else if (token === '--timeout' || token.startsWith('--timeout=')) options.timeout = Number(takeValue('--timeout'));
    else if (token === '--keep-temp') options.keepTemp = true;
    else if (token === '--evidence-dir' || token.startsWith('--evidence-dir=')) options.evidenceDir = takeValue('--evidence-dir');
    else if (token === '--help' || token === '-h') {
      console.log('Usage: node test/titan-scroll.browser.cjs --web-root <dir> | --baseline [--label name] [--keep-temp]');
      process.exit(0);
    } else throw new Error('unknown argument: ' + token);
  }
  return options;
}

/* ------------------------------------------------------------------ */
/* Small utilities                                                     */
/* ------------------------------------------------------------------ */
function assertExists(target, label) {
  if (!fs.existsSync(target)) throw new Error(label + ' does not exist: ' + target);
}

function resolveChrome(explicit) {
  const candidates = explicit ? [explicit, ...CHROME_CANDIDATES] : CHROME_CANDIDATES;
  for (const candidate of candidates) {
    if (candidate && fs.existsSync(candidate)) return candidate;
  }
  throw new Error('Chrome not found. Checked: ' + candidates.join(', '));
}

function pythonCandidates(explicit) {
  const list = [];
  if (explicit) list.push({ command: explicit, prefix: [] });
  else if (process.env.PYTHON) list.push({ command: process.env.PYTHON, prefix: [] });
  list.push({ command: 'python', prefix: [] });
  list.push({ command: 'py', prefix: ['-3'] });
  list.push({ command: 'python3', prefix: [] });
  return list;
}

function decodeEntities(text) {
  return String(text)
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#x27;/gi, "'")
    .replace(/&#39;/g, "'")
    .replace(/&amp;/g, '&');
}

function extractResult(dom) {
  const match = /<pre id="vgt-test-result"[^>]*>([\s\S]*?)<\/pre>/i.exec(dom || '');
  if (!match) return null;
  const lines = decodeEntities(match[1]).split(/\r?\n/).map((line) => line.trimEnd()).filter((line) => line.trim().length > 0);
  const headline = lines.length ? lines[0].trim() : '';
  const failures = lines.filter((line) => line.startsWith('FAIL '));
  const ok = /^RESULT:\s*PASS\b/.test(headline) && failures.length === 0;
  return { headline, lines, failures, ok };
}

function quoteForLog(command, args) {
  if (process.platform === 'win32') return '"' + command + '" ' + args.map((arg) => (/[\s"]/.test(arg) ? '"' + arg.replace(/"/g, '\\"') + '"' : arg)).join(' ');
  return [command, ...args].map((part) => (/[\s"]/.test(part) ? "'" + part.replace(/'/g, "'\\''") + "'" : part)).join(' ');
}

function removeTree(target, label) {
  if (!target) return true;
  try {
    fs.rmSync(target, { recursive: true, force: true, maxRetries: 4, retryDelay: 150 });
    return true;
  } catch (error) {
    console.warn('WARN: could not remove ' + label + ' ' + target + ': ' + error.message);
    return false;
  }
}

/** Persist a failed harness attempt (infrastructure only) for later diagnosis. */
function writeInfraAttemptLog(evidenceDir, label, message) {
  try {
    fs.writeFileSync(
      path.join(evidenceDir, label + '-attempt' + harnessAttempt + '-infra.log'),
      '[' + new Date().toISOString() + '] attempt=' + harnessAttempt + ' label=' + label + '\n' + message + '\n',
    );
  } catch (error) {
    /* diagnostics only - never fail the run because a log could not be written */
  }
}

async function delay(ms) { return new Promise((resolve) => setTimeout(resolve, ms)); }

/* ------------------------------------------------------------------ */
/* Python loopback server                                              */
/* ------------------------------------------------------------------ */
async function startServer(options) {
  const failures = [];
  for (const candidate of pythonCandidates(options.python)) {
    try {
      const server = await startServerOnce(candidate, options);
      return server;
    } catch (error) {
      failures.push(candidate.command + ': ' + error.message);
      if (error && error.code !== 'ENOENT') break;
    }
  }
  throw new Error('could not start the Python loopback server (' + failures.join(' | ') + ')');
}

function startServerOnce(candidate, options) {
  return new Promise((resolve, reject) => {
    const args = [...candidate.prefix, SERVER_SCRIPT, '--web-root', options.webRoot, '--page', HARNESS_PAGE, '--port', '0'];
    const child = spawn(candidate.command, args, { cwd: TEST_DIR, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
    let stdout = '';
    let stderr = '';
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      try { child.kill(); } catch (error) { /* already gone */ }
      reject(new Error('python server did not report PORT within 20000 ms; stderr=' + stderr.trim()));
    }, 20000);
    child.stdout.on('data', (chunk) => {
      stdout += chunk.toString();
      const match = /PORT=(\d+)/.exec(stdout);
      if (match && !settled) {
        settled = true;
        clearTimeout(timer);
        resolve({ child, port: Number(match[1]), command: quoteForLog(candidate.command, args), stderr: () => stderr });
      }
    });
    child.stderr.on('data', (chunk) => { stderr += chunk.toString(); });
    child.on('error', (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(error);
    });
    child.on('exit', (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(new Error('python server exited early (code ' + code + '); stderr=' + stderr.trim()));
    });
  });
}

function stopServer(server) {
  if (!server || !server.child) return;
  try { server.child.kill(); } catch (error) { /* already gone */ }
}

/* ------------------------------------------------------------------ */
/* Static web-tree evidence (reported next to the behavioral result)   */
/* ------------------------------------------------------------------ */
function inspectWebRoot(webRoot) {
  const readText = (name) => {
    const target = path.join(webRoot, name);
    return fs.existsSync(target) ? fs.readFileSync(target, 'utf8') : null;
  };
  const titan = readText('titan.js') || '';
  const index = readText('index.html') || '';
  const listStability = readText('list-stability.js');
  const eventListTag = /<div[^>]*id="titanEventList"[^>]*>/.exec(index);
  const loadEventsAt = titan.indexOf('function loadEvents');
  const loadEventsBody = loadEventsAt >= 0 ? titan.slice(loadEventsAt, loadEventsAt + 2500) : '';
  const replaceIndex = loadEventsBody.indexOf('replaceChildren');
  const fetchIndex = loadEventsBody.indexOf('getTitanEvents');
  return {
    webRoot,
    titanBytes: Buffer.byteLength(titan),
    titanHasLoadTitanExport: /export\s+async\s+function\s+loadTitan/.test(titan),
    titanHasSelectTitanTabExport: /selectTab\s+as\s+selectTitanTab/.test(titan),
    renderStableReferences: (titan.match(/renderStable/g) || []).length,
    listStabilityPresent: listStability !== null,
    listStabilityBytes: listStability ? Buffer.byteLength(listStability) : 0,
    eventListTagAriaLive: /aria-live\s*=\s*"([^"]*)"/i.exec(eventListTag ? eventListTag[0] : ''),
    eventListTag: eventListTag ? eventListTag[0].trim() : '(not found)',
    loadEventsClearsBeforeFetch: replaceIndex >= 0 && (fetchIndex < 0 || replaceIndex < fetchIndex),
  };
}

/* ------------------------------------------------------------------ */
/* Main                                                                */
/* ------------------------------------------------------------------ */
let infraFailure = false;
let harnessAttempt = 0;

async function main() {
  infraFailure = false;
  const options = parseArgs(process.argv.slice(2));
  options.webRoot = path.resolve(options.webRoot || (options.baseline ? BASELINE_WEB_ROOT : DEFAULT_WEB_ROOT));
  const label = options.label || (options.baseline ? 'baseline' : 'fixed');
  const evidenceDir = path.resolve(options.evidenceDir);
  fs.mkdirSync(evidenceDir, { recursive: true });

  assertExists(options.webRoot, 'web-root');
  assertExists(path.join(options.webRoot, 'titan.js'), 'web-root/titan.js');
  assertExists(path.join(options.webRoot, 'index.html'), 'web-root/index.html');
  assertExists(HARNESS_PAGE, 'harness page');
  assertExists(SERVER_SCRIPT, 'harness server script');
  const chrome = resolveChrome(options.chrome);

  const staticEvidence = inspectWebRoot(options.webRoot);
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'vgt-titan-scroll-'));
  const profileDir = path.join(tempRoot, 'chrome-profile');
  let server = null;
  let result = null;
  let infraError = '';
  const startedAt = new Date().toISOString();

  try {
    server = await startServer(options);
    const url = 'http://127.0.0.1:' + server.port + '/';
    const chromeArgs = [
      '--headless=new',
      '--user-data-dir=' + profileDir,
      '--disable-gpu',
      '--no-first-run',
      '--no-default-browser-check',
      '--disable-extensions',
      '--disable-background-networking',
      '--disable-component-update',
      '--disable-sync',
      '--disable-default-apps',
      '--mute-audio',
      '--hide-scrollbars',
      '--window-size=1200,900',
      '--virtual-time-budget=15000',
      '--dump-dom',
      url,
    ];
    const command = quoteForLog(chrome, chromeArgs);
    console.log('chrome command: ' + command);
    const runStarted = Date.now();
    const chromeRun = spawnSync(chrome, chromeArgs, {
      encoding: 'utf8',
      timeout: Number(options.timeout) || 120000,
      maxBuffer: 128 * 1024 * 1024,
      windowsHide: true,
    });
    const elapsedMs = Date.now() - runStarted;
    if (chromeRun.error) throw new Error('chrome execution failed: ' + chromeRun.error.message);
    const dom = chromeRun.stdout || '';
    result = extractResult(dom);
    if (!result) {
      infraFailure = true;
      infraError = 'no #vgt-test-result block found in --dump-dom output'
        + '\nchrome exit=' + chromeRun.status
        + '\nstderr tail:\n' + String(chromeRun.stderr || '').split(/\r?\n/).slice(-12).join('\n');
      writeInfraAttemptLog(evidenceDir, label, infraError);
    }
    const meta = {
      label,
      attempt: harnessAttempt,
      startedAt,
      finishedAt: new Date().toISOString(),
      elapsedMs,
      chromeExitCode: chromeRun.status,
      chromeCommand: command,
      serverCommand: server.command,
      url,
      webRoot: options.webRoot,
      staticEvidence,
      result,
      chromeStderrTail: String(chromeRun.stderr || '').split(/\r?\n/).slice(-20),
    };
    fs.writeFileSync(path.join(evidenceDir, label + '-meta.json'), JSON.stringify(meta, null, 2));
    fs.writeFileSync(path.join(evidenceDir, label + '-dom.html'), dom);
    fs.writeFileSync(path.join(evidenceDir, label + '-result.txt'),
      (result ? result.lines.join('\n') : 'NO RESULT BLOCK') + '\n');
    const humanLog = [
      'label: ' + label,
      'web-root: ' + options.webRoot,
      'url: ' + url,
      'chrome: ' + command,
      'chrome-exit: ' + chromeRun.status + ' elapsed-ms: ' + elapsedMs,
      'static: ' + JSON.stringify(staticEvidence),
      '--- assertions ---',
      ...(result ? result.lines : ['NO RESULT BLOCK']),
      infraError ? '--- harness error ---\n' + infraError : '',
    ].filter(Boolean).join('\n') + '\n';
    fs.writeFileSync(path.join(evidenceDir, label + '.log'), humanLog);
    fs.appendFileSync(path.join(evidenceDir, 'commands.txt'),
      '[' + startedAt + '] label=' + label + ' web-root=' + options.webRoot +
      ' chrome-exit=' + chromeRun.status + ' result=' + (result ? (result.ok ? 'PASS' : 'FAIL') : 'NO-RESULT') + '\n' +
      '  python: ' + server.command + '\n  chrome: ' + command + '\n');
  } catch (error) {
    infraFailure = true;
    infraError = error && error.stack ? error.stack : String(error);
    writeInfraAttemptLog(evidenceDir, label, infraError);
  } finally {
    stopServer(server);
    if (!options.keepTemp) removeTree(tempRoot, 'temp work dir');
  }

  console.log('');
  console.log('=== Titan scroll-stability browser regression ===');
  console.log('label          : ' + label);
  console.log('attempt        : ' + harnessAttempt);
  console.log('web-root       : ' + options.webRoot);
  console.log('static evidence: ' + JSON.stringify(staticEvidence));
  if (infraError) {
    console.error('');
    console.error('HARNESS ERROR:');
    console.error(infraError);
  }
  if (result) {
    for (const line of result.lines) console.log(line);
  }
  console.log('');
  if (result && result.ok) {
    console.log('RESULT: PASS (' + result.lines.filter((line) => line.startsWith('PASS ')).length + ' assertions)');
  } else {
    console.log('RESULT: FAIL');
    if (result && result.failures.length) {
      console.log('failing assertions:');
      for (const failure of result.failures) console.log('  ' + failure);
    }
  }
  console.log('evidence       : ' + evidenceDir + '\\' + label + '.log / ' + label + '-result.txt / ' + label + '-dom.html / ' + label + '-meta.json');
  console.log('temp dir       : ' + (options.keepTemp ? tempRoot : '(cleaned)'));
  return result && result.ok && !infraError ? 0 : 1;
}

/** Run main(), retrying at most once and only for infrastructure failures. */
async function runWithRetry() {
  for (let attempt = 1; ; attempt += 1) {
    harnessAttempt = attempt;
    const code = await main();
    if (!infraFailure || attempt >= 2) return code;
    console.warn('WARN: harness infrastructure failure on attempt ' + attempt + ' (not an assertion result); retrying once.');
  }
}

runWithRetry().then((code) => {
  process.exitCode = code;
}).catch((error) => {
  console.error('FATAL: ' + (error && error.stack ? error.stack : error));
  process.exitCode = 1;
});
