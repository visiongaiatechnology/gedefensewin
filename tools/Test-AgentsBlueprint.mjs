// STATUS: DIAMANT VGT SUPREME
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  AGENT_DEFAULT_VERSION,
  buildAgentStarterPrompt,
  buildWindowsAgentsMarkdown,
  sanitizeAgentLines,
} from '../src/GeDefense/windows/internal/server/web/agents-blueprint.js';

test('sanitizeAgentLines strips control chars, backticks, duplicates and caps length', () => {
  const dirty = [
    '  C:\\Users\\Dev\\Projects`rm -rf`\r\n',
    'C:\\Users\\Dev\\Projects`rm -rf`',
    '',
    'D:\\Workspaces\\Go\x00Bin',
  ];
  const out = sanitizeAgentLines(dirty);
  assert.deepEqual(out, ['C:\\Users\\Dev\\Projectsrm -rf', 'D:\\Workspaces\\Go Bin']);
});

test('buildWindowsAgentsMarkdown generates tailored Windows 6.1.0 blueprint without external AI APIs', () => {
  const md = buildWindowsAgentsMarkdown({
    profile: 'developer',
    profileLabel: 'ENTWICKLER / BUILD',
    targetProfile: 'EnterpriseBalanced',
    titanMode: 'STRICT',
    autoQuarantine: false,
    devRoots: ['C:\\Dev\\RepoA'],
    ownerProcesses: ['C:\\Program Files\\Go\\bin\\go.exe'],
    version: AGENT_DEFAULT_VERSION,
    platform: 'Windows 11 Pro',
    posture: {
      protectionMode: 'guarded',
      protectionHealth: 'VERIFIED',
      defender: true,
      cfa: true,
    },
  });

  assert.match(md, /GeDefense Windows 6\.1\.0/);
  assert.match(md, /Zero Remote AI API/);
  assert.match(md, /http:\/\/127\.0\.0\.1:17831/);
  assert.match(md, /C:\\Dev\\RepoA/);
  assert.match(md, /C:\\Program Files\\Go\\bin\\go\.exe/);
  assert.match(md, /"autoQuarantine": false/);
  assert.match(md, /GET \/api\/v1\/mhx\/symbiosis/);
  assert.match(md, /RESUME CONTAINED PROCESS/);
  assert.match(md, /ADD DEVELOPMENT ROOT/);
  assert.doesNotMatch(md, /https?:\/\/(?!127\.0\.0\.1)/i);
  assert.doesNotMatch(md, /openai\.com|anthropic\.com|generativelanguage\.googleapis\.com/i);
});

test('buildWindowsAgentsMarkdown warns before Isolation RDP/USB lockouts on server profile', () => {
  const md = buildWindowsAgentsMarkdown({
    profile: 'server',
    profileLabel: 'SERVER / HOCHRISIKO',
    targetProfile: 'Isolation',
    titanMode: 'STRICT',
    autoQuarantine: true,
  });
  assert.match(md, /"profile": "Isolation"/);
  assert.match(md, /"autoQuarantine": true/);
  assert.match(md, /USB-Massenspeicher und RDP/);
});

test('buildAgentStarterPrompt avoids hardcoded secrets and stays local-only', () => {
  const prompt = buildAgentStarterPrompt({profile: 'business', profileTitle: 'UNTERNEHMEN / BÜRO', version: '6.1.0'});
  assert.match(prompt, /AGENTS\.md/);
  assert.match(prompt, /6\.1\.0/);
  assert.match(prompt, /http:\/\/127\.0\.0\.1:17831/);
  assert.doesNotMatch(prompt, /dashboard\.token=[A-Za-z0-9]/);
});
