// STATUS: PLATIN
'use strict';
/** First-run setup wizard.
 *
 * The wizard is a thin, honest operator flow over the existing enforcement APIs.
 * It never claims a protection is active from a local checkbox: the completion
 * step is gated by the server's measured Defender/ASR/CFA, policy and integrity
 * posture. Any unavailable or rejected apply remains visible as an error.
 */
import {api, optionalApi} from './api.js';

const CASES = [
  {
    id: 'personal',
    eyebrow: 'PERSÖNLICHER PC',
    title: 'Sicher surfen, ohne Kontrolle zu verlieren',
    body: 'Für Alltag, Browser, Kommunikation und persönliche Dateien. Empfohlen: vollständiger Defender-Schutz, ASR/CFA im Blockmodus, Firewall, Titan STRICT und Integritätsüberwachung.',
    target: 'EnterpriseBalanced',
    titan: 'STRICT',
    autoQuarantine: true,
    warnings: ['Titan kann unautorisierte ausführbare Dateien in geschützte Quarantäne verschieben.', 'Unbekannte Installer werden nach der Einrichtung möglicherweise zusätzlich geprüft.'],
  },
  {
    id: 'business',
    eyebrow: 'UNTERNEHMEN / BÜRO',
    title: 'Nachvollziehbar schützen und reagieren',
    body: 'Für Arbeitsplätze mit geschäftlichen Daten und mehreren Schutzschichten. Empfohlen: EnterpriseBalanced, alle ASR-Regeln im Blockmodus, CFA, Firewall, Titan STRICT und lückenlose Evidenz.',
    target: 'EnterpriseBalanced',
    titan: 'STRICT',
    autoQuarantine: true,
    warnings: ['Blockierende ASR-Regeln können alte, unsignierte Fachanwendungen beeinträchtigen.', 'Titan-Quarantäne ist reversibel, ersetzt aber keine Freigabe durch den Betreiber.'],
  },
  {
    id: 'server',
    eyebrow: 'SERVER / HOCHRISIKO',
    title: 'Angriffsfläche reduzieren, Betrieb sichern',
    body: 'Für dauerhaft laufende Systeme ohne lokale Bedienung. Empfohlen: Isolation-Profil mit zusätzlich deaktiviertem USB-Speicher und RDP, Defender vollständig blockierend, Firewall und Titan STRICT.',
    target: 'Isolation',
    titan: 'STRICT',
    autoQuarantine: true,
    warnings: ['USB-Speicher und RDP werden deaktiviert. Nur wählen, wenn das zum Einsatzgebiet passt.', 'Remote-Verwaltung muss vorher über einen freigegebenen Weg eingerichtet sein.'],
  },
  {
    id: 'developer',
    eyebrow: 'ENTWICKLER / BUILD',
    title: 'Härtung ohne die eigene Toolchain zu blockieren',
    body: 'Für lokale Entwicklung und Builds. Empfohlen: EnterpriseBalanced, Defender blockierend, Titan STRICT mit Entwicklungsbaum und expliziten Owner-Prozessketten. Automatische Quarantäne bleibt hier aus.',
    target: 'EnterpriseBalanced',
    titan: 'STRICT',
    autoQuarantine: false,
    warnings: ['Entwicklungsbaum und Toolchain müssen als Owner-Vertrauen eingetragen werden.', 'Automatische Quarantäne ist für Entwickler nicht aktiv, damit Builds nicht zerstört werden.'],
  },
];

const LEVELS = [
  ['OBSERVE', 'Nur beobachten', 'Erkennt und protokolliert, blockiert nicht. Für Analyse und Erstinbetriebnahme, nicht als Dauerzustand.'],
  ['BALANCED', 'Ausgewogen', 'Defender vollständig, ASR/CFA blockierend, Firewall aktiv, Titan STRICT. Empfohlen für Privat und Büro.'],
  ['ISOLATION', 'Isolation', 'Zusätzlich USB-Speicher und RDP aus. Höchste Härtung, aber nur für passende Einsatzgebiete.'],
];

let overlay = null;
let selected = 'personal';
let step = 0;
let busy = false;
let lastVerification = null;
let previousFocus = null;

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function caseById(id) {
  return CASES.find(item => item.id === id) || CASES[0];
}

function showError(message) {
  const host = overlay?.querySelector('#setupError');
  if (!host) return;
  host.textContent = String(message || 'Unbekannter Fehler');
  host.hidden = false;
}

function clearError() {
  const host = overlay?.querySelector('#setupError');
  if (host) {
    host.hidden = true;
    host.textContent = '';
  }
}

function setBusy(value) {
  busy = Boolean(value);
  if (!overlay) return;
  overlay.querySelectorAll('button').forEach(button => {
    if (button.dataset.allowBusy !== 'true') button.disabled = busy;
  });
  const spinner = overlay.querySelector('#setupBusy');
  if (spinner) spinner.hidden = !busy;
}

function progress(value) {
  if (!overlay) return;
  overlay.querySelectorAll('[data-step-dot]').forEach((dot, index) => {
    dot.dataset.state = index < value ? 'done' : index === value ? 'active' : 'pending';
    if (index === value) dot.setAttribute('aria-current', 'step');
    else dot.removeAttribute('aria-current');
  });
  const bar = overlay.querySelector('#setupProgress');
  if (bar) bar.value = value;
}

function header() {
  const head = el('header', 'setup-head');
  const brand = el('div', 'setup-brand');
  const mark = el('span', 'setup-mark');
  mark.setAttribute('aria-hidden', 'true');
  const copy = el('div', 'setup-brand-copy');
  copy.append(el('p', 'setup-eyebrow', 'GEDEFENSE TITAN · ERSTEINRICHTUNG'), el('h2', 'setup-title', 'Schutz vollständig aktivieren'));
  copy.append(el('p', 'setup-subtitle', 'Ein geführter Weg von der Installation bis zur verifizierten Schutzlage. Jede Freigabe wird durch die Control Plane geprüft.'));
  brand.append(mark, copy);
  const close = el('button', 'setup-close', '×');
  close.type = 'button';
  close.id = 'setupClose';
  close.dataset.allowBusy = 'false';
  close.setAttribute('aria-label', 'Einrichtung später fortsetzen');
  close.addEventListener('click', () => closeWizard());
  head.append(brand, close);
  return head;
}

function progressRail() {
  const rail = el('ol', 'setup-steps');
  rail.setAttribute('aria-label', 'Einrichtungsschritte');
  const labels = ['Einsatzgebiet', 'Empfehlung', 'Aktivierung', 'Verifikation'];
  labels.forEach((label, index) => {
    const item = el('li', 'setup-step');
    const dot = el('span', 'setup-step-dot', String(index + 1));
    dot.dataset.stepDot = String(index);
    const text = el('span', 'setup-step-label', label);
    item.append(dot, text);
    rail.append(item);
  });
  const progress = el('progress', 'setup-progress');
  progress.id = 'setupProgress';
  progress.max = 3;
  progress.value = 0;
  progress.setAttribute('aria-label', 'Fortschritt der Ersteinrichtung');
  const wrap = el('div', 'setup-progress-wrap');
  wrap.append(rail, progress);
  return wrap;
}

function footer() {
  const foot = el('footer', 'setup-foot');
  const error = el('p', 'setup-error');
  error.id = 'setupError';
  error.setAttribute('role', 'alert');
  error.hidden = true;
  const busyIndicator = el('span', 'setup-busy', 'Prüfung läuft …');
  busyIndicator.id = 'setupBusy';
  busyIndicator.hidden = true;
  const back = el('button', 'button ghost setup-back', 'Zurück');
  back.type = 'button';
  back.id = 'setupBack';
  back.addEventListener('click', () => {
    if (busy) return;
    step = Math.max(0, step - 1);
    render();
  });
  const next = el('button', 'button primary setup-next', 'Weiter');
  next.type = 'button';
  next.id = 'setupNext';
  next.dataset.allowBusy = 'false';
  next.addEventListener('click', () => {
    if (busy) return;
    if (step === 0) {
      step = 1;
      render();
    } else if (step === 1) {
      void activate();
    } else if (step === 2) {
      void verify();
    } else {
      void complete();
    }
  });
  foot.append(error, busyIndicator, back, next);
  return foot;
}

function welcomeStep() {
  const fragment = document.createDocumentFragment();
  const intro = el('section', 'setup-intro');
  intro.append(
    el('p', 'setup-kicker', 'SCHRITT 1 · EINSATZGEBIET'),
    el('h3', 'setup-section-title', 'Wofür wird dieser PC geschützt?'),
    el('p', 'setup-copy', 'Die Auswahl bestimmt, welche Schutzstufe empfohlen wird. Sie ist keine Kosmetik: sie steuert die tatsächlich angewendete GeDefense-Härtung und die Titan-Richtlinie.')
  );
  const grid = el('div', 'setup-case-grid');
  CASES.forEach(item => {
    const card = el('button', 'setup-case');
    card.type = 'button';
    card.dataset.caseId = item.id;
    card.setAttribute('aria-pressed', item.id === selected ? 'true' : 'false');
    card.append(
      el('span', 'setup-case-eyebrow', item.eyebrow),
      el('strong', 'setup-case-title', item.title),
      el('span', 'setup-case-copy', item.body)
    );
    card.addEventListener('click', () => {
      selected = item.id;
      grid.querySelectorAll('.setup-case').forEach(other => other.setAttribute('aria-pressed', other.dataset.caseId === selected ? 'true' : 'false'));
    });
    grid.append(card);
  });
  intro.append(grid);
  fragment.append(intro);
  return fragment;
}

function recommendationStep() {
  const item = caseById(selected);
  const fragment = document.createDocumentFragment();
  const section = el('section', 'setup-intro');
  section.append(
    el('p', 'setup-kicker', 'SCHRITT 2 · EMPFEHLUNG'),
    el('h3', 'setup-section-title', item.eyebrow),
    el('p', 'setup-copy', item.body)
  );
  const target = el('div', 'setup-target');
  target.append(el('span', 'setup-target-label', 'ANGEWENDETES PROFIL'), el('strong', 'setup-target-value', item.target === 'Isolation' ? 'VGT Isolation' : 'VGT Enterprise Balanced'));
  section.append(target);
  const list = el('ul', 'setup-checks');
  const checks = [
    ['Defender', 'Echtzeit-, Behavior-, IOAV- und Cloud-Schutz aktiv.'],
    ['ASR', 'Alle elf priorisierten Regeln im Blockmodus, keine Audit-Stilllegung.'],
    ['Controlled Folder Access', 'Schreibzugriffe auf geschützte Ordner werden blockiert.'],
    ['Firewall', 'Eingehend standardmäßig blockiert, Logging aktiv.'],
    ['Titan', `Modus ${item.titan}${item.autoQuarantine ? ' mit reversibler Auto-Quarantäne' : ' ohne automatische Quarantäne'}.`],
    ['Integrität', 'Authentifizierte Überwachung der GeDefense-Konfiguration und Baselines.'],
  ];
  checks.forEach(([name, detail]) => {
    const li = el('li', 'setup-check');
    li.append(el('span', 'setup-check-mark', '✓'), el('strong', '', name), el('span', '', ' ' + detail));
    list.append(li);
  });
  section.append(list);
  const warn = el('div', 'setup-warning');
  warn.append(el('strong', '', 'Bitte beachten'));
  const warnList = el('ul', 'setup-warning-list');
  item.warnings.forEach(text => warnList.append(el('li', '', text)));
  warn.append(warnList);
  section.append(warn);
  const levels = el('details', 'setup-levels');
  levels.append(el('summary', '', 'Was bedeuten die Schutzstufen?'));
  const table = el('div', 'setup-level-table');
  LEVELS.forEach(([id, title, body]) => {
    const row = el('div', 'setup-level-row');
    row.append(el('span', 'setup-level-id', id), el('strong', '', title), el('span', '', body));
    table.append(row);
  });
  levels.append(table);
  section.append(levels);
  if (selected === 'developer') {
    const toolchain = el('div', 'setup-toolchain');
    toolchain.append(
      el('label', 'setup-toolchain-label', 'Entwickler-Toolchain (optional)'),
      el('p', 'setup-toolchain-help', 'Absolute Pfade zu vertrauenswürdigen EXE-Dateien, eine pro Zeile. Sie werden nur für Ingress-/User-Content-Evidenz als TOLERATED behandelt; System- und Persistenzänderungen bleiben prüfpflichtig.')
    );
    const input = el('textarea', 'setup-toolchain-input');
    input.id = 'setupOwnerProcesses';
    input.rows = 3;
    input.spellcheck = false;
    input.placeholder = 'C:\\Program Files\\DeepSeek Harness\\DeepSeek Harness.exe';
    toolchain.append(input);
    section.append(toolchain);
  }
  fragment.append(section);
  return fragment;
}

function activationStep() {
  const fragment = document.createDocumentFragment();
  const section = el('section', 'setup-intro');
  section.append(
    el('p', 'setup-kicker', 'SCHRITT 3 · AKTIVIERUNG'),
    el('h3', 'setup-section-title', 'GeDefense wird jetzt scharf geschaltet'),
    el('p', 'setup-copy', 'Die folgenden Schritte werden serverseitig ausgeführt. Wenn ein Schritt abgelehnt wird, bleibt die Einrichtung offen – es gibt keinen lokalen „erledigt“-Schalter.')
  );
  const list = el('ul', 'setup-action-list');
  const actions = [
    ['Härtungsprofil', `Defender/ASR/CFA/Firewall/Identität über das Profil ${caseById(selected).target === 'Isolation' ? 'Isolation' : 'EnterpriseBalanced'} anwenden.`],
    ['Integritätsmonitor', 'Authentifizierte Überwachung aktivieren und konfigurieren.'],
    ['Titan', `Richtlinie auf ${caseById(selected).titan} setzen; Evidenz bleibt lesbar.`],
    ['Policy-Abgleich', 'MHX-Schutzrichtlinie neu abgleichen und Bereitschaft messen.'],
  ];
  actions.forEach(([name, detail]) => {
    const li = el('li', 'setup-action');
    li.append(el('span', 'setup-check-mark', '›'), el('strong', '', name), el('span', '', ' ' + detail));
    list.append(li);
  });
  section.append(list);
  const note = el('p', 'setup-note', 'Nach der Aktivierung wird die reale Schutzlage gemessen. Erst wenn Defender, ASR/CFA, Firewall, Policy und Integrität tatsächlich verifiziert sind, kann die Einrichtung abgeschlossen werden.');
  section.append(note);
  fragment.append(section);
  return fragment;
}

function verificationStep() {
  const fragment = document.createDocumentFragment();
  const section = el('section', 'setup-intro');
  section.append(
    el('p', 'setup-kicker', 'SCHRITT 4 · VERIFIKATION'),
    el('h3', 'setup-section-title', 'Reale Schutzlage'),
    el('p', 'setup-copy', 'Diese Werte stammen aus der laufenden Control Plane, nicht aus dem Assistenten.')
  );
  const list = el('ul', 'setup-verification');
  list.id = 'setupVerification';
  if (!lastVerification) {
    list.append(el('li', 'setup-verify-pending', 'Messung wird vorbereitet …'));
  } else {
    lastVerification.checks.forEach(check => {
      const li = el('li', 'setup-verify');
      li.dataset.state = check.ok ? 'pass' : 'fail';
      li.append(el('span', 'setup-verify-mark', check.ok ? '✓' : '!'), el('strong', '', check.label), el('span', '', ' ' + check.detail));
      list.append(li);
    });
  }
  section.append(list);
  const summary = el('p', 'setup-note');
  const ready = Boolean(lastVerification?.ready);
  summary.textContent = ready ? 'Alle geprüften Schutzbereiche sind aktiv verifiziert. Die Einrichtung kann abgeschlossen werden.' : 'Mindestens ein Bereich ist noch nicht verifiziert. Bitte den Fehler beheben und erneut messen.';
  section.append(summary);
  fragment.append(section);
  return fragment;
}

function render() {
  if (!overlay) return;
  const body = overlay.querySelector('#setupBody');
  if (!body) return;
  body.replaceChildren();
  if (step === 0) body.append(welcomeStep());
  else if (step === 1) body.append(recommendationStep());
  else if (step === 2) body.append(activationStep());
  else body.append(verificationStep());
  progress(step);
  const back = overlay.querySelector('#setupBack');
  const next = overlay.querySelector('#setupNext');
  if (back) back.hidden = step === 0 || step === 3;
  if (next) {
    next.textContent = step === 0 ? 'Weiter' : step === 1 ? 'Profil anwenden' : step === 2 ? 'Jetzt verifizieren' : (lastVerification?.ready ? 'Einrichtung abschließen' : 'Erneut prüfen');
    next.disabled = busy;
  }
  clearError();
}

function mount() {
  previousFocus = document.activeElement;
  overlay = el('div', 'setup-wizard');
  overlay.id = 'setupWizard';
  overlay.setAttribute('role', 'dialog');
  overlay.setAttribute('aria-modal', 'true');
  overlay.setAttribute('aria-labelledby', 'setupTitle');
  const panel = el('div', 'setup-panel');
  panel.append(header(), progressRail());
  const body = el('div', 'setup-body');
  body.id = 'setupBody';
  panel.append(body, footer());
  overlay.append(panel);
  document.body.append(overlay);
  render();
  const focusTarget = overlay.querySelector('.setup-case');
  if (focusTarget) focusTarget.focus({preventScroll: true});
  overlay.addEventListener('keydown', trapFocus);
  if (typeof overlay.showModal === 'function') {
    // A <div> overlay is intentional: the CSP-safe shell has no inline dialog
    // markup. Keep focus inside and restore it on close.
  }
}

function trapFocus(event) {
  if (event.key !== 'Tab') return;
  const focusable = [...overlay.querySelectorAll('button:not([disabled]), summary, [tabindex="0"]')].filter(node => node.offsetParent !== null);
  if (!focusable.length) return;
  const first = focusable[0];
  const last = focusable[focusable.length - 1];
  if (event.shiftKey && document.activeElement === first) {
    event.preventDefault();
    last.focus();
  } else if (!event.shiftKey && document.activeElement === last) {
    event.preventDefault();
    first.focus();
  }
}

function closeWizard() {
  if (busy) return;
  overlay?.remove();
  overlay = null;
  if (previousFocus instanceof HTMLElement && previousFocus.isConnected) previousFocus.focus({preventScroll: true});
}

async function activate() {
  if (busy) return;
  setBusy(true);
  clearError();
  const choice = caseById(selected);
  const reason = `First-run setup: ${choice.eyebrow} · ${choice.target} · operator choice`;
  try {
    const hardening = await api('/api/v1/hardening/enforce', {
      method: 'POST',
      json: {profile: choice.target, reason, confirmation: 'APPLY HARDENING PROFILE'},
      signal: AbortSignal.timeout(660000),
    });
    if (hardening?.Error || hardening?.error) throw new Error(String(hardening.Error || hardening.error));
    const integrity = await api('/api/v1/integrity/configuration', {
      method: 'POST',
      json: {enabled: true, intervalHours: 24, reason, confirmation: 'CHANGE INTEGRITY MONITORING'},
      signal: AbortSignal.timeout(60000),
    });
    if (integrity?.state === 'DEGRADED') throw new Error('Integritätsmonitor ist nach der Aktivierung noch degradiert.');
    await api('/api/v1/titan/policy', {
      method: 'POST',
      json: {mode: choice.titan, autoQuarantine: choice.autoQuarantine, reason},
      signal: AbortSignal.timeout(60000),
    });
    if (selected === 'developer') {
      const raw = overlay?.querySelector('#setupOwnerProcesses')?.value || '';
      const images = raw.split(/\r?\n/).map(line => line.trim()).filter(Boolean);
      if (images.length) {
        await api('/api/v1/titan/owner-process-images', {
          method: 'POST',
          json: {images, reason, confirmation: 'UPDATE OWNER PROCESS IMAGES'},
          signal: AbortSignal.timeout(60000),
        });
      }
    }
    await api('/api/v1/mhx/policy/reconcile', {method: 'POST', json: {}, signal: AbortSignal.timeout(240000)}).catch(() => {});
    await api('/api/v1/health/refresh', {method: 'POST', json: {}, signal: AbortSignal.timeout(130000)}).catch(() => {});
    step = 3;
    await verify();
  } catch (error) {
    if (step !== 3) {
      step = 2;
      render();
    }
    if (error?.status === 403) showError('Für die Aktivierung ist eine Operator-Sitzung erforderlich. Bitte über das Security Center anmelden und erneut versuchen.');
    else if (error?.status === 409) showError(`Die Control Plane hat die Aktivierung abgelehnt: ${error.message}. Bitte die angezeigten Voraussetzungen prüfen.`);
    else showError(`Aktivierung nicht abgeschlossen: ${error?.message || error}`);
  } finally {
    setBusy(false);
  }
}

function checkFromStatus(status, integrity, titan) {
  const protection = status?.protection || {};
  const mhx = status?.mhx || {};
  const checks = [
    {
      label: 'Microsoft Defender',
      ok: Boolean(protection.Defender && protection.DefenderService && protection.RealTimeProtection && protection.BehaviorProtection && protection.IoavProtection),
      detail: protection.Defender ? 'Echtzeit- und Verhaltensschutz gemeldet.' : 'Defender ist nicht verfügbar.',
    },
    {
      label: 'ASR-Regeln',
      ok: Number(protection.AsrRules || 0) >= 11 && Number(protection.AsrBlockRules || 0) >= 11,
      detail: `${Number(protection.AsrBlockRules || 0)}/${Number(protection.AsrRules || 0)} blockierend; 11/11 erforderlich.`,
    },
    {
      label: 'Controlled Folder Access',
      ok: Boolean(protection.ControlledFolderAccess),
      detail: protection.ControlledFolderAccess ? 'Blockmodus aktiv.' : 'Nicht im Blockmodus.',
    },
    {
      label: 'Windows Firewall',
      ok: Boolean(protection.Firewall),
      detail: protection.Firewall ? 'Firewall aktiv.' : 'Firewall nicht bestätigt.',
    },
    {
      label: 'Schutzrichtlinie',
      ok: mhx.protectionHealth === 'VERIFIED',
      detail: `ProtectionHealth = ${mhx.protectionHealth || 'unbekannt'}`,
    },
    {
      label: 'Integritätsmonitor',
      ok: Boolean(integrity?.enabled) && integrity?.state !== 'DEGRADED',
      detail: `${integrity?.state || 'unbekannt'}${integrity?.error ? ' · ' + integrity.error : ''}`,
    },
    {
      label: 'Titan',
      ok: titan?.mode === caseById(selected).titan,
      detail: `Modus ${titan?.mode || 'unbekannt'}; erwartet ${caseById(selected).titan}.`,
    },
  ];
  return {checks, ready: checks.every(check => check.ok)};
}

async function verify() {
  if (busy) return;
  setBusy(true);
  clearError();
  try {
    const [status, integrity, titan] = await Promise.all([
      api('/api/v1/status'),
      api('/api/v1/integrity/status').catch(() => ({enabled: false, state: 'unavailable'})),
      api('/api/v1/titan/status').catch(() => ({mode: 'unavailable'})),
    ]);
    lastVerification = checkFromStatus(status, integrity, titan);
    step = 3;
    render();
    if (!lastVerification.ready) showError('Die Schutzlage ist noch nicht vollständig verifiziert. Details stehen in der Prüfliste.');
  } catch (error) {
    showError(`Verifikation nicht möglich: ${error?.message || error}`);
  } finally {
    setBusy(false);
  }
}

async function complete() {
  if (busy) return;
  if (!lastVerification?.ready) {
    await verify();
    if (!lastVerification?.ready) return;
  }
  setBusy(true);
  clearError();
  try {
    const choice = caseById(selected);
    await api('/api/v1/setup/complete', {
      method: 'POST',
      json: {profile: selected, reason: `First-run setup completed after verified ${choice.target} posture.`, confirmation: 'COMPLETE SETUP'},
      signal: AbortSignal.timeout(60000),
    });
    const body = overlay?.querySelector('#setupBody');
    if (body) {
      body.replaceChildren();
      const done = el('section', 'setup-intro setup-done');
      done.append(el('p', 'setup-kicker', 'EINRICHTUNG ABGESCHLOSSEN'), el('h3', 'setup-section-title', 'GeDefense ist bereit.'), el('p', 'setup-copy', 'Die geprüfte Schutzlage ist gespeichert. Beim nächsten Start wird der Assistent nicht erneut angezeigt; die Bereitschaftsprüfung bleibt aktiv.'));
      body.append(done);
    }
    const next = overlay?.querySelector('#setupNext');
    if (next) next.hidden = true;
    const back = overlay?.querySelector('#setupBack');
    if (back) back.hidden = true;
    const close = overlay?.querySelector('#setupClose');
    if (close) close.disabled = false;
    const finish = el('button', 'button primary', 'Security Center öffnen');
    finish.type = 'button';
    finish.addEventListener('click', () => globalThis.location.reload());
    overlay?.querySelector('.setup-foot')?.append(finish);
  } catch (error) {
    showError(`Abschluss abgelehnt: ${error?.message || error}`);
  } finally {
    setBusy(false);
  }
}

export async function initSetupWizard() {
  if (overlay) return true;
  let result;
  try {
    result = await optionalApi('/api/v1/setup/status', {signal: AbortSignal.timeout(8000)});
  } catch {
    return false;
  }
  if (!result?.ok || result.data?.complete === true) return false;
  mount();
  return true;
}
