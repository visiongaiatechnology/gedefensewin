// STATUS: PLATIN VGT SUPREME
'use strict';

import {getV6Status, setStyxWhitelist, setV6Mode} from './api.js';
import {byId, clear, formatBytes, metric, node, pill, requestReason, setBusy, setText, severity, toast} from './dom.js';

let initialized = false;
let currentV6 = null;
let v6ModeBusy = false;
const expandedStyxIDs = new Set();

function textOrDash(value) {
  if (value === undefined || value === null || value === '') return '---';
  return String(value);
}

function toneForWitness(status) {
  if (status === 'CONNECTED') return 'ok';
  if (status === 'UNVERIFIED' || status === 'DISABLED') return 'info';
  if (status === 'DEGRADED') return 'warn';
  return 'bad';
}

function toneForSensor(active, degraded) {
  if (degraded) return 'warn';
  return active ? 'ok' : 'info';
}

export async function loadV6({silent = false} = {}) {
  try {
    const data = await getV6Status(50);
    currentV6 = data;
    renderV6(data);
  } catch (error) {
    if (silent) return;
    toast(`V6 Sovereign Status fehlgeschlagen: ${error?.message || error}`, 'bad');
  }
}

async function applyV6ModeChange({spywareMode = '', styxMode = '', button = null} = {}) {
  if (v6ModeBusy) return;
  const curSpy = currentV6?.spyware?.mode || (currentV6?.spyware?.activeEnforced ? 'active' : 'observe');
  const curStyx = currentV6?.styx?.mode || 'observe';
  const rankStyx = m => (m === 'enforce' ? 3 : (m === 'observe' ? 2 : 1));
  const weakeningSpy = spywareMode && curSpy === 'active' && spywareMode !== 'active';
  const weakeningStyx = styxMode && (styxMode === 'off' || rankStyx(styxMode) < rankStyx(curStyx));
  const weakening = Boolean(weakeningSpy || weakeningStyx);

  let reason = 'Operator hat V6 Sovereign Schutz umgeschaltet';
  let confirmation = '';
  if (weakening) {
    const entered = await requestReason({
      title: 'V6 Sovereign Schutzstufe senken',
      text: 'Das Herabstufen von Aktiv/WFP-Enforce auf Observe oder Aus reduziert die aktive Durchsetzung. Bitte Begründung angeben.',
      label: 'Begründung',
      confirmLabel: 'Herabstufen',
      tone: 'danger',
    });
    if (!entered) return;
    reason = entered;
    confirmation = 'CHANGE V6 POSTURE';
  }

  v6ModeBusy = true;
  if (button) setBusy(button, true);
  try {
    const updated = await setV6Mode({spywareMode, styxMode, reason, confirmation});
    currentV6 = updated;
    renderV6(updated);
    const activeLabel = [];
    if (updated?.spyware?.activeEnforced) activeLabel.push('Anti-Spyware AKTIV');
    else if (updated?.spyware?.enabled) activeLabel.push('Anti-Spyware OBSERVE');
    if (updated?.styx?.enforcing) {
      activeLabel.push(updated?.styx?.wfpActive ? `StyX WFP AKTIV (${updated.styx.wfpFilterCount || 0} Filter)` : 'StyX ENFORCE');
    } else if (updated?.styx?.mode) {
      activeLabel.push(`StyX ${String(updated.styx.mode).toUpperCase()}`);
    }
    toast(`V6 Sovereign aktualisiert: ${activeLabel.join(' · ') || 'OK'}`, 'good');
  } catch (error) {
    toast(`V6 Moduswechsel fehlgeschlagen: ${error?.message || error}`, 'bad');
  } finally {
    v6ModeBusy = false;
    if (button) setBusy(button, false);
  }
}

export function bindV6() {
  if (initialized) return;
  initialized = true;
  byId('v6Refresh')?.addEventListener('click', () => {
    void loadV6({silent: false});
  });
  byId('v6ActivateAllBtn')?.addEventListener('click', ev => {
    void applyV6ModeChange({spywareMode: 'active', styxMode: 'enforce', button: ev.currentTarget});
  });
  byId('v6SpyObserveBtn')?.addEventListener('click', () => {
    void applyV6ModeChange({spywareMode: 'observe'});
  });
  byId('v6SpyActiveBtn')?.addEventListener('click', () => {
    void applyV6ModeChange({spywareMode: 'active'});
  });
  byId('v6StyxOffBtn')?.addEventListener('click', () => {
    void applyV6ModeChange({styxMode: 'off'});
  });
  byId('v6StyxObserveBtn')?.addEventListener('click', () => {
    void applyV6ModeChange({styxMode: 'observe'});
  });
  byId('v6StyxEnforceBtn')?.addEventListener('click', () => {
    void applyV6ModeChange({styxMode: 'enforce'});
  });
  byId('v6WhitelistAddBtn')?.addEventListener('click', () => {
    const input = byId('v6WhitelistInput');
    const entry = String(input?.value || '').trim();
    if (!entry) return;
    void applyStyxWhitelist({action: 'add', entry, onSuccess: () => { if (input) input.value = ''; }});
  });
  byId('v6WhitelistInput')?.addEventListener('keydown', ev => {
    if (ev.key !== 'Enter') return;
    ev.preventDefault();
    byId('v6WhitelistAddBtn')?.click();
  });
}

async function applyStyxWhitelist({action = 'add', entry = '', onSuccess = null} = {}) {
  if (v6ModeBusy || !entry) return;
  const isRemove = action === 'remove';
  const reason = await requestReason({
    title: isRemove ? 'StyX-Whitelist-Eintrag entfernen' : 'StyX Egress / WFP freigeben',
    text: isRemove
      ? `Der Eintrag "${entry}" wird aus der StyX-Whitelist entfernt.`
      : `Programm, Pfad oder Ziel "${entry}" wird auf die StyX-Whitelist gesetzt und eine aktive WFP-Sperre sofort aufgehoben.`,
    label: 'Begründung (mind. 8 Zeichen)',
    confirmLabel: isRemove ? 'Entfernen' : 'Freigeben (Whitelist)',
    tone: isRemove ? 'danger' : 'primary',
  });
  if (!reason) return;

  v6ModeBusy = true;
  try {
    const updated = await setStyxWhitelist({action, entry, reason});
    currentV6 = updated;
    renderV6(updated);
    if (typeof onSuccess === 'function') onSuccess();
    toast(isRemove ? `Whitelist-Eintrag entfernt: ${entry}` : `StyX Whitelist freigegeben: ${entry}`, 'good');
  } catch (error) {
    toast(`StyX Whitelist fehlgeschlagen: ${error?.message || error}`, 'bad');
  } finally {
    v6ModeBusy = false;
  }
}

function renderV6(data) {
  const spy = data?.spyware || {};
  const wit = data?.witness || {};
  const styx = data?.styx || {};
  const styxCol = data?.styxCollector || {};
  const spyFindings = Array.isArray(data?.spywareFindings) ? data.spywareFindings : [];
  const styxIncidents = Array.isArray(data?.styxIncidents) ? data.styxIncidents : [];
  const lockState = textOrDash(data?.lockState || 'UNAVAILABLE');

  const activeSensors = [
    spy.byovdWatched ? 'BYOVD' : null,
    spy.capabilityWatch ? 'Capability' : null,
    spy.persistenceWatch ? 'Persistence' : null,
    spy.lsassWatch ? 'LSASS' : null,
  ].filter(Boolean);

  const spyActive = Boolean(spy.enabled && (spy.activeEnforced || spy.mode === 'active'));
  const spyModeLabel = !spy.enabled ? 'DISABLED' : (spy.degraded ? 'DEGRADED' : (spyActive ? 'AKTIV' : 'OBSERVE_ONLY'));
  const styxEnforcing = Boolean(styx.enforcing || styx.mode === 'enforce');
  const styxModeLabel = styxEnforcing
    ? (styx.wfpActive ? 'AKTIV (WFP)' : 'ENFORCE')
    : String(styx.mode || 'off').toUpperCase();
  const styxDetail = styx.wfpActive
    ? `Sensor: ${textOrDash(styx.sensorState)} · WFP: ${styx.wfpFilterCount || 0} Filter · Vorfälle: ${styxIncidents.length}`
    : `Sensor: ${textOrDash(styx.sensorState)} · Vorfälle: ${styxIncidents.length}`;

  const boot = data?.bootPosture || {};
  const metricsEl = clear('v6Metrics');
  if (metricsEl) {
    const spyTone = !spy.enabled ? 'info' : (spy.degraded ? 'warn' : 'ok');
    const bootSummary = boot.tpmAvailable ? `TPM v${boot.tpmVersion || 2} · ${String(boot.quoteKind || 'none').toUpperCase()}` : 'KEIN TPM';
    const bootDetail = `SecureBoot: ${boot.secureBootEnabled ? 'AN' : 'AUS/UNBEK.'} · HVCI: ${boot.hvciEnabled ? 'AN' : 'AUS'} · WBCL: ${boot.wbclBytes || 0}B`;
    metricsEl.append(
      metric(
        'Anti-Spyware Sensoren',
        spyModeLabel,
        `${activeSensors.length}/4 aktiv · ${spyFindings.length} Funde`,
        spyTone,
      ),
      metric(
        'Externer Witness',
        textOrDash(wit.status || 'DISABLED'),
        `Outbox: ${wit.outboxDepth ?? 0} (${wit.settingsState || 'DISABLED'})`,
        toneForWitness(wit.status),
      ),
      metric(
        'StyX Egress / Beacon',
        styxModeLabel,
        styxDetail,
        styx.mode === 'observe' || styx.mode === 'enforce' ? 'ok' : 'info',
      ),
      metric(
        'Boot & TPM Posture',
        bootSummary,
        bootDetail,
        boot.tpmAvailable && boot.secureBootEnabled ? 'ok' : 'warn',
      ),
      metric(
        'Arbeitsplatz-Sperre',
        lockState,
        lockState === 'UNAVAILABLE' ? 'Session-0 ohne Desktop-Zugriff' : 'Direkte Desktop-Prüfung',
        lockState === 'LOCKED' ? 'ok' : 'info',
      ),
    );
  }

  const spyPill = byId('v6SpywarePill');
  if (spyPill) {
    spyPill.className = `status-pill ${toneForSensor(spy.enabled, spy.degraded)}`;
    spyPill.textContent = spyModeLabel;
  }
  const witPill = byId('v6WitnessPill');
  if (witPill) {
    witPill.className = `status-pill ${toneForWitness(wit.status)}`;
    witPill.textContent = textOrDash(wit.status || 'DISABLED');
  }
  const styxPill = byId('v6StyxPill');
  if (styxPill) {
    styxPill.className = `status-pill ${styx.mode && styx.mode !== 'off' ? 'ok' : 'info'}`;
    styxPill.textContent = styx.wfpActive
      ? `${styxModeLabel} · ${styx.wfpFilterCount || 0} Filter`
      : `${styxModeLabel} / ${textOrDash(styx.sensorState)}`;
  }

  const summaryPill = byId('v6ModeSummaryPill');
  if (summaryPill) {
    const fullyActive = spyActive && styxEnforcing && styx.wfpActive;
    const partialActive = spyActive || styxEnforcing;
    summaryPill.className = `status-pill ${fullyActive || partialActive ? 'ok' : 'info'}`;
    summaryPill.textContent = fullyActive ? 'AKTIV // WFP ENFORCE' : (partialActive ? 'TEILWEISE AKTIV' : 'OBSERVE');
  }
  const currentSpyMode = spyActive ? 'active' : 'observe';
  const currentStyxMode = String(styx.mode || 'observe').toLowerCase();
  for (const [id, active] of [
    ['v6SpyObserveBtn', currentSpyMode === 'observe'],
    ['v6SpyActiveBtn', currentSpyMode === 'active'],
    ['v6StyxOffBtn', currentStyxMode === 'off'],
    ['v6StyxObserveBtn', currentStyxMode === 'observe'],
    ['v6StyxEnforceBtn', currentStyxMode === 'enforce'],
  ]) {
    const btn = byId(id);
    if (btn) {
      btn.classList.toggle('active', active);
      btn.setAttribute('aria-pressed', active ? 'true' : 'false');
    }
  }

  const sensorsGrid = clear('v6SensorMatrix');
  if (sensorsGrid) {
    const items = [
      ['BYOVD-Treiber', spy.byovdWatched],
      ['Kamera / Mikrofon / Ort', spy.capabilityWatch],
      ['Persistenz-Pfade', spy.persistenceWatch],
      ['LSASS-Speicherzugriff', spy.lsassWatch],
      ['StyX TCP-Telemetrie', Boolean(styxCol.tcpTableAvailable || styx.mode === 'observe' || styx.mode === 'enforce')],
      ['StyX Bytes / Estats', Boolean(styxCol.dataObservationAvailable)],
    ];
    for (const [label, active] of items) {
      const card = node('div', 'metric-card');
      card.append(node('span', '', label), pill(active ? 'AKTIV' : 'INAKTIV', active ? 'ok' : 'info'));
      sensorsGrid.append(card);
    }
  }

  const notes = [];
  if (spy.lastError) notes.push(`Spyware: ${spy.lastError}`);
  if (wit.lastError) notes.push(`Witness: ${wit.lastError}`);
  else if (wit.settingsReason) notes.push(`Witness-Config: ${wit.settingsReason}`);
  if (styxCol.lastError) notes.push(`StyX: ${styxCol.lastError}`);
  if (styx.wfpLastError) notes.push(`StyX-WFP: ${styx.wfpLastError}`);
  else if (styx.wfpActive) notes.push(`GeDefense-V6-Sovereign-WFP aktiv (${styx.wfpFilterCount || 0} Kernel-Filter)`);
  setText('v6DiagnosticNote', notes.length > 0 ? notes.join(' · ') : 'Alle aktiven V6-Sensoren arbeiten ohne Störung.');

  renderSpywareFindings(spyFindings);
  renderStyxIncidents(styxIncidents);
  renderStyxWhitelist(
    Array.isArray(data?.styxWhitelist) ? data.styxWhitelist : [],
    Array.isArray(data?.styxBlockedTargets) ? data.styxBlockedTargets : [],
  );
}

function renderSpywareFindings(findings) {
  setText('v6SpywareCount', String(findings.length));
  const tbody = clear('v6SpywareRows');
  if (!tbody) return;
  if (findings.length === 0) {
    const tr = node('tr');
    const td = node('td', 'muted', 'Keine Anti-Spyware-Auffälligkeiten im aktuellen Zeitraum.');
    td.colSpan = 6;
    tr.append(td);
    tbody.append(tr);
    return;
  }
  for (const f of findings) {
    const tr = node('tr');
    const tdSev = node('td');
    tdSev.append(severity(f.severity || 'INFO'));
    tr.append(
      tdSev,
      node('td', 'mono', textOrDash(f.source)),
      node('td', '', `${textOrDash(f.title)} — ${textOrDash(f.detail)}`),
      node('td', 'mono', textOrDash(f.asset)),
      node('td', 'mono', textOrDash(f.response || 'OBSERVE_ONLY')),
      node('td', 'mono', textOrDash(f.observedUtc)),
    );
    tbody.append(tr);
  }
}

function renderStyxIncidents(incidents) {
  setText('v6StyxCount', String(incidents.length));
  const tbody = clear('v6StyxRows');
  if (!tbody) return;
  if (incidents.length === 0) {
    const tr = node('tr');
    const td = node('td', 'muted', 'Keine StyX-Egress- oder Beaconing-Vorfälle erkannt.');
    td.colSpan = 7;
    tr.append(td);
    tbody.append(tr);
    return;
  }
  for (const inc of incidents) {
    const id = String(inc.id || `${inc.pid}:${inc.remote}:${inc.observedUtc || inc.timestampUtc}`);
    const isExpanded = expandedStyxIDs.has(id);
    const tr = node('tr');
    const tdSev = node('td');
    tdSev.append(severity(inc.severity || 'INFO'));

    const progLabel = inc.process || `PID ${inc.pid || 0}`;
    const tdProg = node('td');
    tdProg.append(
      node('strong', 'mono', progLabel),
      ...(inc.processPath ? [document.createElement('br'), node('small', 'muted mono', inc.processPath)] : []),
    );

    const tdAction = node('td');
    tdAction.append(pill(
      String(inc.action || 'none').toUpperCase(),
      inc.action === 'wfp-blocked' ? 'bad' : (inc.whitelisted || inc.action === 'whitelisted' ? 'good' : 'info'),
    ));

    const toggleBtn = node('button', 'button ghost small', isExpanded ? 'Ausblenden ▴' : 'Details ▾');
    toggleBtn.type = 'button';
    toggleBtn.setAttribute('aria-expanded', String(isExpanded));
    const tdToggle = node('td');
    tdToggle.append(toggleBtn);

    tr.append(
      tdSev,
      tdProg,
      node('td', 'mono', `${textOrDash(inc.category)} · ${inc.score ?? 0}`),
      node('td', '', textOrDash(inc.summary)),
      tdAction,
      node('td', 'mono', textOrDash(inc.timestampUtc || inc.observedUtc)),
      tdToggle,
    );
    tbody.append(tr);

    const detailTr = node('tr', 'v6-styx-detail-row');
    detailTr.hidden = !isExpanded;
    const detailTd = node('td');
    detailTd.colSpan = 7;

    const card = node('div', 'v6-styx-detail-card');
    const grid = node('div', 'v6-styx-detail-grid');

    const boxProg = node('div', 'v6-styx-detail-box');
    boxProg.append(
      node('small', '', 'Programm & Prozess'),
      node('strong', '', `${progLabel} (PID ${inc.pid ?? 0})`),
      node('code', '', `Lokaler Port: ${inc.localPort || '—'}`),
    );

    const boxPath = node('div', 'v6-styx-detail-box');
    boxPath.append(
      node('small', '', 'Programmpfad (Executable)'),
      node('code', '', inc.processPath || 'Nicht aufgelöst (System-/kurzlebiger Prozess)'),
    );

    const boxActivity = node('div', 'v6-styx-detail-box');
    boxActivity.append(
      node('small', '', 'Was wurde getan (Aktivität & Entscheidung)'),
      node('strong', '', `${(inc.signals || []).join(' + ') || inc.eventType || '—'} · Score ${inc.score ?? 0}`),
      node('code', '', `TX ${formatBytes(inc.txBytes || 0)} · RX ${formatBytes(inc.rxBytes || 0)} · ${inc.intervalSamples || 0} Intervalle`),
      node('span', 'muted', inc.outcome || '—'),
    );

    const geoLabel = inc.countryCode
      ? `${inc.countryCode}${inc.country ? ` · ${inc.country}` : ''}`
      : 'GeoIP nicht aufgelöst';
    const asnLabel = [inc.asn, inc.asName].filter(Boolean).join(' · ') || 'Keine ASN-Angabe';
    const boxDest = node('div', 'v6-styx-detail-box');
    boxDest.append(
      node('small', '', 'Wohin ging der Traffic (Ziel & GeoIP/ASN)'),
      node('code', '', inc.remote || '—'),
      node('strong', '', geoLabel),
      node('span', 'muted', asnLabel),
    );

    grid.append(boxProg, boxPath, boxActivity, boxDest);
    card.append(grid);

    const actions = node('div', 'v6-styx-detail-actions');
    const pathTarget = inc.processPath || (inc.process && inc.process !== 'unknown' ? inc.process : '');
    if (pathTarget) {
      const btnPath = node('button', 'button primary small', `Programm / Pfad freigeben (${inc.process || 'App'})`);
      btnPath.type = 'button';
      btnPath.addEventListener('click', () => {
        void applyStyxWhitelist({action: 'add', entry: pathTarget});
      });
      actions.append(btnPath);
    }
    const remoteTarget = inc.remoteIp || (inc.remote ? String(inc.remote).replace(/:\d+$/, '').replace(/^\[|\]$/g, '') : '');
    if (remoteTarget) {
      const btnIP = node('button', 'button ghost small', `Ziel-IP freigeben (${remoteTarget})`);
      btnIP.type = 'button';
      btnIP.addEventListener('click', () => {
        void applyStyxWhitelist({action: 'add', entry: remoteTarget});
      });
      actions.append(btnIP);
    }
    if (inc.whitelisted || inc.action === 'whitelisted') {
      actions.append(pill('DURCH WHITELIST FREIGEGEBEN', 'good'));
    }
    card.append(actions);
    detailTd.append(card);
    detailTr.append(detailTd);
    tbody.append(detailTr);

    toggleBtn.addEventListener('click', () => {
      const next = detailTr.hidden;
      detailTr.hidden = !next;
      if (next) expandedStyxIDs.add(id);
      else expandedStyxIDs.delete(id);
      toggleBtn.textContent = next ? 'Ausblenden ▴' : 'Details ▾';
      toggleBtn.setAttribute('aria-expanded', String(next));
    });
  }
}

function renderStyxWhitelist(whitelist, blockedTargets) {
  setText('v6WhitelistCount', `${whitelist.length} FREIGABEN`);
  const wlHost = clear('v6WhitelistList');
  if (wlHost) {
    if (!whitelist.length) {
      wlHost.append(node('span', 'muted', 'Noch keine StyX-Whitelist-Einträge konfiguriert.'));
    } else {
      for (const entry of whitelist) {
        const row = node('div', 'v6-chip-row');
        row.append(node('code', '', entry));
        const rmBtn = node('button', 'button ghost small', 'Entfernen');
        rmBtn.type = 'button';
        rmBtn.addEventListener('click', () => {
          void applyStyxWhitelist({action: 'remove', entry});
        });
        row.append(rmBtn);
        wlHost.append(row);
      }
    }
  }
  const blkHost = clear('v6BlockedTargetsList');
  if (blkHost) {
    if (!blockedTargets.length) {
      blkHost.append(node('span', 'muted', 'Keine aktiven dynamischen Kernel-WFP-Sperren.'));
    } else {
      for (const target of blockedTargets) {
        const row = node('div', 'v6-chip-row');
        row.append(node('code', '', target));
        const allowBtn = node('button', 'button primary small', 'Entsperren');
        allowBtn.type = 'button';
        allowBtn.addEventListener('click', () => {
          void applyStyxWhitelist({action: 'add', entry: target});
        });
        row.append(allowBtn);
        blkHost.append(row);
      }
    }
  }
}
