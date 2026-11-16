// STATUS: PLATIN VGT SUPREME
'use strict';

import {getV6Status} from './api.js';
import {byId, clear, metric, node, pill, setText, severity, toast} from './dom.js';

let initialized = false;

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
    renderV6(data);
  } catch (error) {
    if (silent) return;
    toast(`V6 Sovereign Status fehlgeschlagen: ${error?.message || error}`, 'bad');
  }
}

export function bindV6() {
  if (initialized) return;
  initialized = true;
  byId('v6Refresh')?.addEventListener('click', () => {
    void loadV6({silent: false});
  });
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

  const boot = data?.bootPosture || {};
  const metricsEl = clear('v6Metrics');
  if (metricsEl) {
    const spySummary = !spy.enabled ? 'DISABLED' : (spy.degraded ? 'DEGRADED' : 'OBSERVE_ONLY');
    const spyTone = !spy.enabled ? 'info' : (spy.degraded ? 'warn' : 'ok');
    const bootSummary = boot.tpmAvailable ? `TPM v${boot.tpmVersion || 2} · ${String(boot.quoteKind || 'none').toUpperCase()}` : 'KEIN TPM';
    const bootDetail = `SecureBoot: ${boot.secureBootEnabled ? 'AN' : 'AUS/UNBEK.'} · HVCI: ${boot.hvciEnabled ? 'AN' : 'AUS'} · WBCL: ${boot.wbclBytes || 0}B`;
    metricsEl.append(
      metric(
        'Anti-Spyware Sensoren',
        spySummary,
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
        String(styx.mode || 'off').toUpperCase(),
        `Sensor: ${textOrDash(styx.sensorState)} · Vorfälle: ${styxIncidents.length}`,
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
    spyPill.textContent = spy.enabled ? (spy.degraded ? 'DEGRADED' : 'OBSERVE_ONLY') : 'DISABLED';
  }
  const witPill = byId('v6WitnessPill');
  if (witPill) {
    witPill.className = `status-pill ${toneForWitness(wit.status)}`;
    witPill.textContent = textOrDash(wit.status || 'DISABLED');
  }
  const styxPill = byId('v6StyxPill');
  if (styxPill) {
    styxPill.className = `status-pill ${styx.mode && styx.mode !== 'off' ? 'ok' : 'info'}`;
    styxPill.textContent = `${String(styx.mode || 'off').toUpperCase()} / ${textOrDash(styx.sensorState)}`;
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
  setText('v6DiagnosticNote', notes.length > 0 ? notes.join(' · ') : 'Alle aktiven V6-Sensoren arbeiten ohne Störung.');

  renderSpywareFindings(spyFindings);
  renderStyxIncidents(styxIncidents);
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
    td.colSpan = 6;
    tr.append(td);
    tbody.append(tr);
    return;
  }
  for (const inc of incidents) {
    const tr = node('tr');
    const tdSev = node('td');
    tdSev.append(severity(inc.severity || 'INFO'));
    tr.append(
      tdSev,
      node('td', 'mono', textOrDash(inc.category)),
      node('td', 'mono', String(inc.score ?? 0)),
      node('td', '', textOrDash(inc.summary)),
      node('td', 'mono', textOrDash(inc.action || 'none')),
      node('td', 'mono', textOrDash(inc.observedUtc)),
    );
    tbody.append(tr);
  }
}
