// STATUS: DIAMANT VGT SUPREME
'use strict';
/** GeDefense Sentinel & MHX 4.1 Killerdom Control Center.
 *
 *  Real-time control over:
 *  - Killerdom 4.1 Execution Engine
 *  - Paranoia Mode (Default-Deny)
 *  - Titan Cross-Engine Correlation Bridge
 *  - Ghost Mode (Windows Telemetry & Network Kill)
 *  - Selective Developer Signature Toggles (KD-SIG-01 to 06)
 *  - System Apps and Fair-Scored Whitelist Catalog
 */
import {
  getSentinelStatus,
  updateSentinelConfig,
  toggleSentinelSignature,
  toggleSentinelSystemApp,
  toggleSentinelWhitelist,
  addSentinelWhitelist,
  removeSentinelWhitelist,
} from './api.js';
import {byId, announce, setText, toast, requestReason} from './dom.js';

let currentStatus = null;
let initialized = false;

export async function loadSentinel({silent = false} = {}) {  try {
    const status = await getSentinelStatus();
    currentStatus = status;
    renderSentinel(status);
  } catch (error) {
    if (silent) {
      console.warn('Sentinel Hintergrund-Aktualisierung fehlgeschlagen', error);
      return;
    }
    toast(`Sentinel Status Abruf fehlgeschlagen: ${error.message || error}`, 'bad');
  }
}

function renderSentinel(s) {
  if (!s) return;

  // Hero status & badges
  setText('sentinelKillerdomBadge', s.killerdomEnabled ? 'AKTIV // SCHARF' : 'STANDBY');
  const kBadge = byId('sentinelKillerdomBadge');
  if (kBadge) {
    kBadge.className = s.killerdomEnabled ? 'sentinel-badge clean' : 'sentinel-badge neutral';
  }

  setText('sentinelParanoiaBadge', s.paranoiaMode ? 'DEFAULT-DENY' : 'SELECTIVE');
  const pBadge = byId('sentinelParanoiaBadge');
  if (pBadge) {
    pBadge.className = s.paranoiaMode ? 'sentinel-badge warning' : 'sentinel-badge clean';
  }

  setText('sentinelGhostBadge', s.ghostModeTelemetryKill ? (s.ghostModeApplied === false ? 'FEHLER' : 'ABGESCHNITTEN') : 'STANDARD');
  const gBadge = byId('sentinelGhostBadge');
  if (gBadge) {
    const degraded = s.ghostModeTelemetryKill && s.ghostModeApplied === false;
    gBadge.className = s.ghostModeTelemetryKill
      ? (degraded ? 'sentinel-badge danger' : 'sentinel-badge warning')
      : 'sentinel-badge neutral';
    gBadge.title = degraded ? (s.ghostModeLastError || 'Ghost Mode ist konfiguriert, aber nicht wirksam.') : '';
  }

  setText('sentinelTitanBadge', s.titanLinked ? `GEKOPPELT (${s.titanMode})` : 'ENTKOPPELT');
  const tBadge = byId('sentinelTitanBadge');
  if (tBadge) {
    tBadge.className = s.titanLinked ? 'sentinel-badge clean' : 'sentinel-badge neutral';
  }

  // Switches
  const swKillerdom = byId('swKillerdom');
  if (swKillerdom) swKillerdom.checked = Boolean(s.killerdomEnabled);

  const swParanoia = byId('swParanoia');
  if (swParanoia) swParanoia.checked = Boolean(s.paranoiaMode);

  const swTitan = byId('swTitan');
  if (swTitan) swTitan.checked = Boolean(s.correlateWithTitan);

  const swGhost = byId('swGhost');
  if (swGhost) swGhost.checked = Boolean(s.ghostModeTelemetryKill);

  // Render each data block independently: one malformed row must never blank
  // the whole Sentinel view (the original 5.3.0 defect).
  renderSection('Signaturen', () => renderSignatures(s.signatures || []));
  renderSection('System-Apps', () => renderSystemApps(s.systemApps || []));
  renderSection('Whitelist', () => renderWhitelist(s.whitelist || []));
}

function renderSection(label, render) {
  try {
    render();
  } catch (error) {
    console.error(`Sentinel ${label} konnten nicht gerendert werden`, error);
    toast(`Sentinel ${label}: Darstellung fehlgeschlagen.`, 'bad');
  }
}

function renderEmptyRow(container, columns, message) {
  const tr = document.createElement('tr');
  const td = document.createElement('td');
  td.colSpan = columns;
  td.className = 'sentinel-empty';
  td.textContent = message;
  tr.appendChild(td);
  container.appendChild(tr);
}

function renderSignatures(sigs) {
  const container = byId('sentinelSigTableBody');
  if (!container) return;
  container.innerHTML = '';
  if (sigs.length === 0) {
    renderEmptyRow(container, 4, 'Keine Killerdom-Signaturen geladen.');
    return;
  }

  sigs.forEach(sig => {
    const tr = document.createElement('tr');

    const tdId = document.createElement('td');
    tdId.innerHTML = `<span class="sentinel-badge ${sig.enabled ? 'clean' : 'neutral'}">${escapeHtml(sig.id)}</span>`;

    const tdName = document.createElement('td');
    tdName.innerHTML = `<strong>${escapeHtml(sig.name)}</strong><br><small class="sentinel-cell-sub">${escapeHtml(sig.description)}</small>`;

    const tdPat = document.createElement('td');
    const pattern = typeof sig.pattern === 'string' && sig.pattern ? sig.pattern : (sig.description || sig.severity || '');
    tdPat.innerHTML = `<code class="sentinel-signature-pattern">${escapeHtml(pattern.slice(0, 75))}...</code>`;

    const tdAction = document.createElement('td');
    const label = document.createElement('label');
    label.className = 'sentinel-switch';
    const input = document.createElement('input');
    input.type = 'checkbox';
    input.checked = Boolean(sig.enabled);
    input.dataset.sigId = sig.id;
    input.addEventListener('change', async () => {
      const wantsEnabled = input.checked;
      let reason = 'Signatur über Sentinel-Konsole geändert';
      let confirmation = '';
      if (!wantsEnabled) {
        const entered = await requestReason({
          title: `Signatur ${sig.id} deaktivieren`,
          text: 'Das Deaktivieren senkt die Erkennungsabdeckung. Die Begründung wird auditierbar protokolliert.',
          label: 'Begründung',
          confirmLabel: 'Deaktivieren',
          tone: 'danger',
        });
        if (!entered) {
          input.checked = Boolean(sig.enabled);
          return;
        }
        reason = entered;
        confirmation = 'CHANGE SENTINEL POSTURE';
      }
      try {
        await toggleSentinelSignature(sig.id, wantsEnabled, { reason, confirmation });
        toast(`Signatur ${sig.id} ${wantsEnabled ? 'aktiviert' : 'deaktiviert'}.`, 'good');
        await loadSentinel();
      } catch (err) {
        input.checked = Boolean(sig.enabled);
        toast(`Fehler beim Ändern der Signatur: ${err.message || err}`, 'bad');
      }
    });
    const slider = document.createElement('span');
    slider.className = 'sentinel-slider emerald';
    label.appendChild(input);
    label.appendChild(slider);
    tdAction.appendChild(label);

    tr.appendChild(tdId);
    tr.appendChild(tdName);
    tr.appendChild(tdPat);
    tr.appendChild(tdAction);
    container.appendChild(tr);
  });
}

function renderSystemApps(apps) {
  const container = byId('sentinelSysAppTableBody');
  if (!container) return;
  container.innerHTML = '';
  if (apps.length === 0) {
    renderEmptyRow(container, 4, 'Keine kuratierten System-Apps geladen.');
    return;
  }

  apps.forEach(app => {
    const tr = document.createElement('tr');

    const tdName = document.createElement('td');
    tdName.innerHTML = `<strong>${escapeHtml(app.name)}</strong><br><small class="sentinel-cell-sub">${escapeHtml(app.description)}</small>`;

    const tdPath = document.createElement('td');
    tdPath.innerHTML = `<code class="sentinel-code">${escapeHtml(app.path)}</code>`;

    const tdStatus = document.createElement('td');
    tdStatus.innerHTML = app.enabled 
      ? '<span class="sentinel-badge clean">ERLAUBT</span>' 
      : '<span class="sentinel-badge danger">ISOLIERT</span>';

    const tdAction = document.createElement('td');
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = app.enabled ? 'sentinel-btn-sm danger' : 'sentinel-btn-sm primary';
    btn.textContent = app.enabled ? 'Sperren' : 'Erlauben';
    btn.addEventListener('click', async () => {
      const nextEnabled = !app.enabled;
      let reason = 'System-App über Sentinel-Konsole geändert';
      let confirmation = '';
      if (!nextEnabled) {
        const entered = await requestReason({
          title: `System-App ${app.name} isolieren`,
          text: 'Im Paranoia-Modus wird diese Kernkomponente danach nicht mehr pauschal erlaubt.',
          label: 'Begründung',
          confirmLabel: 'Isolieren',
          tone: 'danger',
        });
        if (!entered) return;
        reason = entered;
        confirmation = 'CHANGE SENTINEL POSTURE';
      }
      try {
        await toggleSentinelSystemApp(app.id, nextEnabled, { reason, confirmation });
        toast(`System-App ${app.name} aktualisiert.`, 'good');
        await loadSentinel();
      } catch (err) {
        toast(`Fehler: ${err.message || err}`, 'bad');
      }
    });
    tdAction.appendChild(btn);

    tr.appendChild(tdName);
    tr.appendChild(tdPath);
    tr.appendChild(tdStatus);
    tr.appendChild(tdAction);
    container.appendChild(tr);
  });
}

function renderWhitelist(items) {
  const container = byId('sentinelWlTableBody');
  if (!container) return;
  container.innerHTML = '';
  if (items.length === 0) {
    renderEmptyRow(container, 5, 'Keine Whitelist-Einträge vorhanden.');
    return;
  }

  items.forEach(item => {
    const tr = document.createElement('tr');

    const tdName = document.createElement('td');
    tdName.innerHTML = `<strong>${escapeHtml(item.name)}</strong>`;

    const tdPath = document.createElement('td');
    tdPath.innerHTML = `<code class="sentinel-code">${escapeHtml(item.pathPattern)}</code>`;

    const tdScore = document.createElement('td');
    let scoreClass = 'clean';
    if (item.currentScore >= 75) scoreClass = 'danger';
    else if (item.currentScore >= 25) scoreClass = 'warning';
    tdScore.innerHTML = `<span class="sentinel-score-chip ${scoreClass}" title="Fair Behavioral Threat Score (0-100)">${item.currentScore}</span>`;

    const tdStatus = document.createElement('td');
    tdStatus.innerHTML = item.enabled
      ? '<span class="sentinel-badge clean">AKTIV</span>'
      : '<span class="sentinel-badge neutral">INAKTIV</span>';

    const tdAction = document.createElement('td');
    tdAction.className = 'sentinel-row-actions';

    if (item.isSystemApp) {
      // GeDefense self-protection entries are immutable: the backend rejects
      // toggling/removing them, so the UI must not pretend otherwise.
      const locked = document.createElement('span');
      locked.className = 'sentinel-badge neutral';
      locked.textContent = 'SELBSTSCHUTZ';
      locked.title = 'Diese Ausnahme schützt die GeDefense-Kernkomponenten und ist unveränderlich.';
      tdAction.appendChild(locked);
    } else {
      const toggleBtn = document.createElement('button');
      toggleBtn.type = 'button';
      toggleBtn.className = 'sentinel-btn-sm muted';
      toggleBtn.textContent = item.enabled ? 'Deaktivieren' : 'Aktivieren';
      toggleBtn.addEventListener('click', async () => {
        try {
          await toggleSentinelWhitelist(item.id, !item.enabled);
          toast(`Whitelist-Eintrag ${item.name} aktualisiert.`, 'good');
          await loadSentinel();
        } catch (err) {
          toast(`Fehler: ${err.message || err}`, 'bad');
        }
      });

      const delBtn = document.createElement('button');
      delBtn.type = 'button';
      delBtn.className = 'sentinel-btn-sm danger';
      delBtn.textContent = 'Entfernen';
      delBtn.addEventListener('click', async () => {
        try {
          await removeSentinelWhitelist(item.id);
          toast(`Whitelist-Eintrag ${item.name} entfernt.`, 'good');
          await loadSentinel();
        } catch (err) {
          toast(`Fehler: ${err.message || err}`, 'bad');
        }
      });

      tdAction.appendChild(toggleBtn);
      tdAction.appendChild(delBtn);
    }

    tr.appendChild(tdName);
    tr.appendChild(tdPath);
    tr.appendChild(tdScore);
    tr.appendChild(tdStatus);
    tr.appendChild(tdAction);
    container.appendChild(tr);
  });
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

export function bindSentinel() {
  if (initialized) return;
  initialized = true;

  // Master switches event listeners
  const reducingFieldNames = new Set(['killerdomEnabled', 'paranoiaMode', 'ghostModeTelemetryKill', 'correlateWithTitan']);
  const bindSwitch = (id, fieldName, successMsg) => {
    const el = byId(id);
    if (!el) return;
    el.addEventListener('change', async () => {
      const checked = el.checked;
      let reason = 'Operator Toggle via Web UI';
      let confirmation = '';
      const requiresConfirmation = (!checked && reducingFieldNames.has(fieldName)) || fieldName === 'ghostModeTelemetryKill';
      if (requiresConfirmation) {
        const entered = await requestReason({
          title: `${successMsg} ${checked ? 'aktivieren' : 'deaktivieren'}`,
          text: fieldName === 'ghostModeTelemetryKill'
            ? 'Ghost Mode schreibt die Windows-Hosts-Datei und kappt Telemetrie. Die Begründung wird auditierbar protokolliert.'
            : 'Das senkt die aktive Schutzstufe. Die Begründung wird auditierbar protokolliert.',
          label: 'Begründung',
          confirmLabel: checked ? 'Aktivieren' : 'Deaktivieren',
          tone: checked ? 'primary' : 'danger',
        });
        if (!entered) {
          el.checked = !checked;
          return;
        }
        reason = entered;
        confirmation = 'CHANGE SENTINEL POSTURE';
      }
      try {
        await updateSentinelConfig({ [fieldName]: checked, reason, confirmation });
        toast(`${successMsg}: ${checked ? 'Aktiviert' : 'Deaktiviert'}.`, 'good');
        await loadSentinel();
      } catch (err) {
        el.checked = !checked;
        toast(`Fehler beim Speichern: ${err.message || err}`, 'bad');
      }
    });
  };

  bindSwitch('swKillerdom', 'killerdomEnabled', 'Killerdom Engine');
  bindSwitch('swParanoia', 'paranoiaMode', 'Paranoia Modus (Default-Deny)');
  bindSwitch('swTitan', 'correlateWithTitan', 'Titan-Killerdom-Kopplung');
  bindSwitch('swGhost', 'ghostModeTelemetryKill', 'Ghost Mode Telemetriekappung');

  // Add Whitelist form
  const addBtn = byId('sentinelWlAddBtn');
  if (addBtn) {
    addBtn.addEventListener('click', async () => {
      const nameInput = byId('sentinelWlName');
      const pathInput = byId('sentinelWlPath');
      const shaInput = byId('sentinelWlSha');
      const signerInput = byId('sentinelWlSigner');
      const name = nameInput ? nameInput.value.trim() : '';
      const path = pathInput ? pathInput.value.trim() : '';
      const sha256 = shaInput ? shaInput.value.trim() : '';
      const signerMatch = signerInput ? signerInput.value.trim() : '';

      if (!name || !path) {
        toast('Bitte Name und Pfad/Muster eingeben.', 'warn');
        return;
      }

      try {
        await addSentinelWhitelist(name, path, { sha256, signerMatch });
        toast(`Whitelist-Eintrag "${name}" hinzugefügt.`, 'good');
        if (nameInput) nameInput.value = '';
        if (pathInput) pathInput.value = '';
        if (shaInput) shaInput.value = '';
        if (signerInput) signerInput.value = '';
        await loadSentinel();
      } catch (err) {
        toast(`Fehler beim Hinzufügen: ${err.message || err}`, 'bad');
      }
    });
  }
}
