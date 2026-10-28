// STATUS: DIAMANT VGT SUPREME
'use strict';
/** GeDefense Titan control center.
 *
 *  All rendering uses DOM construction/textContent. Server strings are treated
 *  as untrusted metadata. The controller never claims file-to-process
 *  attribution: temporal correlation is labelled as such.
 */
import {
  acknowledgeTitanEvent,
  acknowledgeTitanOpenFindings,
  addTitanDevelopmentRoot,
  createTitanPermit,
  exportTitanEvidence,
  getTitanCheckpoints,
  getTitanEvents,
  getTitanQuarantine,
  getTitanStatus,
  quarantineTitanEvent,
  removeTitanDevelopmentRoot,
  restoreTitanQuarantine,
  reviewTitanQuarantine,
  revokeTitanPermit,
  saveTitanPolicy,
  verifyTitanEvidence,
} from './api.js';
import {
  byId, announce, emptyState, formatBytes, formatNumber, formatTime, node, requestReason, severity,
  setPill, setText, toast,
} from './dom.js';
import {
  renderStable, resetListSignature, resetVisibleListPosition,
} from './list-stability.js';

const state={
  status:null,
  tab:'lage',
  filter:'all',
  offset:0,
  limit:20,
  total:0,
  eventsLoaded:false,
  quarantineLoaded:false,
  evidenceLoaded:false,
  policyDirty:false,
  busy:false,
  initialized:false,
};

const trustLabels={
  AUTHORIZED:'AUTORISIERT',
  TOLERATED:'GEDULDET',
  UNEXPECTED:'UNERWARTET',
  COMPROMISED:'VERTRAUENSBRUCH',
};
const stateLabels={
  OBSERVING:'BEOBACHTET',
  PROTECTING:'SCHÜTZT',
  DEGRADED:'EINGESCHRÄNKT',
  STOPPED:'GESTOPPT',
  STARTING:'STARTET',
};
const sensorLabels={
  HEALTHY:'Gesund',
  DEGRADED:'Eingeschränkt',
  UNAVAILABLE:'Nicht verfügbar',
  STOPPED:'Gestoppt',
};
const riskLabels={
  USER_CONTENT:'Benutzerinhalt',
  INGRESS:'Ingress',
  PERSISTENCE:'Persistenz',
  SECURITY_CONFIG:'Sicherheitskonfiguration',
  SYSTEM_COMPONENT:'Systemkomponente',
  BOOT_TRUST:'Boot-Vertrauen',
  TITAN_SELF:'Titan-Telemetrie',
  UNKNOWN:'Unbekannt',
};

const permitActionLabels={
  ALLOW_CHANGE:'Jede Änderung',
  FILE_CREATED:'Datei anlegen',
  FILE_MODIFIED:'Datei ändern',
  PERSISTENCE_ADDED:'Persistenz anlegen',
  SECURITY_CHANGED:'Sicherheitskonfiguration ändern',
};

function statusTone(status){
  if(status==='COMPROMISED')return 'bad';
  if(status==='UNEXPECTED')return 'warn';
  if(status==='AUTHORIZED')return 'good';
  return 'info';
}

function setToneText(id,text,tone=''){
  const element=byId(id);
  if(!element)return;
  element.textContent=String(text??'');
  if(tone)element.dataset.tone=tone;
  else delete element.dataset.tone;
}

function eventTime(event){
  const stamp=formatTime(event.timestampUtc);
  return stamp==='---'?'Zeit unbekannt':stamp;
}

function actionButton(label,action,id,variant='ghost'){
  const button=node('button',`button ${variant} small`,label);
  button.type='button';
  button.dataset.titanAction=action;
  button.dataset.titanId=id;
  return button;
}

function renderSensor(sensor){
  const row=node('div','titan-sensor-row');
  row.dataset.titanRow=`sensor:${sensor.id||sensor.label||''}`;
  row.setAttribute('role','listitem');
  const main=node('div','titan-sensor-main');
  const dot=node('span','titan-sensor-dot');
  dot.dataset.state=sensor.state||'STOPPED';
  dot.setAttribute('aria-hidden','true');
  const copy=node('div','titan-sensor-copy');
  copy.append(node('strong','',sensor.label||sensor.id||'Sensor'));
  if(sensor.detail)copy.append(node('small','',sensor.detail));
  main.append(dot,copy);
  const meta=node('div','titan-sensor-meta');
  meta.append(node('b','',sensorLabels[sensor.state]||sensor.state||'Unbekannt'));
  if(Number(sensor.events)>0)meta.append(node('span','',`${formatNumber(sensor.events)} Ereignisse`));
  if(Number(sensor.errors)>0)meta.append(node('span','',`${formatNumber(sensor.errors)} Fehler`));
  row.append(main,meta);
  return row;
}

function renderStatus(status){
  state.status=status;
  const view=document.querySelector('.titan-view');
  if(view)view.dataset.posture=status.trustPosture||'AUTHORIZED';
  setText('titanPosture',trustLabels[status.trustPosture]||status.trustPosture||'UNBEKANNT');
  setText('titanPostureDetail',status.trustPosture==='COMPROMISED'
    ?'Mindestens ein belastbares Signal spricht für einen Vertrauensbruch. Prüfe Quarantäne, Sicherheitslage und externe Kommunikationswege.'
    :status.trustPosture==='UNEXPECTED'
      ?'Titan hat mindestens eine Veränderung ohne gültige Freigabe beobachtet. Die Aktion bleibt bis zur Besitzerentscheidung sichtbar.'
      :status.trustPosture==='TOLERATED'
        ?'Titan beobachtet Veränderungen, die keiner akuten Freigabe bedürfen. Die Evidenzkette bleibt prüfbar.'
        :'Die lokale Evidenzkette ist verifiziert. Das ist eine Aussage über Titan-Belege, nicht über die Absicht eines Akteurs.');
  setText('titanMode',status.mode||'OBSERVE');
  setText('titanOpenFindings',formatNumber(status.openFindings));
  setText('titanEventCount',`${formatNumber(status.eventCount)} EREIGNISSE`);
  setText('titanCheckpointTime',status.lastCheckpoint?.sequence?`#${formatNumber(status.lastCheckpoint.sequence)} · ${formatTime(status.lastCheckpoint.createdUtc)}`:'Noch kein signierter Checkpoint');
  setText('titanWitnessState',status.witness?.configured?'Witness: KONFIGURIERT':'Witness: NICHT KONFIGURIERT');
  setText('titanQuarantineTabCount',formatNumber(status.quarantineCount));
  setPill('titanStatePill',stateLabels[status.state]||status.state||'UNBEKANNT',statusTone(status.state==='DEGRADED'?'UNEXPECTED':'AUTHORIZED'));

  setText('titanWitnessHeadline',status.witness?.configured?(status.witness.reachable?'ERREICHBAR':'NICHT ERREICHBAR'):'NICHT KONFIGURIERT');
  setText('titanWitnessDetail',status.witness?.detail||'Kein unabhängiger Witness konfiguriert.');
  const boot=status.boot||{};
  const secure=boot.secureBoot;
  setText('titanBootState',secure===true?'SECURE BOOT AKTIV':secure===false?'SECURE BOOT DEAKTIVIERT':'NICHT GEMESSEN');
  setText('titanBootDetail',boot.detail||'Keine ausreichende Boot-Messung verfügbar.');
  setText('titanSensorState',status.journalError||(status.sensors||[]).some(sensor=>sensor.state==='DEGRADED')?'Mindestens ein Sensor ist eingeschränkt. Fehlende Abdeckung wird nicht als gesund gewertet.':'Alle gemeldeten Sensoren sind innerhalb ihrer Abdeckung gesund.');

  const sensors=byId('titanSensors');
  if(sensors){
    const list=Array.isArray(status.sensors)?status.sensors:[];
    renderStable(sensors,`sensors:${JSON.stringify(list)}`,()=>{
      const fragment=document.createDocumentFragment();
      if(!list.length)fragment.append(emptyState('Keine Sensoren gemeldet','Titan liefert keine erfundene Abdeckung. Prüfe den Dienststatus.'));
      for(const sensor of list)fragment.append(renderSensor(sensor));
      return fragment;
    });
  }
  renderWatchRoots(status.watchRoots||[]);
  renderSecurityControls(status.securityControls||[]);
  renderPolicy(status.policy||{});
  renderCheckpointSummary(status);
  setText('titanPublicKey',status.lastCheckpoint?.publicKeySha256?status.lastCheckpoint.publicKeySha256.slice(0,32)+'…':'—');
  setText('titanEventPageInfo',status.eventCount?`${formatNumber(status.eventCount)} Ereignisse im Journal`:'Noch keine Ereignisse im Journal');
}

function renderWatchRoots(roots){
  const host=byId('titanWatchRoots');
  if(!host)return;
  const list=roots.slice(0,12);
  renderStable(host,`watch:${JSON.stringify(list)}:${roots.length}`,()=>{
    const fragment=document.createDocumentFragment();
    if(!list.length){
      fragment.append(node('p','titan-muted','Keine überwachten Pfade gemeldet.'));
      return fragment;
    }
    for(const root of list){
      const row=node('div','titan-watch-root');
      row.dataset.titanRow=`watch:${root.path||''}`;
      const dot=node('i');
      dot.dataset.active=String(root.active===true);
      dot.setAttribute('aria-hidden','true');
      const text=node('span');
      text.append(node('strong','',riskLabels[root.class]||root.class||'Pfad'),node('em','',root.path));
      if(root.error)text.append(node('em','',root.error));
      row.append(dot,text);
      fragment.append(row);
    }
    if(roots.length>list.length)fragment.append(node('p','titan-muted',`+ ${roots.length-list.length} weitere Pfade`));
    return fragment;
  });
}

function renderSecurityControls(controls){
  const host=byId('titanSecurityRows');
  if(!host)return;
  let secure=0;
  for(const control of controls)if(control.secure)secure++;
  renderStable(host,`controls:${JSON.stringify(controls)}`,()=>{
    const fragment=document.createDocumentFragment();
    for(const control of controls){
      const row=node('div','titan-control');
      row.dataset.titanRow=`control:${control.id||control.label||''}`;
      row.dataset.secure=String(control.secure===true);
      const copy=node('div','titan-control-copy');
      copy.append(node('strong','',control.label||control.id),node('small','',`Erwartet: ${control.expected||'—'} · Gemessen: ${control.value||'—'}`));
      row.append(copy,node('span','titan-control-value',control.secure?'KONFORM':'ABWEICHEND'));
      fragment.append(row);
    }
    if(!controls.length)fragment.append(emptyState('Sicherheitsmessung noch nicht verfügbar','Der Persistenz-Sensor liefert die gemessenen Kontrollwerte nach dem ersten Scan.'));
    return fragment;
  });
  setText('titanSecuritySummary',controls.length?`${secure} / ${controls.length} KONFORM`:'—');
  setPill('titanSecuritySummary',controls.length?`${secure} / ${controls.length} KONFORM`:'—',controls.length&&secure===controls.length?'good':controls.length?'warn':'info');
}

function renderPolicy(policy){
  setText('titanPolicyBadge',policy.mode||'OBSERVE');
  setPill('titanPolicyBadge',policy.mode||'OBSERVE',policy.mode==='STRICT'?'warn':policy.mode==='CONTAIN'?'info':'good');
  if(!state.policyDirty){
    const mode=byId('titanPolicyMode');
    if(mode)mode.value=policy.mode||'OBSERVE';
    const auto=byId('titanAutoQuarantine');
    if(auto)auto.checked=Boolean(policy.autoQuarantine);
  }
  syncAutoQuarantineState();
  const rules=byId('titanPolicyRules');
  if(!rules)return;
  const definitions=[
    ['PERSISTENZ','Neue Dienste, Autostarts, geplante Aufgaben und Startmechanismen sind hochriskant.'],
    ['SICHERHEIT','Abschwächung von Defender, Firewall, Audit oder LSA erzeugt ein kritisches Ereignis.'],
    ['INGRESS','Neue ausführbare Dateien aus Downloads, Temp, Wechselmedien oder Remote-Kanälen werden geprüft.'],
    ['SYSTEM','Änderungen an Treibern, Code-Integrität und Boot-Vertrauen bleiben sichtbar.'],
    ['BESITZER','Nur eine gültige, begrenzte Freigabe macht eine Änderung autorisiert — Adminrechte allein nicht.'],
  ];
  renderStable(rules,`rules:${definitions.length}`,()=>{
    const fragment=document.createDocumentFragment();
    for(const [label,detail] of definitions){
      const row=node('div','titan-rule-row');
      row.dataset.titanRow=`rule:${label}`;
      row.append(node('b','',label),node('span','',detail));
      fragment.append(row);
    }
    return fragment;
  });
  renderPermits(Array.isArray(policy.permits)?policy.permits:[]);
  renderDevelopmentRoots(Array.isArray(policy.developmentRoots)?policy.developmentRoots:[]);
}

function renderDevelopmentRoots(roots){
  const host=byId('titanDevRootsList');
  if(!host)return;
  setText('titanDevRootsCount',`${formatNumber(roots.length)} BÄUME`);
  setPill('titanDevRootsCount',`${formatNumber(roots.length)} BÄUME`,roots.length?'info':'good');
  const signature=`devroots:${roots.join('\u0000')}`;
  renderStable(host,signature,()=>{
    const fragment=document.createDocumentFragment();
    if(!roots.length){
      fragment.append(emptyState('Kein Entwicklungsbaum markiert','Ohne diese Markierung gilt jede neue ausführbare oder skriptfähige Datei im Ingress-Baum als unerwartet.'));
      return fragment;
    }
    for(const root of roots){
      const row=node('div','titan-permit-row');
      row.dataset.titanRow=`devroot:${root}`;
      const main=node('div','titan-permit-main');
      main.append(node('strong','',root),node('small','','Owner-markierter Source-/Build-Baum · keine automatische Quarantäne'));
      const side=node('div','titan-permit-actions');
      side.append(actionButton('Markierung entfernen','remove-dev-root',root));
      row.append(main,side);
      fragment.append(row);
    }
    return fragment;
  });
}

function renderPermits(permits){
  const host=byId('titanPermitsList');
  if(!host)return;
  const now=Date.now();
  let active=0;
  for(const permit of permits){
    const expires=Date.parse(permit.expiresUtc||'');
    const expired=!Number.isFinite(expires)||expires<=now;
    const used=permit.used===true;
    if(expired||used)continue;
    active++;
  }
  setText('titanPermitsCount',`${formatNumber(active)} AKTIV`);
  setPill('titanPermitsCount',`${formatNumber(active)} AKTIV`,active?'good':'info');
  renderStable(host,`permits:${JSON.stringify(permits)}`,()=>{
    const fragment=document.createDocumentFragment();
    if(!permits.length){
      fragment.append(emptyState('Keine aktiven Owner-Freigaben','Neue Freigaben sind eng begrenzt, ablaufen automatisch und werden als Evidenzereignis protokolliert.'));
      return fragment;
    }
    for(const permit of permits){
      const expires=Date.parse(permit.expiresUtc||'');
      const expired=!Number.isFinite(expires)||expires<=now;
      const row=node('div','titan-permit-row');
      row.dataset.titanRow=`permit:${permit.id||''}`;
      const main=node('div','titan-permit-main');
      main.append(node('strong','',permit.path||'Pfad unbekannt'));
      const meta=node('div','titan-permit-meta');
      meta.append(node('span','',permitActionLabels[permit.action]||permit.action||'Freigabe'));
      meta.append(node('span','',permit.singleUse?'einmalig':'mehrfach'));
      meta.append(node('span','',expired?'abgelaufen':`bis ${formatTime(permit.expiresUtc)}`));
      if(permit.sha256)meta.append(node('span','',`SHA ${String(permit.sha256).slice(0,12)}…`));
      main.append(meta,node('small','',permit.reason||''));
      const side=node('div','titan-permit-actions');
      const state=node('span','titan-permit-state',permit.used?'VERBRAUCHT':expired?'ABGELAUFEN':'AKTIV');
      state.dataset.used=String(permit.used===true);
      state.dataset.expired=String(expired);
      side.append(state);
      if(!expired&&!permit.used)side.append(actionButton('Widerrufen','revoke-permit',permit.id));
      row.append(main,side);
      fragment.append(row);
    }
    return fragment;
  });
}

function syncAutoQuarantineState(){
  const mode=byId('titanPolicyMode');
  const auto=byId('titanAutoQuarantine');
  if(!mode||!auto)return;
  const observe=mode.value==='OBSERVE';
  auto.disabled=observe;
  if(observe)auto.checked=false;
}

function renderCheckpointSummary(status){
  const badge=byId('titanEvidenceBadge');
  if(!badge)return;
  const verified=status.journalVerified===true;
  setText('titanEvidenceBadge',verified?'JOURNAL VERIFIZIERT':'PRÜFUNG OFFEN');
  setPill('titanEvidenceBadge',verified?'JOURNAL VERIFIZIERT':'PRÜFUNG OFFEN',verified?'good':'warn');
  setToneText('titanEvidenceStatus',verified?'Verifiziert: Journal-Kette und Checkpoint-Signaturen sind konsistent.':(status.journalError||'Noch keine vollständige Verifikation.'),verified?'good':'warn');
}

function renderEvent(event){
  const row=node('article','titan-event-row');
  row.dataset.titanRow=`event:${event.id||''}`;
  row.dataset.trust=event.authorization?.status||'TOLERATED';
  const time=node('div','titan-event-time');
  time.append(node('b','',eventTime(event)),node('span','',event.eventType||''));
  const sev=node('div','titan-event-severity');
  sev.append(severity(event.severity||'LOW'));
  const object=node('div','titan-event-object');
  object.append(node('strong','',event.object?.name||event.object?.path||'Unbekanntes Objekt'));
  if(event.object?.path)object.append(node('small','',event.object.path));
  const objectMeta=[event.object?.fileType,event.object?.size?formatBytes(event.object.size):''].filter(Boolean).join(' · ');
  if(objectMeta)object.append(node('small','',objectMeta));
  const actor=node('div','titan-event-actor');
  if(Number(event.actor?.pid)>0){
    actor.append(node('b','',event.actor.image||`PID ${event.actor.pid}`),node('span','',`PID ${event.actor.pid} · ${event.actor.correlationQuality||'NONE'}`));
  }else{
    actor.append(node('b','','Keine direkte Zuordnung'),node('span','','Kein Prozessbezug beobachtet'));
  }
  const trust=node('div','titan-event-trust');
  const badge=node('span','titan-trust-badge',trustLabels[event.authorization?.status]||event.authorization?.status||'UNBEKANNT');
  badge.dataset.status=event.authorization?.status||'TOLERATED';
  trust.append(badge,node('small','',event.authorization?.reason||'Keine Begründung aufgezeichnet.'));
  const actions=node('div','titan-event-action');
  const canQuarantine=event.object?.kind==='FILE'&&event.eventType!=='FILE_DELETED'&&event.response?.state!=='QUARANTINED';
  if(canQuarantine)actions.append(actionButton('Isolieren','quarantine',event.id));
  if(event.authorization?.needsReview)actions.append(actionButton('Prüfen','ack',event.id,'ghost'));
  row.append(time,sev,object,actor,trust,actions);
  const details=node('details','titan-event-more');
  details.append(node('summary','','Belege und Grenzen'));
  const evidence=node('dl','titan-event-evidence');
  const add=(term,value)=>{const wrap=node('div');wrap.append(node('dt','',term),node('dd','',value||'—'));evidence.append(wrap)};
  add('SHA-256',event.object?.sha256||'Nicht verfügbar');
  add('Risikoklasse',riskLabels[event.authorization?.riskClass]||event.authorization?.riskClass||'Unbekannt');
  add('Risiko-Score',event.authorization?.riskScore!==undefined?String(event.authorization.riskScore):'—');
  add('Prozesskorrelation',event.actor?.correlationNote||'Keine direkte Zuordnung');
  add('Netzwerkkorrelation',`${event.network?.correlationQuality||'NONE'} · ${event.network?.detail||'Keine Netzwerkzuordnung'}`);
  add('Quelle / Health',`${event.collection?.source||'—'} · ${event.collection?.telemetryHealth||'—'}`);
  add('Antwort',`${event.response?.action||'—'} · ${event.response?.state||'—'}`);
  add('Ereignis-ID',event.id||'—');
  details.append(evidence);
  row.append(details);
  return row;
}

async function loadEvents(options={}){
  const host=byId('titanEventList');
  if(!host)return;
  const resetScroll=options.resetScroll===true;
  if(resetScroll)resetListSignature(host);
  try{
    // Fetch first: the list must never collapse while the request is in flight.
    const result=await getTitanEvents({limit:state.limit,offset:state.offset,filter:state.filter});
    const events=Array.isArray(result.events)?result.events:[];
    const previousTotal=state.total;
    state.total=Number(result.total)||0;
    state.eventsLoaded=true;
    const empty=byId('titanEventEmpty');
    if(empty)empty.hidden=events.length>0;
    const signature=`events:${state.filter}:${state.offset}:${state.total}:`+events.map(event=>`${event.id}|${event.eventType}|${event.authorization?.status}|${event.response?.state}|${event.severity}`).join(';');
    renderStable(host,signature,()=>{
      const fragment=document.createDocumentFragment();
      for(const event of events)fragment.append(renderEvent(event));
      if(!events.length){
        fragment.append(emptyState('Keine Ereignisse in diesem Filter','Titan erfindet keine Beobachtungen. Wähle einen anderen Filter oder warte auf reale Sensorereignisse.'));
      }
      return fragment;
    });
    if(resetScroll)resetVisibleListPosition(host);
    setText('titanIngressTotal',`${formatNumber(state.total)} BEOBACHTET`);
    setText('titanEventPageInfo',state.total?`${formatNumber(state.offset+1)}–${formatNumber(Math.min(state.offset+state.limit,state.total))} von ${formatNumber(state.total)}`:'Keine Ereignisse');
    setText('titanEventState',state.total?`Filter: ${state.filter} · neueste zuerst`:'Noch keine Ereignisse.');
    if(previousTotal>0&&state.total>previousTotal){
      announce(`${formatNumber(state.total-previousTotal)} neue Titan-Ereignisse geladen.`);
    }
    const prev=byId('titanEventPrev');
    const next=byId('titanEventNext');
    if(prev)prev.disabled=state.offset<=0;
    if(next)next.disabled=state.offset+state.limit>=state.total;
  }catch(error){
    state.eventsLoaded=false;
    renderStable(host,`events-error:${error?.message||''}`,()=>{
      const fragment=document.createDocumentFragment();
      fragment.append(emptyState('Evidenz-Timeline nicht erreichbar',error?.message||'Die Control Plane antwortet nicht.'));
      return fragment;
    });
    setToneText('titanEventState',`Nicht erreichbar: ${error?.message||'unbekannter Fehler'}`,'bad');
  }
}

function renderQuarantineEntry(entry){
  const row=node('div','titan-quarantine-row');
  row.dataset.titanRow=`quarantine:${entry.id||''}`;
  const main=node('div','titan-quarantine-main');
  main.append(node('strong','',entry.originalName||entry.originalPath||entry.id),node('small','',entry.originalPath||''));
  const meta=node('div','titan-quarantine-meta');
  meta.append(node('span','',`SHA-256 ${String(entry.sha256||'').slice(0,16)}…`),node('span','',formatBytes(entry.size||0)),node('span','',formatTime(entry.createdUtc)));
  main.append(meta);
  if(entry.reason)main.append(node('small','',entry.reason));
  const side=node('div','titan-quarantine-actions');
  const stateBadge=node('span','titan-quarantine-state',entry.state==='RESTORED'?'WIEDERHERGESTELLT':entry.originalGone?'ISOLIERT':'ORIGINAL GESPERRT');
  stateBadge.dataset.state=entry.state||'';
  side.append(stateBadge);
  if(entry.state!=='RESTORED'&&entry.originalGone!==false)side.append(actionButton('Wiederherstellen','restore',entry.id));
  if(!entry.reviewed)side.append(actionButton('Als geprüft','review',entry.id,'ghost'));
  row.append(main,side);
  return row;
}

async function loadQuarantine(options={}){
  const host=byId('titanQuarantineList');
  if(!host)return;
  const resetScroll=options.resetScroll===true;
  if(resetScroll)resetListSignature(host);
  try{
    const result=await getTitanQuarantine();
    const entries=Array.isArray(result.entries)?result.entries:[];
    state.quarantineLoaded=true;
    const empty=byId('titanQuarantineEmpty');
    if(empty)empty.hidden=entries.length>0;
    renderStable(host,`quarantine:${JSON.stringify(entries)}`,()=>{
      const fragment=document.createDocumentFragment();
      for(const entry of entries)fragment.append(renderQuarantineEntry(entry));
      if(!entries.length)fragment.append(emptyState('Quarantäne ist leer','Titan isoliert nur nach einer Richtlinie oder einer ausdrücklichen Besitzerentscheidung.'));
      return fragment;
    });
    if(resetScroll)resetVisibleListPosition(host);
    setText('titanQuarantineSummary',`${formatNumber(entries.length)} OBJEKTE · ${formatBytes(result.bytes||0)}`);
    setPill('titanQuarantineSummary',`${formatNumber(entries.length)} OBJEKTE · ${formatBytes(result.bytes||0)}`,entries.length?'warn':'good');
  }catch(error){
    state.quarantineLoaded=false;
    renderStable(host,`quarantine-error:${error?.message||''}`,()=>{
      const fragment=document.createDocumentFragment();
      fragment.append(emptyState('Quarantäne nicht erreichbar',error?.message||'Die Control Plane antwortet nicht.'));
      return fragment;
    });
  }
}

async function loadEvidence(options={}){
  const host=byId('titanCheckpoints');
  if(!host)return;
  const resetScroll=options.resetScroll===true;
  if(resetScroll)resetListSignature(host);
  try{
    const result=await getTitanCheckpoints(50);
    const checkpoints=Array.isArray(result.checkpoints)?result.checkpoints:[];
    state.evidenceLoaded=true;
    renderStable(host,`checkpoints:${JSON.stringify(checkpoints)}`,()=>{
      const fragment=document.createDocumentFragment();
      if(!checkpoints.length)fragment.append(emptyState('Noch kein signierter Checkpoint','Titan signiert die Evidenzkette automatisch nach den ersten Ereignissen oder beim nächsten Prüflauf.'));
      for(const checkpoint of checkpoints){
        const row=node('div','titan-checkpoint-row');
        row.dataset.titanRow=`checkpoint:${checkpoint.sequence}`;
        row.append(node('span','titan-checkpoint-seq',`#${formatNumber(checkpoint.sequence)}`));
        const copy=node('div','titan-checkpoint-copy');
        copy.append(node('strong','',checkpoint.lastHash?`Kette ${String(checkpoint.lastHash).slice(0,24)}…`:'Kettenhash nicht verfügbar'),node('small','',`${formatTime(checkpoint.createdUtc)} · Boot ${String(checkpoint.bootId||'').slice(0,12)}…`));
        row.append(copy,node('span','titan-checkpoint-state','ED25519'));
        fragment.append(row);
      }
      return fragment;
    });
    if(resetScroll)resetVisibleListPosition(host);
  }catch(error){
    state.evidenceLoaded=false;
    renderStable(host,`checkpoints-error:${error?.message||''}`,()=>{
      const fragment=document.createDocumentFragment();
      fragment.append(emptyState('Checkpoints nicht erreichbar',error?.message||'Die Control Plane antwortet nicht.'));
      return fragment;
    });
  }
}

async function reloadCurrentTab(){
  if(state.tab==='ingress')await loadEvents({resetScroll:true});
  else if(state.tab==='quarantine')await loadQuarantine({resetScroll:true});
  else if(state.tab==='policy')renderPolicy(state.status?.policy||{});
  else if(state.tab==='evidence')await loadEvidence({resetScroll:true});
}

export async function loadTitan(options={}){
  try{
    const status=await getTitanStatus();
    renderStatus(status);
    if(options.force||options.refresh||!state.eventsLoaded){
      if(state.tab==='ingress')await loadEvents();
      else if(state.tab==='quarantine')await loadQuarantine();
      else if(state.tab==='evidence')await loadEvidence();
    }
  }catch(error){
    const host=byId('titanSensors');
    if(host)host.replaceChildren(emptyState('Titan nicht erreichbar',error?.message||'Die Control Plane antwortet nicht.'));
    setPill('titanStatePill','NICHT ERREICHBAR','bad');
    if(!options.refresh)toast(`Titan nicht erreichbar: ${error?.message||error}`,'bad');
  }
}

function selectTab(tab){
  if(!['lage','ingress','quarantine','policy','evidence'].includes(tab))return;
  state.tab=tab;
  for(const button of document.querySelectorAll('[data-titan-tab]')){
    const selected=button.dataset.titanTab===tab;
    button.classList.toggle('active',selected);
    button.setAttribute('aria-selected',String(selected));
  }
  for(const panel of document.querySelectorAll('[data-titan-panel]')){
    const shown=panel.dataset.titanPanel===tab;
    panel.hidden=!shown;
    panel.classList.toggle('active',shown);
  }
  void reloadCurrentTab().catch(()=>{});
}

async function runEventAction(action,id){
  if(state.busy)return;
  const prompt=action==='quarantine'
    ?{title:'Objekt isolieren',text:'Titan legt eine verschlüsselte Beweiskopie an und entfernt das Original nach erfolgreicher Prüfung. Die Ausführung wird nicht nachträglich beendet.',label:'Begründung der Quarantäne'}
    :action==='ack'
      ?{title:'Befund prüfen',text:'Der Befund bleibt in der Evidenzkette erhalten. Die Prüfung wird als eigenes Ereignis protokolliert.',label:'Was wurde geprüft?'}
      :null;
  if(!prompt)return;
  const reason=await requestReason(prompt);
  if(!reason)return;
  state.busy=true;
  try{
    if(action==='quarantine')await quarantineTitanEvent(id,reason);
    else await acknowledgeTitanEvent(id,reason);
    toast(action==='quarantine'?'Objekt in die Titan-Quarantäne überführt.':'Befund als geprüft dokumentiert.','good');
    await loadTitan({force:true});
    await loadEvents();
  }catch(error){
    toast(`Aktion abgelehnt: ${error?.message||error}`,'bad');
  }finally{
    state.busy=false;
  }
}

async function runQuarantineAction(action,id){
  if(state.busy)return;
  const prompt=action==='restore'
    ?{title:'Objekt wiederherstellen',text:'Titan prüft den SHA-256-Wert und stellt das Objekt nur wieder her, wenn das Originalziel frei ist. Jede Entscheidung wird protokolliert.',label:'Begründung der Wiederherstellung'}
    :{title:'Quarantäne prüfen',text:'Die verschlüsselte Kopie bleibt als Nachweis erhalten. Die Prüfung wird dokumentiert.',label:'Prüfnotiz'};
  const reason=await requestReason(prompt);
  if(!reason)return;
  state.busy=true;
  try{
    if(action==='restore')await restoreTitanQuarantine(id,reason);
    else await reviewTitanQuarantine(id,reason);
    setToneText('titanQuarantineStatus',action==='restore'?'Objekt wurde hashgeprüft wiederhergestellt und die Entscheidung protokolliert.':'Quarantäne wurde als geprüft dokumentiert.','good');
    toast(action==='restore'?'Objekt integritätsgeprüft wiederhergestellt.':'Quarantäne als geprüft dokumentiert.','good');
    await loadTitan({force:true});
    await loadQuarantine();
    await loadEvents();
  }catch(error){
    setToneText('titanQuarantineStatus',`Aktion abgelehnt: ${error?.message||error}`,'bad');
    toast(`Aktion abgelehnt: ${error?.message||error}`,'bad');
  }finally{
    state.busy=false;
  }
}

async function createPermit(){
  const path=String(byId('titanPermitPath')?.value||'').trim();
  const sha256=String(byId('titanPermitHash')?.value||'').trim().toUpperCase();
  const action=String(byId('titanPermitAction')?.value||'ALLOW_CHANGE');
  const ttlMinutes=Number(byId('titanPermitTTL')?.value||60);
  const singleUse=Boolean(byId('titanPermitSingle')?.checked);
  if(!/^[A-Za-z]:\\/.test(path)||path.length>260){
    setToneText('titanPermitStatus','Bitte einen absoluten Windows-Pfad mit Laufwerksbuchstaben angeben.','bad');
    byId('titanPermitPath')?.focus();
    return;
  }
  if(sha256&&!/^[A-F0-9]{64}$/.test(sha256)){
    setToneText('titanPermitStatus','Der optionale Hash muss aus genau 64 Hex-Zeichen bestehen.','bad');
    byId('titanPermitHash')?.focus();
    return;
  }
  if(!Number.isFinite(ttlMinutes)||ttlMinutes<5||ttlMinutes>43200){
    setToneText('titanPermitStatus','Die Gültigkeit muss zwischen 5 Minuten und 30 Tagen liegen.','bad');
    return;
  }
  const reason=await requestReason({
    title:'Titan-Freigabe erteilen',
    text:'Die Freigabe gilt nur für den angegebenen Pfad, optional den Hash, diese Aktion und den gewählten Zeitraum. Sie wird als Evidenzereignis protokolliert.',
    label:'Begründung der Freigabe',
    confirmLabel:'Freigabe erteilen',
  });
  if(!reason)return;
  const button=byId('titanPermitCreate');
  if(button){button.disabled=true;button.classList.add('loading')}
  setText('titanPermitStatus','Freigabe wird validiert …');
  try{
    await createTitanPermit({path,sha256,action,ttlMinutes,singleUse,reason});
    setInputValue('titanPermitPath','');
    setInputValue('titanPermitHash','');
    setToneText('titanPermitStatus','Freigabe gespeichert und als Evidenzereignis protokolliert.','good');
    toast('Titan-Freigabe erteilt.','good');
    await loadTitan({force:true});
  }catch(error){
    setToneText('titanPermitStatus',`Freigabe abgelehnt: ${error?.message||error}`,'bad');
    toast(`Freigabe abgelehnt: ${error?.message||error}`,'bad');
  }finally{
    if(button){button.disabled=false;button.classList.remove('loading')}
  }
}

async function revokePermit(id){
  if(state.busy)return;
  const reason=await requestReason({
    title:'Titan-Freigabe widerrufen',
    text:'Die Freigabe kann danach nicht mehr zur Autorisierung einer Änderung verwendet werden. Der Widerruf wird protokolliert.',
    label:'Begründung des Widerrufs',
    confirmLabel:'Freigabe widerrufen',
  });
  if(!reason)return;
  state.busy=true;
  try{
    await revokeTitanPermit(id,reason);
    setToneText('titanPermitStatus','Freigabe widerrufen und als Evidenzereignis protokolliert.','good');
    toast('Titan-Freigabe widerrufen.','good');
    await loadTitan({force:true});
  }catch(error){
    setToneText('titanPermitStatus',`Widerruf abgelehnt: ${error?.message||error}`,'bad');
    toast(`Widerruf abgelehnt: ${error?.message||error}`,'bad');
  }finally{
    state.busy=false;
  }
}

async function acknowledgeVisibleFindings(){
  if(state.busy)return;
  const reason=await requestReason({
    title:'Offene Befunde prüfen',
    text:'Titan markiert bis zu 100 sichtbare offene Befunde als geprüft. Die Ereignisse bleiben unverändert in der Evidenzkette; es wird keine Datei gelöscht oder umgeschrieben.',
    label:'Begründung der Prüfung',
    confirmLabel:'Befunde prüfen',
  });
  if(!reason)return;
  state.busy=true;
  try{
    const result=await acknowledgeTitanOpenFindings(100,reason);
    const reviewed=Number(result?.reviewed||0);
    setToneText('titanReviewStatus',`${reviewed} Befund(e) als geprüft protokolliert.`,'good');
    toast(`${reviewed} Befund(e) als geprüft protokolliert.`,'good');
    await loadTitan({force:true});
    await loadEvents();
  }catch(error){
    setToneText('titanReviewStatus',`Prüfung abgelehnt: ${error?.message||error}`,'bad');
    toast(`Prüfung abgelehnt: ${error?.message||error}`,'bad');
  }finally{
    state.busy=false;
  }
}

async function addDevelopmentRoot(){  const path=String(byId('titanDevRootPath')?.value||'').trim();
  if(!/^[A-Za-z]:\\/.test(path)||path.length>260){
    setToneText('titanDevRootStatus','Bitte einen absoluten Windows-Projektpfad angeben.','bad');
    byId('titanDevRootPath')?.focus();
    return;
  }
  const reason=await requestReason({
    title:'Entwicklungsbaum markieren',
    text:'Dateiereignisse in diesem Baum bleiben vollständig in der Evidenz, werden aber nicht als Ingress-Hochrisiko eskaliert. System- und Persistenzänderungen bleiben unverändert streng.',
    label:'Begründung der Markierung',
    confirmLabel:'Entwicklungsbaum markieren',
  });
  if(!reason)return;
  const button=byId('titanDevRootAdd');
  if(button){button.disabled=true;button.classList.add('loading')}
  setText('titanDevRootStatus','Markierung wird validiert …');
  try{
    await addTitanDevelopmentRoot(path,reason);
    setInputValue('titanDevRootPath','');
    setToneText('titanDevRootStatus','Entwicklungsbaum markiert und protokolliert.','good');
    toast('Entwicklungsbaum markiert.','good');
    await loadTitan({force:true});
  }catch(error){
    setToneText('titanDevRootStatus',`Markierung abgelehnt: ${error?.message||error}`,'bad');
    toast(`Markierung abgelehnt: ${error?.message||error}`,'bad');
  }finally{
    if(button){button.disabled=false;button.classList.remove('loading')}
  }
}

async function removeDevelopmentRoot(path){
  if(state.busy)return;
  const reason=await requestReason({
    title:'Entwicklungsbaum-Markierung entfernen',
    text:'Neue ausführbare oder skriptfähige Dateien in diesem Baum werden wieder als Ingress-Hochrisiko bewertet.',
    label:'Begründung der Entfernung',
    confirmLabel:'Markierung entfernen',
  });
  if(!reason)return;
  state.busy=true;
  try{
    await removeTitanDevelopmentRoot(path,reason);
    setToneText('titanDevRootStatus','Markierung entfernt und protokolliert.','good');
    toast('Entwicklungsbaum-Markierung entfernt.','good');
    await loadTitan({force:true});
  }catch(error){
    setToneText('titanDevRootStatus',`Entfernung abgelehnt: ${error?.message||error}`,'bad');
    toast(`Entfernung abgelehnt: ${error?.message||error}`,'bad');
  }finally{
    state.busy=false;
  }
}

function setInputValue(id,value){
  const input=byId(id);
  if(input)input.value=value===undefined||value===null?'':String(value);
}

async function savePolicy(){
  const mode=String(byId('titanPolicyMode')?.value||'OBSERVE');
  const autoQuarantine=Boolean(byId('titanAutoQuarantine')?.checked)&&mode!=='OBSERVE';
  const reason=await requestReason({
    title:'Titan-Richtlinie ändern',
    text:'Der Antwortmodus und die automatische Quarantäne werden serverseitig validiert und als Sicherheitsereignis protokolliert.',
    label:'Begründung der Richtlinienänderung',
    confirmLabel:'Richtlinie speichern',
  });
  if(!reason)return;
  const button=byId('titanPolicySave');
  if(button){button.disabled=true;button.classList.add('loading')}
  setText('titanPolicyStatus','Richtlinie wird validiert und gespeichert …');
  try{
    const policy=await saveTitanPolicy({mode,autoQuarantine,reason});
    state.policyDirty=false;
    renderPolicy(policy);
    setText('titanPolicyStatus','Richtlinie gespeichert und als Evidenzereignis protokolliert.');
    toast('Titan-Richtlinie gespeichert.','good');
    await loadTitan({force:true});
  }catch(error){
    setToneText('titanPolicyStatus',`Abgelehnt: ${error?.message||error}`,'bad');
    toast(`Richtlinie abgelehnt: ${error?.message||error}`,'bad');
  }finally{
    if(button){button.disabled=false;button.classList.remove('loading')}
  }
}

async function verifyEvidence(){
  setText('titanEvidenceStatus','Journal und Checkpoint-Signaturen werden geprüft …');
  setText('titanExportStatus','');
  try{
    const result=await verifyTitanEvidence();
    const detail=result.detail||'';
    setToneText('titanEvidenceStatus',result.verified?`Verifiziert: ${formatNumber(result.events)} Ereignisse, ${formatNumber(result.checkpoints)} Checkpoints. ${detail}`:`Nicht verifiziert: ${detail}`,result.verified?'good':'bad');
    setPill('titanEvidenceBadge',result.verified?'JOURNAL VERIFIZIERT':'PRÜFUNG FEHLGESCHLAGEN',result.verified?'good':'bad');
    toast(result.verified?'Titan-Evidenz verifiziert.':'Titan-Evidenz konnte nicht verifiziert werden.',result.verified?'good':'bad');
    await loadTitan({force:true});
    await loadEvidence();
  }catch(error){
    setToneText('titanEvidenceStatus',`Prüfung fehlgeschlagen: ${error?.message||error}`,'bad');
    toast(`Evidenzprüfung fehlgeschlagen: ${error?.message||error}`,'bad');
  }
}

async function exportEvidence(){
  const button=byId('titanExportButton');
  if(button){button.disabled=true;button.classList.add('loading')}
  setText('titanExportStatus','Evidenzpaket wird erstellt …');
  try{
    const bundle=await exportTitanEvidence(500);
    const blob=new Blob([JSON.stringify(bundle,null,2)],{type:'application/json'});
    const url=URL.createObjectURL(blob);
    const link=document.createElement('a');
    link.href=url;
    link.download=`gedefense-titan-evidence-${new Date().toISOString().slice(0,10)}.json`;
    document.body.append(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
    setText('titanExportStatus','Signiertes, begrenztes Evidenzpaket exportiert. Es belegt Beobachtungen, keine Urheberschaft.');
    toast('Titan-Evidenzpaket exportiert.','good');
  }catch(error){
    setToneText('titanExportStatus',`Export abgelehnt: ${error?.message||error}`,'bad');
    toast(`Evidenzexport abgelehnt: ${error?.message||error}`,'bad');
  }finally{
    if(button){button.disabled=false;button.classList.remove('loading')}
  }
}

function eventActionFrom(target){
  const element=target.closest('[data-titan-action]');
  if(!element||element.disabled)return;
  const action=element.dataset.titanAction;
  const id=element.dataset.titanId;
  if(!id)return;
  if(action==='quarantine'||action==='ack')void runEventAction(action,id);
  if(action==='restore'||action==='review')void runQuarantineAction(action,id);
  if(action==='revoke-permit')void revokePermit(id);
  if(action==='remove-dev-root')void removeDevelopmentRoot(id);
}

export function bindTitan(){
  if(state.initialized)return;
  state.initialized=true;
  for(const button of document.querySelectorAll('[data-titan-tab]')){
    button.addEventListener('click',()=>selectTab(button.dataset.titanTab));
    button.addEventListener('keydown',event=>{
      const tabs=[...document.querySelectorAll('[data-titan-tab]')];
      const index=tabs.indexOf(button);
      if(index<0)return;
      let next=-1;
      if(event.key==='ArrowRight')next=(index+1)%tabs.length;
      else if(event.key==='ArrowLeft')next=(index-1+tabs.length)%tabs.length;
      else if(event.key==='Home')next=0;
      else if(event.key==='End')next=tabs.length-1;
      if(next<0)return;
      event.preventDefault();
      tabs[next].focus();
      selectTab(tabs[next].dataset.titanTab);
    });
  }
  for(const button of document.querySelectorAll('[data-titan-filter]')){
    button.addEventListener('click',()=>{
      state.filter=button.dataset.titanFilter||'all';
      state.offset=0;
      for(const filterButton of document.querySelectorAll('[data-titan-filter]')){
        const selected=filterButton===button;
        filterButton.classList.toggle('active',selected);
        filterButton.setAttribute('aria-pressed',String(selected));
      }
      void loadEvents({resetScroll:true});
    });
  }
  byId('titanEventPrev')?.addEventListener('click',()=>{
    state.offset=Math.max(0,state.offset-state.limit);void loadEvents({resetScroll:true});
  });
  byId('titanEventNext')?.addEventListener('click',()=>{
    state.offset+=state.limit;void loadEvents({resetScroll:true});
  });
  byId('titanRefresh')?.addEventListener('click',()=>{void loadTitan({force:true})});
  byId('titanVerifyButton')?.addEventListener('click',()=>{void verifyEvidence()});
  byId('titanVerifyInline')?.addEventListener('click',()=>{void verifyEvidence()});
  byId('titanExportButton')?.addEventListener('click',()=>{void exportEvidence()});
  byId('titanPolicySave')?.addEventListener('click',()=>{void savePolicy()});
  byId('titanPermitCreate')?.addEventListener('click',()=>{void createPermit()});
  byId('titanDevRootAdd')?.addEventListener('click',()=>{void addDevelopmentRoot()});
  byId('titanAcknowledgeOpen')?.addEventListener('click',()=>{void acknowledgeVisibleFindings()});
  byId('titanPolicyMode')?.addEventListener('change',()=>{state.policyDirty=true;syncAutoQuarantineState()});
  byId('titanAutoQuarantine')?.addEventListener('change',()=>{state.policyDirty=true});
  byId('titanEventList')?.addEventListener('click',event=>eventActionFrom(event.target));
  byId('titanQuarantineList')?.addEventListener('click',event=>eventActionFrom(event.target));
  byId('titanPermitsList')?.addEventListener('click',event=>eventActionFrom(event.target));
  byId('titanDevRootsList')?.addEventListener('click',event=>eventActionFrom(event.target));
}

export { selectTab as selectTitanTab };
