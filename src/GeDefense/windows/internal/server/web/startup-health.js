// STATUS: PLATIN
'use strict';
/** Startup readiness gate and health refresh.
 *
 *  The readiness dialog is only shown when the server says a review is
 *  required (after reboot/update). On a normal UI open the shell performs a
 *  silent health refresh instead. A missing/unsupported startup endpoint means
 *  "do not show the dialog" — the operator can always start the check manually.
 */
import {acknowledgeStartup, api, getHealthRefresh, getHealthStatus, getStartupState} from './api.js';
import {byId, formatTime, setText} from './dom.js';
import {locale} from './i18n.js';

const definitions=[
  ['policy','Schutzrichtlinie'],
  ['defender','Microsoft Defender'],
  ['firewall','Windows Firewall'],
  ['telemetry','Prozess- und Netzwerk-Telemetrie'],
  ['intelligence','Threat Intelligence'],
  ['enforcement','Threat-IP-Firewallregeln'],
  ['evidence','Evidenz und Audit-Kette'],
];
const states={pending:'Wartet',running:'Prüfung läuft',healthy:'Bereit',attention:'Prüfen'};
const rows=new Map();

let currentRun=null;
let opener=null;
let startupGate=null;
let ackSent=false;
let lastReport=null;
let lastError='';
let lastRefreshUtc='';
let syncTimer=null;
let syncStartedAt=0;
const gateChecked={required:false,checked:false,reason:'',unavailable:false};

function paint(id,state,detail){
  const row=rows.get(id);
  if(!row)return;
  row.item.dataset.state=state;
  row.state.textContent=states[state];
  row.detail.textContent=detail;
}

function progress(value,text){
  const progressEl=byId('startupProgress');
  if(progressEl)progressEl.value=value;
  setText('startupStage',text);
  setText('startupCount',`${value} / 4`);
}

function stopSyncFeedback(){
  if(syncTimer){clearInterval(syncTimer);syncTimer=null}
  const spinner=byId('startupSpinner');
  if(spinner)spinner.hidden=true;
  const progressEl=byId('startupProgress');
  if(progressEl)progressEl.dataset.busy='false';
}

function startSyncFeedback(){
  stopSyncFeedback();
  syncStartedAt=Date.now();
  const spinner=byId('startupSpinner');
  if(spinner)spinner.hidden=false;
  const progressEl=byId('startupProgress');
  if(progressEl)progressEl.dataset.busy='true';
  const update=()=>{
    const elapsed=Math.max(0,Math.floor((Date.now()-syncStartedAt)/1000));
    setText('startupElapsed',elapsed>=60?`${Math.floor(elapsed/60)} min ${elapsed%60} s`:`${elapsed} s`);
  };
  update();
  syncTimer=setInterval(update,1000);
}

function prepare(){
  const list=byId('startupChecks');
  if(!list)return;
  list.replaceChildren();
  rows.clear();
  for(const [id,label]of definitions){
    const item=document.createElement('li');
    item.dataset.state='pending';
    const marker=document.createElement('span');
    marker.className='health-marker';
    marker.setAttribute('aria-hidden','true');
    const copy=document.createElement('div');
    const name=document.createElement('strong');
    name.textContent=label;
    const detail=document.createElement('p');
    const state=document.createElement('span');
    state.className='health-state';
    copy.append(name,detail);
    item.append(marker,copy,state);
    list.append(item);
    rows.set(id,{item,state,detail});
    paint(id,'pending','Wird beim Start geprüft.');
  }
  setText('startupTitle','GeDefense wird vorbereitet');
  setText('startupSummary','Lokale Schutzbereiche werden in wenigen Sekunden geprüft. Netzwerk-Synchronisation läuft bei Bedarf im Hintergrund weiter.');
  const retry=byId('startupRetry');
  if(retry)retry.hidden=true;
  const close=byId('startupClose');
  if(close)close.textContent='Im Hintergrund fortsetzen';
  progress(0,'Lokale Verbindung prüfen');
}

function validateReport(report){
  if(!report||typeof report.healthy!=='boolean'||!Number.isFinite(Date.parse(report.checkedUtc))||!Array.isArray(report.checks)||report.checks.length!==definitions.length)throw new Error('Ungültiger Healthcheck-Bericht.');
  const ids=new Set();
  for(const check of report.checks){
    if(!rows.has(check.id)||ids.has(check.id)||!['healthy','attention'].includes(check.state)||typeof check.detail!=='string'||check.detail.length>1024)throw new Error('Ungültiger Healthcheck-Bereich.');
    ids.add(check.id);
  }
  if(report.healthy!==report.checks.every(check=>check.state==='healthy'))throw new Error('Widersprüchlicher Healthcheck-Bericht.');
  return report;
}

function healthIndicator(tone,label,detail){
  const dot=byId('healthRefreshDot');
  const text=byId('healthRefreshLabel');
  const button=byId('healthRefreshButton');
  if(dot)dot.dataset.state=tone;
  if(text)text.textContent=label;
  if(button)button.title=detail;
}

function applyReport(report){
  lastReport=report;
  lastError='';
  lastRefreshUtc=report.checkedUtc;
  const healthy=Boolean(report?.healthy);
  healthIndicator(healthy?'good':'warn',healthy?'Bereit':'Prüfen',healthy?'Bereitschaft zuletzt bestätigt.':`Letzte Prüfung ${formatTime(report?.checkedUtc)}: Aufmerksamkeit erforderlich.`);
  setText('systemHealthChecked',formatTime(report?.checkedUtc));
  setText('systemHealthHealthy',healthy?'Alle geprüften Bereiche bereit':'Mindestens ein Bereich benötigt Aufmerksamkeit');
}

function applyRefreshError(error){
  lastError=String(error?.message||error||'Nicht erreichbar');
  healthIndicator('bad','Nicht erreichbar',`Bereitschaftsprüfung fehlgeschlagen: ${lastError}`);
  setText('systemHealthChecked',formatTime(new Date().toISOString()));
  setText('systemHealthHealthy',`Prüfung fehlgeschlagen: ${lastError}`);
}

/** Silent refresh used on normal UI opens. No dialog, no toast on success. */
export async function silentHealthRefresh(){
  healthIndicator('busy','Prüfe …','Bereitschaft wird im Hintergrund geprüft.');
  let result=await getHealthStatus();
  if(!result.ok)result=await getHealthRefresh();
  if(result.ok){
    try{
      const report=validateReport(result.data);
      applyReport(report);
      return report;
    }catch(error){
      applyRefreshError(error);
      return null;
    }
  }
  applyRefreshError({message:result.message});
  return null;
}

/** Full staged readiness review with dialog feedback. */
async function run(){
  prepare();
  startSyncFeedback();
  const issues=[];
  const dialog=byId('startupDialog');
  if(dialog&&!dialog.open){
    opener=document.activeElement;
    try{dialog.showModal()}catch{/* dialog unavailable */}
  }
  healthIndicator('busy','Prüfe …','Bereitschaftsprüfung läuft.');
  try{
    const background=[];
    let status=await apiStatus();
    progress(1,'Schutzrichtlinie prüfen');
    paint('policy','running','Konfigurierter Schutzmodus wird gelesen.');
    if(status.protectionHealth!=='VERIFIED'){
      const reconcile=post('/api/v1/mhx/policy/reconcile',{},240000).catch(()=>{});
      const settled=await Promise.race([
        reconcile.then(()=>true),
        new Promise(resolve=>setTimeout(()=>resolve(false),3000)),
      ]);
      if(!settled)background.push('Schutzrichtlinie');
      status=await apiStatus();
    }
    paint('policy',status.protectionHealth==='VERIFIED'?'healthy':'attention',status.protectionHealth==='VERIFIED'?'Konfigurierter Schutzmodus ist verifiziert.':'Richtlinie wird im Hintergrund abgeglichen.');
    progress(2,'Threat Intelligence und Firewallregeln prüfen');
    paint('intelligence','running','Lokale Datenbasis und Feed-Aktualität werden gelesen.');
    paint('enforcement','running','Aktive Regelgeneration wird mit der Datenbasis verglichen.');
    status=await apiStatus();
    const ti=status.threatIntelligence||{};
    const te=status.threatEnforcement||{};
    const feedsCurrent=ti.state==='CURRENT'&&ti.indicators>0&&ti.blockingFeedsReady===ti.blockingFeedsTotal&&ti.blockingFeedsTotal>0;
    const rulesCurrent=te.state==='VERIFIED'&&Boolean(te.activeGenerationSha256)&&te.activeGenerationSha256===ti.enforcementGenerationSha256;
    if(!feedsCurrent||!rulesCurrent){
      background.push('Threat-Intelligence-Synchronisation');
      void post('/api/v1/mhx/feeds/sync',{},660000).catch(()=>{});
    }
    progress(3,'Windows-Schutzbereiche und Evidenzkette lesen');
    for(const [id,row]of rows)if(row.item.dataset.state!=='healthy')paint(id,'running','Aktueller Zustand wird gelesen.');
    let result=await getHealthStatus();
    if(!result.ok)result=await post('/api/v1/health/refresh',{},130000);
    const report=validateReport(result.data??result);
    for(const check of report.checks)paint(check.id,check.state,check.detail);
    progress(4,'Prüfung abgeschlossen · '+new Date(report.checkedUtc).toLocaleTimeString(locale()));
    applyReport(report);
    const ready=report.healthy;
    const attention=report.checks.filter(check=>check.state!=='healthy').map(check=>check.label);
    setText('startupTitle',ready?'GeDefense ist bereit':'Einige Bereiche benötigen Aufmerksamkeit');
    setText('startupSummary',ready
      ?(background.length?`Lokale Schutzbereiche sind bereit. ${background.join(' und ')} läuft im Hintergrund weiter.`:'Alle geprüften Schutzbereiche sind bereit. Der konfigurierte Schutzmodus ist verifiziert.')
      :(issues.length?issues.join(' · '):`Noch nicht bereit: ${attention.join(', ')}. Hinweise prüfen und die Bereitschaft erneut messen.`));
    const retry=byId('startupRetry');
    if(retry)retry.hidden=ready;
    await acknowledgeGate();
    return report;
  }catch(error){
    for(const [id,row]of rows)if(['pending','running'].includes(row.item.dataset.state))paint(id,'attention','Prüfung nicht abgeschlossen. Erneut versuchen.');
    setText('startupTitle','Startcheck konnte nicht abgeschlossen werden');
    setText('startupSummary',error.name==='TimeoutError'?'Zeitlimit erreicht. Dienst und Verbindung prüfen und erneut versuchen.':String(error.message||'Lokaler GeDefense-Dienst nicht erreichbar.'));
    setText('startupStage','Prüfung unterbrochen');
    const retry=byId('startupRetry');
    if(retry)retry.hidden=false;
    applyRefreshError(error);
    return null;
  }finally{
    stopSyncFeedback();
    const close=byId('startupClose');
    if(close)close.textContent='Zum Security Center';
    healthIndicator(lastError?'bad':lastReport?.healthy?'good':'warn',lastError?'Nicht erreichbar':lastReport?.healthy?'Bereit':'Prüfen',lastError?lastError:'Bereitschaftsprüfung abgeschlossen.');
  }
}

async function acknowledgeGate(){
  if(!startupGate?.required||ackSent)return;
  ackSent=true;
  const result=await acknowledgeStartup();
  if(result.ok)startupGate=result.data;
  else if(!result.unavailable){
    /* The review is complete but the server rejected the acknowledgement; the
       next open will ask again. */
  }
}

async function apiStatus(){
  return api('/api/v1/mhx/status',{signal:AbortSignal.timeout(20000)});
}

async function post(path,body,timeoutMs){
  return api(path,{method:'POST',json:body,signal:AbortSignal.timeout(timeoutMs)});
}

/** Manual readiness review (topbar / system page). Always shows the dialog. */
export function startHealthCheck(){
  if(currentRun)return currentRun;
  currentRun=run().finally(()=>{currentRun=null});
  return currentRun;
}

/** Startup gate: show the dialog only when the server requires a review. */
export async function initializeStartup(){
  prepare();
  let gateResult;
  try{
    gateResult=await getStartupState(AbortSignal.timeout(8000));
  }catch{
    gateResult={ok:false,unavailable:true,status:0,message:'Startup-Status nicht erreichbar'};
  }
  gateChecked.checked=true;
  if(gateResult.ok&&gateResult.data&&gateResult.data.required===true){
    startupGate=gateResult.data;
    gateChecked.required=true;
    gateChecked.reason=String(gateResult.data.reason||'');
    gateChecked.unavailable=false;
    if(!currentRun)currentRun=run().finally(()=>{currentRun=null});
    return {shown:true,gate:gateResult.data};
  }
  startupGate=gateResult.ok?gateResult.data:null;
  gateChecked.required=false;
  gateChecked.reason=String(gateResult.data?.reason||'');
  gateChecked.unavailable=!gateResult.ok;
  if(gateResult.ok&&gateResult.data?.reason)healthIndicator('good','Bereit','Startup-Review nicht erforderlich.');
  else if(!gateResult.ok)healthIndicator('warn','Bereitschaft','Startup-Status nicht verfügbar – keine automatische Anzeige.');
  void silentHealthRefresh();
  return {shown:false,gate:startupGate};
}

export function startupGateState(){return {...gateChecked}}
export function lastHealthReport(){return {report:lastReport,error:lastError,refreshedUtc:lastRefreshUtc}}
export function showReadinessDialog(){
  const dialog=byId('startupDialog');
  if(!dialog)return;
  try{if(!dialog.open)dialog.showModal()}catch{return}
}

byId('startupRetry')?.addEventListener('click',()=>{void startHealthCheck()});
byId('startupClose')?.addEventListener('click',()=>byId('startupDialog')?.close());
byId('startupDialog')?.addEventListener('close',()=>{if(opener instanceof HTMLElement&&opener.isConnected)opener.focus({preventScroll:true})});

export function bindHealthRefreshButton(){
  const button=byId('healthRefreshButton');
  if(!button||button.dataset.bound==='true')return;
  button.dataset.bound='true';
  button.addEventListener('click',()=>{void startHealthCheck()});
}

export function ensureHealthIndicator(){
  if(lastReport)applyReport(lastReport);
  else if(lastError)applyRefreshError({message:lastError});
  else healthIndicator('warn','Bereitschaft','Bereitschaftsprüfung öffnen');
}
