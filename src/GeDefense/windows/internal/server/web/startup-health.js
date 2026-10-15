// STATUS: PLATIN
'use strict';
import {api} from './api.js';
import {byId} from './dom.js';

const definitions=[
 ['policy','Schutzrichtlinie'],['defender','Microsoft Defender'],
 ['firewall','Windows Firewall'],['telemetry','Prozess- und Netzwerk-Telemetrie'],
 ['intelligence','Threat Intelligence'],['enforcement','Threat-IP-Firewallregeln'],
 ['evidence','Evidenz und Audit-Kette']
];
const states={pending:'Wartet',running:'Prüfung läuft',healthy:'Bereit',attention:'Prüfen'};
let currentRun=null;
let opener=null;
const rows=new Map();

function paint(id,state,detail){
 const row=rows.get(id);
 if(!row)return;
 row.item.dataset.state=state;
 row.state.textContent=states[state];
 row.detail.textContent=detail;
}
function progress(value,text){
 byId('startupProgress').value=value;
 byId('startupStage').textContent=text;
 byId('startupCount').textContent=value+' / 4';
}
function prepare(){
 const list=byId('startupChecks');
 list.replaceChildren();
 rows.clear();
 for(const [id,label]of definitions){
  const item=document.createElement('li');
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
 byId('startupTitle').textContent='GeDefense wird vorbereitet';
 byId('startupSummary').textContent='Lokale Schutzbereiche synchronisieren und ihre Bereitschaft bestätigen. Das kann einige Minuten dauern.';
 byId('startupRetry').hidden=true;
 byId('startupClose').textContent='Im Hintergrund fortsetzen';
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
async function run(){
 prepare();
 const issues=[];
 try{
  let status=await api('/api/v1/mhx/status',{signal:AbortSignal.timeout(20000)});
  progress(1,'Schutzrichtlinie synchronisieren');
  paint('policy','running','Konfigurierter Schutzmodus wird abgeglichen.');
  if(status.protectionHealth!=='VERIFIED'){
   try{await api('/api/v1/mhx/policy/reconcile',{method:'POST',json:{},signal:AbortSignal.timeout(240000)})}
   catch(error){if(error.status===401)throw error;issues.push('Richtlinie: '+error.message)}
  }
  status=await api('/api/v1/mhx/status',{signal:AbortSignal.timeout(20000)});
  paint('policy',status.protectionHealth==='VERIFIED'?'healthy':'attention',status.protectionHealth==='VERIFIED'?'Konfigurierter Schutzmodus ist verifiziert.':'Richtlinie nicht verifiziert. Hinweise nach Abschluss prüfen.');
  progress(2,'Threat Intelligence und Firewallregeln abgleichen');
  paint('intelligence','running','Lokale Datenbasis und Feed-Aktualität werden geprüft.');
  paint('enforcement','running','Aktive Regelgeneration wird mit der Datenbasis abgeglichen.');
  status=await api('/api/v1/mhx/status',{signal:AbortSignal.timeout(20000)});
  const ti=status.threatIntelligence||{};
  const te=status.threatEnforcement||{};
  const feedsCurrent=ti.state==='CURRENT'&&ti.indicators>0&&ti.blockingFeedsReady===ti.blockingFeedsTotal&&ti.blockingFeedsTotal>0;
  const rulesCurrent=te.state==='VERIFIED'&&Boolean(te.activeGenerationSha256)&&te.activeGenerationSha256===ti.enforcementGenerationSha256;
  if(!feedsCurrent||!rulesCurrent){
   try{await api('/api/v1/mhx/feeds/sync',{method:'POST',json:{},signal:AbortSignal.timeout(660000)})}
   catch(error){if(error.status===401)throw error;issues.push('Threat Intelligence: '+error.message)}
  }
  progress(3,'Windows-Schutzbereiche und Evidenzkette verifizieren');
  for(const [id,row]of rows)if(row.item.dataset.state!=='healthy')paint(id,'running','Aktueller Zustand wird gemessen.');
  const report=validateReport(await api('/api/v1/health/refresh',{method:'POST',json:{},signal:AbortSignal.timeout(130000)}));
  for(const check of report.checks)paint(check.id,check.state,check.detail);
  progress(4,'Prüfung abgeschlossen · '+new Date(report.checkedUtc).toLocaleTimeString('de-DE'));
  const ready=report.healthy;
  byId('startupTitle').textContent=ready?'GeDefense ist bereit':'Einige Bereiche benötigen Aufmerksamkeit';
  byId('startupSummary').textContent=ready?'Alle geprüften Schutzbereiche sind bereit. Der konfigurierte Schutzmodus ist verifiziert.':(issues.length?issues.join(' · '):'Die markierten Bereiche sind noch nicht bereit. Hinweise prüfen und die Synchronisierung erneut starten.');
  byId('startupRetry').hidden=ready;
 }catch(error){
  for(const [id,row]of rows)if(['pending','running'].includes(row.item.dataset.state))paint(id,'attention','Prüfung nicht abgeschlossen. Erneut versuchen.');
  byId('startupTitle').textContent='Startcheck konnte nicht abgeschlossen werden';
  byId('startupSummary').textContent=error.name==='TimeoutError'?'Zeitlimit erreicht. Dienst und Verbindung prüfen und erneut versuchen.':String(error.message||'Lokaler GeDefense-Dienst nicht erreichbar.');
  byId('startupStage').textContent='Prüfung unterbrochen';
  byId('startupRetry').hidden=false;
 }finally{
  byId('startupClose').textContent='Zum Security Center';
 }
}
export function startHealthCheck(){
 const dialog=byId('startupDialog');
 if(!dialog.open){opener=document.activeElement;dialog.showModal()}
 if(currentRun)return currentRun;
 currentRun=run().finally(()=>{currentRun=null});
 return currentRun;
}
byId('startupRetry').addEventListener('click',()=>{void startHealthCheck()});
byId('startupClose').addEventListener('click',()=>byId('startupDialog').close());
byId('startupDialog').addEventListener('close',()=>{if(opener instanceof HTMLElement&&opener.isConnected)opener.focus()});
