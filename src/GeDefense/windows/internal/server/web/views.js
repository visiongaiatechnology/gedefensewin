// STATUS: DIAMANT VGT SUPREME
'use strict';
/** GeDefense Windows Beta V5 view controllers.
 *
 *  Every endpoint is treated as fallible: pages render their catalogue and
 *  honest unavailable states first, then enrich with live data. No value is
 *  fabricated and no blocked page is left blank.
 */
import {startOverviewThreatMap} from './overview-map.js';
import {updateGeoMap} from './geo-map-windows.js';
import {
  activateHardeningComponent as activateHardeningComponentRequest,
  api,
  applyHardeningProfile,
  getEvidencePage,
  getEvidenceSnapshot,
  getHardeningCatalog,
  getHardeningComponents,
  getProtectedNetworks,
  getThreatIntelStatus,
  rollbackHardening,
  saveHardeningSettings,
  setIntegrityConfiguration,
  setProtectedNetworks,
} from './api.js';
import {
  byId, clear, emptyRow, emptyState, formatBytes, formatNumber, formatPercent, formatTime,
  metric, node, pill, requestConfirm, requestReason, severity, setPill, setText, toast,
} from './dom.js';
import {HARDENING_CATALOG, mergeHardeningCatalog} from './hardening-catalog.js';
import {
  loadProtection as loadProtectionPage,
  selectProtectionMode,
  showReadiness,
} from './protection.js';
import {
  bindKineticSettingsPanel,
  bindMhxSettingsPanel,
  bindThreatIntelSettingsPanel,
  loadFeedPolicyPanel,
  loadKineticSettingsPanel,
  loadMhxApplicationDenies,
  loadMhxApplications,
  loadMhxSettingsPanel,
  loadThreatIntelSettingsPanel,
  renderSettingsBadge,
} from './settings.js';

let lastStatus=null;
let lastIntegrity=null;
const trafficSeries=[];

const modeLabel={monitor:'MONITOR',guarded:'GUARDED',sovereign:'SOVEREIGN'};
const modeTone=mode=>mode==='sovereign'?'bad':mode==='guarded'?'good':'warn';

const hardeningState={
  catalog:[],
  filter:'ALL',
  componentsLoaded:false,
  catalogLive:false,
  lastCheckedUtc:'',
  loading:false,
  detailId:'',
  detailConfig:{},
};

const auditState={running:false,result:null,startedAt:0,timer:null,lastRunUtc:''};

const evidenceState={offset:0,limit:20,total:0,loaded:false,fallback:false,loading:false};

const tiState={nextSyncUtc:'',intervalMinutes:null};

const analysisState={items:[],page:0,pageSize:20};

function boolCount(values){return values.filter(Boolean).length}

function listFrom(value){return Array.isArray(value)?value:[]}

function setAttributeSafe(element,name,value){
  if(element&&typeof element.setAttribute==='function')element.setAttribute(name,value);
}

/* ------------------------------------------------------------------ */
/* Overview                                                            */
/* ------------------------------------------------------------------ */
function renderTraffic(sample){
  const state=sample?.state||'UNAVAILABLE';
  setText('trafficState',state);
  setPill('trafficState',state,state==='LIVE'?'good':'warn');
  setText('trafficDescription',state==='LIVE'?'Native Netzwerkadapter-Durchsatzwerte (RX/TX)':state==='WARMING_UP'?'Messung läuft an, bitte zwei Sekunden warten':'Keine verlässlichen Netzwerkadapter-Zähler verfügbar');
  setText('trafficRx',state==='LIVE'?`${formatBytes(sample.receivedBytesPerSec)}/s`:'--');
  setText('trafficTx',state==='LIVE'?`${formatBytes(sample.sentBytesPerSec)}/s`:'--');
  const rxPath=byId('trafficRxPath');
  const txPath=byId('trafficTxPath');
  if(state!=='LIVE'){
    trafficSeries.length=0;
    setAttributeSafe(rxPath,'d','');
    setAttributeSafe(txPath,'d','');
    return;
  }
  const timestamp=new Date(sample.observedUtc).getTime();
  if(!Number.isFinite(timestamp))return;
  if(trafficSeries.length&&timestamp<=trafficSeries.at(-1).t)return;
  trafficSeries.push({t:timestamp,rx:Number(sample.receivedBytesPerSec)||0,tx:Number(sample.sentBytesPerSec)||0});
  if(trafficSeries.length>60)trafficSeries.shift();
  const peak=Math.max(1024,...trafficSeries.map(entry=>Math.max(entry.rx,entry.tx)));
  const count=trafficSeries.length;
  const pointY=value=>Math.round(158-(value/peak)*142);
  if(count===1){
    /* A single live sample still reads as a full-width level line. */
    setAttributeSafe(rxPath,'d',`M12,${pointY(trafficSeries[0].rx)} L628,${pointY(trafficSeries[0].rx)}`);
    setAttributeSafe(txPath,'d',`M12,${pointY(trafficSeries[0].tx)} L628,${pointY(trafficSeries[0].tx)}`);
    return;
  }
  const trace=key=>trafficSeries.map((value,index)=>{
    const x=Math.round(12+(index/(count-1))*616);
    return `${index?'L':'M'}${x},${pointY(value[key])}`;
  }).join(' ');
  setAttributeSafe(rxPath,'d',trace('rx'));
  setAttributeSafe(txPath,'d',trace('tx'));
}

export function renderKinetic(status){
  const kinetic=status?.kinetic||{};
  const readiness=status?.kineticReadiness||{};
  const armed=Boolean(status?.kineticArmed);
  const verified=readiness.threatRules==='GENERATION_VERIFIED';
  const effective=armed&&verified&&readiness.wfpAudit==='BLOCK_EVENTS_OBSERVED';
  setText('kineticState',effective?'ARMED · WFP CORRELATED':armed?'ARMED · DEGRADED':'OBSERVE ONLY');
  setPill('kineticState',effective?'ARMED · WFP CORRELATED':armed?'ARMED · DEGRADED':'OBSERVE ONLY',effective?'good':'warn');
  setText('kineticTitle',effective?'Threat-IP-Korrelation scharf':armed?'Korrelation angefordert, Durchsetzung nicht bestätigt':'Beobachtungsmodus');
  setText('kineticExplanation',armed?'Kinetic korreliert Burst-Signale mit Threat-IP-Feeds. Als blockiert gelten ausschließlich tatsächlich beobachtete, unserer WFP-Regelgeneration zugeordnete Sperren.':'Kinetic erkennt auffällige WFP-Sperrhaufen ohne neue Firewall-Regeln zu installieren.');
  setText('kineticCoverage',`Audit: ${readiness.wfpAudit||'UNVERIFIED'} · TI-WFP: ${readiness.threatRules||'UNVERIFIED'}`);
  const timeline=clear('kineticTimeline');
  if(timeline){
    for(const incident of [...(Array.isArray(status.kineticIncidents)?status.kineticIncidents:[])].reverse()){
      const card=node('div','kinetic-incident');
      const headline=node('strong','',`${incident.threatMatched?'THREAT-IP · ':'BEOBACHTUNG · '}${incident.remoteIp||'unbekannt'}:${incident.localPort||'—'}`);
      const detail=node('small','',`${formatTime(incident.timestampUtc)} · ${incident.classification||'BURST'} · ${Array.isArray(incident.threatSources)?incident.threatSources.join(', '):''}`);
      const tag=pill(incident.verifiedWfpBlock?'WFP BLOCK BEOBACHTET':incident.threatMatched?'FEED MATCH':'SIGNAL',incident.verifiedWfpBlock?'good':incident.threatMatched?'warn':'info');
      card.append(headline,detail,tag);
      timeline.append(card);
    }
    if(!timeline.children.length){
      timeline.className='story-list empty-state';
      timeline.textContent=`Noch keine Bursts: ${formatNumber(kinetic.blocksObserved)} eingehende WFP-Sperren wurden beobachtet. Ein Burst benötigt mindestens 12 Ereignisse in 10 Sekunden an 3 Ports. Quellen erscheinen unabhängig davon auf der Karte.`;
    }else{
      timeline.className='story-list';
    }
  }
  const armButton=byId('kineticArm');
  if(armButton){armButton.disabled=armed;armButton.title=armed?'Bereits aktiviert':''}
  const disarmButton=byId('kineticDisarm');
  if(disarmButton)disarmButton.disabled=!armed;
  const metrics=clear('kineticMetrics');
  if(metrics)metrics.append(
    metric('WFP BLOCKS',formatNumber(kinetic.blocksObserved),'eingehend, 5157 · auch ohne Port'),
    metric('BURST-KANDIDATEN',formatNumber(kinetic.burstCandidates),'noch kein Beweis eines Angriffs'),
    metric('THREAT-IP KORRELATIONEN',formatNumber(status.kineticThreatCorrelations),'Feed-Match zu Burst'),
    metric('VERIFIZIERTE WFP BLOCKS',formatNumber(status.kineticBlockedCorrelations),'bereits durch Windows blockiert'),
    metric('TRACKED SOURCES',formatNumber(kinetic.trackedSources),`${kinetic.capacity||2048} maximal`),
  );
}

export async function loadTraffic(){
  const status=await api('/api/v1/mhx/status');
  renderTraffic(status.traffic);
}

export async function loadKinetic(options={}){
  const results=await Promise.allSettled([api('/api/v1/mhx/status'),api('/api/v1/mhx/geo')]);
  if(results[0].status==='fulfilled'){
    renderKinetic(results[0].value);
    if(options.includeSettings!==false){
      void loadKineticSettingsPanel(results[0].value);
      bindKineticSettingsPanel();
    }
  }else{
    setText('kineticCoverage','Kinetic-Telemetrie nicht abrufbar. Erneuter Abruf folgt.');
    throw results[0].reason;
  }
  if(results[1].status==='fulfilled')updateGeoMap(results[1].value);
  else setText('kineticGeoSummary','GeoIP-Daten nicht abrufbar. Kinetic-Status bleibt unabhängig sichtbar.');
}

export async function setKineticMode(mode,reason){
  await api('/api/v1/mhx/kinetic/mode',{method:'POST',json:{mode,reason,confirmation:mode==='armed'?'ARM KINETIC TI':'DISARM KINETIC'}});
  toast(mode==='armed'?'Kinetic-Korrelation scharfgeschaltet.':'Kinetic zurück auf Observe-Only.','good');
  await loadKinetic();
}

export async function loadOverview(){
  startOverviewThreatMap();
  const [status,stories]=await Promise.allSettled([api('/api/v1/status'),api('/api/v1/mhx/stories?limit=6')]);
  if(status.status!=='fulfilled')throw status.reason;
  lastStatus=status.value;
  renderStatus(status.value);
  renderStories('overviewStories',stories.status==='fulfilled'?stories.value:[]);
}

export function renderStatus(status){
  lastStatus=status;
  const protection=status?.protection||{};
  const mhx=status?.mhx||{};
  const ti=mhx.threatIntelligence||{};
  const enforcement=mhx.threatEnforcement||{};
  const tiVerified=(enforcement.state==='VERIFIED'||enforcement.state==='VERIFIED_CLEANUP_PENDING')&&Boolean(enforcement.activeGenerationSha256)&&enforcement.activeGenerationSha256===ti.enforcementGenerationSha256;
  const controls=[
    ['Defender',protection.Defender&&protection.DefenderService],['Realtime',protection.RealTimeProtection],
    ['Behavior',protection.BehaviorProtection],['Cloud',protection.CloudProtection],
    ['Network',protection.NetworkProtection],['Tamper',protection.TamperProtection],
    ['Firewall',protection.Firewall],['Secure Boot',protection.SecureBoot],['TPM',protection.Tpm],
    ['BitLocker',protection.BitLocker],['VBS',protection.Vbs],['Credential Guard',protection.CredentialGuard],
    ['Memory Integrity',protection.MemoryIntegrity],['LSASS PPL',protection.LsaProtection],
    ['Windows Update',protection.WindowsUpdate],
  ];
  const active=boolCount(controls.map(item=>item[1]));
  const score=Math.round((active/controls.length)*100);
  setText('postureScore',score);
  setText('anchorCount',`${active}/${controls.length}`);
  setText('postureCoverage',`${active}/${controls.length}`);
  setText('mhxEvents',formatNumber(mhx.eventsEvaluated));
  setText('mhxBlocked',formatNumber(mhx.eventsBlocked));
  setText('wfpBlocks',formatNumber(mhx.wfpBlockedEvents));
  setText('networkHits',formatNumber(mhx.threatNetworkHits));
  setText('storyCount',formatNumber(mhx.attackStories));
  renderTraffic(mhx.traffic);
  const policyVerified=mhx.protectionHealth==='VERIFIED';
  const mode=modeLabel[mhx.protectionMode]||String(mhx.protectionMode||'---').toUpperCase();
  setText('overviewMode',`${mode} · ${mhx.realtime&&policyVerified?'Prozessschutz verifiziert':mhx.protectionHealth==='STARTING'?'Initialisierung läuft':mhx.realtime?'Policy degraded':'Realtime degraded'}`);
  setText('postureMode',mode);
  setText('posturePolicy',String(mhx.protectionHealth||'STARTING'));
  const meter=byId('postureMeterFill');
  if(meter)meter.style.width=`${Math.max(0,Math.min(100,score))}%`;
  const postureBadge=byId('postureBadge');
  if(postureBadge){
    postureBadge.textContent=tiVerified?'VERIFIZIERT':policyVerified?'PRÜFEN':'DEGRADED';
    postureBadge.className=`status-pill ${tiVerified?'good':policyVerified?'warn':'bad'}`;
  }
  const overview=clear('overviewMetrics');
  if(overview)overview.append(
    metric('SCHUTZMODUS',mode,mhx.enforcement||'',mhx.protectionMode==='monitor'?'warn':'good'),
    metric('REALTIME',mhx.realtime?'ONLINE':'DEGRADED',mhx.telemetry||'',mhx.realtime?'good':'bad'),
    metric('POLICY',mhx.protectionHealth||'STARTING',policyVerified&&mhx.protectionVerifiedUtc?`verifiziert ${formatTime(mhx.protectionVerifiedUtc)}`:'serverseitige Verifikation',policyVerified?'good':'bad'),
    metric('THREAT INTEL',formatNumber(ti.indicators),tiVerified?'WFP-Generation verifiziert':`WFP ungeprüft: ${enforcement.state||'UNVERIFIED'}`,tiVerified?'good':'warn'),
    metric('APP CONTROL',mhx.appControl||'---',mhx.kernelEnforcement?'Kernel Enforcement aktiv':'Audit/Guarded',mhx.kernelEnforcement?'good':'warn'),
  );
  const domains=[
    ['ENDPOINT',[protection.Defender&&protection.DefenderService,protection.RealTimeProtection,protection.BehaviorProtection,protection.CloudProtection,protection.TamperProtection]],
    ['NETZWERK',[protection.NetworkProtection,protection.Firewall,tiVerified]],
    ['PLATTFORM',[protection.SecureBoot,protection.Tpm,protection.BitLocker,protection.Vbs,protection.CredentialGuard,protection.MemoryIntegrity]],
    ['REAKTION',[mhx.realtime,mhx.protectionMode!=='monitor',protection.AsrBlockRules>0,protection.ControlledFolderAccess]],
  ];
  const bars=clear('domainBars');
  if(bars)for(const [domain,values]of domains)bars.append(barNode(domain,boolCount(values),values.length));
  const wfpHealth=mhx.wfpBlockTelemetry||'DEGRADED';
  const netHealth=mhx.networkTelemetry||'DEGRADED';
  const generationHealth=tiVerified?'verifiziert':`${enforcement.state||'UNVERIFIED'}${enforcement.error?` (${enforcement.error})`:''}`;
  setText('telemetryHealth',`TCP: ${netHealth} · WFP-Audit: ${wfpHealth} · Feed-Blockregeln: ${generationHealth}`);
  setPill('realtimeBadge',mhx.realtime?'PROZESS-TELEMETRIE ONLINE':'PROZESS-TELEMETRIE DEGRADED',mhx.realtime?'good':'bad');
  const fabricHealthy=Boolean(mhx.realtime)&&policyVerified;
  const verifiedForOverall=fabricHealthy&&(!Number(ti.blockingIndicators)||tiVerified);
  setText('sideState',verifiedForOverall?'MASTER CONTROL ONLINE':mhx.realtime&&policyVerified?'ENDPOINT ONLINE // WFP UNVERIFIED':mhx.protectionHealth==='STARTING'?'SCHUTZ WIRD VORBEREITET':mhx.realtime?'PROTECTION DEGRADED':'TELEMETRIE DEGRADED');
  setText('sideDetail',`${mode} · ${status.platform||'Windows'}`);
  setText('sideVersion',`VERSION ${status.version||'—'} · LOKAL`);
  const pulse=byId('sidePulse');
  if(pulse)pulse.dataset.state=verifiedForOverall?'good':fabricHealthy?'warn':'bad';
  const globalMode=byId('globalMode');
  if(globalMode){
    globalMode.textContent=mode;
    globalMode.className=`status-pill ${modeTone(mhx.protectionMode)}`;
  }
  setText('systemVersion',status.version);
  setText('systemPlatform',status.platform);
  setText('systemTelemetry',mhx.telemetry);
  setText('systemNetwork',mhx.networkTelemetry);
  setText('systemAppControl',mhx.appControl);
  setText('systemProtectionHealth',mhx.protectionHealth||'---');
  const titlePulse=byId('titlePulseBadge');
  if(titlePulse){
    const modeString=mode;
    titlePulse.textContent=verifiedForOverall?`${modeString} // OPTIMAL`:fabricHealthy&&Number(ti.blockingIndicators)?`${modeString} // WFP UNVERIFIED`:mhx.realtime?`${modeString} // DEGRADED`:'OFFLINE';
    titlePulse.style.color=verifiedForOverall?'#31d0aa':mhx.realtime?'#ffb340':'#ff4772';
    titlePulse.style.borderColor=verifiedForOverall?'rgba(49,208,170,.35)':mhx.realtime?'rgba(255,179,64,.35)':'rgba(255,71,114,.35)';
  }
}

function barNode(label,active,total){
  const wrap=node('div');
  const head=node('div','bar-head');
  const percent=total>0?Math.round((active/total)*100):0;
  head.append(node('span','',label),node('strong','',`${percent}%`));
  const track=node('div','bar-track');
  const fill=node('div','bar-fill');
  fill.style.width=`${percent}%`;
  track.append(fill);
  wrap.append(head,track);
  return wrap;
}

/* ------------------------------------------------------------------ */
/* Protection Center                                                   */
/* ------------------------------------------------------------------ */
export async function loadProtection(){
  const status=await api('/api/v1/status');
  renderStatus(status);
  await loadProtectionPage(status,{onRefresh:loadProtection});
}

export async function reconcilePolicy(){
  const result=await api('/api/v1/mhx/policy/reconcile',{method:'POST',json:{}});
  toast('Policy erfolgreich synchronisiert und verifiziert.','good');
  await loadProtection();
  return result;
}

export async function setProtectionMode(target,reason){
  const confirmations={monitor:'RETURN TO MONITOR',guarded:'ACTIVATE GUARDED',sovereign:'SOVEREIGN DEFAULT DENY'};
  const result=await api('/api/v1/mhx/mode',{method:'POST',json:{mode:target,confirmation:confirmations[target],reason}});
  toast(`Schutzmodus ${modeLabel[target]} ist aktiv.`,'good');
  await loadProtection();
  return result;
}

export {selectProtectionMode as chooseProtectionMode,showReadiness as readiness};

/* ------------------------------------------------------------------ */
/* XDR                                                                 */
/* ------------------------------------------------------------------ */
export async function loadXdr(options={}){
  const [status,analyses,stories,deep]=await Promise.allSettled([
    api('/api/v1/mhx/status'),
    api('/api/v1/mhx/analyses?limit=500'),
    api('/api/v1/mhx/stories?limit=100'),
    api('/api/v1/xdr/findings'),
  ]);
  if(status.status==='fulfilled'){
    renderXdrMetrics(status.value);
    settingsPanelReady();
    bindMhxSettingsPanel();
    if(options.includeSettings!==false){
      void loadMhxSettingsPanel({includeApplications:false});
      void loadMhxApplications();
      void loadMhxApplicationDenies();
    }
  }else{
    renderXdrStatusUnavailable(status.reason?.message||'Control Plane nicht erreichbar');
  }
  analysisState.page=0;
  if(analyses.status==='fulfilled')renderAnalyses(analyses.value);
  else renderAnalyses([],'Realtime-Analysen nicht abrufbar.');
  if(stories.status==='fulfilled')renderStories('attackStories',stories.value);
  else renderStories('attackStories',[]);
  if(deep.status==='fulfilled')renderDeepXdr(deep.value);
  else clearTable('xdrRows',5,'Forensische Findings nicht abrufbar.');
}

function settingsPanelReady(){renderSettingsBadge('mhxSettingsBadge')}

function displayToken(value){
  return String(value??'---').replace(/_/g,' ');
}

function xdrStatusRow(label,detail,value,valueDetail,tone){
  const row=node('div','xdr-status-row');
  const labelNode=node('div','xdr-status-label');
  labelNode.append(node('span','',label));
  if(detail)labelNode.append(node('small','',detail));
  const valueNode=node('div','xdr-status-value');
  if(tone)valueNode.dataset.tone=tone;
  valueNode.append(node('span','',value));
  if(valueDetail)valueNode.append(node('small','',valueDetail));
  row.append(labelNode,valueNode);
  return row;
}

function xdrStatusGroup(title,badgeText,badgeTone,rows){
  const group=node('section','xdr-status-group');
  const head=node('header','xdr-status-head');
  head.append(node('strong','',title),pill(badgeText,badgeTone));
  const body=node('div','xdr-status-body');
  for(const row of rows)body.append(row);
  group.append(head,body);
  return group;
}

function renderXdrStatusUnavailable(detail){
  const root=clear('xdrMetrics');
  if(!root)return;
  root.append(xdrStatusGroup('XDR-STATUS','NICHT VERFÜGBAR','bad',[
    xdrStatusRow('Control Plane','Live-Telemetrie nicht erreichbar','Keine Daten',detail,'bad'),
  ]));
}

function renderXdrMetrics(status){
  const ti=status.threatIntelligence||{};
  const enforcement=status.threatEnforcement||{};
  const readiness=status.kineticReadiness||{};
  const kineticArmed=Boolean(status.kineticArmed);
  const kineticEffective=kineticArmed&&readiness.threatRules==='GENERATION_VERIFIED';
  const kineticMode=kineticEffective?'ARMED TI CORRELATION':displayToken(status.kinetic?.mode||readiness.mode||'OBSERVE ONLY');
  const enforcementReady=enforcement.state==='VERIFIED';
  const wfpObserved=String(readiness.wfpAudit||status.wfpBlockTelemetry||'').includes('OBSERVED');
  const tiTone=ti.state==='CURRENT'||ti.state==='CACHED'?'good':ti.state==='STALE'||ti.state==='DEGRADED'?'warn':'bad';
  const feedCoverage=`${formatNumber(ti.blockingFeedsReady)}/${formatNumber(ti.blockingFeedsTotal)} Feeds`;
  const root=clear('xdrMetrics');
  if(!root)return;
  root.append(
    xdrStatusGroup('Enforcement','WFP',enforcementReady?'good':'bad',[
      xdrStatusRow('WFP-Enforcement',enforcement.error||enforcement.mode||'Generation-Verifikation',
        displayToken(enforcement.state||'UNVERIFIED'),
        enforcement.activeGenerationSha256?`Generation ${String(enforcement.activeGenerationSha256).slice(0,12)}…`:'Keine aktive Generation bestätigt',
        enforcementReady?'good':'bad'),
      xdrStatusRow('WFP-Sperrereignisse','Windows-Security-Event 5157',
        formatNumber(status.wfpBlockedEvents),displayToken(status.wfpBlockTelemetry||'---')),
      xdrStatusRow('WFP-Audit','Ereignisabfrage der Control Plane',
        displayToken(readiness.wfpAudit||status.wfpBlockTelemetry||'POLLING'),
        wfpObserved?'Blockereignisse beobachtet':'Audit-Policy nicht bestätigt',
        wfpObserved?'good':'warn'),
    ]),
    xdrStatusGroup('Telemetrie & Kinetic',kineticEffective?'ARMED':'OBSERVE ONLY',kineticEffective?'good':'warn',[
      xdrStatusRow('Kinetic-Korrelation','Burst-Signale × Threat-IP',kineticMode,
        `${formatNumber(status.kinetic?.burstCandidates||0)} Burst-Kandidaten · ${formatNumber(status.kinetic?.trackedSources||0)} Quellen`,
        kineticEffective?'good':'warn'),
      xdrStatusRow('Kinetic × TI','Korrelierte Ingress-Bursts',formatNumber(status.kineticThreatCorrelations),
        `${formatNumber(status.kineticBlockedCorrelations)} bereits durch Windows blockiert`),
      xdrStatusRow('Unkorrelierte TI-Treffer','Feed-Matches ohne gültigen Prozesskontext',formatNumber(status.uncorrelatedThreatHits)),
    ]),
    xdrStatusGroup('Threat Intelligence',feedCoverage,tiTone,[
      xdrStatusRow('Block-Indikatoren','Feodo + Spamhaus nach Protected-Subtraktion',formatNumber(ti.blockingIndicators)),
      xdrStatusRow('Korrelationsindikatoren','5 Intelligenz-Feeds',formatNumber(ti.correlationIndicators)),
      xdrStatusRow('Geschützte Prefixe','Management-Safety-Plane',formatNumber(ti.protectedPrefixes),
        ti.state?`Feed-Status ${displayToken(ti.state)}`:'Feed-Status unbekannt',tiTone),
    ]),
  );
}

function renderStories(id,stories){
  const root=clear(id);
  if(!root)return;
  if(!Array.isArray(stories)||!stories.length){
    root.className='story-list empty-state';
    root.textContent='Noch keine korrelierten Angriffe.';
    return;
  }
  root.className='story-list';
  for(const story of stories){
    const item=node('article','story');
    item.append(severity(story.severity));
    const body=node('div');
    const title=node('strong','',`${story.image||'Prozess'} → ${story.remoteIp||'Netzwerkziel'}`);
    const flow=node('div','story-flow');
    for(const signal of (Array.isArray(story.signals)?story.signals:[]).slice(0,5)){
      if(flow.childElementCount)flow.append(node('i'));
      flow.append(node('span','',signal));
    }
    body.append(title,flow,node('small','',`${formatTime(story.updatedUtc)} · PID ${story.pid||'—'}${story.remotePort?` · Port ${story.remotePort}`:''}`));
    item.append(body,pill(story.response||'CORRELATED',String(story.response||'').includes('HOST_RESPONSE')?'bad':String(story.response||'').includes('BLOCK')?'warn':'info'));
    root.append(item);
  }
}

function renderAnalyses(items,emptyMessage='Noch keine Realtime-Analysen.'){
  analysisState.items=Array.isArray(items)?items:[];
  const pages=Math.max(1,Math.ceil(analysisState.items.length/analysisState.pageSize));
  if(analysisState.page>pages-1)analysisState.page=pages-1;
  if(analysisState.page<0)analysisState.page=0;
  const body=clear('analysisRows');
  if(body){
    const total=analysisState.items.length;
    if(!total){
      body.append(emptyRow(6,emptyMessage));
    }else{
      const start=analysisState.page*analysisState.pageSize;
      for(const analysis of analysisState.items.slice(start,start+analysisState.pageSize)){
        const row=node('tr');
        row.append(node('td','',formatTime(analysis.timestampUtc)));
        const sev=node('td');
        sev.append(severity(analysis.effectiveSeverity));
        const signals=(analysis.signalCategories||analysis.signals||[]).slice(0,5).join(', ');
        row.append(sev,node('td','',`${analysis.image||'—'} · PID ${analysis.pid||'—'}`),node('td','',analysis.detection||analysis.classification||'—'),node('td','',signals||'—'));
        const action=node('td');
        action.append(pill(analysis.disposition||'AUDIT',analysis.disposition==='BLOCK'?'bad':analysis.disposition==='ALLOW'?'good':'info'));
        row.append(action);
        body.append(row);
      }
    }
  }
  renderAnalysisPager();
}

function renderAnalysisPager(){
  const total=analysisState.items.length;
  const pages=Math.max(1,Math.ceil(total/analysisState.pageSize));
  const page=Math.min(analysisState.page,pages-1);
  setPill('analysisCount',total?`${formatNumber(total)} EINTRÄGE`:'KEINE EINTRÄGE',total?'info':'warn');
  const info=byId('analysisPageInfo');
  if(info){
    const start=page*analysisState.pageSize+1;
    const end=Math.min((page+1)*analysisState.pageSize,total);
    info.textContent=total
      ?`Seite ${formatNumber(page+1)} von ${formatNumber(pages)} · Einträge ${formatNumber(start)}–${formatNumber(end)} von ${formatNumber(total)}`
      :'Noch keine Analysen geladen';
  }
  const prev=byId('analysisPrev');
  const next=byId('analysisNext');
  if(prev)prev.disabled=total===0||page<=0;
  if(next)next.disabled=total===0||page>=pages-1;
}

export function analysisPage(direction){
  const pages=Math.max(1,Math.ceil(analysisState.items.length/analysisState.pageSize));
  const nextPage=Math.min(pages-1,Math.max(0,analysisState.page+(Number(direction)||0)));
  if(nextPage===analysisState.page)return;
  analysisState.page=nextPage;
  const body=clear('analysisRows');
  if(body){
    const start=analysisState.page*analysisState.pageSize;
    for(const analysis of analysisState.items.slice(start,start+analysisState.pageSize)){
      const row=node('tr');
      row.append(node('td','',formatTime(analysis.timestampUtc)));
      const sev=node('td');
      sev.append(severity(analysis.effectiveSeverity));
      const signals=(analysis.signalCategories||analysis.signals||[]).slice(0,5).join(', ');
      row.append(sev,node('td','',`${analysis.image||'—'} · PID ${analysis.pid||'—'}`),node('td','',analysis.detection||analysis.classification||'—'),node('td','',signals||'—'));
      const action=node('td');
      action.append(pill(analysis.disposition||'AUDIT',analysis.disposition==='BLOCK'?'bad':analysis.disposition==='ALLOW'?'good':'info'));
      row.append(action);
      body.append(row);
    }
  }
  renderAnalysisPager();
}

function renderDeepXdr(result){
  const body=clear('xdrRows');
  if(!body)return;
  const findings=Array.isArray(result?.Findings)?result.Findings:[];
  if(!findings.length){
    body.append(emptyRow(5,'Keine Findings im letzten Tiefenscan.'));
    return;
  }
  for(const finding of findings){
    const row=node('tr');
    const sev=node('td');
    sev.append(severity(finding.Severity));
    row.append(sev,node('td','',finding.Category||'—'),node('td','',finding.Title||'—'),node('td','',finding.Entity||'—'),node('td','',finding.Evidence||'—'));
    body.append(row);
  }
}

function clearTable(id,columns,message){
  const body=clear(id);
  if(body)body.append(emptyRow(columns,message));
}

export async function runXdr(){
  const button=byId('runXdr');
  if(button){button.disabled=true;button.classList.add('loading');button.textContent='Scan läuft …'}
  try{
    await api('/api/v1/xdr/scan',{method:'POST',json:{}});
    toast('Forensischer XDR-Scan abgeschlossen.','good');
    await loadXdr();
  }finally{
    if(button){button.disabled=false;button.classList.remove('loading');button.textContent='Tiefenscan starten'}
  }
}

export function renderSyncOperation(state,detail){
  const strip=byId('threatIntelOperationStrip');
  if(!strip)return;
  strip.hidden=false;
  setPill('threatIntelOperationState',state,state==='APPLIED'||state==='OK'?'good':state==='FETCHING'||state==='APPLYING'||state==='SYNCING'?'info':state==='PARTIAL'?'warn':'bad');
  setText('threatIntelOperationDetail',detail);
}

export async function syncFeeds(){
  const button=byId('syncFeeds');
  const dialog=byId('syncDialog');
  const closeButton=byId('syncDialogClose');
  const progressBar=byId('syncDialogProgressBar');
  if(button){button.disabled=true;button.classList.add('loading');button.textContent='Synchronisiere …'}
  if(closeButton)closeButton.disabled=true;
  if(progressBar)progressBar.style.width='8%';
  setText('syncDialogTitle','Threat Intelligence Synchronisation');
  setText('syncDialogStatusText','Feeds werden abgerufen und WFP-Blockregeln kompiliert …');
  setText('syncDialogDetails','Verbindung zu den lokalen Threat-Intelligence-Quellen wird aufgebaut.');
  try{if(dialog&&!dialog.open)dialog.showModal()}catch{/* dialog unavailable */}
  renderSyncOperation('SYNCING','Feeds werden abgerufen und WFP-Regeln kompiliert …');
  toast('Threat Intelligence wird synchronisiert …','info');
  try{
    if(progressBar)progressBar.style.width='35%';
    const result=await api('/api/v1/mhx/feeds/sync',{method:'POST',json:{}});
    if(progressBar)progressBar.style.width='100%';
    const indicators=Number(result?.indicators||0);
    const blocking=Number(result?.blockingIndicators||0);
    const generation=String(result?.enforcementGenerationSha256||result?.generationSha256||'');
    const generationShort=generation?`${generation.slice(0,16)}…`:'---';
    setText('syncDialogStatusText','Synchronisation und WFP-Enforcement erfolgreich.');
    setText('syncDialogDetails',`Indikatoren: ${formatNumber(indicators)} · WFP-Blockregeln: ${formatNumber(blocking)} · Generation: ${generationShort}`);
    renderSyncOperation('APPLIED',`Synchronisiert: ${formatNumber(indicators)} Indikatoren (${formatNumber(blocking)} Block) · Generation ${generationShort}`);
    toast(`Threat Intelligence synchronisiert (${formatNumber(indicators)} Indikatoren, WFP verifiziert).`,'good');
    await loadThreatIntel();
  }catch(error){
    if(progressBar)progressBar.style.width='100%';
    const message=error.message||String(error);
    setText('syncDialogStatusText','Synchronisation fehlgeschlagen');
    setText('syncDialogDetails',`Fehler: ${message}`);
    renderSyncOperation('ERROR',message);
    toast(`Synchronisation fehlgeschlagen: ${message}`,'bad');
    await loadThreatIntel().catch(()=>{});
  }finally{
    if(closeButton)closeButton.disabled=false;
    if(button){button.disabled=false;button.classList.remove('loading');button.textContent='Jetzt synchronisieren'}
  }
}

/* ------------------------------------------------------------------ */
/* Shell status                                                        */
/* ------------------------------------------------------------------ */
export async function loadShellStatus(){
  try{
    const status=await api('/api/v1/status');
    renderStatus(status);
    return status;
  }catch(error){
    if(error?.status===401)throw error;
    return null;
  }
}

/* ------------------------------------------------------------------ */
/* Network                                                             */
/* ------------------------------------------------------------------ */
export async function loadNetwork(){
  const [status,findings]=await Promise.allSettled([api('/api/v1/mhx/status'),api('/api/v1/mhx/network?limit=250')]);
  const metrics=clear('networkMetrics');
  if(status.status==='fulfilled'){
    const value=status.value;
    setPill('networkState',displayToken(value.networkTelemetry||'NATIVE TCP'),'info');
    if(metrics)metrics.append(
      metric('TCP TELEMETRIE',displayToken(value.networkTelemetry||'---'),'Owner PID'),
      metric('WFP BLOCKS',displayToken(value.wfpBlockTelemetry||'---'),`${formatNumber(value.wfpBlockedEvents)} Events`),
      metric('THREAT-IP-TREFFER',formatNumber(value.threatNetworkHits),'Feed-Korrelation'),
      metric('INDIKATOREN',formatNumber(value.threatIntelligence?.indicators),displayToken(value.threatIntelligence?.state||'')),
    );
  }else if(metrics){
    metrics.append(metric('NETZWERK-TELEMETRIE','NICHT VERFÜGBAR',status.reason?.message||'','bad'));
  }
  const body=clear('networkRows');
  if(!body)return;
  const findingsList=findings.status==='fulfilled'&&Array.isArray(findings.value)?findings.value:[];
  setPill('networkFindingsCount',`${formatNumber(findingsList.length)} VERBINDUNGEN`,findingsList.length?'warn':'info');
  if(findings.status!=='fulfilled'||!findingsList.length){
    body.append(emptyRow(8,findings.status==='fulfilled'?'Keine Threat-Intel-Netzwerkverbindungen beobachtet.':'Netzwerk-Findings nicht abrufbar.'));
    return;
  }
  for(const finding of findingsList){
    const row=node('tr');
    row.append(node('td','',formatTime(finding.timestampUtc)),node('td','',`${finding.image||'PID'} ${finding.pid||''}`),node('td','',finding.remoteIp||'—'),node('td','',String(finding.remotePort||'—')));
    const policy=node('td');
    policy.append(pill(finding.threatAction||'MATCH',finding.threatAction==='BLOCK'?'bad':finding.threatAction==='CORRELATE_ONLY'?'warn':'info'));
    row.append(policy,node('td','',Array.isArray(finding.threatSources)?finding.threatSources.join(', '):'—'));
    const sev=node('td');
    sev.append(severity(finding.severity));
    row.append(sev,node('td','',finding.response||'—'));
    body.append(row);
  }
}

/* ------------------------------------------------------------------ */
/* Integrity                                                           */
/* ------------------------------------------------------------------ */
export async function loadIntegrity(){
  const [status,changes]=await Promise.all([api('/api/v1/integrity/status'),api('/api/v1/integrity/changes?limit=500')]);
  lastIntegrity=status;
  const metrics=clear('integrityMetrics');
  if(metrics)metrics.append(
    metric('DATEIEN',formatNumber(status.filesHashed),'gehasht'),
    metric('DATEN',formatBytes(status.bytesHashed),'SHA-256'),
    metric('ÄNDERUNGEN',formatNumber((status.added||0)+(status.modified||0)+(status.deleted||0)),`${status.added||0} neu · ${status.modified||0} geändert · ${status.deleted||0} gelöscht`),
    metric('LESEFEHLER',formatNumber(status.readErrors),'Scanfehler'),
  );
  setText('integrityState',status.state||'---');
  setPill('integrityState',status.state||'---',status.running?'info':status.error?'bad':'good');
  setText('integrityProgressText',status.running?`${formatNumber(status.filesHashed)} Dateien verarbeitet`:status.generation?`Generation ${status.generation}`:'Noch keine Baseline');
  setText('integritySchedule',status.enabled?`Nächster Scan: ${formatTime(status.nextScanUtc)}`:'Überwachung ist deaktiviert.');
  const interval=byId('integrityInterval');
  if(interval)interval.value=String(status.intervalHours||24);
  setText('integrityToggle',status.enabled?'Überwachung deaktivieren':'Überwachung aktivieren');
  const progress=byId('integrityProgressBar');
  if(progress)progress.style.width=status.running?'65%':status.generation?'100%':'0%';
  const body=clear('integrityRows');
  if(!body)return;
  const changeList=Array.isArray(changes)?changes:[];
  setPill('integrityChangesCount',`${formatNumber(changeList.length)} ÄNDERUNGEN`,changeList.length?'warn':'info');
  if(!changeList.length){
    body.append(emptyRow(5,'Noch keine Dateiveränderungen registriert.'));
    return;
  }
  for(const change of changeList){
    const row=node('tr');
    const type=node('td');
    type.append(severity(change.kind));
    row.append(type,node('td','',change.path||'—'),node('td','',shortHash(change.oldSha256)),node('td','',shortHash(change.newSha256)),node('td','',formatBytes(change.size)));
    body.append(row);
  }
}

function shortHash(value){return value?`${String(value).slice(0,14)}…`:'—'}

export async function toggleIntegrity(){
  const current=lastIntegrity||await api('/api/v1/integrity/status');
  const disabling=Boolean(current.enabled);
  // Disabling file-integrity monitoring is a protection downgrade: require an
  // explicit consequence review and a server-verified reason (UI-FIND-003).
  const reason=await requestReason({
    title:disabling?'Dateiintegritäts-Überwachung deaktivieren':'Dateiintegritäts-Überwachung aktivieren',
    text:disabling
      ?'Achtung: Nach dem Deaktivieren werden Änderungen an geschützten Systemdateien nicht mehr erkannt und nicht mehr in der Evidenzkette protokolliert. Die Control Plane verlangt eine dokumentierte Begründung; die Änderung ist protokolliert und reversibel.'
      :'Die periodische SHA-256-Baseline-Prüfung wird wieder aktiviert. Die Änderung verlangt eine dokumentierte Begründung und wird protokolliert.',
    label:'Begründung der Änderung',
    confirmLabel:disabling?'Überwachung deaktivieren':'Überwachung aktivieren',
    tone:disabling?'danger':'primary',
  });
  if(!reason)return;
  await setIntegrityConfiguration(!current.enabled,Number(byId('integrityInterval')?.value||24),reason);
  toast('Integritätskonfiguration aktualisiert.','good');
  await loadIntegrity();
}

export async function scanIntegrity(){
  await api('/api/v1/integrity/scan',{method:'POST',json:{}});
  toast('Integritätsscan gestartet.','good');
  await loadIntegrity();
}

/* ------------------------------------------------------------------ */
/* Hardening                                                           */
/* ------------------------------------------------------------------ */
function statusPillForComponent(active,measured){
  if(!measured)return {text:'STATUS UNBEKANNT',tone:'warn'};
  return active?{text:'AKTIV',tone:'good'}:{text:'FEHLT',tone:'bad'};
}

function renderHardeningFilters(){
  const host=byId('hardeningFilters');
  if(!host)return;
  host.replaceChildren();
  const categories=['ALL',...new Set(HARDENING_CATALOG.map(item=>item.category))];
  for(const category of categories){
    const count=category==='ALL'?HARDENING_CATALOG.length:HARDENING_CATALOG.filter(item=>item.category===category).length;
    const button=node('button','filter-chip',`${category==='ALL'?'Alle':category} ${count}`);
    button.type='button';
    button.setAttribute('aria-pressed',String(hardeningState.filter===category));
    button.addEventListener('click',()=>{
      hardeningState.filter=category;
      renderHardeningFilters();
      renderHardeningGrid();
    });
    host.append(button);
  }
}

function visibleHardening(){
  return hardeningState.filter==='ALL'?hardeningState.catalog:hardeningState.catalog.filter(item=>item.category===hardeningState.filter);
}

function renderHardeningGrid(){
  const host=clear('hardeningComponents');
  if(!host)return;
  const items=visibleHardening();
  setText('hardeningCount',`${formatNumber(items.length)} von ${formatNumber(hardeningState.catalog.length)} Komponenten sichtbar`);
  if(!items.length){
    host.append(emptyState('Keine Komponenten in diesem Filter','Filter wechseln oder Status aktualisieren.'));
    return;
  }
  for(const component of items){
    const card=node('article','component-card');
    const measured=Boolean(component.measured);
    const state=statusPillForComponent(component.active,measured);
    card.dataset.state=measured?(component.active?'active':'missing'):'unknown';
    const head=node('div','section-head');
    const headCopy=node('div');
    headCopy.append(node('span','eyebrow',component.category));
    head.append(headCopy,pill(state.text,state.tone));
    const title=node('h3','',component.name);
    const description=node('p','',component.description||'Beschreibung nicht verfügbar.');
    const check=node('div','component-check');
    if(measured){
      check.append(node('small','',`✓ Gemessen ${formatTime(hardeningState.lastCheckedUtc)} · Live-Wert aus der Control Plane`));
    }else{
      const label=node('small','',hardeningState.componentsLoaded?'Status konnte nicht gemessen werden.':'Messung wird durchgeführt …');
      const bar=node('div','progress');
      bar.dataset.indeterminate='true';
      bar.append(node('span',''));
      check.append(bar,label);
    }
    const meta=node('div','component-meta');
    meta.append(node('span','',component.rebootRequired?'Neustart erforderlich':'Live / idempotent'),node('span','',component.configurable?'Konfigurierbar':'Feste Richtlinie'));
    const foot=node('div','component-foot');
    const detailButton=node('button','button ghost small','Details');
    detailButton.type='button';
    detailButton.addEventListener('click',()=>openHardeningDetail(component.id));
    const activate=node('button',`button ${component.active?'ghost':'primary'} small`,component.active?'Aktiv':'Aktivieren');
    activate.type='button';
    activate.disabled=Boolean(component.active);
    activate.dataset.hardeningActivate=component.id;
    activate.addEventListener('click',()=>{void activateHardeningComponent(component.id,activate)});
    foot.append(detailButton,activate);
    card.append(head,title,description,check,meta,foot);
    host.append(card);
  }
}

export async function loadHardening(){
  hardeningState.loading=true;
  // First paint: the complete catalogue is visible before any network result.
  if(!hardeningState.catalog.length){
    hardeningState.catalog=mergeHardeningCatalog([],[]);
    setText('hardeningCatalogState','Katalog wird angezeigt · Live-Status wird gemessen …');
    renderHardeningFilters();
    renderHardeningGrid();
  }else{
    setText('hardeningCatalogState','Status wird aktualisiert …');
  }
  const [components,catalog]=await Promise.all([getHardeningComponents(),getHardeningCatalog()]);
  if(components.ok&&Array.isArray(components.data))hardeningState.componentsLoaded=true;
  if(catalog.ok&&Array.isArray(catalog.data))hardeningState.catalogLive=true;
  hardeningState.catalog=mergeHardeningCatalog(
    components.ok?components.data:[],
    catalog.ok?catalog.data:[],
  );
  hardeningState.lastCheckedUtc=new Date().toISOString();
  hardeningState.loading=false;
  if(components.ok)setText('hardeningCatalogState',catalog.ok?'Live-Katalog und Messwerte geladen':'Live-Messwerte geladen · Basiskatalog');
  else setText('hardeningCatalogState','Statischer Katalog · Live-Messung nicht verfügbar');
  renderHardeningFilters();
  renderHardeningGrid();
  if(!components.ok){
    const host=byId('hardeningComponents');
    if(host&&host.firstElementChild?.classList.contains('notice'))host.firstElementChild.remove();
    if(host){
      const container=document.createElement('div');
      container.className='notice';
      container.dataset.tone='warn';
      const icon=node('span','notice-icon','!');
      icon.setAttribute('aria-hidden','true');
      const body=node('div','notice-content');
      body.append(node('p','notice-title','Live-Messung nicht verfügbar'),node('p','notice-body',`Der Katalog bleibt vollständig sichtbar. Der gemessene Aktivstatus ist unbekannt, nicht „fehlt“. Grund: ${components.message}`));
      const actions=node('div','notice-actions');
      const retry=node('button','button ghost small','Erneut messen');
      retry.type='button';
      retry.addEventListener('click',()=>{void loadHardening()});
      actions.append(retry);
      body.append(actions);
      container.append(icon,body);
      host.prepend(container);
    }
  }
  return hardeningState.catalog;
}

async function activateHardeningComponent(id,button){
  const component=hardeningState.catalog.find(item=>item.id===id);
  const reason=await requestReason({
    title:'Härtungskomponente aktivieren',
    text:`Komponente „${component?.name||id}“ (${id}) idempotent anwenden? Die Änderung verändert die Systemhärtung, wird als Sicherheits-Transaktion protokolliert und ist über den gesicherten Vorzustand reversibel.${component?.rebootRequired?' Ein Neustart kann erforderlich sein.':''}`,
    label:'Begründung der Härtungsänderung',
    confirmLabel:'Komponente aktivieren',
    tone:'primary',
  });
  if(!reason)return;
  if(button){button.disabled=true;button.classList.add('loading');button.textContent='Wird angewendet …'}
  try{
    await activateHardeningComponentRequest(id,reason);
    toast(`Härtungskomponente ${id} wurde verifiziert.`,'good');
    await loadHardening();
  }catch(error){
    toast(`Härtungskomponente abgelehnt: ${error.message||error}`,'bad');
    if(button){button.disabled=false;button.classList.remove('loading');button.textContent='Aktivieren'}
  }
}

export async function enforceComponent(id){
  const reason=await requestReason({
    title:'Härtungskomponente aktivieren',
    text:`Komponente „${id}“ idempotent anwenden? Die Änderung wird als Sicherheits-Transaktion protokolliert.`,
    label:'Begründung der Härtungsänderung',
    confirmLabel:'Komponente aktivieren',
  });
  if(!reason)return;
  await activateHardeningComponentRequest(id,reason);
  toast('Hardening-Komponente verifiziert.','good');
  await loadHardening();
}

export async function enforceBalanced(reason){
  await applyHardeningProfile('EnterpriseBalanced',reason);
  toast('Empfohlenes Härtungsprofil wurde angewendet.','good');
  await Promise.all([loadHardening(),loadOverview()]);
}

export async function rollback(reason){
  await rollbackHardening(reason);
  toast('Gesicherter Vorzustand wurde wiederhergestellt.','good');
  await Promise.all([loadHardening(),loadOverview()]);
}

function hardeningFieldModel(field){
  if(!field||typeof field!=='object')return null;
  const key=String(field.key||field.id||'');
  if(!key)return null;
  const parts=key.split('.');
  const section=parts.length>1?parts[0]:'';
  const controlId=parts.length>1?parts.slice(1).join('.'):key;
  const type=String(field.type||'').toLowerCase();
  const values=Array.isArray(field.values)?field.values:[];
  if(type==='array'||type==='uuid')return {unsupported:true,key,label:String(field.label||key),description:String(field.description||'')};
  if(type==='enum'||values.length){
    return {kind:'enum',section,controlId,key,label:String(field.label||key),description:String(field.description||''),values};
  }
  if(type==='boolean')return {kind:'boolean',section,controlId,key,label:String(field.label||key),description:String(field.description||'')};
  if(['int','integer','number','duration'].includes(type)){
    return {kind:'number',section,controlId,key,label:String(field.label||key),description:String(field.description||''),minimum:Number(field.minimum),maximum:Number(field.maximum)};
  }
  return {unsupported:true,key,label:String(field.label||key),description:String(field.description||'')};
}

function collectHardeningConfig(){
  const config={schemaVersion:1};
  for(const [section,values]of Object.entries(hardeningState.detailConfig)){
    if(!values||!Object.keys(values).length)continue;
    if(section==='defender'){config.defender={...values};continue}
    if(section==='firewall'){config.firewall=values}
  }
  return Object.keys(config).length>1?config:null;
}

function updateHardeningConfigState(){
  const apply=byId('hardeningDetailApply');
  if(!apply)return;
  const component=hardeningState.catalog.find(item=>item.id===hardeningState.detailId);
  if(!component)return;
  const config=collectHardeningConfig();
  if(component.configurable&&hardeningState.detailEditable){
    apply.disabled=!config;
    apply.textContent='Konfiguration anwenden';
    apply.title=config?'Ausgewählte Einstellungen serverseitig validieren und anwenden.':'Wähle mindestens eine Einstellung.';
  }else if(component.configurable===false){
    apply.textContent='Komponente aktivieren';
    apply.disabled=false;
  }else{
    apply.textContent='Komponente aktivieren';
    apply.disabled=false;
  }
}

export function openHardeningDetail(id){
  const component=hardeningState.catalog.find(item=>item.id===id);
  if(!component)return;
  hardeningState.detailId=id;
  hardeningState.detailConfig={};
  hardeningState.detailEditable=false;
  setText('hardeningDetailTitle',component.name);
  const body=clear('hardeningDetailBody');
  if(body){
    const status=statusPillForComponent(component.active,component.measured);
    const intro=node('div','section-head');
    const introCopy=node('div');
    introCopy.append(node('p','eyebrow',component.category),node('p','',component.description||'Beschreibung nicht verfügbar.'));
    intro.append(introCopy,pill(status.text,status.tone));
    const dl=node('dl','');
    const pairs=[
      ['ID',component.id],
      ['Kategorie',component.category],
      ['Live-Status',component.measured?(component.active?'Aktiv':'Fehlt'):'Unbekannt (nicht gemessen)'],
      ['Neustart',component.rebootRequired?'Erforderlich':'Nicht erforderlich'],
      ['Konfigurierbar',component.configurable?'Ja':'Nein, feste Richtlinie'],
    ];
    for(const [label,value]of pairs){
      dl.append(node('dt','',label),node('dd','',value));
    }
    body.append(intro,dl);
    const fields=listFrom(component.fields).map(hardeningFieldModel).filter(Boolean);
    const editable=fields.filter(field=>!field.unsupported);
    if(editable.length){
      hardeningState.detailEditable=true;
      body.append(node('p','eyebrow','Konfiguration (nur ausgewählte Werte werden geändert)'));
      const grid=node('div','field-grid');
      for(const field of editable.slice(0,12)){
        const label=node('label');
        label.append(node('span','',field.label));
        if(field.kind==='enum'){
          const select=document.createElement('select');
          const untouched=document.createElement('option');
          untouched.value='';
          untouched.textContent='Unverändert';
          select.append(untouched);
          for(const value of field.values.slice(0,30)){
            const option=document.createElement('option');
            option.value=String(value);
            option.textContent=String(value);
            select.append(option);
          }
          select.addEventListener('change',()=>{
            if(!select.value){
              delete hardeningState.detailConfig[field.section]?.[field.controlId];
              updateHardeningConfigState();
              return;
            }
            hardeningState.detailConfig[field.section]={...(hardeningState.detailConfig[field.section]||{}),[field.controlId]:select.value};
            updateHardeningConfigState();
          });
          label.append(select);
        }else if(field.kind==='boolean'){
          const select=document.createElement('select');
          for(const [value,labelText]of [['','Unverändert'],['true','Aktiviert'],['false','Deaktiviert']]){
            const option=document.createElement('option');
            option.value=value;
            option.textContent=labelText;
            select.append(option);
          }
          select.addEventListener('change',()=>{
            if(select.value===''){delete hardeningState.detailConfig[field.section]?.[field.controlId]}
            else{hardeningState.detailConfig[field.section]={...(hardeningState.detailConfig[field.section]||{}),[field.controlId]:select.value==='true'}}
            updateHardeningConfigState();
          });
          label.append(select);
        }else{
          const input=document.createElement('input');
          input.type='number';
          if(Number.isFinite(field.minimum))input.min=String(field.minimum);
          if(Number.isFinite(field.maximum))input.max=String(field.maximum);
          input.placeholder='Unverändert';
          input.addEventListener('input',()=>{
            const raw=input.value.trim();
            if(raw===''){delete hardeningState.detailConfig[field.section]?.[field.controlId]}
            else{
              const number=Number(raw);
              if(Number.isFinite(number))hardeningState.detailConfig[field.section]={...(hardeningState.detailConfig[field.section]||{}),[field.controlId]:number};
            }
            updateHardeningConfigState();
          });
          label.append(input);
        }
        if(field.description)label.append(node('small','field-hint',field.description));
        grid.append(label);
      }
      body.append(grid);
      body.append(node('p','field-hint','Die Control Plane validiert jeden Wert vor der Anwendung und lehnt unbekannte oder nicht unterstützte Kombinationen ab. Nicht ausgewählte Werte bleiben unverändert; die Anwendung wird protokolliert.'));
    }else if(fields.some(field=>field.unsupported)){
      body.append(node('p','field-hint','Diese Komponente enthält Listen-/Regelstrukturen (z. B. ASR-Regelaktionen oder Firewallprofile), die nicht als Einzelfeld bearbeitet werden. Sie wird als Ganzes angewendet oder über die Richtlinien-Profile gesteuert.'));
    }else{
      body.append(node('p','field-hint','Für diese Komponente ist keine feingranulare Konfiguration vorgesehen; sie wird als Ganzes angewendet oder zurückgerollt.'));
    }
  }
  const apply=byId('hardeningDetailApply');
  if(apply){apply.disabled=false}
  updateHardeningConfigState();
  const dialog=byId('hardeningDetailDialog');
  try{if(dialog&&!dialog.open)dialog.showModal()}catch{/* dialog unavailable */}
  byId('hardeningDetailDismiss')?.focus({preventScroll:true});
}

export function closeHardeningDetail(){
  byId('hardeningDetailDialog')?.close();
}

export async function applyHardeningDetail(){
  const id=hardeningState.detailId;
  if(!id)return;
  const component=hardeningState.catalog.find(item=>item.id===id);
  if(!component)return;
  const config=collectHardeningConfig();
  if(config&&component.configurable){
    const reason=await requestReason({
      title:`${component.name}: Konfiguration anwenden`,
      text:'Die ausgewählten Einstellungen werden von der Control Plane validiert, als Sicherheits-Transaktion angewendet und durch die bestehende Evidenzkette protokolliert.',
      label:'Begründung der Konfigurationsänderung',
      confirmLabel:'Konfiguration anwenden',
    });
    if(!reason)return;
    const result=await saveHardeningSettings(config,reason);
    if(result.ok){
      toast(`Konfiguration für ${component.id} wurde angewendet und gemessen.`,'good');
      closeHardeningDetail();
      await loadHardening();
    }else{
      toast(`Konfiguration abgelehnt: ${result.message}`,'bad');
      renderHardeningGrid();
    }
    return;
  }
  closeHardeningDetail();
  await activateHardeningComponent(id,null);
}

/* ------------------------------------------------------------------ */
/* Audit                                                               */
/* ------------------------------------------------------------------ */
function auditStage(stage,state,text){
  const item=document.querySelector(`#auditStages [data-stage="${stage}"]`);
  if(!item)return;
  item.dataset.state=state;
  const label=item.querySelector('.audit-stage-state');
  if(label)label.textContent=text;
}

function auditResetStages(){
  for(const stage of ['request','run','eval','report'])auditStage(stage,'pending','Wartet');
}

function auditElapsed(startedAt){
  const seconds=Math.max(0,Math.floor((Date.now()-startedAt)/1000));
  const minutes=Math.floor(seconds/60);
  return `${minutes}:${String(seconds%60).padStart(2,'0')}`;
}

function auditStartTimer(){
  auditStopTimer();
  auditState.startedAt=Date.now();
  setText('auditElapsed','0:00');
  auditState.timer=globalThis.setInterval(()=>{
    setText('auditElapsed',auditElapsed(auditState.startedAt));
  },250);
}

function auditStopTimer(){
  if(auditState.timer){clearInterval(auditState.timer);auditState.timer=null}
}

function setAuditDialogBusy(busy){
  const close=byId('auditClose');
  const rerun=byId('auditRerun');
  const keep=byId('auditKeepOpen');
  if(close)close.disabled=busy;
  if(rerun)rerun.disabled=busy;
  if(keep)keep.hidden=busy;
}

function auditSummaryNode(result){
  const wrap=node('div','');
  const failed=Array.isArray(result.Checks)?result.Checks.filter(check=>String(check.Status).toUpperCase()!=='PASS'):[];
  wrap.append(node('p','',`Framework: ${result.Framework||'—'} · Zeitpunkt: ${formatTime(result.TimestampUtc)}`));
  const stats=node('div','audit-summary-stats');
  const entries=[
    ['COMPLIANCE',formatPercent(Number(result.Percent),1),'Score'],
    ['BESTANDEN',formatNumber(result.Passed),'Kontrollen'],
    ['FEHLER',formatNumber(result.Failed),'Kontrollen'],
    ['WARNUNGEN',formatNumber(result.Warnings),'Kontrollen'],
  ];
  for(const [label,value,detail]of entries){
    const item=node('div');
    item.append(node('strong','',value),node('span','',`${label} · ${detail}`));
    stats.append(item);
  }
  wrap.append(stats);
  if(failed.length){
    const list=node('ul','audit-failures');
    for(const check of failed.slice(0,8)){
      const item=node('li');
      const severityNode=severity(check.Status);
      const copy=node('span');
      copy.append(node('b','',`${check.Id||'—'} · ${check.Title||'Kontrolle'}`));
      copy.append(node('span','',`Ist ${check.Actual||'—'} / Soll ${check.Expected||'—'}`));
      item.append(severityNode,copy);
      list.append(item);
    }
    wrap.append(node('p','eyebrow','Offene Kontrollen (Auszug)'),list);
  }else{
    wrap.append(node('p','muted','Alle geprüften Kontrollen bestanden. Es werden keine Änderungen vorgenommen.'));
  }
  return wrap;
}

function renderAuditPage(result){
  auditState.result=result;
  auditState.lastRunUtc=result?.TimestampUtc||new Date().toISOString();
  setText('auditLastRun',`Letzter Lauf: ${formatTime(result?.TimestampUtc)}`);
  const failed=Number(result?.Failed||0);
  const warnings=Number(result?.Warnings||0);
  setPill('auditState',failed?'ABWEICHUNGEN':warnings?'MIT HINWEISEN':'BESTANDEN',failed?'bad':warnings?'warn':'good');
  setText('auditScope',`Framework ${result?.Framework||'—'} · Read-only · ${formatNumber((result?.Checks||[]).length)} Kontrollen geprüft`);
  const metrics=clear('auditMetrics');
  if(metrics)metrics.append(
    metric('COMPLIANCE',formatPercent(Number(result?.Percent),1),result?.Framework||'',Number(result?.Percent)>=90?'good':'warn'),
    metric('BESTANDEN',formatNumber(result?.Passed),'Kontrollen','good'),
    metric('FEHLER',formatNumber(result?.Failed),'Kontrollen',failed?'bad':'good'),
    metric('WARNUNGEN',formatNumber(result?.Warnings),'Kontrollen',warnings?'warn':'good'),
  );
  const body=clear('auditRows');
  if(!body)return;
  const checks=Array.isArray(result?.Checks)?result.Checks:[];
  if(!checks.length){
    body.append(emptyRow(5,'Keine Audit-Daten.'));
    return;
  }
  for(const check of checks){
    const row=node('tr');
    row.append(node('td','',check.Id||'—'),node('td','',check.Category||'—'),node('td','',check.Title||'—'));
    const statusCell=node('td');
    statusCell.append(severity(check.Status));
    row.append(statusCell,node('td','',`${check.Actual||'—'} / ${check.Expected||'—'}`));
    body.append(row);
  }
  setText('auditTableNote',`Ergebnis vom ${formatTime(result?.TimestampUtc)}. Ein neuer Lauf ersetzt die Anzeige, nicht die lokale Evidenz.`);
}

export async function loadAudit(run=false){
  if(run){await openAuditDialogAndRun();return}
  if(auditState.result)renderAuditPage(auditState.result);
  else{
    setText('auditLastRun','Noch kein Audit in dieser Sitzung');
    setText('auditScope','Read-only. Es werden keine Einstellungen verändert.');
    setPill('auditState','BEREIT','info');
    const metrics=clear('auditMetrics');
    if(metrics)metrics.append(
      metric('STATUS','BEREIT','Audit manuell starten','info'),
      metric('KONTROLLEN','—','Noch kein Lauf in dieser Sitzung'),
      metric('LETZTER LAUF','—','Read-only, keine Änderungen'),
    );
    const body=clear('auditRows');
    if(body)body.append(emptyRow(5,'Noch keine Audit-Ergebnisse in dieser Sitzung.'));
    setText('auditTableNote','Ergebnisse erscheinen nach einem abgeschlossenen Audit. Ein neuer Lauf ersetzt die Anzeige, nicht die lokale Evidenz.');
  }
}

export async function openAuditDialogAndRun(){
  if(auditState.running)return;
  auditState.running=true;
  auditResetStages();
  const summary=byId('auditDialogSummary');
  if(summary){summary.hidden=true;summary.replaceChildren()}
  setAuditDialogBusy(true);
  setText('auditDialogTitle','Audit läuft');
  setText('auditDialogStatus','Audit-Transaktion wird an die lokale Control Plane übergeben …');
  setPill('auditDialogPhase','ANFRAGE','info');
  const dialog=byId('auditDialog');
  try{if(dialog&&!dialog.open)dialog.showModal()}catch{/* dialog unavailable */}
  auditStartTimer();
  auditStage('request','running','Auftrag wird übergeben');
  try{
    await new Promise(resolve=>setTimeout(resolve,60));
    auditStage('request','done','Auftrag angenommen');
    auditStage('run','running','Windows-Baseline wird gemessen');
    setPill('auditDialogPhase','MESSUNG','info');
    setText('auditDialogStatus','Read-only Audit läuft. Die Control Plane misst Windows-Kontrollen; das kann bis zu fünf Minuten dauern.');
    const result=await api('/api/v1/audit/run',{method:'POST',json:{}});
    auditStage('run','done','Baseline gemessen');
    auditStage('eval','running','Ergebnisse werden ausgewertet');
    setPill('auditDialogPhase','AUSWERTUNG','info');
    setText('auditDialogStatus','Ergebnisse werden zusammengeführt …');
    auditStopTimer();
    setText('auditElapsed',auditElapsed(auditState.startedAt));
    renderAuditPage(result);
    auditStage('eval','done','Auswertung abgeschlossen');
    auditStage('report','running','Bericht wird angezeigt');
    if(summary){
      summary.replaceChildren(auditSummaryNode(result));
      summary.hidden=false;
    }
    setText('auditDialogTitle',Number(result.Failed)?'Audit mit Abweichungen abgeschlossen':'Audit abgeschlossen');
    setText('auditDialogStatus',`${formatNumber(result.Passed)} bestanden · ${formatNumber(result.Failed)} Fehler · ${formatNumber(result.Warnings)} Warnungen · Compliance ${formatPercent(Number(result.Percent),1)}`);
    setPill('auditDialogPhase',Number(result.Failed)?'ABWEICHUNGEN':'BESTANDEN',Number(result.Failed)?'bad':'good');
    auditStage('report','done','Bericht bereit');
    setAuditDialogBusy(false);
    const closeButton=byId('auditClose');
    if(closeButton){closeButton.disabled=false;closeButton.textContent='Ergebnisse anzeigen'}
    const rerun=byId('auditRerun');
    if(rerun){rerun.disabled=false;rerun.hidden=false}
    const keep=byId('auditKeepOpen');
    if(keep){keep.hidden=false;keep.disabled=false}
    toast(Number(result.Failed)?`Audit abgeschlossen: ${formatNumber(result.Failed)} Abweichungen.`:'Audit abgeschlossen: alle Kontrollen bestanden.',Number(result.Failed)?'warn':'good');
  }catch(error){
    auditStopTimer();
    setText('auditElapsed',auditElapsed(auditState.startedAt));
    for(const stage of ['request','run','eval','report']){
      const item=document.querySelector(`#auditStages [data-stage="${stage}"]`);
      if(item&&item.dataset.state==='running')auditStage(stage,'error','Fehlgeschlagen');
      else if(item&&item.dataset.state==='pending')auditStage(stage,'pending','Nicht ausgeführt');
    }
    setText('auditDialogTitle','Audit konnte nicht abgeschlossen werden');
    setText('auditDialogStatus',`Fehler: ${error.message||error}`);
    setPill('auditDialogPhase','FEHLER','bad');
    if(summary){
      summary.replaceChildren(node('p','',`Der Audit-Lauf wurde nicht abgeschlossen: ${error.message||error}`),node('p','muted','Der Dialog kann geschlossen und der Lauf erneut gestartet werden. Es wurden keine Einstellungen verändert.'));
      summary.hidden=false;
    }
    setAuditDialogBusy(false);
    const close=byId('auditClose');
    if(close){close.disabled=false;close.textContent='Schließen'}
    const rerun=byId('auditRerun');
    if(rerun){rerun.disabled=false;rerun.hidden=false}
    toast(`Audit fehlgeschlagen: ${error.message||error}`,'bad');
  }finally{
    auditState.running=false;
  }
}

let auditDialogBound=false;
export function bindAuditDialog(){
  if(auditDialogBound)return;
  auditDialogBound=true;
  byId('auditClose')?.addEventListener('click',()=>{
    byId('auditDialog')?.close();
    byId('auditLastRun')?.focus?.({preventScroll:true});
    byId('auditRows')?.closest('.table-card')?.scrollIntoView({block:'start',behavior:'smooth'});
  });
  byId('auditKeepOpen')?.addEventListener('click',()=>{
    byId('auditDialogSummary')?.focus?.({preventScroll:true});
    toast('Dialog bleibt geöffnet. Ergebnisse sind auch auf der Seite verfügbar.','info');
  });
  byId('auditRerun')?.addEventListener('click',()=>{void openAuditDialogAndRun()});
  byId('auditDialogClose')?.addEventListener('click',()=>byId('auditDialog')?.close());
}

/* ------------------------------------------------------------------ */
/* Evidence                                                            */
/* ------------------------------------------------------------------ */
export async function loadEvidence(offset=0){
  if(evidenceState.loading)return;
  evidenceState.loading=true;
  const safeOffset=Math.max(0,Number(offset)||0);
  const pageResult=await getEvidencePage(safeOffset,evidenceState.limit);
  let records=[];
  let total=0;
  let fallback=false;
  let sourceLabel='Server (paginiert)';
  if(pageResult.ok){
    const data=pageResult.data||{};
    records=Array.isArray(data.items)?data.items:[];
    total=Number(data.total||0);
    const serverOffset=Number(data.offset);
    if(Number.isFinite(serverOffset)&&serverOffset>=0)evidenceState.offset=serverOffset;
    else evidenceState.offset=safeOffset;
    if(Number(data.limit)>0)evidenceState.limit=Math.min(100,Number(data.limit));
  }else{
    fallback=true;
    evidenceState.offset=safeOffset;
    const snapshot=await getEvidenceSnapshot();
    if(snapshot.ok&&Array.isArray(snapshot.data)){
      const all=snapshot.data;
      total=all.length;
      records=all.slice(evidenceState.offset,evidenceState.offset+evidenceState.limit);
      sourceLabel=`Lokaler Fallback (maximal ${formatNumber(all.length)} Einträge)`;
    }else{
      evidenceState.loading=false;
      const stateHost=byId('evidenceState');
      if(stateHost){
        stateHost.replaceChildren();
        const card=node('div','notice');
        card.dataset.tone='bad';
        const icon=node('span','notice-icon','!');
        icon.setAttribute('aria-hidden','true');
        const body=node('div','notice-content');
        body.append(node('p','notice-title','Evidence nicht abrufbar'),node('p','notice-body',`${pageResult.message}${snapshot.ok?'':' · Snapshot: '+snapshot.message}`));
        const actions=node('div','notice-actions');
        const retry=node('button','button ghost small','Erneut laden');
        retry.type='button';
        retry.addEventListener('click',()=>{void loadEvidence(evidenceState.offset)});
        actions.append(retry);
        body.append(actions);
        card.append(icon,body);
        stateHost.append(card);
      }
      clearTable('evidenceRows',5,'Evidence-Einträge nicht abrufbar.');
      setText('evidenceRange','Keine Einträge geladen');
      setText('evidencePageInfo','Seite —');
      setText('evidenceSource','Nicht erreichbar');
      setText('evidenceTotal','');
      updateEvidencePagination();
      return;
    }
  }
  evidenceState.loaded=true;
  evidenceState.fallback=fallback;
  evidenceState.total=total;
  const stateHost=byId('evidenceState');
  if(stateHost){
    stateHost.replaceChildren();
    if(fallback){
      const card=node('div','notice');
      card.dataset.tone='warn';
      const icon=node('span','notice-icon','!');
      icon.setAttribute('aria-hidden','true');
      const body=node('div','notice-content');
      body.append(node('p','notice-title','Server-Paginierung nicht verfügbar'),node('p','notice-body',`GET ${'/api/v1/evidence/page'} ist noch nicht erreichbar. Angezeigt wird lokal aus dem begrenzten Snapshot (maximal 100 Einträge). Die Seitenzahlen beziehen sich nur auf diesen Ausschnitt.`));
      card.append(icon,body);
      stateHost.append(card);
    }
  }
  setText('evidenceSource',sourceLabel);
  setText('evidenceTotal',total?`${formatNumber(total)} Einträge`:'');
  const body=clear('evidenceRows');
  if(body){
    if(!records.length){
      body.append(emptyRow(5,'Keine Evidence-Einträge auf dieser Seite.'));
    }else{
      for(const record of records.slice(0,evidenceState.limit)){
        const row=node('tr');
        row.append(
          node('td','',record.sequence??record.Sequence??'—'),
          node('td','',formatTime(record.timestamp??record.TimestampUTC)),
          node('td','',record.kind??record.Kind??'—'),
          node('td','',record.action??record.Action??'—'),
          node('td','',record.result??record.Result??'—'),
        );
        body.append(row);
      }
    }
  }
  const page=Math.floor(evidenceState.offset/evidenceState.limit)+1;
  const pages=Math.max(1,Math.ceil(total/evidenceState.limit));
  setText('evidencePageInfo',`Seite ${formatNumber(page)} von ${formatNumber(pages)}`);
  setText('evidenceRange',total?`Einträge ${formatNumber(evidenceState.offset+1)}–${formatNumber(Math.min(evidenceState.offset+records.length,total))} von ${formatNumber(total)}`:'Keine Einträge geladen');
  updateEvidencePagination();
  evidenceState.loading=false;
}

function updateEvidencePagination(){
  const prev=byId('evidencePrev');
  const next=byId('evidenceNext');
  if(prev)prev.disabled=evidenceState.offset<=0;
  if(next)next.disabled=evidenceState.offset+evidenceState.limit>=evidenceState.total;
}

export async function setEvidencePage(direction){
  const next=Math.max(0,evidenceState.offset+direction*evidenceState.limit);
  if(next===evidenceState.offset)return;
  await loadEvidence(next);
}

export async function reloadEvidence(){
  await loadEvidence(evidenceState.offset);
}

export function tickThreatIntelCountdown(){
  if(!tiState.nextSyncUtc)return;
  setText('tiCountdown',`Server-Intervall · ${relativeLabel(tiState.nextSyncUtc)}`);
}

export async function verifyEvidence(){
  const button=byId('verifyEvidence');
  if(button){button.disabled=true;button.classList.add('loading');button.textContent='Verifiziere …'}
  try{
    await api('/api/v1/evidence/verify',{method:'POST',json:{}});
    toast('Evidence Ledger ist kryptografisch konsistent.','good');
  }finally{
    if(button){button.disabled=false;button.classList.remove('loading');button.textContent='Ledger verifizieren'}
  }
}

/* ------------------------------------------------------------------ */
/* Threat Intelligence                                                 */
/* ------------------------------------------------------------------ */
function feedTone(state){
  const value=String(state||'').toUpperCase();
  return value==='CURRENT'||value==='CACHED'?'good':value==='STALE'||value==='DEGRADED'?'warn':'bad';
}

function renderThreatFeeds(threatIntelligence,enforcement){
  const ti=threatIntelligence||{};
  setPill('threatIntelState',String(ti.state||'STARTING'),feedTone(ti.state));
  setPill('threatEnforcementState',`WFP ${String(enforcement.state||'UNVERIFIED')}`,enforcement.state==='VERIFIED'?'good':enforcement.state==='VERIFIED_CLEANUP_PENDING'||enforcement.state==='APPLYING'?'warn':'bad');
  const generation=String(ti.generationSha256||'');
  const desired=String(ti.enforcementGenerationSha256||'');
  const active=String(enforcement.activeGenerationSha256||'');
  setText('threatIntelGeneration',generation?`Index ${generation.slice(0,16)}… · WFP desired ${desired.slice(0,16)}… · aktiv ${active?active.slice(0,16)+'…':'nicht verifiziert'} · Block-Feeds ${ti.blockingFeedsReady||0}/${ti.blockingFeedsTotal||0}`:'Noch keine validierte Generation');
  setText('tiLimitations',`Enforcement-Generation: ${active?`${active.slice(0,20)}…`:'nicht verifiziert'} · gewünscht: ${desired?`${desired.slice(0,20)}…`:'—'} · übereinstimmend: ${active&&desired&&active===desired?'ja':'nein'}`);
  const host=byId('threatFeedMatrix');
  if(!host)return;
  host.replaceChildren();
  const feeds=Array.isArray(ti.feeds)?ti.feeds:[];
  if(!feeds.length){
    host.append(node('div','empty-state','Noch keine Feed-Generation verfügbar.'));
    return;
  }
  for(const feed of feeds.slice(0,12)){
    const row=node('div','feed-row');
    const main=node('div','feed-row-main');
    const name=node('strong','',String(feed.name||feed.key||'Feed'));
    const action=String(feed.effectiveAction||feed.action||'—').toUpperCase();
    const role=node('span','feed-role');
    role.dataset.role=action;
    role.append(node('i','feed-role-dot'),document.createTextNode(action==='BLOCK'?'BLOCK':action==='CORRELATE_ONLY'?'KORRELATION':action==='ANNOTATE_ONLY'?'ANNOTATION':action));
    const nameLine=node('div','feed-policy-name');
    nameLine.append(name,role);
    if(String(feed.actionSource||'').toUpperCase()==='OVERRIDE')nameLine.append(node('span','mode-caption','OVERRIDE'));
    main.append(nameLine);
    const metaBits=[];
    if(feed.lastSuccessUtc)metaBits.push(`Letzter Erfolg ${formatTime(feed.lastSuccessUtc)}`);
    else if(feed.lastAttemptUtc)metaBits.push(`Letzter Versuch ${formatTime(feed.lastAttemptUtc)}`);
    if(feed.enforcement)metaBits.push(String(feed.enforcement));
    if(metaBits.length)main.append(node('small','',metaBits.join(' · ')));
    if(feed.error)main.append(node('p','feed-error',String(feed.error)));
    const count=node('div','feed-row-count');
    count.append(node('span','',formatNumber(feed.indicators)));
    count.append(node('small','','Indikatoren'));
    const statePill=pill(String(feed.state||'UNAVAILABLE'),feedTone(feed.state));
    row.append(main,count,statePill);
    host.append(row);
  }
}

export async function loadThreatIntel(options={}){
  const [status,protectedNetworks,threatIntelStatus]=await Promise.allSettled([
    api('/api/v1/mhx/status'),
    getProtectedNetworks(),
    getThreatIntelStatus(),
  ]);
  bindThreatIntelSettingsPanel();
  if(status.status==='fulfilled'){
    const mhx=status.value;
    const ti=mhx.threatIntelligence||{};
    const enforcement=mhx.threatEnforcement||{};
    renderThreatFeeds(ti,enforcement);
    setText('tiBlockingIndicators',formatNumber(ti.blockingIndicators));
    setText('tiIndicators',formatNumber(ti.indicators));
    setText('tiFeedsReady',`Block-Feeds: ${formatNumber(ti.blockingFeedsReady)} / ${formatNumber(ti.blockingFeedsTotal)}`);
    setText('tiCorrelationIndicators',formatNumber(ti.correlationIndicators));
    setText('tiProtectedPrefixes',formatNumber(ti.protectedPrefixes));
    setText('tiLastSuccess',ti.lastSuccessUtc?formatTime(ti.lastSuccessUtc):'—');
    setText('tiLastAttempt',`Versuch: ${ti.lastAttemptUtc?formatTime(ti.lastAttemptUtc):'—'}`);
    tiState.nextSyncUtc=ti.nextSyncUtc||'';
    setText('tiNextPoll',ti.nextSyncUtc?formatTime(ti.nextSyncUtc):'—');
    setText('tiCountdown',ti.nextSyncUtc?`Server-Intervall · ${relativeLabel(ti.nextSyncUtc)}`:'Kein Serverintervall verfügbar');
    const errors=[];
    if(ti.error)errors.push(`Threat Intelligence: ${ti.error}`);
    if(enforcement.error)errors.push(`WFP-Enforcement: ${enforcement.error}`);
    const errorHost=byId('tiErrorNotice');
    if(errorHost){
      errorHost.replaceChildren();
      if(errors.length){
        const card=node('div','notice');
        card.dataset.tone='bad';
        const icon=node('span','notice-icon','!');
        icon.setAttribute('aria-hidden','true');
        const body=node('div','notice-content');
        body.append(node('p','notice-title','Control Plane meldet Feed-/Enforcement-Fehler'));
        for(const error of errors)body.append(node('p','notice-body',error));
        body.append(node('p','notice-body','Fehler werden nicht verdeckt. Ein fehlender Feed-Treffer ist kein Beweis für einen Angriff.'));
        card.append(icon,body);
        errorHost.append(card);
      }
    }
  }else{
    setPill('threatIntelState','NICHT VERFÜGBAR','bad');
    const errorHost=byId('tiErrorNotice');
    if(errorHost){
      errorHost.replaceChildren();
      const card=node('div','notice');
      card.dataset.tone='bad';
      const icon=node('span','notice-icon','!');
      icon.setAttribute('aria-hidden','true');
      const body=node('div','notice-content');
      body.append(node('p','notice-title','Threat-Intelligence-Status nicht abrufbar'),node('p','notice-body',status.reason?.message||'Control Plane nicht erreichbar.'));
      card.append(icon,body);
      errorHost.append(card);
    }
    const feedHost=clear('threatFeedMatrix');
    if(feedHost)feedHost.append(node('div','empty-state','Feed-Matrix nicht abrufbar.'));
  }
  if(protectedNetworks.status==='fulfilled'&&protectedNetworks.value.ok){
    renderProtectedNetworkPolicy(protectedNetworks.value.data);
  }else{
    setPill('protectedNetworkState','NICHT VERFÜGBAR','warn');
    setText('protectedNetworkGeneration','Protected-Network-Policy nicht abrufbar.');
  }
  if(threatIntelStatus.status==='fulfilled'&&threatIntelStatus.value.ok){
    const data=threatIntelStatus.value.data||{};
    const minutes=Number(data.pollIntervalMinutes);
    tiState.intervalMinutes=Number.isFinite(minutes)&&minutes>0?minutes:null;
  }
  if(options.includeSettings!==false){
    void loadThreatIntelSettingsPanel();
    void loadFeedPolicyPanel();
  }
}

function relativeLabel(value){
  const target=new Date(value).getTime();
  if(!Number.isFinite(target)||target<=0)return '';
  const delta=target-Date.now();
  const minutes=Math.round(Math.abs(delta)/60000);
  if(minutes<1)return delta>=0?'in weniger als 1 Min.':'vor weniger als 1 Min.';
  const hours=Math.floor(minutes/60);
  const text=hours>0?`${hours} Std. ${minutes%60} Min.`:`${minutes} Min.`;
  return delta>=0?`in ${text}`:`vor ${text}`;
}

function renderProtectedNetworkPolicy(policy){
  const data=policy||{};
  const prefixes=Array.isArray(data.prefixes)?data.prefixes:[];
  const input=byId('protectedNetworks');
  if(input&&input.dataset.dirty!=='true')input.value=prefixes.join('\n');
  setPill('protectedNetworkState',`${formatNumber(prefixes.length)} PREFIXE`,prefixes.length?'warn':'info');
  const generation=String(data.generationSha256||'');
  setText('protectedNetworkGeneration',generation?`Policy ${generation.slice(0,20)}… · aktualisiert ${formatTime(data.updatedUtc)}`:'Keine Protected-Network-Ausnahmen aktiv');
}

export async function updateProtectedNetworks(){
  const input=byId('protectedNetworks');
  const reason=String(byId('protectedNetworkReason')?.value||'').trim();
  const prefixes=String(input?.value||'').split(/\r?\n/).map(value=>value.trim()).filter(Boolean);
  if(reason.length<8){
    toast('Bitte eine Begründung mit mindestens 8 Zeichen angeben.','bad');
    return;
  }
  if(prefixes.length>256){
    toast('Maximal 256 geschützte Prefixe sind zulässig.','bad');
    return;
  }
  const confirmed=await requestConfirm({
    title:'Protected Networks anwenden',
    text:`${prefixes.length} Management-Prefix(e) werden vor der WFP-Block-Generation subtrahiert. Die Änderung wird protokolliert und löst eine Reconciliation aus.`,
    label:'Anwenden',
    tone:'danger',
  });
  if(!confirmed)return;
  const button=byId('updateProtectedNetworks');
  if(button){button.disabled=true;button.classList.add('loading');button.textContent='Wird angewendet …'}
  try{
    const result=await setProtectedNetworks(prefixes,reason);
    if(!result.ok)throw new Error(result.message);
    if(input)input.dataset.dirty='false';
    const reasonInput=byId('protectedNetworkReason');
    if(reasonInput)reasonInput.value='';
    renderProtectedNetworkPolicy(result.data);
    toast('Protected-Network-Policy verifiziert und WFP-Reconciliation ausgelöst.','good');
    await loadThreatIntel();
  }finally{
    if(button){button.disabled=false;button.classList.remove('loading');button.textContent='Protected Networks anwenden'}
  }
}

/* ------------------------------------------------------------------ */
/* Status helper                                                       */
/* ------------------------------------------------------------------ */
export function lastKnownStatus(){return lastStatus}
