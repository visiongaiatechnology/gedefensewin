// STATUS: DIAMANT VGT SUPREME
'use strict';
/** Protection Center: protection levels, live control values and the custom
 *  profile studio. All writes stay server-gated; the browser only requests and
 *  explains transitions. */
import {api, getDefenderTelemetry, getHardeningComponents} from './api.js';
import {
  byId, formatNumber, formatTime, node, pill, setPill, setText, toast,
} from './dom.js';
import {
  ensureSettingsProbe, initProfileStudio, rememberStatus, renderProfileStudioState, refreshProfileStudio,
} from './settings.js';

export const MODE_INFO={
  monitor:{
    id:'monitor',label:'MONITOR',title:'Monitor',
    summary:'Erkennen, korrelieren und protokollieren.',
    detail:'GeDefense misst Defender, Firewall, Telemetrie und Threat Intelligence. MHX bewertet Prozesse, beendet aber keine Prozesse. Die Schutzlage ist sichtbar, ohne dass die Control Plane eingreift.',
    consequences:['Prozesse werden bewertet und protokolliert','Keine MHX-Prozessterminierung','Kein App-Control-Enforcement','Threat-IP-WFP-Regeln bleiben unabhängig wirksam'],
    requirement:'Immer verfügbar; keine Voraussetzung.',
  },
  guarded:{
    id:'guarded',label:'GUARDED',title:'Guarded',
    summary:'Kontextuelle Response nach erneuter Identitätsprüfung.',
    detail:'Guarded erlaubt MHX, einen als blockierend bewerteten Prozess nach erneuter Prüfung von Signatur, Herkunft und Prozessidentität zu beenden. Die Schutzrichtlinie muss serverseitig verifiziert sein.',
    consequences:['Blockierende MHX-Entscheidungen dürfen Prozesse beenden','Jede Response wird erneut identitätsgeprüft','Windows App Control bleibt im Audit-/Guarded-Kontext','Keine Default-Deny-Policy für ausgehenden Verkehr'],
    requirement:'Realtime-Prozesstelemetrie und verifizierte Schutzrichtlinie erforderlich.',
  },
  sovereign:{
    id:'sovereign',label:'SOVEREIGN',title:'Sovereign',
    summary:'Höchste Eingriffstiefe: Enforcement und Default-Deny.',
    detail:'Sovereign erweitert Guarded um Windows App Control Enforcement und eine Default-Deny-Policy für ausgehende Netzwerkkommunikation. Zusätzlich müssen Threat-Intelligence-Blockabdeckung und die verifizierte WFP-Generation übereinstimmen.',
    consequences:['Guarded-Response bleibt aktiv','Windows App Control Enforcement','Ausgehende Netzwerkkommunikation wird standardmäßig verweigert','Threat-IP-Generation muss mit der Datenbasis übereinstimmen'],
    requirement:'Guarded aktiv, verifizierte TI-Blockabdeckung und verifizierte WFP-Generation erforderlich.',
  },
};

const MODE_ORDER=['monitor','guarded','sovereign'];

const state={
  status:null,
  components:[],
  readiness:{},
  defender:null,
  defenderError:'',
  loading:false,
  onRefresh:null,
  onModeChanged:null,
};

function protectionFromStatus(){
  return state.status?.protection||{};
}
function mhxFromStatus(){
  return state.status?.mhx||{};
}
function boolValue(value){return typeof value==='boolean'?value:null}
function text(value,fallback='---'){return value===undefined||value===null||value===''?fallback:String(value)}
function triState(value,good='Aktiv',bad='Inaktiv'){
  if(value===null||value===undefined)return {text:'Unbekannt',tone:'warn'};
  return value?{text:good,tone:'good'}:{text:bad,tone:'bad'};
}
function controlRow({name,detail,value,valueDetail,tone,action}){
  const row=node('div','control-row');
  const nameNode=node('div','control-name');
  nameNode.append(node('span','',name));
  if(detail)nameNode.append(node('small','',detail));
  const valueNode=node('div','control-value');
  valueNode.append(node('span','',value));
  if(valueDetail)valueNode.append(node('small','',valueDetail));
  const stateNode=node('span',`status-pill ${tone}`,tone==='good'?'KONFORM':tone==='bad'?'ABWEICHEND':tone==='info'?'INFO':'PRÜFEN');
  row.append(nameNode,valueNode,stateNode);
  const actions=node('div','control-actions');
  if(action){
    const button=node('button','button ghost','Einstellungen');
    button.type='button';
    button.dataset.go=action;
    actions.append(button);
  }
  row.append(actions);
  return row;
}

function renderControls(){
  const host=byId('protectionControls');
  if(!host)return;
  const protection=protectionFromStatus();
  const mhx=mhxFromStatus();
  const ti=mhx.threatIntelligence||{};
  const enforcement=mhx.threatEnforcement||{};
  const rows=[];
  const push=(options)=>rows.push(controlRow(options));
  const unknown='Nicht verfügbar';

  push({name:'Microsoft Defender',detail:'Dienst + Echtzeitschutz',value:protection.Defender?'Dienst aktiv':'Dienst nicht bestätigt',valueDetail:protection.DefenderService?'DefenderService erreichbar':'DefenderService nicht bestätigt',tone:protection.Defender&&protection.DefenderService?'good':'bad',action:'hardening'});
  push({name:'Realtime- und Verhaltensschutz',detail:'Defender-Kontrollen',value:`Realtime ${protection.RealTimeProtection?'an':'aus'} · Verhalten ${protection.BehaviorProtection?'an':'aus'}`,tone:protection.RealTimeProtection&&protection.BehaviorProtection?'good':'bad',action:'hardening'});
  push({name:'Cloud- und Netzwerkschutz',detail:'Defender-Schutzebene',value:`Cloud ${protection.CloudProtection?'an':'aus'}${protection.CloudBlockLevel?` · Stufe ${protection.CloudBlockLevel}`:''} · Netzwerk ${protection.NetworkProtection?'an':'aus'}`,tone:protection.CloudProtection&&protection.NetworkProtection?'good':'bad',action:'hardening'});
  push({name:'ASR-Regeln',detail:'Blockmodus',value:`${formatNumber(protection.ASRRules)} Regeln · ${formatNumber(protection.ASRBlockRules)} blockierend`,tone:Number(protection.ASRBlockRules||0)>=11?'good':Number(protection.ASRRules||0)>0?'warn':'bad',action:'hardening'});
  push({name:'Controlled Folder Access',detail:'Ransomware-Schutz',value:triState(boolValue(protection.ControlledFolderAccess)).text,tone:triState(boolValue(protection.ControlledFolderAccess)).tone,action:'hardening'});
  push({name:'Windows Firewall',detail:'Alle Profile',value:triState(boolValue(protection.Firewall)).text,tone:triState(boolValue(protection.Firewall)).tone,action:'hardening'});
  push({name:'Plattform-Isolation',detail:'Secure Boot · TPM · VBS · HVCI · LSASS',value:`SB ${protection.SecureBoot?'✓':'—'} · TPM ${protection.Tpm?'✓':'—'} · VBS ${protection.Vbs?'✓':'—'} · HVCI ${protection.MemoryIntegrity?'✓':'—'} · LSASS ${protection.LsaProtection?'✓':'—'}`,tone:[protection.SecureBoot,protection.Tpm,protection.Vbs,protection.MemoryIntegrity,protection.LsaProtection].every(Boolean)?'good':'warn',action:'hardening'});
  push({name:'MHX Schutzrichtlinie',detail:'Server-Verifikation der aktiven Richtlinie',value:String(mhx.protectionHealth||unknown),valueDetail:mhx.protectionVerifiedUtc?`Verifiziert ${formatTime(mhx.protectionVerifiedUtc)}`:'Keine Verifikationszeit verfügbar',tone:mhx.protectionHealth==='VERIFIED'?'good':'bad',action:'xdr'});
  push({name:'App Control',detail:'Windows-Anwendungsfreigaben',value:String(mhx.appControl||unknown),valueDetail:mhx.kernelEnforcement?'Kernel Enforcement aktiv':'Kernel Enforcement nicht bestätigt',tone:mhx.appControl?'info':'warn',action:'xdr'});
  push({name:'Threat-IP-Firewallgeneration',detail:'WFP-Enforcement',value:String(enforcement.state||unknown),valueDetail:enforcement.activeGenerationSha256?`Aktiv ${String(enforcement.activeGenerationSha256).slice(0,16)}…`:'Keine aktive Generation bestätigt',tone:enforcement.state==='VERIFIED'?'good':enforcement.state==='VERIFIED_CLEANUP_PENDING'?'warn':'bad',action:'threat-intel'});
  push({name:'Threat-Intelligence-Feeds',detail:'Blockabdeckung',value:`${formatNumber(ti.blockingFeedsReady)} / ${formatNumber(ti.blockingFeedsTotal)} Block-Feeds`,valueDetail:`${formatNumber(ti.indicators)} Indikatoren · ${String(ti.state||unknown)}`,tone:Number(ti.blockingFeedsReady)>0&&ti.blockingFeedsReady===ti.blockingFeedsTotal?'good':'warn',action:'threat-intel'});
  push({name:'WFP-Sperrtelemetrie',detail:'Security-Event 5157',value:String(mhx.wfpBlockTelemetry||unknown),valueDetail:`${formatNumber(mhx.wfpBlockedEvents)} beobachtete Sperren`,tone:mhx.wfpBlockTelemetry?'info':'warn',action:'xdr'});
  push({name:'Kinetic-Korrelation',detail:'Operator-gesteuert',value:mhx.kineticArmed?'Bewaffnet':'Beobachtungsmodus',valueDetail:`TI-Regeln ${String(mhx.kineticReadiness?.threatRules||'unbekannt')} · WFP-Audit ${String(mhx.kineticReadiness?.wfpAudit||'unbekannt')}`,tone:mhx.kineticArmed?'warn':'info',action:'kinetic'});

  renderDefenderTelemetryRows(push);

  host.replaceChildren(...rows);
  const source=byId('protectionControlSource');
  if(source)source.textContent=`Werte aus /api/v1/status${state.components.length?', Hardening-Messung':''}${state.defender?', Defender-Telemetrie':''}. Stand: ${formatTime(state.status?.protection?.TimestampUtc||new Date().toISOString())}. Fehlende Felder werden als nicht verfügbar angezeigt.`;
}

function defenderValue(container,...keys){
  for(const key of keys){
    if(container&&container[key]!==undefined&&container[key]!==null)return container[key];
  }
  return undefined;
}

function boolTone(value){
  if(typeof value!=='boolean')return 'warn';
  return value?'good':'bad';
}

function boolText(value,on='Aktiv',off='Inaktiv'){
  if(typeof value!=='boolean')return 'Nicht verfügbar';
  return value?on:off;
}

function renderDefenderTelemetryRows(push){
  const telemetry=state.defender;
  if(!telemetry){
    if(state.defenderError)push({name:'Defender-Detailtelemetrie',detail:'GET /api/v1/defender/telemetry',value:'Nicht verfügbar',valueDetail:state.defenderError,tone:'warn'});
    return;
  }
  if(telemetry.Available!==true){
    push({name:'Defender-Detailtelemetrie',detail:'GET /api/v1/defender/telemetry',value:'Noch keine Messung',valueDetail:String(telemetry.Reason||'Die Control Plane hat noch keinen Defender-Snapshot gemessen.'),tone:'warn'});
    return;
  }
  const status=telemetry.Status||{};
  const preference=telemetry.Preference||{};
  const asr=telemetry.AttackSurfaceReduction||{};
  const firewall=telemetry.Firewall||{};
  const threats=telemetry.Threats||{};
  const exclusions=telemetry.Exclusions||{};
  const signatureAge=defenderValue(status,'AntivirusSignatureAge');
  const signatureVersion=defenderValue(status,'AntivirusSignatureVersion');
  const signatureUpdated=defenderValue(status,'AntivirusSignatureLastUpdated');
  push({
    name:'Defender-Signaturen',
    detail:'Get-MpComputerStatus',
    value:signatureAge!==undefined?`${formatNumber(signatureAge)} Tage alt`:'Nicht verfügbar',
    valueDetail:[signatureVersion?`Version ${signatureVersion}`:'',signatureUpdated?`Stand ${formatTime(signatureUpdated)}`:''].filter(Boolean).join(' · ')||'Versions-/Zeitfeld nicht verfügbar',
    tone:typeof signatureAge==='number'?(signatureAge<=3?'good':'warn'):'warn',
    action:'hardening',
  });
  push({
    name:'Defender-Cloud, PUA & Samples',
    detail:'Get-MpPreference',
    value:`Cloud ${text(defenderValue(preference,'CloudBlockLevel'),'—')} · MAPS ${text(defenderValue(preference,'MAPSReporting'),'—')}`,
    valueDetail:`PUA ${text(defenderValue(preference,'PUAProtection'),'—')} · Samples ${text(defenderValue(preference,'SubmitSamplesConsent'),'—')}`,
    tone:'info',
    action:'hardening',
  });
  push({
    name:'Defender Angriffsfläche (gemessen)',
    detail:'ASR-Regelzustand',
    value:`${formatNumber(asr.EnabledCount)} blockierend · ${formatNumber(asr.AuditCount)} Audit`,
    valueDetail:`${formatNumber(asr.ConfiguredCount)} konfiguriert · ${formatNumber((asr.RecommendedMissing||[]).length)} empfohlene fehlen${asr.RulesTruncated?' · Liste begrenzt':''}`,
    tone:Number(asr.RecommendedMissing?.length||0)===0?'good':'warn',
    action:'hardening',
  });
  const profileStates=Array.isArray(firewall.Profiles)?firewall.Profiles:[];
  push({
    name:'Defender-Netzwerkschutz & Firewall',
    detail:'Gemessene Firewallprofile',
    value:`Netzwerkschutz ${text(defenderValue(preference,'NetworkProtection'),'—')} · CFA ${text(defenderValue(preference,'ControlledFolderAccess'),'—')}`,
    valueDetail:profileStates.length?profileStates.map(profile=>`${profile.Name||'?'}: ${profile.Enabled===true?'an':profile.Enabled===false?'aus':'unbekannt'}`).join(' · '):'Keine Firewallprofil-Messung verfügbar',
    tone:typeof firewall.EnabledProfileCount==='number'&&Number(firewall.EnabledProfileCount)>=Number(firewall.ProfileCount||0)?'good':'warn',
    action:'hardening',
  });
  push({
    name:'Defender-Bedrohungen & Ausschlüsse',
    detail:'Erkennungsinventar (nur Zähler)',
    value:threats.Available?`${formatNumber(threats.DetectionCount)} Erkennungen · ${formatNumber(threats.ActiveThreatCount)} aktiv`:'Bedrohungsinventar nicht verfügbar',
    valueDetail:exclusions.Available?`Ausschlüsse: ${formatNumber(exclusions.PathCount)} Pfade · ${formatNumber(exclusions.ProcessCount)} Prozesse · ${formatNumber(exclusions.ExtensionCount)} Endungen`:'Ausschlussinventar nicht verfügbar (Rechte oder Quelle fehlen).',
    tone:threats.Available&&Number(threats.ActiveThreatCount||0)===0?'good':'warn',
    action:'hardening',
  });
  push({
    name:'Defender-Telemetriequelle',
    detail:'Zeitpunkt & Quellen',
    value:`Stand ${formatTime(defenderValue(telemetry,'CapturedUtc'))}`,
    valueDetail:`${Array.isArray(telemetry.SourcesAttempted)?telemetry.SourcesAttempted.length:0} Quellen abgefragt · ComputerStatus ${telemetry.ComputerStatusAvailable?'ja':'nein'} · Preferences ${telemetry.PreferenceAvailable?'ja':'nein'}`,
    tone:'info',
  });
}

function readinessSummary(target){
  const result=state.readiness[target];
  if(!result)return {text:'Wird geprüft',tone:'warn'};
  if(result.ready)return {text:'Bereit',tone:'good'};
  const count=Array.isArray(result.blockers)?result.blockers.length:0;
  return {text:count?`${count} Voraussetzung${count===1?'':'en'} ${count===1?'fehlt':'fehlen'}`:'Nicht bereit',tone:'bad'};
}

function renderModes(){
  const host=byId('modeGrid');
  if(!host)return;
  const mhx=mhxFromStatus();
  const current=String(mhx.protectionMode||'monitor').toLowerCase();
  host.replaceChildren();
  MODE_ORDER.forEach((id,index)=>{
    const info=MODE_INFO[id];
    const ready=readinessSummary(id);
    const active=current===id;
    const card=node('article','mode-step');
    card.dataset.mode=id;
    if(active)card.dataset.active='true';
    const head=node('div','mode-step-head');
    const title=node('div');
    title.append(node('span','mode-step-index',`0${index+1} · ${info.label}`),node('h3','',info.title));
    head.append(title,pill(active?'AKTIV':ready.tone==='good'?'BEREIT':ready.tone==='bad'?'NICHT BEREIT':'PRÜFUNG',active?'good':ready.tone));
    const description=node('p','',info.detail);
    const consequences=node('ul','mode-step-consequences');
    for(const consequence of info.consequences){
      const item=node('li','',consequence);
      consequences.append(item);
    }
    const meta=node('div','mode-step-meta');
    meta.append(node('span','status-pill info',ready.text));
    if(active)meta.append(node('span','status-pill good','AKTIVER MODUS'));
    const actions=node('div','mode-step-actions');
    const button=node('button',`button ${active?'ghost':id==='guarded'?'primary':id==='sovereign'?'danger':'ghost'}`,active?'Aktiver Modus':`${info.title} aktivieren`);
    button.type='button';
    button.dataset.protection=id;
    if(active)button.disabled=true;
    if(!active)button.title=`${info.title}: Voraussetzungen werden bei Auswahl geprüft.`;
    const readinessButton=node('button','button quiet small','Voraussetzungen');
    readinessButton.type='button';
    readinessButton.addEventListener('click',()=>{void showReadiness(id)});
    actions.append(button,readinessButton);
    card.append(head,description,consequences,meta,actions);
    host.append(card);
  });
  renderActiveState();
}

function renderActiveState(){
  const mhx=mhxFromStatus();
  const current=String(mhx.protectionMode||'monitor').toLowerCase();
  const info=MODE_INFO[current]||MODE_INFO.monitor;
  setText('currentMode',info.label);
  setText('currentModeText',`${info.title}: ${info.summary} ${info.detail}`);
  setPill('protectionBadge',info.label,current==='sovereign'?'bad':current==='guarded'?'good':'warn');
  const health=String(mhx.protectionHealth||'STARTING');
  setPill('protectionHealth',health,health==='VERIFIED'?'good':'bad');
  setText('protectionVerified',mhx.protectionVerifiedUtc?`Verifiziert ${formatTime(mhx.protectionVerifiedUtc)}`:'Policy-Verifikation ausstehend');
}

function renderReadiness(rootElement,result){
  const root=rootElement;
  if(!root)return;
  root.classList.remove('empty-state');
  root.replaceChildren();
  if(result.ready){
    root.append(pill('✓ Alle serverseitigen Voraussetzungen erfüllt','good'));
  }
  for(const blocker of Array.isArray(result.blockers)?result.blockers:[]){
    const row=node('div','readiness-row');
    row.append(pill('×','bad'),node('span','',blocker));
    root.append(row);
  }
  for(const consequence of Array.isArray(result.consequences)?result.consequences:[]){
    const row=node('div','readiness-row');
    row.append(pill('→','info'),node('span','',consequence));
    root.append(row);
  }
  if(!root.childElementCount){
    root.append(node('p','muted','Keine weiteren Voraussetzungen gemeldet.'));
  }
}

export async function showReadiness(target){
  const label=MODE_INFO[target]?.title||target;
  setText('readinessTitle',`${label} — Voraussetzungen`);
  const root=byId('readiness');
  if(root){
    root.classList.remove('empty-state');
    root.replaceChildren(node('p','muted',`Voraussetzungen für ${label} werden serverseitig geprüft …`));
  }
  try{
    const result=await api(`/api/v1/protection/readiness?target=${encodeURIComponent(target)}`);
    state.readiness[target]=result;
    renderReadiness(root,result);
    renderModes();
    return result;
  }catch(error){
    if(root){
      root.replaceChildren();
      root.append(pill('!','bad'),node('span','',`Readiness-Abfrage fehlgeschlagen: ${error.message||error}`));
    }
    throw error;
  }
}

let pendingTarget='';
let modeDialogBound=false;
let protectionBusy=false;
let protectionTimer=null;
let protectionStartedAt=0;

export function bindProtectionDialogs(){
  if(modeDialogBound)return;
  modeDialogBound=true;
  byId('protectionConfirm')?.addEventListener('click',event=>{
    event.preventDefault();
    void confirmModeTransition();
  });
  const dialog=byId('protectionDialog');
  dialog?.addEventListener('cancel',event=>{
    if(protectionBusy)event.preventDefault();
  });
  dialog?.addEventListener('close',()=>{
    pendingTarget='';
    if(!protectionBusy)resetProtectionProgress();
  });
  byId('protectionReason')?.addEventListener('keydown',event=>{
    if(event.key==='Enter'){event.preventDefault();void confirmModeTransition();}
  });
}

function protectionElapsedText(elapsed){
  return elapsed<10000?`${(elapsed/1000).toFixed(1)} s`:`${Math.round(elapsed/1000)} s`;
}

function renderProtectionProgress(tone,title,detail,elapsed){
  const progress=byId('protectionProgress');
  const dialog=byId('protectionDialog');
  if(dialog)dialog.dataset.busy=tone==='busy'?'true':'false';
  if(dialog)dialog.setAttribute('aria-busy',tone==='busy'?'true':'false');
  if(!progress)return;
  progress.hidden=false;
  progress.dataset.tone=tone;
  setText('protectionProgressTitle',title);
  setText('protectionProgressDetail',detail);
  setText('protectionProgressElapsed',protectionElapsedText(elapsed));
}

function updateProtectionProgress(){
  const elapsed=performance.now()-protectionStartedAt;
  let title='Schutzstufe wird angewendet …';
  let detail='Die Schutzregeln werden serverseitig angewendet. Windows Defender, ASR und Firewall werden danach verifiziert.';
  if(elapsed>=6500){
    title='Abschlussprüfung läuft …';
    detail='Evidenz und Schutzstatus werden abschließend verifiziert. Der Dialog bestätigt den Wechsel, sobald die Control Plane fertig ist.';
  }else if(elapsed>=2500){
    title='Schutzregeln werden verifiziert …';
    detail='Windows Defender, ASR und Firewall werden gegen die Zielstufe geprüft. Das kann einige Sekunden dauern.';
  }
  renderProtectionProgress('busy',title,detail,elapsed);
}

function beginProtectionProgress(){
  protectionBusy=true;
  protectionStartedAt=performance.now();
  const reason=byId('protectionReason');
  const cancel=byId('protectionCancel');
  const confirm=byId('protectionConfirm');
  if(reason)reason.disabled=true;
  if(cancel)cancel.disabled=true;
  if(confirm){confirm.disabled=true;confirm.classList.add('loading');confirm.textContent='Wird angewendet …'}
  updateProtectionProgress();
  if(protectionTimer)clearInterval(protectionTimer);
  protectionTimer=setInterval(updateProtectionProgress,250);
}

function endProtectionProgress(tone,title,detail){
  if(protectionTimer){
    clearInterval(protectionTimer);
    protectionTimer=null;
  }
  const elapsed=protectionStartedAt?performance.now()-protectionStartedAt:0;
  renderProtectionProgress(tone,title,detail,elapsed);
  protectionBusy=false;
  const reason=byId('protectionReason');
  const cancel=byId('protectionCancel');
  const confirm=byId('protectionConfirm');
  if(reason)reason.disabled=false;
  if(cancel)cancel.disabled=false;
  if(confirm){confirm.disabled=false;confirm.classList.remove('loading');confirm.textContent='Bestätigen'}
}

function resetProtectionProgress(){
  if(protectionTimer){
    clearInterval(protectionTimer);
    protectionTimer=null;
  }
  protectionBusy=false;
  protectionStartedAt=0;
  const progress=byId('protectionProgress');
  if(progress){progress.hidden=true;delete progress.dataset.tone}
  const dialog=byId('protectionDialog');
  if(dialog){delete dialog.dataset.busy;dialog.setAttribute('aria-busy','false')}
  const reason=byId('protectionReason');
  const cancel=byId('protectionCancel');
  const confirm=byId('protectionConfirm');
  if(reason)reason.disabled=false;
  if(cancel)cancel.disabled=false;
  if(confirm){confirm.disabled=false;confirm.classList.remove('loading');confirm.textContent='Bestätigen'}
}

async function requestMode(target){
  if(!MODE_INFO[target])return;
  const current=String(mhxFromStatus().protectionMode||'monitor').toLowerCase();
  if(target===current){
    toast(`Der Modus ${MODE_INFO[target].label} ist bereits aktiv. Es wurde nichts geändert.`,'info');
    await showReadiness(target);
    return;
  }
  const result=await showReadiness(target);
  if(!result.ready){
    toast(`${MODE_INFO[target].title} ist noch nicht freigegeben. Die blockierenden Voraussetzungen stehen im Readiness-Bereich.`,'bad');
    byId('readiness')?.scrollIntoView({block:'center',behavior:'smooth'});
    return;
  }
  pendingTarget=target;
  setText('protectionDialogTitle',`${MODE_INFO[target].title} aktivieren`);
  const body=byId('protectionDialogBody');
  if(body){
    body.replaceChildren();
    body.append(node('p','',MODE_INFO[target].detail));
    const consequences=node('ul','');
    for(const consequence of [...MODE_INFO[target].consequences,...(Array.isArray(result.consequences)?result.consequences:[])]){
      consequences.append(node('li','',consequence));
    }
    body.append(consequences);
  }
  const reason=byId('protectionReason');
  if(reason)reason.value='';
  resetProtectionProgress();
  const dialog=byId('protectionDialog');
  try{if(dialog&&!dialog.open)dialog.showModal()}catch{/* dialog unavailable */}
  byId('protectionReason')?.focus();
}

async function confirmModeTransition(){
  if(protectionBusy)return;
  const target=pendingTarget;
  const reason=String(byId('protectionReason')?.value||'').trim();
  if(reason.length<8){
    toast('Bitte eine kurze Begründung mit mindestens 8 Zeichen angeben.','bad');
    return;
  }
  const confirmations={monitor:'RETURN TO MONITOR',guarded:'ACTIVATE GUARDED',sovereign:'SOVEREIGN DEFAULT DENY'};
  beginProtectionProgress();
  try{
    await api('/api/v1/mhx/mode',{method:'POST',json:{mode:target,confirmation:confirmations[target],reason}});
    endProtectionProgress('good','Schutzstufe aktiv und verifiziert',`${MODE_INFO[target].label} ist aktiv. Defender-, ASR- und Firewall-Regeln wurden serverseitig verifiziert.`);
    toast(`Schutzmodus ${MODE_INFO[target].label} ist aktiv und verifiziert.`,'good');
    try{await reloadProtection()}catch{/* the transition itself succeeded; refresh reports separately */}
    setTimeout(()=>{byId('protectionDialog')?.close()},700);
  }catch(error){
    endProtectionProgress('bad','Wechsel nicht abgeschlossen',String(error.message||error));
    toast(`Schutzmodus konnte nicht gewechselt werden: ${error.message||error}`,'bad');
    byId('protectionReason')?.focus();
  }
}

export async function selectProtectionMode(target){
  try{
    await requestMode(target);
  }catch(error){
    toast(`Readiness-Abfrage fehlgeschlagen: ${error.message||error}`,'bad');
  }
}

async function reloadProtection(){
  if(typeof state.onRefresh==='function'){
    await state.onRefresh();
    return;
  }
  if(state.status){
    await loadProtection(state.status,{onRefresh:state.onRefresh,onModeChanged:state.onModeChanged});
  }
}

export async function loadProtection(status,options={}){
  state.status=status;
  state.onRefresh=options.onRefresh||state.onRefresh;
  state.onModeChanged=options.onModeChanged||state.onModeChanged;
  rememberStatus(status);
  renderActiveState();
  renderModes();
  renderControls();
  const [readinessMonitor,readinessGuarded,readinessSovereign,components,defender]=await Promise.allSettled([
    api('/api/v1/protection/readiness?target=monitor'),
    api('/api/v1/protection/readiness?target=guarded'),
    api('/api/v1/protection/readiness?target=sovereign'),
    getHardeningComponents(),
    getDefenderTelemetry(),
  ]);
  for(const [target,result] of [['monitor',readinessMonitor],['guarded',readinessGuarded],['sovereign',readinessSovereign]]){
    if(result.status==='fulfilled')state.readiness[target]=result.value;
  }
  if(components.status==='fulfilled'&&components.value.ok)state.components=Array.isArray(components.value.data)?components.value.data:[];
  if(defender.status==='fulfilled'&&defender.value.ok){
    state.defender=defender.value.data;
    state.defenderError='';
  }else if(defender.status==='fulfilled'){
    state.defender=null;
    state.defenderError=defender.value.message||'Telemetrie nicht verfügbar';
  }else{
    state.defender=null;
    state.defenderError='Telemetrie nicht verfügbar';
  }
  renderModes();
  renderControls();
  const current=String(mhxFromStatus().protectionMode||'monitor').toLowerCase();
  if(state.readiness[current]){
    setText('readinessTitle',`${MODE_INFO[current]?.title||current} — Voraussetzungen`);
    renderReadiness(byId('readiness'),state.readiness[current]);
  }
  bindProtectionDialogs();
  await ensureSettingsProbe();
  renderProfileStudioState();
  await initProfileStudio();
  return state;
}

export async function recoverProfileStudio(){
  await refreshProfileStudio();
}
