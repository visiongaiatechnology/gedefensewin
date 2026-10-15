// STATUS: DIAMANT VGT SUPREME
'use strict';
import{startHealthCheck}from'./startup-health.js';
import{initWindowControls}from'./window-controls.js';
import{api,exchangeBootstrap,setOperatorToken}from'./api.js';import{byId,setText,toast}from'./dom.js';import{enforceBalanced,enforceComponent,lastKnownStatus,loadAudit,loadEvidence,loadHardening,loadIntegrity,loadNetwork,loadKinetic,loadTraffic,loadOverview,loadProtection,loadXdr,readiness,reconcilePolicy,rollback,runXdr,scanIntegrity,setProtectionMode,setKineticMode,syncFeeds,toggleIntegrity,updateProtectedNetworks,verifyEvidence}from'./views.js';
const pages=new Set(['overview','protection','xdr','network','kinetic','integrity','hardening','audit','evidence','system']);let active='overview';let refreshBusy=false;let pendingProtection='';let pendingConfirm=null;
const titles={overview:'Übersicht',protection:'Protection Center',xdr:'MHX XDR',network:'Netzwerk',kinetic:'Kinetic Defense',integrity:'Integrität',hardening:'Härtung',audit:'SafetySys Audit',evidence:'Evidenz',system:'System'};
function errorMessage(error){const id=error?.errorId?` · Fehler-ID ${error.errorId}`:'';return `${error?.message||'Operation fehlgeschlagen'}${id}`}
function handleError(error){toast(errorMessage(error),'bad');if(error?.status===401)byId('authDialog').showModal()}
async function loadPage(page){if(page==='overview'||page==='system')return loadOverview();if(page==='protection')return loadProtection();if(page==='xdr')return loadXdr();if(page==='network')return loadNetwork();if(page==='kinetic')return loadKinetic();if(page==='integrity')return loadIntegrity();if(page==='hardening')return loadHardening();if(page==='audit')return loadAudit(false);if(page==='evidence')return loadEvidence()}
async function activate(page){active=pages.has(page)?page:'overview';document.querySelectorAll('[data-page]').forEach(n=>{const on=n.dataset.page===active;n.hidden=!on;n.classList.toggle('active',on)});document.querySelectorAll('[data-view]').forEach(n=>n.classList.toggle('active',n.dataset.view===active));setText('viewTitle',titles[active]);byId('sidebar').classList.remove('open');history.replaceState(null,'',`#${active}`);try{await loadPage(active)}catch(error){handleError(error)}}
document.querySelectorAll('[data-view]').forEach(b=>b.addEventListener('click',()=>activate(b.dataset.view)));document.querySelectorAll('[data-go]').forEach(b=>b.addEventListener('click',()=>activate(b.dataset.go)));byId('menuToggle').addEventListener('click',()=>byId('sidebar').classList.toggle('open'));
byId('authButton').addEventListener('click',()=>byId('authDialog').showModal());byId('authSubmit').addEventListener('click',async event=>{event.preventDefault();const token=byId('operatorKey').value.trim();if(!token)return;setOperatorToken(token);try{await api('/api/v1/status');byId('operatorKey').value='';byId('authDialog').close();toast('Operator-Sitzung entsperrt.','good');initWindowControls();await startHealthCheck();await activate(active)}catch(error){setOperatorToken('');handleError(error)}});
document.querySelectorAll('[data-protection]').forEach(button=>button.addEventListener('click',async()=>{const target=button.dataset.protection;try{const result=await readiness(target);if(!result.ready){toast('Diese Schutzstufe ist noch nicht freigegeben.','bad');return}pendingProtection=target;setText('protectionDialogTitle',`${target.toUpperCase()} aktivieren`);const body=byId('protectionDialogBody');body.replaceChildren();for(const consequence of result.consequences||[]){const p=document.createElement('p');p.textContent=`• ${consequence}`;body.append(p)}byId('protectionReason').value='';byId('protectionDialog').showModal()}catch(error){handleError(error)}}));
byId('protectionConfirm').addEventListener('click',async event=>{event.preventDefault();const reason=byId('protectionReason').value.trim();if(reason.length<8){toast('Bitte eine kurze Begründung mit mindestens 8 Zeichen angeben.','bad');return}try{await setProtectionMode(pendingProtection,reason);byId('protectionDialog').close();pendingProtection=''}catch(error){handleError(error)}});
const triggerPolicyReconcile=async()=>{await startHealthCheck();try{await loadPage(active)}catch(error){handleError(error)}};
for(const id of ['reconcilePolicy','heroReconcilePolicy'])byId(id)?.addEventListener('click',()=>{void triggerPolicyReconcile()});
let pendingKinetic='';
for(const [id,mode] of [['kineticArm','armed'],['kineticDisarm','observe']])byId(id).addEventListener('click',()=>{pendingKinetic=mode;setText('kineticDialogTitle',mode==='armed'?'Threat-IP-Korrelation scharfschalten':'Auf Observe-Only zurückstellen');setText('kineticDialogExplanation',mode==='armed'?'Voraussetzung: verifizierte Threat-IP-WFP-Regelgeneration und Windows-Telemetrie. Keine neuen dynamischen Kinetic-Sperrregeln.':'Kinetic stellt die zusätzliche Korrelation zurück; bestehende TI-WFP-Policies bleiben unverändert.');byId('kineticReason').value='';byId('kineticDialog').showModal()});
byId('kineticConfirm').addEventListener('click',async ev=>{ev.preventDefault();const reason=byId('kineticReason').value.trim();if(reason.length<8){toast('Bitte Begründung mit mindestens 8 Zeichen.','bad');return}try{await setKineticMode(pendingKinetic,reason);byId('kineticDialog').close();pendingKinetic=''}catch(e){handleError(e)}});
byId('syncFeeds').addEventListener('click',()=>syncFeeds().catch(handleError));byId('runXdr').addEventListener('click',()=>runXdr().catch(handleError));byId('protectedNetworks').addEventListener('input',event=>{event.currentTarget.dataset.dirty='true'});byId('updateProtectedNetworks').addEventListener('click',()=>updateProtectedNetworks().catch(handleError));byId('integrityToggle').addEventListener('click',()=>toggleIntegrity().catch(handleError));byId('integrityScan').addEventListener('click',()=>scanIntegrity().catch(handleError));byId('refreshHardening').addEventListener('click',()=>loadHardening().catch(handleError));byId('enforceBalanced').addEventListener('click',()=>confirmAction('Empfohlenes Profil anwenden','GeDefense wendet die idempotente Enterprise-Balanced-Härtung an.',enforceBalanced));byId('rollback').addEventListener('click',()=>confirmAction('Hardening zurücksetzen','Der zuletzt gesicherte Vorzustand wird wiederhergestellt.',rollback));byId('runAudit').addEventListener('click',()=>loadAudit(true).catch(handleError));byId('verifyEvidence').addEventListener('click',()=>verifyEvidence().catch(handleError));byId('hardeningComponents').addEventListener('click',event=>{const button=event.target.closest('[data-component]');if(button)confirmAction('Komponente aktivieren',`Sicherheitskomponente ${button.dataset.component} aktivieren?`,()=>enforceComponent(button.dataset.component))});
function confirmAction(title,text,action){pendingConfirm=action;setText('confirmTitle',title);setText('confirmText',text);byId('confirmDialog').showModal()}
byId('confirmAction').addEventListener('click',async event=>{event.preventDefault();const action=pendingConfirm;pendingConfirm=null;byId('confirmDialog').close();if(!action)return;try{await action()}catch(error){handleError(error)}});
globalThis.setInterval(()=>setText('clock',new Date().toLocaleTimeString('de-DE')),1000);
globalThis.setInterval(async()=>{if(document.hidden||active!=='overview')return;try{await loadTraffic()}catch{}},2000);globalThis.setInterval(async()=>{if(document.hidden||refreshBusy)return;refreshBusy=true;try{if(active==='overview'||active==='system')await loadOverview();else if(active==='protection')await loadProtection();else if(active==='xdr')await loadXdr();else if(active==='network')await loadNetwork();else if(active==='kinetic')await loadKinetic();else if(active==='integrity')await loadIntegrity()}catch{}finally{refreshBusy=false}},6000);
async function initialize(){
 const fragment=new URLSearchParams(location.hash.slice(1));
 const bootstrap=fragment.get('bootstrap');
 let authenticated=false;
 if(bootstrap){
  history.replaceState(null,'',location.pathname+'#overview');
  try{await exchangeBootstrap(bootstrap.trim());authenticated=true}catch(error){handleError(error)}
 }else{
  try{await api('/api/v1/mhx/status');authenticated=true}catch(error){if(error.status===401)handleError(error);else{await startHealthCheck();return}}
 }
 const requested=location.hash.slice(1);
 if(authenticated){
  initWindowControls();
  const startup=startHealthCheck();
  await activate(pages.has(requested)?requested:'overview');
  await startup;
  await loadPage(active);
 }
}
void initialize().catch(handleError);
