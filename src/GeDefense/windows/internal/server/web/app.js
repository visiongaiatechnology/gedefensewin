// STATUS: DIAMANT VGT SUPREME
'use strict';
/** GeDefense Windows Beta V5 shell.
 *
 *  Single-page console: navigation, hash routing, operator authentication,
 *  bounded polling and the startup readiness gate. All rendering stays in the
 *  view controllers; the shell owns lifecycle and operator intents.
 */
import {
  api, clearOperatorToken, exchangeBrowserSession, logoutSession, setOperatorToken,
} from './api.js';
import {
  announce, byId, openDialog, requestConfirm, requestReason, setText, toast,
} from './dom.js';
import {startHealthCheck, initializeStartup, silentHealthRefresh, bindHealthRefreshButton} from './startup-health.js';
import {collectNotifications, initNotificationCenter, openNotificationCenter} from './notifications.js';
import {initWindowControls} from './window-controls.js';
import {
  enforceBalanced,
  loadAudit,
  loadEvidence,
  loadHardening,
  loadIntegrity,
  loadKinetic,
  loadNetwork,
  loadOverview,
  loadProtection,
  loadShellStatus,
  loadThreatIntel,
  loadTraffic,
  loadXdr,
  openAuditDialogAndRun,
  reconcilePolicy,
  reloadEvidence,
  rollback,
  runXdr,
  scanIntegrity,
  setEvidencePage,
  setKineticMode,
  tickThreatIntelCountdown,
  toggleIntegrity,
  updateProtectedNetworks,
  verifyEvidence,
  bindAuditDialog,
  chooseProtectionMode,
  syncFeeds,
  closeHardeningDetail,
  applyHardeningDetail,
  analysisPage,
} from './views.js';
import {
  bindKineticSettingsPanel,
  bindMhxSettingsPanel,
  bindThreatIntelSettingsPanel,
} from './settings.js';
import {bindTitan, loadTitan} from './titan.js';
import {locale} from './i18n.js';

const pages=new Set(['overview','titan','protection','threat-intel','xdr','network','kinetic','integrity','hardening','audit','evidence','system']);
const pageMeta={
  overview:{title:'Übersicht',subtitle:'Schutzlage, Telemetrie und Evidenz dieser Windows-Instanz.'},
  titan:{title:'Titan Control Center',subtitle:'Sovereign Endpoint Integrity: Ingress, Autorisierung, Quarantäne und Beweise.'},
  protection:{title:'Protection Center',subtitle:'Schutzstufen, Readiness, aktive Kontrollen und eigene Profile.'},
  'threat-intel':{title:'Threat Intelligence',subtitle:'Feeds, Synchronisationszyklus, Enforcement-Generation und geschützte Netze.'},
  xdr:{title:'MHX XDR',subtitle:'Prozess-, Defender- und Netzwerk-Korrelation mit überprüfbaren Antworten.'},
  network:{title:'Netzwerk',subtitle:'Remote-Ziel, Owning PID und Prozesskontext aus nativer Windows-Telemetrie.'},
  kinetic:{title:'Kinetic Defense',subtitle:'Operator-gesteuerte Burst-Korrelation und persistierte Schwellen.'},
  integrity:{title:'Integrität',subtitle:'Atomare SHA-256-Baseline und erkannte Dateiveränderungen.'},
  hardening:{title:'Härtung',subtitle:'Vollständiger Kontrollkatalog mit Live-Messung und idempotenter Anwendung.'},
  audit:{title:'SafetySys Audit',subtitle:'Read-only Windows-Baseline-Audit mit sofortigem Fortschritts-Feedback.'},
  evidence:{title:'Evidenz',subtitle:'HMAC-verkettete Ereignisse, serverseitig paginiert.'},
  system:{title:'System',subtitle:'Lokale GeDefense-Instanz, Bereitschaft und Plattformzustand.'},
};
const liveRefreshPages=new Set(['overview','titan','protection','xdr','network','kinetic','integrity','threat-intel','system']);
const trafficPages=new Set(['overview']);

let active='overview';
let refreshBusy=false;
let authenticated=false;
let initialized=false;
let pendingKinetic='';

function errorMessage(error){
  const id=error?.errorId?` · Fehler-ID ${error.errorId}`:'';
  return `${error?.message||'Operation fehlgeschlagen'}${id}`;
}

function handleError(error){
  toast(errorMessage(error),'bad');
  announce(errorMessage(error));
  if(error?.status===401){
    clearOperatorToken();
    authenticated=false;
    openDialog('authDialog');
  }
}

function activePage(){
  return document.querySelector('[data-page].active')?.dataset.page||active;
}

function setMobileNavigation(open){
  const sidebar=byId('sidebar');
  const toggle=byId('menuToggle');
  if(sidebar)sidebar.classList.toggle('open',open);
  if(toggle)toggle.setAttribute('aria-expanded',String(open));
}

async function loadPage(page){
  if(page==='overview'||page==='system')return loadOverview();
  if(page==='titan')return loadTitan();
  if(page==='protection')return loadProtection();
  if(page==='threat-intel')return loadThreatIntel();
  if(page==='xdr')return loadXdr();
  if(page==='network')return loadNetwork();
  if(page==='kinetic')return loadKinetic();
  if(page==='integrity')return loadIntegrity();
  if(page==='hardening')return loadHardening();
  if(page==='audit')return loadAudit(false);
  if(page==='evidence')return loadEvidence(0);
  return undefined;
}

function updateNavigation(page){
  document.querySelectorAll('[data-view]').forEach(button=>{
    const current=button.dataset.view===page;
    button.classList.toggle('active',current);
    if(current)button.setAttribute('aria-current','page');
    else button.removeAttribute('aria-current');
  });
}

function focusViewHeading(){
  const heading=byId('viewTitle');
  if(heading&&typeof heading.focus==='function'){
    if(!heading.hasAttribute('tabindex'))heading.setAttribute('tabindex','-1');
    heading.focus({preventScroll:true});
  }
}

async function activate(page,options={}){
  active=pages.has(page)?page:'overview';
  document.querySelectorAll('[data-page]').forEach(section=>{
    const shown=section.dataset.page===active;
    section.hidden=!shown;
    section.classList.toggle('active',shown);
  });
  updateNavigation(active);
  const meta=pageMeta[active];
  setText('viewTitle',meta.title);
  setText('viewSubtitle',meta.subtitle);
  document.title=`GeDefense Titan · ${meta.title}`;
  setMobileNavigation(false);
  if(!options.silent)history.replaceState(null,'',`#${active}`);
  if(!options.keepFocus)focusViewHeading();
  announce(`${meta.title} geöffnet.`);
  if(options.skipLoad)return;
  try{
    await loadPage(active);
  }catch(error){
    handleError(error);
  }
}

/* ------------------------------------------------------------------ */
/* Static operator controls                                            */
/* ------------------------------------------------------------------ */
function on(id,event,handler){
  const element=byId(id);
  if(element)element.addEventListener(event,handler);
}

async function triggerPolicyReconcile(){
  const buttons=[byId('reconcilePolicy'),byId('heroReconcilePolicy')].filter(Boolean);
  for(const button of buttons){button.disabled=true;button.classList.add('loading')}
  try{
    await reconcilePolicy();
    toast('Policy synchronisiert und verifiziert.','good');
    await activate(active,{keepFocus:true});
  }catch(error){
    handleError(error);
  }finally{
    for(const button of buttons){button.disabled=false;button.classList.remove('loading')}
  }
}

async function confirmPolicyAction({title,text,label,action}){
  // Policy-changing actions require an operator reason server-side as well; the
  // reason dialog is the conscious step-up for this local single-operator model.
  const reason=await requestReason({title,text,label:'Begründung der Änderung',confirmLabel:label,tone:'danger'});
  if(!reason)return;
  try{
    await action(reason);
  }catch(error){
    handleError(error);
  }
}

function bindStaticControls(){
  on('menuToggle','click',()=>{
    const sidebar=byId('sidebar');
    setMobileNavigation(!sidebar?.classList.contains('open'));
  });

  document.addEventListener('click',event=>{
    const navigation=event.target.closest('[data-go]');
    if(navigation){
      event.preventDefault();
      void activate(navigation.dataset.go);
      return;
    }
    const viewButton=event.target.closest('[data-view]');
    if(viewButton){
      event.preventDefault();
      void activate(viewButton.dataset.view);
      return;
    }
    const protectionButton=event.target.closest('[data-protection]');
    if(protectionButton&&!protectionButton.disabled){
      event.preventDefault();
      void chooseProtectionMode(protectionButton.dataset.protection);
    }
  });

  on('heroReconcilePolicy','click',()=>{void triggerPolicyReconcile()});
  on('reconcilePolicy','click',()=>{void triggerPolicyReconcile()});

  for(const id of ['healthRefreshButton','protectionHealthCheck','systemHealthCheck'])on(id,'click',()=>{void startHealthCheck()});

  on('authButton','click',()=>openDialog('authDialog'));
  on('logoutButton','click',async()=>{
    try{
      await logoutSession();
      toast('Sitzung wurde serverseitig widerrufen.','good');
    }catch(error){
      // A rejected/absent session is still a logged-out client.
      if(error?.status!==401)toast(errorMessage(error),'bad');
    }finally{
      clearOperatorToken();
      authenticated=false;
      openDialog('authDialog');
    }
  });
  on('authSubmit','click',async event=>{
    event.preventDefault();
    const token=String(byId('operatorKey')?.value||'').trim();
    if(!token)return;
    setOperatorToken(token);
    try{
      await api('/api/v1/status');
      if(byId('operatorKey'))byId('operatorKey').value='';
      byId('authDialog')?.close();
      authenticated=true;
      toast('Operator-Sitzung entsperrt.','good');
      initWindowControls();
      bindHealthRefreshButton();
      void loadShellStatus();
      void initializeStartup();
      await activate(active,{silent:true});
    }catch(error){
      setOperatorToken('');
      handleError(error);
    }
  });

  on('kineticArm','click',()=>openKineticDialog('armed'));
  on('kineticDisarm','click',()=>openKineticDialog('observe'));
  on('kineticConfirm','click',async event=>{
    event.preventDefault();
    const reason=String(byId('kineticReason')?.value||'').trim();
    if(reason.length<8){
      toast('Bitte Begründung mit mindestens 8 Zeichen angeben.','bad');
      return;
    }
    const mode=pendingKinetic;
    try{
      await setKineticMode(mode,reason);
      byId('kineticDialog')?.close();
      pendingKinetic='';
      await activate('kinetic',{keepFocus:true,silent:true});
    }catch(error){
      handleError(error);
    }
  });

  on('syncFeeds','click',()=>{void syncFeeds()});
  on('runXdr','click',()=>{void runXdr()});
  on('protectedNetworks','input',event=>{event.currentTarget.dataset.dirty='true'});
  on('updateProtectedNetworks','click',()=>{void updateProtectedNetworks().catch(handleError)});
  on('integrityToggle','click',()=>{void toggleIntegrity().catch(handleError)});
  on('integrityScan','click',()=>{void scanIntegrity().catch(handleError)});
  on('refreshHardening','click',()=>{void loadHardening().catch(handleError)});
  on('enforceBalanced','click',()=>confirmPolicyAction({
    title:'Empfohlenes Härtungsprofil anwenden',
    text:'GeDefense wendet die idempotente Enterprise-Balanced-Härtung an. Jede Änderung wird als Sicherheits-Transaktion protokolliert und ist reversibel.',
    label:'Profil anwenden',
    action:enforceBalanced,
  }));
  on('rollback','click',()=>confirmPolicyAction({
    title:'Hardening zurücksetzen',
    text:'Der zuletzt gesicherte Vorzustand wird wiederhergestellt. Diese Aktion verändert Sicherheitseinstellungen, wird protokolliert und ist reversibel.',
    label:'Rollback ausführen',
    action:rollback,
  }));
  on('runAudit','click',()=>{void openAuditDialogAndRun().catch(handleError)});
  on('verifyEvidence','click',()=>{void verifyEvidence().catch(handleError)});
  on('evidenceRefresh','click',()=>{void reloadEvidence().catch(handleError)});
  on('evidencePrev','click',()=>{void setEvidencePage(-1).catch(handleError)});
  on('evidenceNext','click',()=>{void setEvidencePage(1).catch(handleError)});
  on('analysisPrev','click',()=>analysisPage(-1));
  on('analysisNext','click',()=>analysisPage(1));

  on('hardeningDetailClose','click',closeHardeningDetail);
  on('hardeningDetailDismiss','click',closeHardeningDetail);
  on('hardeningDetailApply','click',()=>{void applyHardeningDetail().catch(handleError)});

  bindAuditDialog();
  bindMhxSettingsPanel();
  bindKineticSettingsPanel();
  bindThreatIntelSettingsPanel();
  bindTitan();
  bindHealthRefreshButton();

  document.addEventListener('keydown',event=>{
    if(event.key==='Escape'){
      setMobileNavigation(false);
    }
  });

  initSidebarKeyboardNavigation();
  initHashRouting();
}

function openKineticDialog(mode){
  pendingKinetic=mode;
  setText('kineticDialogTitle',mode==='armed'?'Threat-IP-Korrelation scharfschalten':'Auf Observe-Only zurückstellen');
  setText('kineticDialogExplanation',mode==='armed'
    ?'Voraussetzung: verifizierte Threat-IP-WFP-Regelgeneration und Windows-Telemetrie. Es werden keine neuen dynamischen Kinetic-Sperrregeln installiert.'
    :'Kinetic stellt die zusätzliche Korrelation zurück; bestehende Threat-IP-WFP-Policies bleiben unverändert.');
  const reason=byId('kineticReason');
  if(reason)reason.value='';
  const dialog=byId('kineticDialog');
  try{if(dialog&&!dialog.open)dialog.showModal()}catch{/* dialog unavailable */}
  reason?.focus();
}

function initSidebarKeyboardNavigation(){
  const sidebar=byId('sidebar');
  const nav=sidebar?.querySelector('nav');
  if(!nav)return;
  const items=()=>[...nav.querySelectorAll('.nav')];
  nav.addEventListener('keydown',event=>{
    const buttons=items();
    const index=buttons.indexOf(document.activeElement);
    if(index<0)return;
    if(event.key==='ArrowDown'||event.key==='ArrowUp'){
      event.preventDefault();
      const next=event.key==='ArrowDown'?(index+1)%buttons.length:(index-1+buttons.length)%buttons.length;
      buttons[next]?.focus();
    }else if(event.key==='Home'){
      event.preventDefault();
      buttons[0]?.focus();
    }else if(event.key==='End'){
      event.preventDefault();
      buttons.at(-1)?.focus();
    }
  });
}

function initHashRouting(){
  globalThis.addEventListener('hashchange',()=>{
    const target=location.hash.slice(1);
    if(pages.has(target)&&target!==active)void activate(target);
  });
}

/* ------------------------------------------------------------------ */
/* Polling                                                             */
/* ------------------------------------------------------------------ */
function startPolling(){
  globalThis.setInterval(()=>setText('clock',new Date().toLocaleTimeString(locale())),1000);
  globalThis.setInterval(()=>{tickThreatIntelCountdown()},1000);

  globalThis.setInterval(async()=>{
    if(document.hidden)return;
    try{await loadShellStatus()}catch{/* shell badge keeps last known value */}
  },30000);

  globalThis.setInterval(async()=>{
    if(document.hidden||!trafficPages.has(activePage()))return;
    try{await loadTraffic()}catch{/* transient; overview refresh reports state */}
  },2000);

  globalThis.setInterval(async()=>{
    if(document.hidden||refreshBusy)return;
    if(!liveRefreshPages.has(activePage()))return;
    refreshBusy=true;
    try{
      const page=activePage();
      if(page==='overview'||page==='system')await loadOverview();
      else if(page==='titan')await loadTitan({refresh:true});
      else if(page==='protection')await loadProtection();
      else if(page==='xdr')await loadXdr({includeSettings:false});
      else if(page==='network')await loadNetwork();
      else if(page==='kinetic')await loadKinetic({includeSettings:false});
      else if(page==='integrity')await loadIntegrity();
      else if(page==='threat-intel')await loadThreatIntel({includeSettings:false});
    }catch{
      /* Background refresh stays silent; explicit operator actions report errors. */
    }finally{
      refreshBusy=false;
    }
  },6000);
}

/* ------------------------------------------------------------------ */
/* Initialization                                                      */
/* ------------------------------------------------------------------ */
async function initialize(){
  if(initialized)return;
  initialized=true;
  bindStaticControls();
  initNotificationCenter({onNavigate:page=>{void activate(page)}});
  startPolling();
  // No session credential is accepted from the document URL or from process
  // arguments. The Center's launcher registers this browser process server-side
  // and the exchange is bound to that peer process (AN-FIND-002/UI-FIND-004).
  try{
    await api('/api/v1/mhx/status');
    authenticated=true;
  }catch(error){
    if(error?.status===401){
      try{
        await exchangeBrowserSession();
        authenticated=true;
      }catch{
        openDialog('authDialog');
      }
    }
  }
  const requested=location.hash.slice(1);
  if(authenticated){
    initWindowControls();
    void loadShellStatus();
    void initializeStartup();
    await activate(pages.has(requested)?requested:'overview',{silent:true});
    void collectNotifications().catch(()=>{});
  }else{
    await activate(pages.has(requested)?requested:'overview',{silent:true,skipLoad:true});
  }
}

void initialize().catch(handleError);

export {activePage, silentHealthRefresh, openNotificationCenter, requestConfirm};
