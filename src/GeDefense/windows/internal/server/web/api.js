// STATUS: DIAMANT VGT SUPREME
'use strict';
/** Authenticated control-plane client. The operator token lives in memory only. */
let operatorToken = '';

export function setOperatorToken(value){operatorToken=String(value||'').trim()}
export function clearOperatorToken(){operatorToken=''}
export function hasOperatorToken(){return operatorToken.length>0}

function requestID(){
  if(globalThis.crypto?.randomUUID)return globalThis.crypto.randomUUID();
  const b=new Uint8Array(16);
  globalThis.crypto.getRandomValues(b);
  b[6]=(b[6]&15)|64;b[8]=(b[8]&63)|128;
  const h=[...b].map(x=>x.toString(16).padStart(2,'0')).join('');
  return `${h.slice(0,8)}-${h.slice(8,12)}-${h.slice(12,16)}-${h.slice(16,20)}-${h.slice(20)}`;
}

export class APIError extends Error{
  constructor(message,id,status){super(message);this.name='APIError';this.errorId=id||'';this.status=status||0}
}

export async function api(path,options={}){
  const method=String(options.method||'GET').toUpperCase();
  const headers=new Headers({Accept:'application/json'});
  if(operatorToken)headers.set('Authorization',`Bearer ${operatorToken}`);
  let body;
  if(Object.prototype.hasOwnProperty.call(options,'json')){headers.set('Content-Type','application/json');body=JSON.stringify(options.json)}
  if(method!=='GET'&&method!=='HEAD')headers.set('X-VGT-Request-ID',requestID());
  const response=await fetch(path,{method,headers,body,credentials:'same-origin',cache:'no-store',signal:options.signal});
  const payload=await response.json().catch(()=>({error:'Ungültige Serverantwort'}));
  if(!response.ok){
    // A rejected operator token is useless from this point on: drop it from
    // memory so a stale credential is never replayed and the shell can open the
    // operator dialog (UI-FIND-005).
    if(response.status===401)clearOperatorToken();
    throw new APIError(String(payload.error||`HTTP ${response.status}`),String(payload.errorId||''),response.status);
  }
  return payload;
}

/**
 * Tolerant request for endpoints that may not exist yet (planned V5 APIs).
 * 401 is re-thrown so the shell can open the operator dialog. Every other
 * failure resolves as an explicit, honest availability result.
 */
export async function optionalApi(path,options={}){
  try{
    return {ok:true,data:await api(path,options)};
  }catch(error){
    if(error?.status===401)throw error;
    const status=Number(error?.status||0);
    const unavailable=!status||[404,405,501,502,503].includes(status);
    return {ok:false,status,message:String(error?.message||'Control Plane nicht erreichbar'),unavailable};
  }
}

export async function exchangeBootstrap(code){
  const response=await fetch('/api/v1/session/exchange',{method:'POST',headers:{'Content-Type':'application/json','X-VGT-Request-ID':requestID()},body:JSON.stringify({code}),credentials:'same-origin',cache:'no-store'});
  const payload=await response.json().catch(()=>({error:'Bootstrap-Sitzung wurde abgelehnt'}));
  if(!response.ok)throw new APIError(String(payload.error||'Bootstrap-Sitzung wurde abgelehnt'),String(payload.errorId||''),response.status);
  return payload;
}

/**
 * Establish the browser session without any URL credential. The launcher already
 * registered this browser process server-side (AN-FIND-002/UI-FIND-004); a short
 * retry covers the millisecond race between browser start and registration.
 * No bootstrap secret ever appears in the browser command line or document URL.
 */
export async function exchangeBrowserSession({attempts=8,delayMs=300}={}){
  let lastError=new Error('Bootstrap-Sitzung wurde abgelehnt');
  for(let attempt=0;attempt<attempts;attempt++){
    const response=await fetch('/api/v1/session/exchange',{
      method:'POST',
      headers:{'Content-Type':'application/json','X-VGT-Request-ID':requestID()},
      body:'{}',
      credentials:'same-origin',
      cache:'no-store',
    });
    const payload=await response.json().catch(()=>({error:'Bootstrap-Sitzung wurde abgelehnt'}));
    if(response.ok)return payload;
    lastError=new APIError(String(payload.error||'Bootstrap-Sitzung wurde abgelehnt'),String(payload.errorId||''),response.status);
    // Only the short registration race is retried; a definitive rejection ends the loop.
    if(response.status!==401&&response.status!==409)break;
    await new Promise(resolve=>globalThis.setTimeout(resolve,delayMs));
  }
  throw lastError;
}

/** Revoke this browser session server-side and expire the cookie. */

export async function logoutSession(){
  return api('/api/v1/session/logout',{method:'POST',json:{},signal:AbortSignal.timeout(15000)});
}

/** Server-side session facts (client, scopes, remaining lifetime). */
export async function getSessionState(){
  return api('/api/v1/session/state',{signal:AbortSignal.timeout(15000)});
}

export const getOverviewThreatMap = (limit=250,events=120,signal) =>
  api(`/api/v1/overview/threat-map?limit=${encodeURIComponent(limit)}&events=${encodeURIComponent(events)}`,{signal});

/* ------------------------------------------------------------------ */
/* V5 planned endpoints (graceful fallback when not wired yet)          */
/* ------------------------------------------------------------------ */
export const V5_ENDPOINTS={
  startupState:'/api/v1/startup/state',
  startupAck:'/api/v1/startup/ack',
  evidencePage:'/api/v1/evidence/page',
  hardeningCatalog:'/api/v1/hardening/catalog',
  hardeningSettings:'/api/v1/hardening/settings',
  settings:'/api/v1/settings',
  settingsCatalog:'/api/v1/settings/catalog',
  settingsProfiles:'/api/v1/settings/profiles',
  mhxSettings:'/api/v1/mhx/settings',
  mhxApplicationDenies:'/api/v1/mhx/application-denies',
  kineticSettings:'/api/v1/kinetic/settings',
  threatIntelStatus:'/api/v1/threat-intel/status',
  threatIntelSettings:'/api/v1/threat-intel/settings',
  feedPolicy:'/api/v1/mhx/threat-intelligence/feed-policy',
  notifications:'/api/v1/notifications',
  defenderTelemetry:'/api/v1/defender/telemetry',
};

export function getStartupState(signal){
  return optionalApi(V5_ENDPOINTS.startupState,{signal});
}

export function acknowledgeStartup(){
  return optionalApi(V5_ENDPOINTS.startupAck,{method:'POST',json:{},signal:AbortSignal.timeout(15000)});
}

export function getEvidencePage(offset=0,limit=20){
  const safeLimit=Math.max(1,Math.min(100,Number(limit)||20));
  const safeOffset=Math.max(0,Number(offset)||0);
  return optionalApi(`${V5_ENDPOINTS.evidencePage}?limit=${safeLimit}&offset=${safeOffset}`);
}

export function getEvidenceSnapshot(){
  return optionalApi('/api/v1/evidence');
}

export function getHardeningComponents(){
  return optionalApi('/api/v1/hardening/components');
}

export function getHardeningCatalog(){
  return optionalApi(V5_ENDPOINTS.hardeningCatalog);
}

export function getSettings(){
  return optionalApi(V5_ENDPOINTS.settings);
}

export function getSettingsCatalog(){
  return optionalApi(V5_ENDPOINTS.settingsCatalog);
}

export function getSettingsProfiles(){
  return optionalApi(V5_ENDPOINTS.settingsProfiles);
}

export function mutateSettingsProfile(payload){
  return optionalApi(V5_ENDPOINTS.settingsProfiles,{method:'POST',json:payload,signal:AbortSignal.timeout(310000)});
}

export function saveSettings(payload,confirmation='APPLY SETTINGS'){
  return optionalApi(V5_ENDPOINTS.settings,{method:'POST',json:{...payload,confirmation},signal:AbortSignal.timeout(310000)});
}

export function saveHardeningSettings(config,reason){
  return optionalApi(V5_ENDPOINTS.hardeningSettings,{
    method:'POST',
    json:{config,reason,confirmation:'APPLY PROTECTION SETTINGS'},
    signal:AbortSignal.timeout(620000),
  });
}

export function getMhxApplicationDenies(){
  return optionalApi(V5_ENDPOINTS.mhxApplicationDenies);
}

export function setMhxApplicationDeny(payload){
  return optionalApi(V5_ENDPOINTS.mhxApplicationDenies,{method:'POST',json:payload,signal:AbortSignal.timeout(190000)});
}

export function getMhxSettings(){
  return optionalApi(V5_ENDPOINTS.mhxSettings);
}

export function saveMhxSettings(payload){
  return optionalApi(V5_ENDPOINTS.mhxSettings,{method:'POST',json:payload,signal:AbortSignal.timeout(310000)});
}

export function getKineticSettings(){
  return optionalApi(V5_ENDPOINTS.kineticSettings);
}

export function saveKineticSettings(payload){
  return optionalApi(V5_ENDPOINTS.kineticSettings,{method:'POST',json:payload,signal:AbortSignal.timeout(310000)});
}

export function getFeedPolicy(){
  return optionalApi(V5_ENDPOINTS.feedPolicy);
}

export function setFeedPolicy(payload){
  return optionalApi(V5_ENDPOINTS.feedPolicy,{
    method:'POST',
    json:{...payload,confirmation:'UPDATE THREAT FEED POLICY'},
    signal:AbortSignal.timeout(430000),
  });
}

export function getThreatIntelStatus(){
  return optionalApi(V5_ENDPOINTS.threatIntelStatus);
}

export function saveThreatIntelSettings(payload){
  return optionalApi(V5_ENDPOINTS.threatIntelSettings,{method:'POST',json:payload,signal:AbortSignal.timeout(120000)});
}

export function getNotifications(limit=100){
  const safeLimit=Math.max(1,Math.min(100,Number(limit)||100));
  return optionalApi(`${V5_ENDPOINTS.notifications}?limit=${safeLimit}`);
}

export function getDefenderTelemetry(){
  return optionalApi(V5_ENDPOINTS.defenderTelemetry);
}

/* GeDefense Titan: sovereign endpoint integrity. */
export function getTitanStatus(){
  return api('/api/v1/titan/status',{signal:AbortSignal.timeout(15000)});
}

export function getTitanEvents({limit=50,offset=0,filter='all'}={}){
  const safeLimit=Math.max(1,Math.min(100,Number(limit)||50));
  const safeOffset=Math.max(0,Math.min(1_000_000,Number(offset)||0));
  const safeFilter=['all','unexpected','persistence','security','quarantine'].includes(filter)?filter:'all';
  return api(`/api/v1/titan/events?limit=${safeLimit}&offset=${safeOffset}&filter=${safeFilter}`,{signal:AbortSignal.timeout(15000)});
}

export function getTitanQuarantine(){
  return api('/api/v1/titan/quarantine',{signal:AbortSignal.timeout(15000)});
}

export function quarantineTitanEvent(id,reason){
  return api(`/api/v1/titan/events/${encodeURIComponent(id)}/quarantine`,{
    method:'POST',json:{reason},signal:AbortSignal.timeout(30000),
  });
}

export function acknowledgeTitanEvent(id,reason){
  return api(`/api/v1/titan/events/${encodeURIComponent(id)}/acknowledge`,{
    method:'POST',json:{reason},signal:AbortSignal.timeout(30000),
  });
}

export function acknowledgeTitanOpenFindings(limit,reason){
  return api('/api/v1/titan/events/acknowledge',{
    method:'POST',json:{limit,reason},signal:AbortSignal.timeout(60000),
  });
}

export function restoreTitanQuarantine(id,reason){
  return api(`/api/v1/titan/quarantine/${encodeURIComponent(id)}/restore`,{
    method:'POST',json:{reason},signal:AbortSignal.timeout(60000),
  });
}

export function reviewTitanQuarantine(id,reason){
  return api(`/api/v1/titan/quarantine/${encodeURIComponent(id)}/review`,{
    method:'POST',json:{reason},signal:AbortSignal.timeout(30000),
  });
}

export function saveTitanPolicy(payload){
  return api('/api/v1/titan/policy',{method:'POST',json:payload,signal:AbortSignal.timeout(30000)});
}

export function getTitanPermits(){
  return api('/api/v1/titan/permits',{signal:AbortSignal.timeout(15000)});
}

export function createTitanPermit(payload){
  return api('/api/v1/titan/permits',{method:'POST',json:{...payload,confirmation:'CREATE TITAN PERMIT'},signal:AbortSignal.timeout(30000)});
}

export function revokeTitanPermit(id,reason){
  return api(`/api/v1/titan/permits/${encodeURIComponent(id)}/revoke`,{
    method:'POST',json:{reason},signal:AbortSignal.timeout(30000),
  });
}

export function addTitanDevelopmentRoot(path,reason){
  return api('/api/v1/titan/development-roots',{method:'POST',json:{path,reason,confirmation:'ADD DEVELOPMENT ROOT'},signal:AbortSignal.timeout(30000)});
}

export function removeTitanDevelopmentRoot(path,reason){
  return api('/api/v1/titan/development-roots/remove',{method:'POST',json:{path,reason,confirmation:'REMOVE DEVELOPMENT ROOT'},signal:AbortSignal.timeout(30000)});
}

export function getTitanCheckpoints(limit=50){
  const safeLimit=Math.max(1,Math.min(100,Number(limit)||50));
  return api(`/api/v1/titan/checkpoints?limit=${safeLimit}`,{signal:AbortSignal.timeout(15000)});
}

export function verifyTitanEvidence(){
  return api('/api/v1/titan/verify',{method:'POST',json:{},signal:AbortSignal.timeout(60000)});
}

export function exportTitanEvidence(limit=500){
  const safeLimit=Math.max(1,Math.min(500,Number(limit)||500));
  return api(`/api/v1/titan/export?limit=${safeLimit}`,{signal:AbortSignal.timeout(60000)});
}

/* Existing, verified endpoints used by the V5 pages. */
export function getHealthRefresh(){
  return optionalApi('/api/v1/health/refresh',{method:'POST',json:{},signal:AbortSignal.timeout(130000)});
}

export function getHealthStatus(){
  return optionalApi('/api/v1/health/status',{signal:AbortSignal.timeout(20000)});
}

export function getMhxApplications(){
  return optionalApi('/api/v1/mhx/applications',{signal:AbortSignal.timeout(620000)});
}

export function setMhxApplication(action,path,reason){
  return optionalApi('/api/v1/mhx/applications',{
    method:'POST',
    json:{action,path,confirmation:'UPDATE APPLICATION ALLOWLIST',reason},
    signal:AbortSignal.timeout(620000),
  });
}

export function getProtectedNetworks(){
  return optionalApi('/api/v1/mhx/threat-intelligence/protected-networks');
}

export function setProtectedNetworks(prefixes,reason){
  return optionalApi('/api/v1/mhx/threat-intelligence/protected-networks',{
    method:'POST',
    json:{prefixes,confirmation:'UPDATE PROTECTED NETWORKS',reason},
    signal:AbortSignal.timeout(430000),
  });
}

/* Security-reducing mutations: a typed confirmation phrase plus an operator
 * reason is enforced server-side (AN-FIND-005/UI-FIND-003). The UI supplies both
 * so no protection downgrade is a single unconfirmed click. */
export function applyHardeningProfile(profile,reason){
  return api('/api/v1/hardening/enforce',{
    method:'POST',json:{profile,confirmation:'APPLY HARDENING PROFILE',reason},
    signal:AbortSignal.timeout(620000),
  });
}

export function rollbackHardening(reason){
  return api('/api/v1/hardening/rollback',{
    method:'POST',json:{confirmation:'ROLLBACK HARDENING',reason},
    signal:AbortSignal.timeout(620000),
  });
}

export function activateHardeningComponent(id,reason){
  return api('/api/v1/hardening/components',{
    method:'POST',json:{id,confirmation:'ENABLE HARDENING COMPONENT',reason},
    signal:AbortSignal.timeout(200000),
  });
}

export function setIntegrityConfiguration(enabled,intervalHours,reason){
  return api('/api/v1/integrity/configuration',{
    method:'POST',
    json:{enabled,intervalHours,confirmation:'CHANGE INTEGRITY MONITORING',reason},
    signal:AbortSignal.timeout(30000),
  });
}
