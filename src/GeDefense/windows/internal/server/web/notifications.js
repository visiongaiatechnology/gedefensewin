// STATUS: DIAMANT VGT SUPREME
'use strict';
/** Notification Center.
 *
 *  Events are derived exclusively from existing control-plane endpoints:
 *  MHX attack stories, MHX network findings, XDR findings, the evidence ledger
 *  and explicit error states in the live MHX status. Nothing is simulated.
 *  Unread state is session-local because persistent browser storage is not
 *  permitted by the release gate.
 */
import {getEvidenceSnapshot, getNotifications, optionalApi} from './api.js';
import {
  byId, clear, formatTime, node, replaceNotice, toast,
} from './dom.js';

const MAX_ITEMS=50;
const state={
  items:[],
  read:new Set(),
  loading:false,
  loaded:false,
  error:'',
  lastCollectedUtc:'',
  bound:false,
  onNavigate:null,
  timer:null,
};

const severityRank={critical:4,high:3,medium:2,warning:2,low:1,informational:0,info:0};

function normalizeSeverity(value){
  const raw=String(value||'').toLowerCase();
  if(raw==='critical')return 'critical';
  if(raw==='high')return 'high';
  if(raw==='medium'||raw==='warning')return 'warning';
  if(raw==='low'||raw==='informational'||raw==='info')return 'info';
  return 'info';
}

function timestamp(value){
  if(!value)return '';
  const date=new Date(value);
  return Number.isNaN(date.getTime())||date.getTime()<=0?'':date.toISOString();
}

function addItem(map,item){
  if(!item||!item.id)return;
  if(!map.has(item.id))map.set(item.id,item);
}

function fromStories(payload,map){
  if(!Array.isArray(payload))return;
  for(const raw of payload.slice(0,100)){
    if(!raw||typeof raw!=='object')continue;
    const severity=normalizeSeverity(raw.severity);
    const response=String(raw.response||'');
    if(severityRank[severity]<2&&!/BLOCK|HOST_RESPONSE|TERMINAT/i.test(response))continue;
    const id=`story:${String(raw.id||`${raw.image}:${raw.remoteIp}:${raw.updatedUtc}`)}`;
    addItem(map,{
      id,
      time:timestamp(raw.updatedUtc||raw.startedUtc),
      title:`${String(raw.image||'Prozess')} → ${String(raw.remoteIp||'Netzwerkziel')}`,
      detail:`${String(response||'KORRELIERT')}${Array.isArray(raw.signals)&&raw.signals.length?` · ${raw.signals.slice(0,3).join(' · ')}`:''}`,
      severity:severity==='info'?'warning':severity,
      source:'MHX XDR',
      page:'xdr',
      action:'XDR öffnen',
    });
  }
}

function fromNetwork(payload,map){
  if(!Array.isArray(payload))return;
  for(const raw of payload.slice(0,100)){
    if(!raw||typeof raw!=='object')continue;
    const severity=normalizeSeverity(raw.severity);
    const action=String(raw.threatAction||'');
    if(!raw.threatIntel&&action!=='BLOCK'&&severityRank[severity]<2)continue;
    const id=`network:${String(raw.id||'')||`${raw.remoteIp}:${raw.remotePort}:${raw.timestampUtc}`}`;
    addItem(map,{
      id,
      time:timestamp(raw.timestampUtc),
      title:`${String(raw.image||`PID ${raw.pid??'—'}`)} → ${String(raw.remoteIp||'—')}:${String(raw.remotePort??'—')}`,
      detail:`${action||'MATCH'}${Array.isArray(raw.threatSources)&&raw.threatSources.length?` · ${raw.threatSources.slice(0,3).join(', ')}`:''}${raw.response?` · ${raw.response}`:''}`,
      severity:severity==='info'?'warning':severity,
      source:'Netzwerk',
      page:'network',
      action:'Netzwerk öffnen',
    });
  }
}

function fromXdr(payload,map){
  if(!payload||typeof payload!=='object')return;
  const result=payload;
  const findings=Array.isArray(result.Findings)?result.Findings:[];
  for(const raw of findings.slice(0,100)){
    if(!raw||typeof raw!=='object')continue;
    const severity=normalizeSeverity(raw.Severity);
    if(severityRank[severity]<2)continue;
    const id=`xdr:${String(raw.Category||'')}:${String(raw.Title||'')}:${String(raw.Entity||'')}`;
    addItem(map,{
      id,
      time:timestamp(raw.TimestampUtc||result.TimestampUtc),
      title:String(raw.Title||'XDR-Finding'),
      detail:`${String(raw.Category||'—')} · ${String(raw.Entity||'—')}${raw.Evidence?` · ${String(raw.Evidence).slice(0,180)}`:''}`,
      severity,
      source:'XDR',
      page:'xdr',
      action:'XDR öffnen',
    });
  }
}

function fromEvidence(payload,map){
  if(!Array.isArray(payload))return;
  for(const raw of payload.slice(0,100)){
    if(!raw||typeof raw!=='object')continue;
    const kind=String(raw.kind||'');
    const action=String(raw.action||'');
    const result=String(raw.result||'');
    if(!/(block|deny|reject|fail|terminat|quarant|error)/i.test(`${kind} ${action} ${result}`))continue;
    const id=`evidence:${String(raw.sequence??`${raw.timestamp}:${kind}:${action}`)}`;
    addItem(map,{
      id,
      time:timestamp(raw.timestamp),
      title:`${kind||'Evidenz'} · ${action||'Ereignis'}`,
      detail:result||'Ergebnis nicht dokumentiert',
      severity:'warning',
      source:'Evidenz',
      page:'evidence',
      action:'Evidenz öffnen',
    });
  }
}

function fromStatus(payload,map){
  if(!payload||typeof payload!=='object')return;
  const mhx=payload.mhx||payload;
  const ti=mhx.threatIntelligence||{};
  const enforcement=mhx.threatEnforcement||{};
  if(ti.error){
    addItem(map,{
      id:'status:threat-intelligence-error',
      time:timestamp(ti.lastAttemptUtc),
      title:'Threat Intelligence meldet einen Fehler',
      detail:String(ti.error),
      severity:'high',
      source:'Threat Intelligence',
      page:'threat-intel',
      action:'Feeds öffnen',
    });
  }
  if(enforcement.error){
    addItem(map,{
      id:'status:enforcement-error',
      time:timestamp(enforcement.verifiedUtc),
      title:'WFP-Enforcement nicht verifiziert',
      detail:String(enforcement.error),
      severity:'high',
      source:'Threat Intelligence',
      page:'threat-intel',
      action:'Enforcement prüfen',
    });
  }
  if(mhx.kineticArmed&&mhx.kineticReadiness?.threatRules&&mhx.kineticReadiness.threatRules!=='GENERATION_VERIFIED'){
    addItem(map,{
      id:'status:kinetic-degraded',
      time:timestamp(mhx.telemetryHeartbeatUtc),
      title:'Kinetic bewaffnet, Threat-IP-Generation nicht verifiziert',
      detail:`TI-Regeln: ${String(mhx.kineticReadiness.threatRules)} · WFP-Audit: ${String(mhx.kineticReadiness.wfpAudit||'unbekannt')}`,
      severity:'warning',
      source:'Kinetic Defense',
      page:'kinetic',
      action:'Kinetic prüfen',
    });
  }
}

function serverNotificationPage(kind){
  const value=String(kind||'').toLowerCase();
  if(value.includes('kinetic'))return {page:'kinetic',action:'Kinetic öffnen'};
  if(value.includes('network'))return {page:'network',action:'Netzwerk öffnen'};
  if(value.includes('threat')||value.includes('intel')||value.includes('feed'))return {page:'threat-intel',action:'Feeds öffnen'};
  if(value.includes('evidence')||value.includes('audit'))return {page:'evidence',action:'Evidenz öffnen'};
  if(value.includes('protection')||value.includes('policy'))return {page:'protection',action:'Protection Center öffnen'};
  return {page:'xdr',action:'XDR öffnen'};
}

function fromServerFeed(payload,map){
  if(!Array.isArray(payload))return 0;
  let added=0;
  for(const raw of payload.slice(0,100)){
    if(!raw||typeof raw!=='object')continue;
    const kind=String(raw.kind||raw.Kind||'mhx');
    const id=`server:${String(raw.id||raw.ID||`${kind}:${raw.timestampUtc||''}`)}`;
    if(map.has(id))continue;
    const target=serverNotificationPage(kind);
    addItem(map,{
      id,
      time:timestamp(raw.timestampUtc||raw.TimestampUTC),
      title:String(raw.title||raw.Title||'Sicherheitsereignis'),
      detail:String(raw.detail||raw.Detail||'').slice(0,320),
      severity:normalizeSeverity(raw.severity||raw.Severity),
      source:kindLabel(kind),
      page:target.page,
      action:target.action,
    });
    added++;
  }
  return added;
}

function kindLabel(kind){
  const value=String(kind||'').toLowerCase();
  if(value.includes('kinetic'))return 'Kinetic Defense';
  if(value.includes('network'))return 'Netzwerk';
  if(value.includes('threat')||value.includes('intel')||value.includes('feed'))return 'Threat Intelligence';
  if(value.includes('evidence')||value.includes('audit'))return 'Evidenz';
  if(value.includes('protection')||value.includes('policy'))return 'Protection Center';
  return 'MHX XDR';
}

function sortItems(items){
  return [...items].sort((left,right)=>{
    const leftTime=Date.parse(left.time||'')||0;
    const rightTime=Date.parse(right.time||'')||0;
    if(leftTime!==rightTime)return rightTime-leftTime;
    return (severityRank[right.severity]||0)-(severityRank[left.severity]||0);
  });
}

export async function collectNotifications(){
  if(state.loading)return state.items;
  state.loading=true;
  try{
    const serverFeed=await getNotifications(100);
    const map=new Map();
    let reachable=0;
    if(serverFeed.ok){
      fromServerFeed(serverFeed.data,map);
      reachable++;
      state.error=map.size?'Ereignisse stammen aus dem MHX-Ereignisstrom der Control Plane.':'Der MHX-Ereignisstrom ist erreichbar, enthält aber noch keine Ereignisse.';
    }else{
      const [stories,network,findings,evidence,status]=await Promise.all([
        optionalApi('/api/v1/mhx/stories?limit=50'),
        optionalApi('/api/v1/mhx/network?limit=100'),
        optionalApi('/api/v1/xdr/findings'),
        getEvidenceSnapshot(),
        optionalApi('/api/v1/mhx/status'),
      ]);
      if(stories.ok){fromStories(stories.data,map);reachable++}
      if(network.ok){fromNetwork(network.data,map);reachable++}
      if(findings.ok){fromXdr(findings.data,map);reachable++}
      if(evidence.ok){fromEvidence(evidence.data,map);reachable++}
      if(status.ok){fromStatus(status.data,map);reachable++}
      state.error=reachable?`Server-Ereignisstrom nicht verfügbar; ${reachable} Ersatzquellen erreichbar.`:'Keine Benachrichtigungsquelle erreichbar.';
    }
    const items=sortItems([...map.values()]).slice(0,MAX_ITEMS);
    const known=new Set(items.map(item=>item.id));
    state.read=new Set([...state.read].filter(id=>known.has(id)));
    state.items=items;
    state.loaded=true;
    state.lastCollectedUtc=new Date().toISOString();
    return state.items;
  }finally{
    state.loading=false;
    renderNotificationCenter();
  }
}

export function unreadCount(){
  return state.items.reduce((count,item)=>count+(state.read.has(item.id)?0:1),0);
}

export function renderNotificationCenter(){
  renderBadge();
  const host=byId('notificationList');
  if(!host)return;
  host.replaceChildren();
  const stateHost=byId('notificationState');
  if(stateHost)clear(stateHost);
  if(!state.loaded){
    if(stateHost)replaceNotice(stateHost,{tone:'info',title:'Benachrichtigungen werden geladen …',body:'Echte Ereignisse aus Evidence, MHX-Netzwerktreffern und XDR-Findings werden zusammengeführt.'});
    return;
  }
  if(!state.items.length){
    const empty=byId('notificationEmpty');
    if(empty)empty.hidden=false;
    if(stateHost&&!state.error)clear(stateHost);
    return;
  }
  const empty=byId('notificationEmpty');
  if(empty)empty.hidden=true;
  if(stateHost&&/Keine Benachrichtigungsquelle/.test(state.error)){
    replaceNotice(stateHost,{tone:'warn',title:'Benachrichtigungsquellen nicht erreichbar',body:state.error,actions:[{label:'Erneut laden',variant:'ghost',onClick:()=>{void collectNotifications()}}]});
  }
  const fragment=document.createDocumentFragment();
  for(const item of state.items){
    const listItem=node('li','notification-item');
    listItem.dataset.severity=item.severity;
    if(!state.read.has(item.id))listItem.classList.add('unread');
    const dot=node('span','notification-severity');
    dot.setAttribute('aria-hidden','true');
    const main=node('div','notification-main');
    const titleRow=node('div','notification-title');
    titleRow.append(node('span','notification-unread'),node('strong','',item.title));
    const detail=node('p','notification-detail',item.detail);
    const meta=node('div','notification-meta');
    meta.append(node('span','notification-source',item.source));
    meta.append(node('span','',item.time?formatTime(item.time):'Zeit nicht verfügbar'));
    const actions=node('div','notification-actions');
    const open=node('button','button ghost small',item.action||'Öffnen');
    open.type='button';
    open.addEventListener('click',()=>{
      state.read.add(item.id);
      renderNotificationCenter();
      byId('notificationDialog')?.close();
      if(typeof state.onNavigate==='function')state.onNavigate(item.page);
    });
    const markRead=node('button','button quiet small','Als gelesen markieren');
    markRead.type='button';
    markRead.disabled=state.read.has(item.id);
    markRead.addEventListener('click',()=>{
      state.read.add(item.id);
      renderNotificationCenter();
    });
    actions.append(open,markRead);
    main.append(titleRow,detail,meta,actions);
    listItem.append(dot,main);
    fragment.append(listItem);
  }
  host.append(fragment);
}

export function renderBadge(){
  const badge=byId('notificationCount');
  const button=byId('notificationButton');
  if(!badge)return;
  const count=unreadCount();
  badge.hidden=count===0;
  badge.textContent=count>99?'99+':String(count);
  if(button){
    const text=count?`, ${count} ungelesen`:'';
    button.setAttribute('aria-label',`Benachrichtigungen öffnen${text}`);
  }
}

export function initNotificationCenter(options={}){
  state.onNavigate=typeof options.onNavigate==='function'?options.onNavigate:null;
  if(state.bound)return;
  state.bound=true;
  byId('notificationButton')?.addEventListener('click',()=>{
    openNotificationCenter();
  });
  byId('notificationClose')?.addEventListener('click',()=>byId('notificationDialog')?.close());
  byId('notificationMarkAll')?.addEventListener('click',()=>{
    for(const item of state.items)state.read.add(item.id);
    renderNotificationCenter();
    toast('Alle sichtbaren Ereignisse als gelesen markiert.','info');
  });
  byId('notificationRefresh')?.addEventListener('click',()=>{void collectNotifications()});
  const dialog=byId('notificationDialog');
  dialog?.addEventListener('close',()=>{byId('notificationButton')?.focus({preventScroll:true})});
  state.timer=globalThis.setInterval(()=>{
    if(document.hidden)return;
    void collectNotifications().catch(()=>{});
  },30000);
  void collectNotifications().catch(()=>{});
}

export function openNotificationCenter(){
  const dialog=byId('notificationDialog');
  if(!dialog)return;
  void collectNotifications().catch(()=>{});
  try{if(!dialog.open)dialog.showModal()}catch{return}
  renderNotificationCenter();
  const closeButton=byId('notificationClose');
  closeButton?.focus({preventScroll:true});
}
