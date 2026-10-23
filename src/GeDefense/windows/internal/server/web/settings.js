// STATUS: DIAMANT VGT SUPREME
'use strict';
/** V5 settings layer.
 *
 *  Wires the settings authority, MHX policy, Kinetic policy, Threat-Intelligence
 *  polling and application allow-list surfaces. Every write is server-gated and
 *  reason-bound. When an endpoint is unavailable the UI renders an explicit
 *  unavailable state and never fabricates a stored value.
 */
import {
  getFeedPolicy,
  getKineticSettings,
  getMhxApplicationDenies,
  getMhxApplications,
  getMhxSettings,
  getSettings,
  getSettingsCatalog,
  getSettingsProfiles,
  getThreatIntelStatus,
  mutateSettingsProfile,
  saveKineticSettings,
  saveMhxSettings,
  saveThreatIntelSettings,
  setFeedPolicy,
  setMhxApplication,
  setMhxApplicationDeny,
} from './api.js';
import {
  byId, clear, formatNumber, formatTime, node, replaceNotice, requestConfirm, requestReason,
  setPill, setText, toast,
} from './dom.js';

const LEVEL_CONFIRMATION={
  monitor:'RETURN TO MONITOR',
  guarded:'ACTIVATE GUARDED',
  sovereign:'SOVEREIGN DEFAULT DENY',
  custom:'APPLY CUSTOM PROFILE',
};
const LEVEL_LABEL={monitor:'MONITOR',guarded:'GUARDED',sovereign:'SOVEREIGN',custom:'BENUTZERDEFINIERT'};

const FALLBACK_LEVELS=[
  {id:'monitor',label:'Nur Überwachung',description:'Erkennt und protokolliert, erzwingt keine aktive Antwort.',risk:'MEDIUM'},
  {id:'guarded',label:'Guarded',description:'Verifizierte Standardverteidigung mit begrenzter Prozessantwort.',risk:'HIGH'},
  {id:'sovereign',label:'Sovereign',description:'Maximalprofil mit Enforcement und Default-Deny.',risk:'CRITICAL'},
  {id:'custom',label:'Benutzerdefiniert',description:'Operator-definiertes Profil mit expliziter Bestätigung.',risk:'HIGH'},
];

const FALLBACK_CONTROLS=[
  {section:'defender',key:'cloudBlockLevel',label:'Cloud-Block-Level',type:'enum',values:['Default','Normal','High','HighPlus','ZeroTolerance']},
  {section:'defender',key:'networkProtection',label:'Defender Netzwerkschutz',type:'enum',values:['Enabled','AuditMode','Disabled']},
  {section:'defender',key:'puaProtection',label:'PUA-Schutz',type:'enum',values:['Enabled','AuditMode','Disabled']},
  {section:'defender',key:'controlledFolderAccess',label:'Controlled Folder Access',type:'enum',values:['Enabled','AuditMode','Disabled']},
  {section:'defender',key:'mapsReporting',label:'Cloud-Schutz (MAPS)',type:'enum',values:['Disabled','Basic','Advanced']},
  {section:'defender',key:'submitSamplesConsent',label:'Sample-Übermittlung',type:'enum',values:['AlwaysPrompt','SendSafeSamples','NeverSend','SendAllSamples']},
];

const state={
  checked:false,
  probing:null,
  settingsResult:null,
  catalogResult:null,
  profilesResult:null,
  data:null,
  catalog:null,
  profilesPayload:null,
  available:false,
  catalogAvailable:false,
  profilesAvailable:false,
  profiles:[],
  levels:FALLBACK_LEVELS,
  controls:[],
  activeProfileId:'',
  activeLevel:'',
  applierReady:null,
  protectionLevel:'',
  updatedUtc:'',
};

let localProfiles=[];
let profileSeq=0;
let editingProfileId='';
let profileFormBound=false;
let mhxBound=false;
let kineticBound=false;
let tiBound=false;
let lastStatus=null;

function asObject(value){return value&&typeof value==='object'&&!Array.isArray(value)?value:{}}
function pick(object,...keys){for(const key of keys){if(object&&object[key]!==undefined&&object[key]!==null)return object[key]}return undefined}
function text(value,fallback='---'){return value===undefined||value===null||value===''?fallback:String(value)}
function bool(value,fallback=false){return typeof value==='boolean'?value:fallback}
function listFrom(value){return Array.isArray(value)?value:[]}
function payloadObject(result){return result?.ok?asObject(result.data):{}}

/* ------------------------------------------------------------------ */
/* Settings authority probe                                            */
/* ------------------------------------------------------------------ */
export async function ensureSettingsProbe(force=false){
  if(state.checked&&!force)return state;
  if(state.probing&&!force)return state.probing;
  state.probing=(async()=>{
    try{
      const [settingsResult,catalogResult,profilesResult]=await Promise.all([
        getSettings(),getSettingsCatalog(),getSettingsProfiles(),
      ]);
      state.settingsResult=settingsResult;
      state.catalogResult=catalogResult;
      state.profilesResult=profilesResult;
      state.data=payloadObject(settingsResult);
      state.catalog=payloadObject(catalogResult);
      state.profilesPayload=payloadObject(profilesResult);
      state.available=Boolean(settingsResult.ok)||Boolean(profilesResult.ok);
      state.catalogAvailable=Boolean(catalogResult.ok);
      state.profilesAvailable=Boolean(profilesResult.ok);
      state.checked=true;
      const levels=listFrom(pick(state.profilesPayload,'levels','Levels'));
      state.levels=levels.length?levels:FALLBACK_LEVELS;
      state.controls=listFrom(pick(state.catalog,'controls','Controls')).length?listFrom(pick(state.catalog,'controls','Controls')):FALLBACK_CONTROLS.map(field=>({...field,section:field.section,id:field.key}));
      state.profiles=normalizeServerProfiles(pick(state.profilesPayload,'profiles')??state.data.profiles);
      state.activeProfileId=String(pick(state.profilesPayload,'activeProfileId')??pick(state.data,'activeProfileId')??'');
      state.activeLevel=String(pick(state.profilesPayload,'activeLevel')??pick(state.data,'activeLevel')??'');
      state.protectionLevel=String(pick(state.profilesPayload,'protectionLevel')??pick(state.data,'protectionLevel')??'');
      state.applierReady=typeof pick(state.profilesPayload,'applierReady')==='boolean'?pick(state.profilesPayload,'applierReady'):null;
      state.updatedUtc=String(pick(state.data,'updatedUtc')??pick(state.profilesPayload,'updatedUtc')??'');
      return state;
    }finally{
      state.probing=null;
    }
  })();
  return state.probing;
}

export function settingsAvailable(){return Boolean(state.available)}
export function settingsState(){return state}
export function settingsCatalogData(){return state.catalog}
export function settingsProfiles(){return state.profiles}
export function profileCanApply(){
  return Boolean(state.available&&state.profilesAvailable&&state.applierReady!==false);
}

export function renderSettingsBadge(badgeId){
  if(!state.checked){setPill(badgeId,'API WIRD GEPRÜFT','warn');return}
  if(profileCanApply())setPill(badgeId,'SETTINGS-API VERFÜGBAR','good');
  else if(state.available)setPill(badgeId,'SETTINGS-API EINGESCHRÄNKT','warn');
  else setPill(badgeId,'SETTINGS-API NICHT VERFÜGBAR','warn');
}

export function settingsUnavailableNotice(host,feature,retry){
  return replaceNotice(host,{
    tone:'warn',
    title:`${feature}: serverseitige Speicherung nicht verfügbar`,
    body:'Die V5-Settings-API der Control Plane ist in dieser Instanz nicht erreichbar. Anzeige und Prüfung funktionieren; Änderungen werden nicht simuliert und nicht als gespeichert ausgegeben.',
    actions:retry?[{label:'Erneut prüfen',onClick:retry,variant:'ghost'}]:undefined,
  });
}

function setFormAvailability(formId,available){
  const form=byId(formId);
  if(!form)return;
  form.dataset.available=String(Boolean(available));
  for(const control of form.querySelectorAll('input,select,textarea,button'))control.disabled=!available;
}

function setFormStatus(element,message,tone=''){
  if(!element)return;
  element.textContent=String(message||'');
  if(tone)element.dataset.tone=tone;else delete element.dataset.tone;
}

function markUnavailableSelect(select,label='Nicht verfügbar (Settings-API fehlt)'){
  if(!select||!select.options)return;
  const options=Array.from(select.options);
  let placeholder=options.find(option=>option.value==='');
  if(!placeholder){
    placeholder=document.createElement('option');
    placeholder.value='';
    placeholder.textContent=label;
    select.prepend(placeholder);
  }
  select.value='';
}

function humanSource(value,fallback='Nicht verfügbar'){
  const source=String(value||'').toLowerCase();
  if(!source)return fallback;
  if(source.includes('persist'))return 'Persistierte Konfiguration';
  if(source.includes('default'))return 'Standardkonfiguration';
  if(source.includes('invalid'))return 'Ungültige Konfiguration (Fallback aktiv)';
  if(source.includes('live')||source.includes('status'))return 'Live-Status (nicht persistiert)';
  if(source.includes('protection'))return 'Schutzmodus';
  if(source.includes('server'))return 'Serverkonfiguration';
  return String(value);
}

/* ------------------------------------------------------------------ */
/* Custom protection profiles                                          */
/* ------------------------------------------------------------------ */
function normalizeServerProfiles(raw){
  return listFrom(raw).map((item,index)=>{
    const profile=asObject(item);
    return {
      id:String(pick(profile,'id','ID')||`server-${index}`),
      name:text(pick(profile,'name','Name'),`Profil ${index+1}`),
      level:String(pick(profile,'level','Level')||'monitor').toLowerCase(),
      description:text(pick(profile,'description','Description'),''),
      builtIn:Boolean(pick(profile,'builtIn','BuiltIn')),
      values:asObject(pick(profile,'values','Values')),
      updatedUtc:String(pick(profile,'updatedUtc','UpdatedUTC')||''),
      source:'server',
    };
  });
}

function profileLevels(){
  const levels=listFrom(state.levels);
  if(!levels.length)return FALLBACK_LEVELS;
  return levels.map(level=>({id:String(level.id||'').toLowerCase(),label:String(level.label||level.id||''),description:String(level.description||''),risk:String(level.risk||''),confirmation:String(level.confirmation||LEVEL_CONFIRMATION[String(level.id||'').toLowerCase()]||'')}));
}

function selectLevelOptions(){
  const select=byId('profileLevel');
  if(!select)return;
  const current=select.value||'guarded';
  select.replaceChildren();
  for(const level of profileLevels()){
    const option=document.createElement('option');
    option.value=level.id;
    option.textContent=`${level.label}${level.risk?` · Risiko ${level.risk}`:''}`;
    select.append(option);
  }
  if([...select.options].some(option=>option.value===current))select.value=current;
}

function profileControlsModel(){
  const controls=listFrom(state.controls);
  if(!controls.length)return FALLBACK_CONTROLS.map(field=>({...field,id:field.key}));
  const result=[];
  for(const raw of controls){
    if(!raw||typeof raw!=='object')continue;
    const key=String(raw.key||raw.id||'');
    if(!key)continue;
    const section=String(raw.section||key.split('.')[0]||'defender');
    const id=key.includes('.')?key.split('.').slice(1).join('.'):key;
    const type=String(raw.type||'');
    if(type==='array')continue;
    if(!['boolean','enum','int','integer'].includes(type))continue;
    result.push({
      id,
      section,
      key,
      label:String(raw.label||key),
      description:String(raw.description||''),
      type:type==='enum'?'enum':type==='boolean'?'boolean':'int',
      values:listFrom(raw.values),
      default:raw.default,
      minimum:Number(raw.minimum),
      maximum:Number(raw.maximum),
      risk:String(raw.risk||''),
      requiresRestart:Boolean(raw.requiresRestart),
    });
    if(result.length>=18)break;
  }
  return result.length?result:FALLBACK_CONTROLS.map(field=>({...field,id:field.key,label:field.label,description:''}));
}

function renderProfileControls(){
  const host=byId('profileControls');
  if(!host)return;
  host.replaceChildren();
  for(const control of profileControlsModel()){
    if(control.type==='boolean'){
      const label=node('label','switch');
      const input=document.createElement('input');
      input.type='checkbox';
      input.id=`profileControl-${control.key}`;
      input.dataset.controlKey=control.key;
      input.dataset.controlSection=control.section;
      input.checked=Boolean(control.default);
      input.dataset.defaultChecked=String(Boolean(control.default));
      const track=node('span','switch-track');
      track.setAttribute('aria-hidden','true');
      const copy=node('span','switch-copy');
      copy.append(node('strong','',control.label),node('small','',control.description||(control.section?`Abschnitt ${control.section}`:'')));
      label.append(input,track,copy);
      host.append(label);
    }else if(control.type==='enum'){
      const label=node('label');
      const title=node('span','',control.label);
      const select=document.createElement('select');
      select.id=`profileControl-${control.key}`;
      select.dataset.controlKey=control.key;
      select.dataset.controlSection=control.section;
      for(const value of control.values){
        const option=document.createElement('option');
        option.value=String(value);
        option.textContent=String(value);
        if(String(value)===String(control.default))option.selected=true;
        select.append(option);
      }
      if(!control.values.length){
        const option=document.createElement('option');
        option.value='';
        option.textContent='Nicht verfügbar';
        select.append(option);
      }
      label.append(title,select);
      if(control.description)label.append(node('small','field-hint',control.description));
      host.append(label);
    }else{
      const label=node('label');
      label.append(node('span','',control.label));
      const input=document.createElement('input');
      input.type='number';
      input.id=`profileControl-${control.key}`;
      input.dataset.controlKey=control.key;
      input.dataset.controlSection=control.section;
      if(Number.isFinite(control.minimum))input.min=String(control.minimum);
      if(Number.isFinite(control.maximum))input.max=String(control.maximum);
      input.value=control.default!==undefined?String(control.default):'';
      label.append(input);
      if(control.description)label.append(node('small','field-hint',control.description));
      host.append(label);
    }
  }
}

function readProfileValues(){
  const values={};
  for(const input of document.querySelectorAll('#profileControls [data-control-key]')){
    const section=input.dataset.controlSection||'defender';
    const key=input.dataset.controlKey;
    if(!key)continue;
    if(!values[section])values[section]={};
    if(input.type==='checkbox')values[section][key]=Boolean(input.checked);
    else if(input.type==='number'){
      const number=Number(input.value);
      if(Number.isFinite(number))values[section][key]=number;
    }else if(input.tagName==='SELECT'&&input.value!=='')values[section][key]=input.value;
  }
  return values;
}

function applyValuesToControls(values){
  for(const input of document.querySelectorAll('#profileControls [data-control-key]')){
    const section=input.dataset.controlSection||'defender';
    const key=input.dataset.controlKey;
    const sectionValues=asObject(values?.[section]);
    const value=sectionValues[key];
    if(input.type==='checkbox')input.checked=typeof value==='boolean'?value:input.dataset.defaultChecked==='true';
    else if(input.type==='number')input.value=value!==undefined&&value!==null&&Number.isFinite(Number(value))?String(value):'';
    else if(input.tagName==='SELECT'&&value!==undefined&&value!==null&&[...input.options].some(option=>option.value===String(value)))input.value=String(value);
  }
}

function resetProfileForm(){
  editingProfileId='';
  if(byId('profileName'))byId('profileName').value='';
  if(byId('profileLevel'))byId('profileLevel').value='guarded';
  if(byId('profileDescription'))byId('profileDescription').value='';
  for(const input of document.querySelectorAll('#profileControls input[type="checkbox"]'))input.checked=Boolean(input.dataset.defaultChecked==='true');
  for(const input of document.querySelectorAll('#profileControls input[type="number"]'))input.value='';
  for(const select of document.querySelectorAll('#profileControls select')){
    if(select.options.length)select.selectedIndex=0;
  }
  setText('profileFormTitle','Neues Profil');
  setText('profileFormStatus','');
}

function fillProfileForm(profile){
  editingProfileId=profile.source==='local'?profile.id:'';
  if(byId('profileName'))byId('profileName').value=profile.name;
  selectLevelOptions();
  if(byId('profileLevel'))byId('profileLevel').value=profile.level||'guarded';
  if(byId('profileDescription'))byId('profileDescription').value=profile.description||'';
  applyValuesToControls(profile.values||{});
  setText('profileFormTitle',profile.source==='local'?'Profil bearbeiten':`„${profile.name}“ als neuen Entwurf bearbeiten`);
  setText('profileFormStatus',profile.source==='local'?`Entwurf „${profile.name}“ wird bearbeitet.`:`Serverprofil „${profile.name}“ ist eingelesen. Speichern erzeugt ein eigenes Profil.`);
  byId('profileName')?.focus();
}

function renderProfileList(){
  const host=byId('profileList');
  if(!host)return;
  host.replaceChildren();
  const serverProfiles=state.profiles;
  const rows=[...serverProfiles,...localProfiles];
  if(!rows.length){
    host.append(node('p','field-hint','Noch kein eigenes Profil entworfen. Die Standardstufen bleiben unabhängig davon verfügbar.'));
  }
  for(const profile of rows){
    const row=node('article','profile-row');
    const info=node('div');
    const active=profile.id===state.activeProfileId;
    const title=node('strong','',profile.name);
    const meta=node('small','');
    const bits=[LEVEL_LABEL[profile.level]||String(profile.level).toUpperCase(),profile.source==='server'?(profile.builtIn?'Standardprofil':'Serverprofil'):'Lokaler Entwurf'];
    if(profile.description)bits.push(profile.description);
    meta.textContent=bits.join(' · ');
    info.append(title,meta);
    if(active)row.dataset.active='true';
    const actions=node('div','profile-row-actions');
    const apply=node('button','button ghost small',active?'Aktiv':'Anwenden');
    apply.type='button';
    apply.disabled=active||!profileCanApply();
    if(!profileCanApply())apply.title='Anwenden benötigt die verfügbare Settings-API und einen bereiten Applier.';
    apply.addEventListener('click',()=>{void applyProfile(profile)});
    actions.append(apply);
    if(profile.source==='server'&&!profile.builtIn){
      const edit=node('button','button ghost small','Bearbeiten');
      edit.type='button';
      edit.disabled=!profileCanApply();
      edit.addEventListener('click',()=>fillProfileForm(profile));
      const remove=node('button','button quiet small','Entfernen');
      remove.type='button';
      remove.disabled=!profileCanApply()||active;
      remove.title=active?'Das aktive Profil kann nicht entfernt werden.':'';
      remove.addEventListener('click',()=>{void deleteProfile(profile)});
      actions.append(edit,remove);
    }else if(profile.source==='server'&&profile.builtIn){
      const duplicate=node('button','button ghost small','Duplizieren');
      duplicate.type='button';
      duplicate.addEventListener('click',()=>{
        fillProfileForm({...profile,source:'local',id:'',name:`${profile.name} (Entwurf)`});
        setText('profileFormStatus','Standardprofil als Entwurf eingelesen. Speichern legt ein eigenes Profil an.');
      });
      actions.append(duplicate);
    }else{
      const edit=node('button','button ghost small','Bearbeiten');
      edit.type='button';
      edit.addEventListener('click',()=>fillProfileForm(profile));
      const remove=node('button','button quiet small','Entfernen');
      remove.type='button';
      remove.addEventListener('click',()=>{
        localProfiles=localProfiles.filter(item=>item.id!==profile.id);
        if(editingProfileId===profile.id)resetProfileForm();
        renderProfileList();
      });
      actions.append(edit,remove);
    }
    row.append(info,actions);
    host.append(row);
  }
  const hint=byId('profileListHint');
  if(hint)hint.textContent=profileCanApply()
    ?'Serverprofile sind anwendbar. Anwenden erfordert eine operatorbegründete Bestätigung; nicht unterstützte Kontrollwerte lehnt die Control Plane ab.'
    :'Server-API nicht verfügbar oder Applier nicht bereit: Entwürfe bleiben lokal und werden nicht als aktive Richtlinie dargestellt.';
}

async function applyProfile(profile){
  if(!profileCanApply()){
    toast('Profil-Anwendung nicht verfügbar: Settings-API oder Applier fehlt.','bad');
    renderProfileStudioState();
    return;
  }
  if(profile.id===state.activeProfileId){
    toast('Dieses Profil ist bereits aktiv.','info');
    return;
  }
  const reason=await requestReason({
    title:'Schutzprofil anwenden',
    text:`Profil „${profile.name}“ (${LEVEL_LABEL[profile.level]||profile.level}) soll als aktive Schutzrichtlinie angewendet werden. Die Control Plane validiert alle Voraussetzungen und lehnt nicht unterstützte Kombinationen ab.`,
    label:'Begründung der Schutztransaktion',
    confirmLabel:'Profil anwenden',
  });
  if(!reason)return;
  let targetId=profile.id;
  try{
    if(profile.source==='local'){
      if(profile.id.startsWith('local-')){
        localProfiles=localProfiles.filter(item=>item.id!==profile.id);
      }
      const created=await mutateSettingsProfile({action:'create',profile:{name:profile.name,description:profile.description,level:profile.level,values:profile.values}});
      if(!created.ok){
        toast(`Profil konnte nicht gespeichert werden: ${created.message}`,'bad');
        return;
      }
      const snapshot=asObject(created.data);
      const createdProfiles=normalizeServerProfiles(pick(snapshot,'profiles'));
      const match=createdProfiles.find(item=>item.name===profile.name&&item.level===profile.level);
      if(!match){toast('Profil gespeichert, aber die Server-ID konnte nicht ermittelt werden. Bitte Liste aktualisieren.','warn');await refreshProfileStudio();return}
      targetId=match.id;
      applyServerSnapshot(snapshot);
    }
    const confirmation=LEVEL_CONFIRMATION[profile.level]||LEVEL_CONFIRMATION.custom;
    const applied=await mutateSettingsProfile({action:'apply',id:targetId,reason,confirmation});
    if(applied.ok){
      applyServerSnapshot(asObject(applied.data));
      toast(`Profil „${profile.name}“ wurde angewendet.`,'good');
      renderProfileList();
      renderProfileStudioState();
      await refreshProfileStudio();
    }else{
      toast(`Profil abgelehnt: ${applied.message}`,'bad');
      renderProfileStudioState();
    }
  }catch(error){
    toast(`Profil-Anwendung fehlgeschlagen: ${error.message||error}`,'bad');
  }
}

async function deleteProfile(profile){
  const confirmed=await requestConfirm({
    title:'Profil entfernen',
    text:`Serverprofil „${profile.name}“ dauerhaft entfernen? Das aktive Profil kann nicht entfernt werden; die Sicherheitsrichtlinie selbst wird dabei nicht verändert.`,
    label:'Profil entfernen',
    tone:'danger',
  });
  if(!confirmed)return;
  const result=await mutateSettingsProfile({action:'delete',id:profile.id});
  if(result.ok){
    applyServerSnapshot(asObject(result.data));
    toast(`Profil „${profile.name}“ entfernt.`,'good');
    renderProfileList();
    renderProfileStudioState();
  }else{
    toast(`Profil konnte nicht entfernt werden: ${result.message}`,'bad');
  }
}

function applyServerSnapshot(snapshot){
  if(!snapshot||typeof snapshot!=='object')return;
  if(Array.isArray(snapshot.profiles)){
    state.profiles=normalizeServerProfiles(snapshot.profiles);
    state.activeProfileId=String(snapshot.activeProfileId||state.activeProfileId);
    state.activeLevel=String(snapshot.activeLevel||state.activeLevel);
    state.protectionLevel=String(snapshot.protectionLevel||state.protectionLevel);
    state.updatedUtc=String(snapshot.updatedUtc||state.updatedUtc);
    if(typeof snapshot.applierReady==='boolean')state.applierReady=snapshot.applierReady;
  }
  renderProfileList();
}

export function renderProfileStudioState(){
  const host=byId('profileStudioState');
  if(!host)return;
  renderSettingsBadge('profileApiBadge');
  if(!state.checked){
    replaceNotice(host,{tone:'info',title:'Settings-API wird geprüft …',body:'Profile, Katalog und Applier-Bereitschaft werden gegen die Control Plane geprüft.'});
    return;
  }
  if(profileCanApply()){
    const detail=[
      state.activeProfileId?`Aktiv: ${state.activeProfileId}`:'',
      state.protectionLevel?`Schutzstufe: ${LEVEL_LABEL[state.protectionLevel]||state.protectionLevel}`:'',
      state.updatedUtc?`Stand: ${formatTime(state.updatedUtc)}`:'',
    ].filter(Boolean).join(' · ');
    replaceNotice(host,{
      tone:'good',
      title:'Settings-API erreichbar und schreibbereit',
      body:detail||'Serverprofile können angewendet werden. Nicht unterstützte Kombinationen lehnt die Control Plane mit Begründung ab.',
    });
    return;
  }
  if(state.available){
    replaceNotice(host,{
      tone:'warn',
      title:'Settings gelesen, Anwenden derzeit nicht möglich',
      body:'Die Control Plane liefert Einstellungen, meldet aber den Applier nicht bereit. Änderungen werden deshalb nicht angeboten; es werden keine Werte simuliert.',
      actions:[{label:'API erneut prüfen',variant:'ghost',onClick:()=>{void refreshProfileStudio()}}],
    });
    return;
  }
  replaceNotice(host,{
    tone:'warn',
    title:'Profile können entworfen, aber nicht angewendet werden',
    body:'Die V5-Settings-API ist nicht erreichbar. Entwürfe bleiben lokal in dieser Sitzung; die Oberfläche zeigt keine simulierte aktive Richtlinie. Sobald die API verfügbar ist, erscheint hier die serverseitige Profilliste.',
    actions:[{label:'API erneut prüfen',variant:'ghost',onClick:()=>{void refreshProfileStudio()}}],
  });
}

export async function initProfileStudio(){
  selectLevelOptions();
  renderProfileControls();
  if(!profileFormBound){
    profileFormBound=true;
    byId('profileForm')?.addEventListener('submit',event=>{
      event.preventDefault();
      void saveProfileFromForm();
    });
    byId('profileReset')?.addEventListener('click',resetProfileForm);
  }
  await ensureSettingsProbe();
  selectLevelOptions();
  renderProfileControls();
  renderProfileStudioState();
  renderProfileList();
}

async function saveProfileFromForm(){
  const name=String(byId('profileName')?.value||'').trim();
  const level=String(byId('profileLevel')?.value||'guarded');
  const description=String(byId('profileDescription')?.value||'').trim().slice(0,240);
  const values=readProfileValues();
  if(name.length<2||name.length>64){
    setText('profileFormStatus','Profilname muss zwischen 2 und 64 Zeichen lang sein.');
    return;
  }
  if(!Object.keys(values).length){
    setText('profileFormStatus','Mindestens ein Kontrollwert muss im Profil gesetzt sein.');
    return;
  }
  if(profileCanApply()){
    const updating=Boolean(editingProfileId);
    const payload={action:updating?'update':'create',profile:{name,description,level,values}};
    if(updating)payload.id=editingProfileId;
    const result=await mutateSettingsProfile(payload);
    if(result.ok){
      applyServerSnapshot(asObject(result.data));
      resetProfileForm();
      renderProfileStudioState();
      toast(updating?'Profil aktualisiert.':'Profil gespeichert.','good');
      await refreshProfileStudio();
    }else{
      setText('profileFormStatus',`Abgelehnt: ${result.message}`);
      toast(`Profil abgelehnt: ${result.message}`,'bad');
    }
    return;
  }
  const draft={id:editingProfileId||`local-${++profileSeq}`,name,level,description,values,source:'local'};
  const existing=localProfiles.findIndex(item=>item.id===draft.id);
  if(existing>=0)localProfiles[existing]=draft;else localProfiles=[...localProfiles,draft];
  editingProfileId=draft.id;
  renderProfileList();
  setText('profileFormStatus',`Entwurf „${draft.name}“ lokal gespeichert. Nicht angewendet.`);
  toast('Profilentwurf lokal gespeichert. Anwenden erfordert die Settings-API.','info');
}

export async function refreshProfileStudio(){
  await ensureSettingsProbe(true);
  selectLevelOptions();
  renderProfileControls();
  renderProfileStudioState();
  renderProfileList();
}

/* ------------------------------------------------------------------ */
/* MHX XDR settings                                                    */
/* ------------------------------------------------------------------ */
function setMhxFormState(available,reason){
  const form=byId('mhxSettingsForm');
  if(!form)return;
  form.dataset.available=String(Boolean(available));
  for(const control of form.querySelectorAll('select,input'))control.disabled=!available;
  const save=byId('mhxSettingsSave');
  if(save)save.disabled=!available;
  const reload=byId('mhxSettingsReload');
  if(reload)reload.disabled=false;
  if(!available){
    for(const id of ['mhxProcessLevel','mhxNetworkLevel','mhxApplicationLevel','mhxUnknownAppPolicy'])markUnavailableSelect(byId(id));
    for(const id of ['mhxAutoTerminate','mhxNotifyEvents','mhxNotifyCritical']){
      const input=byId(id);
      if(input)input.checked=false;
    }
    const limits=byId('mhxLimits');
    if(limits)limits.replaceChildren();
    replaceNotice('mhxSettingsState',{
      tone:'warn',
      title:'XDR-Richtlinie: Einstellungs-API nicht verfügbar',
      body:`Grund: ${reason||'Die Control Plane liefert noch keine schreibbare MHX-Konfiguration.'} · Die Live-Telemetrie und der Tiefenscan bleiben nutzbar. Es werden keine Werte simuliert.`,
      actions:[{label:'Erneut prüfen',variant:'ghost',onClick:()=>{void reloadMhxSettings()}}],
    });
  }else{
    replaceNotice('mhxSettingsState',{
      tone:'info',
      title:'XDR-Richtlinie aus der Control Plane',
      body:'Werte werden serverseitig validiert. Nicht unterstützte Kombinationen werden abgelehnt und mit Begründung zurückgegeben. Ein Speichern verlangt eine Begründung der Sicherheits-Transaktion.',
    });
  }
}

function fillMhxForm(data){
  const settings=asObject(data);
  const aggressiveness=asObject(pick(settings,'aggressiveness','Aggressiveness'));
  const autoResponse=asObject(pick(settings,'autoResponse','AutoResponse'));
  const notifications=asObject(pick(settings,'notifications','Notifications'));
  const restrictions=asObject(pick(settings,'applicationNetworkRestrictions','ApplicationNetworkRestrictions','applicationRestrictions'));
  const level=String(pick(aggressiveness,'process')||pick(settings,'processAggressiveness')||'balanced');
  setSelect('mhxProcessLevel',level);
  setSelect('mhxNetworkLevel',level);
  setSelect('mhxApplicationLevel',level);
  setSelect('mhxUnknownAppPolicy',String(pick(restrictions,'unknownPolicy')||'audit'));
  const autoTerminate=byId('mhxAutoTerminate');
  if(autoTerminate)autoTerminate.checked=Boolean(pick(autoResponse,'terminate','termination','enabled'));
  const notifyEvents=byId('mhxNotifyEvents');
  if(notifyEvents)notifyEvents.checked=Boolean(pick(notifications,'events','blockEvents','enabled'));
  const criticalValue=pick(notifications,'critical','minimumSeverity');
  const notifyCritical=byId('mhxNotifyCritical');
  if(notifyCritical){
    notifyCritical.checked=typeof criticalValue==='boolean'?criticalValue:String(criticalValue||'').toUpperCase()==='CRITICAL';
  }
  const toastEnabled=byId('mhxToastEnabled');
  if(toastEnabled)toastEnabled.checked=pick(notifications,'windowsToasts','WindowsToasts')!==false;
  const toastSeverity=byId('mhxToastSeverity');
  if(toastSeverity)toastSeverity.value=String(pick(notifications,'toastMinimumSeverity','ToastMinimumSeverity')||'LOW').toUpperCase();
  renderMhxLimits(settings);
}

function renderMhxLimits(settings){
  const host=byId('mhxLimits');
  if(!host)return;
  host.replaceChildren();
  const data=asObject(settings);
  const readOnly=asObject(pick(data,'readOnly','readonly'));
  const process=asObject(readOnly.process);
  const application=asObject(readOnly.application);
  const network=asObject(readOnly.network);
  const autoResponse=asObject(pick(data,'autoResponse'));
  const rows=[
    ['Auto-Response ab Schwere',String(pick(autoResponse,'minimumSeverity','MinimumSeverity')||'—')],
    ['Prozess-/Kommando-Restriktionen',process.supported===false?`Nicht unterstützt: ${text(process.reason,'kein Mechanismus in diesem Build')}`:`Unterstützt${process.reason?`: ${process.reason}`:''}`],
    ['Anwendungs-Deny-Liste',application.denyListSupported===true?'Unterstützt':'Nicht unterstützt – nur Authenticode-Allowlist'],
    ['Allowlist durchgesetzt',application.allowListEnforced===true?'Ja':'Nein'],
    ['Netzwerk-Durchsetzung',text(network.enforcedBy,'nicht gemeldet')],
    ['Konfigurationsquelle',humanSource(pick(data,'source'),'nicht gemeldet')],
  ];
  const warnings=listFrom(pick(data,'warnings'));
  for(const [label,value]of rows){
    const row=node('div','app-row');
    const main=node('div','app-row-main');
    main.append(node('strong','',label),node('small','',value));
    row.append(main);
    host.append(row);
  }
  if(warnings.length){
    const row=node('div','app-row');
    const main=node('div','app-row-main');
    main.append(node('strong','','Warnungen der Control Plane'),node('small','',warnings.join(' · ')));
    row.append(main);
    host.append(row);
  }
}

function setSelect(id,value){
  const select=byId(id);
  if(!select)return;
  const wanted=String(value||'');
  if([...select.options].some(option=>option.value===wanted))select.value=wanted;
}

function syncAggressiveness(event){
  const value=event.currentTarget.value;
  for(const id of ['mhxProcessLevel','mhxNetworkLevel','mhxApplicationLevel']){
    const select=byId(id);
    if(select&&select.value!==value)select.value=value;
  }
}

export async function loadMhxSettingsPanel(options={}){
  renderSettingsBadge('mhxSettingsBadge');
  const [settingsResult]=await Promise.all([getMhxSettings(),ensureSettingsProbe()]);
  if(settingsResult.ok){
    fillMhxForm(settingsResult.data);
    setMhxFormState(true);
    const source=String(pick(asObject(settingsResult.data),'source','configSource')||'');
    if(source&&!options.preserveStatus)setText('mhxSettingsStatus',`Quelle: ${humanSource(source)}`);
    setPill('mhxSettingsBadge','MHX-SETTINGS VERFÜGBAR','good');
  }else{
    setMhxFormState(false,settingsResult.message);
    setPill('mhxSettingsBadge','MHX-SETTINGS NICHT VERFÜGBAR','warn');
  }
  if(options.includeApplications!==false){await loadMhxApplications();await loadMhxApplicationDenies()}
  return Boolean(settingsResult.ok);
}

export function bindMhxSettingsPanel(){
  if(mhxBound)return;
  mhxBound=true;
  for(const id of ['mhxProcessLevel','mhxNetworkLevel','mhxApplicationLevel']){
    byId(id)?.addEventListener('change',()=>{syncAggressiveness();scheduleMhxAutoSave()});
  }
  for(const id of ['mhxAutoTerminate','mhxNotifyEvents','mhxNotifyCritical','mhxToastEnabled','mhxToastSeverity','mhxUnknownAppPolicy']){
    byId(id)?.addEventListener('change',scheduleMhxAutoSave);
  }
  byId('mhxSettingsForm')?.addEventListener('submit',event=>{event.preventDefault();void persistMhxSettings()});
  byId('mhxSettingsReload')?.addEventListener('click',()=>{void reloadMhxSettings()});
  byId('mhxAppAdd')?.addEventListener('click',()=>{void changeMhxApplication('Add')});
  byId('mhxApplicationsReload')?.addEventListener('click',()=>{void loadMhxApplications()});
  byId('mhxDenyAdd')?.addEventListener('click',()=>{void changeMhxApplicationDeny('Add')});
  byId('mhxDeniesReload')?.addEventListener('click',()=>{void loadMhxApplicationDenies()});
}

let mhxAutoTimer=null;
let mhxAutoSaving=false;

function scheduleMhxAutoSave(){
  const form=byId('mhxSettingsForm');
  if(!form||form.dataset.available!=='true')return;
  if(mhxAutoTimer)clearTimeout(mhxAutoTimer);
  mhxAutoTimer=setTimeout(()=>{mhxAutoTimer=null;void persistMhxSettings({auto:true})},650);
}

async function persistMhxSettings(options={}){
  const button=byId('mhxSettingsSave');
  const status=byId('mhxSettingsStatus');
  if(mhxAutoSaving&&options.auto)return;
  const level=String(byId('mhxProcessLevel')?.value||'');
  if(!level){
    setFormStatus(status,'Keine Aggressivitätsstufe ausgewählt.','bad');
    return;
  }
  let reason=String(options.reason||'').trim();
  if(!reason&&!options.auto){
    reason=await requestReason({
      title:'XDR-Richtlinie speichern',
      text:'Aggressivität, Auto-Response und Benachrichtigungen der MHX-Policy werden serverseitig validiert und als Sicherheits-Transaktion protokolliert.',
      label:'Begründung der Richtlinienänderung',
      confirmLabel:'Richtlinie speichern',
    })||'';
  }
  if(options.auto&&!reason)reason='Automatische XDR-Richtlinienänderung über die Operator-Oberfläche';
  if(!reason)return;
  const payload={
    aggressiveness:{process:level,network:level,application:level},
    autoResponse:{terminate:Boolean(byId('mhxAutoTerminate')?.checked)},
    notifications:{
      events:Boolean(byId('mhxNotifyEvents')?.checked),
      critical:Boolean(byId('mhxNotifyCritical')?.checked),
      windowsToasts:Boolean(byId('mhxToastEnabled')?.checked),
      toastMinimumSeverity:String(byId('mhxToastSeverity')?.value||'LOW'),
    },
    applicationNetworkRestrictions:{unknownPolicy:String(byId('mhxUnknownAppPolicy')?.value||'audit')},
    reason,
  };
  if(button){button.disabled=true;button.classList.add('loading');button.textContent='Speichere …'}
  mhxAutoSaving=Boolean(options.auto);
  setFormStatus(status,options.auto?'Änderung wird automatisch gespeichert …':'Richtlinie wird an die Control Plane übergeben …','');
  try{
    const result=await saveMhxSettings(payload);
    if(result.ok){
      setFormStatus(status,options.auto?'Änderung automatisch gespeichert und validiert.':'XDR-Richtlinie gespeichert und validiert.','good');
      if(!options.auto)toast('XDR-Richtlinie gespeichert.','good');
      await loadMhxSettingsPanel({includeApplications:false,preserveStatus:options.auto===true});
    }else if(result.unavailable){
      setMhxFormState(false,result.message);
      setFormStatus(status,`Nicht verfügbar: ${result.message}`,'bad');
      toast('XDR-Richtlinie nicht verfügbar: Settings-API fehlt.','bad');
    }else{
      setFormStatus(status,`Abgelehnt: ${result.message}`,'bad');
      if(!options.auto)toast(`XDR-Richtlinie abgelehnt: ${result.message}`,'bad');
    }
  }finally{
    mhxAutoSaving=false;
    if(button){button.disabled=false;button.classList.remove('loading');button.textContent='XDR-Richtlinie speichern'}
  }
}

async function reloadMhxSettings(){
  await loadMhxSettingsPanel();
}

export async function loadMhxApplications(){
  const host=byId('mhxApplicationsList');
  if(!host)return;
  const result=await getMhxApplications();
  const stateEl=byId('mhxApplicationsState');
  if(!result.ok){
    if(stateEl)replaceNotice(stateEl,{tone:'warn',title:'App-Control-Allowlist nicht abrufbar',body:result.message});
    host.replaceChildren();
    setPill('mhxApplicationsCount','NICHT VERFÜGBAR','warn');
    return;
  }
  if(stateEl)clear(stateEl);
  const entries=listFrom(pick(asObject(result.data),'Entries','entries'));
  setPill('mhxApplicationsCount',`${formatNumber(entries.length)} FREIGABEN`,entries.length?'good':'info');
  host.replaceChildren();
  if(!entries.length){
    host.append(node('p','field-hint','Keine Anwendungsfreigaben hinterlegt. Die App-Control-Schicht kann keine zusätzlichen Anwendungen zulassen.'));
    return;
  }
  for(const raw of entries.slice(0,100)){
    const entry=asObject(raw);
    const path=text(pick(entry,'path','Path'));
    const row=node('div','app-row');
    const info=node('div','app-row-main');
    info.append(node('strong','',path),node('small','',`${text(pick(entry,'signer','Signer'),'Signatur unbekannt')} · ${text(pick(entry,'rule','Rule'),'Regel unbekannt')} · ${formatTime(pick(entry,'addedUtc','AddedUTC'))}`));
    const remove=node('button','button quiet small','Entfernen');
    remove.type='button';
    remove.addEventListener('click',()=>{void changeMhxApplication('Remove',path)});
    row.append(info,remove);
    host.append(row);
  }
}

async function changeMhxApplication(action,explicitPath){
  const path=String(explicitPath||byId('mhxAppPath')?.value||'').trim();
  const status=byId('mhxApplicationsStatus');
  if(path.length<3||path.length>1024){
    setFormStatus(status,'Programmpfad muss zwischen 3 und 1024 Zeichen lang sein.','bad');
    return;
  }
  // Changing the executable allow-list is a security-reducing mutation: the
  // server requires the typed confirmation phrase PLUS an operator reason
  // (AN-FIND-005/UI-FIND-003). Require both here as well.
  const reason=await requestReason({
    title:action==='Add'?'Anwendung freigeben':'Anwendung aus Allowlist entfernen',
    text:action==='Add'
      ?`„${path}“ zur App-Control-Allowlist hinzufügen? Die Transaktion wird protokolliert und ist reversibel.`
      :`„${path}“ aus der App-Control-Allowlist entfernen? Die Transaktion wird protokolliert und ist reversibel.`,
    label:'Begründung der Allowlist-Änderung',
    confirmLabel:action==='Add'?'Hinzufügen':'Entfernen',
    tone:action==='Add'?'primary':'danger',
  });
  if(!reason)return;
  setFormStatus(status,action==='Add'?'Freigabe wird geprüft und angewendet …':'Freigabe wird entfernt …','');
  const result=await setMhxApplication(action,path,reason);
  if(result.ok){
    if(byId('mhxAppPath'))byId('mhxAppPath').value='';
    setFormStatus(status,action==='Add'?'Anwendung freigegeben und Allowlist neu erzeugt.':'Anwendung entfernt und Allowlist neu erzeugt.','good');
    toast(action==='Add'?'Anwendung freigegeben.':'Anwendung aus Allowlist entfernt.','good');
    await loadMhxApplications();
  }else{
    setFormStatus(status,`Abgelehnt: ${result.message}`,'bad');
    toast(`App-Control-Aktion abgelehnt: ${result.message}`,'bad');
  }
}

export async function loadMhxApplicationDenies(){
  const host=byId('mhxDeniesList');
  if(!host)return;
  const result=await getMhxApplicationDenies();
  const stateEl=byId('mhxDeniesState');
  if(!result.ok){
    if(stateEl)replaceNotice(stateEl,{tone:'warn',title:'Netzwerk-Sperren nicht abrufbar',body:result.message});
    host.replaceChildren();
    setPill('mhxDeniesCount','NICHT VERFÜGBAR','warn');
    return;
  }
  if(stateEl)clear(stateEl);
  const payload=asObject(result.data);
  const entries=Array.isArray(result.data)?result.data:listFrom(pick(payload,'Entries','entries'));
  setPill('mhxDeniesCount',`${formatNumber(entries.length)} SPERREN`,entries.length?'warn':'info');
  host.replaceChildren();
  if(!entries.length){
    host.append(node('p','field-hint','Keine Anwendung ist aktuell per Windows-Firewall vom Netzwerk ausgeschlossen.'));
    return;
  }
  for(const raw of entries.slice(0,100)){
    const entry=asObject(raw);
    const path=text(pick(entry,'path','Path'));
    const row=node('div','app-row');
    const info=node('div','app-row-main');
    const hash=text(pick(entry,'sha256','SHA256'));
    info.append(node('strong','',path),node('small','',`${hash?hash.slice(0,16)+'…':'Hash unbekannt'} · ${text(pick(entry,'rule','Rule'),'Regel unbekannt')} · ${formatTime(pick(entry,'addedUtc','AddedUTC'))}`));
    const remove=node('button','button quiet small','Sperre aufheben');
    remove.type='button';
    remove.addEventListener('click',()=>{void changeMhxApplicationDeny('Remove',path)});
    row.append(info,remove);
    host.append(row);
  }
}

async function changeMhxApplicationDeny(action,explicitPath){
  const path=String(explicitPath||byId('mhxDenyPath')?.value||'').trim();
  const status=byId('mhxDeniesStatus');
  if(path.length<3||path.length>1024){
    setFormStatus(status,'Programmpfad muss zwischen 3 und 1024 Zeichen lang sein.','bad');
    return;
  }
  const reason=await requestReason({
    title:action==='Add'?'Anwendung vom Netzwerk ausschließen':'Netzwerksperre aufheben',
    text:action==='Add'
      ?`Für „${path}“ werden echte Windows-Firewall-Regeln (ausgehend und eingehend, Aktion Block) erzeugt. Die Transaktion wird protokolliert und kann über „Sperre aufheben“ zurückgenommen werden.`
      :`Die Windows-Firewall-Sperren für „${path}“ werden entfernt. Die Änderung wird protokolliert.`,
    label:'Begründung der Netzwerk-Transaktion',
    confirmLabel:action==='Add'?'Netzwerk blockieren':'Sperre aufheben',
  });
  if(!reason)return;
  setFormStatus(status,action==='Add'?'Netzwerksperre wird geprüft und angewendet …':'Netzwerksperre wird entfernt …','');
  const result=await setMhxApplicationDeny({action,path,reason});
  if(result.ok){
    if(byId('mhxDenyPath'))byId('mhxDenyPath').value='';
    setFormStatus(status,action==='Add'?'Anwendung im Netzwerk blockiert.':'Netzwerksperre entfernt.','good');
    toast(action==='Add'?'Anwendung vom Traffic ausgeschlossen.':'Netzwerksperre entfernt.','good');
    await loadMhxApplicationDenies();
  }else{
    setFormStatus(status,`Abgelehnt: ${result.message}`,'bad');
    toast(`Netzwerk-Transaktion abgelehnt: ${result.message}`,'bad');
  }
}

/* ------------------------------------------------------------------ */
/* Kinetic settings                                                    */
/* ------------------------------------------------------------------ */
function setKineticFormState(available,reason){
  const form=byId('kineticSettingsForm');
  if(!form)return;
  form.dataset.available=String(Boolean(available));
  for(const control of form.querySelectorAll('input,button'))control.disabled=!available;
  const reload=byId('kineticSettingsReload');
  if(reload)reload.disabled=false;
  if(!available){
    replaceNotice('kineticSettingsState',{
      tone:'warn',
      title:'Kinetic-Richtlinie: Einstellungs-API nicht verfügbar',
      body:`Grund: ${reason||'Die Control Plane liefert noch keine schreibbare Kinetic-Konfiguration.'} · Die Live-Korrelation und die Bedienung oben bleiben nutzbar. Es werden keine Schwellenwerte simuliert.`,
      actions:[{label:'Erneut prüfen',variant:'ghost',onClick:()=>{void reloadKineticSettings()}}],
    });
  }else{
    replaceNotice('kineticSettingsState',{
      tone:'info',
      title:'Kinetic-Richtlinie aus der Control Plane',
      body:'Persistenz wird nur nach erneuter Verifikation von Threat-IP-Regelgeneration und WFP-Telemetrie wiederhergestellt. Jede Änderung verlangt eine Begründung; fail-secure bleibt erhalten.',
    });
  }
}

function markKineticFieldsUnavailable(){
  for(const id of ['kineticWindowSeconds','kineticMinEvents','kineticMinDistinctPorts','kineticAutoDisarm']){
    const input=byId(id);
    if(!input)continue;
    input.value='';
    input.placeholder='Nicht verfügbar';
  }
  for(const id of ['kineticPersistArmed','kineticNotifyEnabled']){
    const input=byId(id);
    if(input)input.checked=false;
  }
}

function applyKineticLimitAttributes(limits){
  const groups=asObject(limits);
  const setRange=(id,range,scale=1)=>{
    const input=byId(id);
    const limitsRange=asObject(range);
    if(!input)return;
    const min=Number(limitsRange.min);
    const max=Number(limitsRange.max);
    if(Number.isFinite(min))input.min=String(Math.ceil(min/scale));
    if(Number.isFinite(max))input.max=String(Math.floor(max/scale));
  };
  setRange('kineticWindowSeconds',groups.burstWindowSeconds);
  setRange('kineticMinEvents',groups.minEvents);
  setRange('kineticMinDistinctPorts',groups.minDistinctPorts);
  const disarm=byId('kineticAutoDisarm');
  const auto=asObject(groups.autoDisarmSeconds);
  if(disarm&&Object.keys(auto).length){
    const min=Number(auto.min);
    const max=Number(auto.max);
    if(Number.isFinite(min))disarm.dataset.activeMin=String(Math.ceil(min/60));
    if(Number.isFinite(max))disarm.max=String(Math.max(0,Math.floor(max/60)));
  }
}

function fillKineticForm(data,status){
  const settings=asObject(data);
  const thresholds=asObject(pick(settings,'thresholds','Thresholds'));
  const notifications=asObject(pick(settings,'notifications','Notifications'));
  applyKineticLimitAttributes(settings.limits);
  const armedAfterRestart=byId('kineticPersistArmed');
  if(armedAfterRestart){
    armedAfterRestart.checked=Boolean(pick(settings,'desiredArmed','armedAfterRestart','persistArmed','persistence'));
  }
  setInputValue('kineticWindowSeconds',pick(thresholds,'windowSeconds','burstWindowSeconds','window'));
  setInputValue('kineticMinEvents',pick(thresholds,'minEvents','minimumEvents'));
  setInputValue('kineticMinDistinctPorts',pick(thresholds,'minDistinctPorts','distinctPorts'));
  const autoDisarmSeconds=Number(pick(thresholds,'autoDisarmSeconds'));
  setInputValue('kineticAutoDisarm',Number.isFinite(autoDisarmSeconds)&&autoDisarmSeconds>0?Math.round(autoDisarmSeconds/60):0);
  const notify=byId('kineticNotifyEnabled');
  if(notify)notify.checked=Boolean(pick(notifications,'enabled','kineticEvents'));
  renderKineticPersistence(settings,status);
}

function setInputValue(id,value){
  const input=byId(id);
  if(input)input.value=value===undefined||value===null?'':String(value);
}

function renderKineticPersistence(settings,status){
  const data=asObject(settings);
  const armed=typeof data.armed==='boolean'?data.armed:Boolean(status?.kineticArmed);
  const persisted=typeof data.persisted==='boolean'?data.persisted:undefined;
  const desired=typeof data.desiredArmed==='boolean'?data.desiredArmed:undefined;
  const rearmed=typeof data.rearmedAfterRestart==='boolean'?data.rearmedAfterRestart:undefined;
  const configSource=pick(data,'configSource','source');
  const armingSource=pick(data,'armingSource','persistenceSource');
  setText('kineticPersistState',persisted===undefined?'Nicht verfügbar':persisted?'Gespeichert':'Nicht gespeichert');
  setText('kineticConfigSource',configSource?humanSource(configSource):'Live-Status (Settings-API fehlt)');
  setText('kineticRearmedState',rearmed===undefined?'Unbekannt':rearmed?'Wiederhergestellt':'Nicht wiederhergestellt');
  const badge=byId('kineticPersistenceBadge');
  if(badge){
    if(desired===true){badge.textContent='RE-ARM GEPLANT';badge.className='status-pill warn'}
    else if(armed){badge.textContent='BEWAFFNET';badge.className='status-pill warn'}
    else if(persisted===false){badge.textContent='OBSERVE ONLY';badge.className='status-pill info'}
    else{badge.textContent='OBSERVE ONLY';badge.className='status-pill info'}
  }
  const detail=byId('kineticCoverage');
  if(detail&&armingSource){
    const base=detail.textContent||'';
    if(!base.includes('Quelle:'))detail.textContent=`${base} · Quelle: ${humanSource(armingSource)}`;
  }
  const warning=String(pick(data,'configWarning','reason')||'');
  const stateHost=byId('kineticSettingsState');
  if(stateHost&&warning&&stateHost.dataset.warningShown!=='true'){
    stateHost.dataset.warningShown='true';
    stateHost.append(node('p','field-hint',`Hinweis der Control Plane: ${warning}`));
  }
}

export async function loadKineticSettingsPanel(status){
  lastStatus=status;
  const result=await getKineticSettings();
  if(result.ok){
    fillKineticForm(result.data,status);
    setKineticFormState(true);
    setPill('kineticSettingsBadge','KINETIC-SETTINGS VERFÜGBAR','good');
  }else{
    markKineticFieldsUnavailable();
    renderKineticPersistence({},status);
    setKineticFormState(false,result.message);
    setPill('kineticSettingsBadge','KINETIC-SETTINGS NICHT VERFÜGBAR','warn');
  }
}

export function bindKineticSettingsPanel(){
  if(kineticBound)return;
  kineticBound=true;
  for(const id of ['kineticPersistArmed','kineticNotifyEnabled','kineticWindowSeconds','kineticMinEvents','kineticMinDistinctPorts','kineticAutoDisarm']){
    byId(id)?.addEventListener('change',scheduleKineticAutoSave);
  }
  byId('kineticSettingsForm')?.addEventListener('submit',event=>{event.preventDefault();void persistKineticSettings()});
  byId('kineticSettingsReload')?.addEventListener('click',()=>{void reloadKineticSettings()});
}

let kineticAutoTimer=null;
let kineticAutoSaving=false;

function scheduleKineticAutoSave(){
  if(byId('kineticSettingsForm')?.dataset.available!=='true')return;
  if(kineticAutoTimer)clearTimeout(kineticAutoTimer);
  kineticAutoTimer=setTimeout(()=>{kineticAutoTimer=null;void persistKineticSettings({auto:true})},650);
}

async function persistKineticSettings(options={}){
  const button=byId('kineticSettingsSave');
  const status=byId('kineticSettingsStatus');
  if(kineticAutoSaving&&options.auto)return;
  const windowSeconds=Number(byId('kineticWindowSeconds')?.value||0);
  const minEvents=Number(byId('kineticMinEvents')?.value||0);
  const minDistinctPorts=Number(byId('kineticMinDistinctPorts')?.value||0);
  const autoDisarmRaw=byId('kineticAutoDisarm')?.value;
  const autoDisarmMinutes=autoDisarmRaw===''?0:Number(autoDisarmRaw);
  const rangeOf=(id,fallbackMin,fallbackMax)=>{
    const input=byId(id);
    const min=Number(input?.min);
    const max=Number(input?.max);
    return {min:Number.isFinite(min)?min:fallbackMin,max:Number.isFinite(max)?max:fallbackMax};
  };
  const windowRange=rangeOf('kineticWindowSeconds',2,300);
  const eventRange=rangeOf('kineticMinEvents',3,32);
  const portRange=rangeOf('kineticMinDistinctPorts',2,16);
  const autoDisarmRange=rangeOf('kineticAutoDisarm',0,10080);
  const autoDisarmActiveMin=Number(byId('kineticAutoDisarm')?.dataset.activeMin||5);
  if(!Number.isFinite(windowSeconds)||windowSeconds<windowRange.min||windowSeconds>windowRange.max){
    setFormStatus(status,`Burst-Fenster muss zwischen ${windowRange.min} und ${windowRange.max} Sekunden liegen.`,'bad');
    return;
  }
  if(!Number.isFinite(minEvents)||minEvents<eventRange.min||minEvents>eventRange.max){
    setFormStatus(status,`Mindest-Ereignisse müssen zwischen ${eventRange.min} und ${eventRange.max} liegen.`,'bad');
    return;
  }
  if(!Number.isInteger(minDistinctPorts)||minDistinctPorts<portRange.min||minDistinctPorts>portRange.max){
    setFormStatus(status,`Mindest-Portvielfalt muss zwischen ${portRange.min} und ${portRange.max} distinkten Ports liegen.`,'bad');
    return;
  }
  if(minDistinctPorts>minEvents){
    setFormStatus(status,'Die Mindest-Portvielfalt darf die Mindest-Ereignisse nicht überschreiten.','bad');
    return;
  }
  if(!Number.isFinite(autoDisarmMinutes)||autoDisarmMinutes<0||autoDisarmMinutes>autoDisarmRange.max||(autoDisarmMinutes>0&&autoDisarmMinutes<autoDisarmActiveMin)){
    setFormStatus(status,`Auto-Disarm muss 0 (aus) oder zwischen ${autoDisarmActiveMin} und ${autoDisarmRange.max} Minuten liegen.`,'bad');
    return;
  }
  let reason=String(options.reason||'').trim();
  if(!reason&&!options.auto){
    reason=await requestReason({
      title:'Kinetic-Richtlinie speichern',
      text:'Persistenz, Schwellen und Benachrichtigungen der Kinetic-Korrelation werden serverseitig validiert. Die Bewaffnung wird nach einem Neustart nur nach erneuter Verifikation wiederhergestellt.',
      label:'Begründung der Kinetic-Änderung',
      confirmLabel:'Kinetic-Richtlinie speichern',
    })||'';
  }
  if(options.auto&&!reason)reason='Automatische Kinetic-Richtlinienänderung über die Operator-Oberfläche';
  if(!reason)return;
  const payload={
    armedAfterRestart:Boolean(byId('kineticPersistArmed')?.checked),
    thresholds:{windowSeconds,minEvents,minDistinctPorts},
    autoDisarmMinutes,
    notifications:{enabled:Boolean(byId('kineticNotifyEnabled')?.checked)},
    reason,
  };
  kineticAutoSaving=Boolean(options.auto);
  if(button){button.disabled=true;button.classList.add('loading');button.textContent='Speichere …'}
  setFormStatus(status,options.auto?'Änderung wird automatisch gespeichert …':'Kinetic-Richtlinie wird geprüft …','');
  try{
    const result=await saveKineticSettings(payload);
    if(result.ok){
      setFormStatus(status,options.auto?'Änderung automatisch gespeichert und validiert.':'Kinetic-Richtlinie gespeichert und validiert.','good');
      if(!options.auto)toast('Kinetic-Richtlinie gespeichert.','good');
      await loadKineticSettingsPanel(lastStatus);
    }else if(result.unavailable){
      setKineticFormState(false,result.message);
      setFormStatus(status,`Nicht verfügbar: ${result.message}`,'bad');
      toast('Kinetic-Richtlinie nicht verfügbar: Settings-API fehlt.','bad');
    }else{
      setFormStatus(status,`Abgelehnt: ${result.message}`,'bad');
      if(!options.auto)toast(`Kinetic-Richtlinie abgelehnt: ${result.message}`,'bad');
    }
  }finally{
    kineticAutoSaving=false;
    if(button){button.disabled=false;button.classList.remove('loading');button.textContent='Kinetic-Richtlinie speichern'}
  }
}

async function reloadKineticSettings(){
  await loadKineticSettingsPanel(lastStatus);
}

export function rememberStatus(status){lastStatus=status}

/* ------------------------------------------------------------------ */
/* Threat Intelligence polling interval                                */
/* ------------------------------------------------------------------ */
let localTiInterval=null;
let tiServerInterval=null;
let tiPollingBounds={min:5,max:1440};

export async function loadThreatIntelSettingsPanel(){
  const result=await getThreatIntelStatus();
  const status=result.ok?asObject(result.data):{};
  const serverValue=Number(pick(status,'pollIntervalMinutes','intervalMinutes','pollInterval'));
  tiServerInterval=Number.isFinite(serverValue)&&serverValue>0?serverValue:null;
  const min=Number(pick(status,'minIntervalSeconds'))/60;
  const max=Number(pick(status,'maxIntervalSeconds'))/60;
  tiPollingBounds={
    min:Number.isFinite(min)&&min>=1?Math.ceil(min):5,
    max:Number.isFinite(max)&&max>=5?Math.floor(max):1440,
  };
  const select=byId('tiInterval');
  if(!select)return;
  const wanted=tiServerInterval||localTiInterval||60;
  if(![...select.options].some(option=>Number(option.value)===wanted)){
    const option=document.createElement('option');
    option.value=String(wanted);
    option.textContent=`Alle ${wanted} Minuten (Serverwert)`;
    select.prepend(option);
  }
  select.value=String(wanted);
  const note=byId('tiIntervalNote');
  const statusEl=byId('tiIntervalStatus');
  const source=String(pick(status,'pollingSource','source')||'');
  if(result.ok){
    if(note)note.textContent=`Dieses Intervall stammt aus der Control Plane (${humanSource(source,'Serverkonfiguration')}) und wird serverseitig persistiert. Erlaubt: ${tiPollingBounds.min}–${tiPollingBounds.max} Minuten.`;
    const next=pick(status,'nextPollUtc','nextSyncUtc');
    setFormStatus(statusEl,`Serverwert: ${tiServerInterval||'—'} Minuten${next?` · nächster Abruf ${formatTime(next)}`:''}`,'');
  }else{
    if(note)note.textContent='Die Polling-API ist nicht erreichbar. Eine Auswahl bleibt nur lokal in dieser Sitzung; sie wird ausdrücklich nicht als gespeichert ausgegeben.';
    setFormStatus(statusEl,'Lokale Sitzungseinstellung – nicht persistiert.','');
  }
}

let tiAutoTimer=null;

export function bindThreatIntelSettingsPanel(){
  if(tiBound)return;
  tiBound=true;
  byId('tiIntervalSave')?.addEventListener('click',()=>{void persistTiInterval()});
  byId('tiInterval')?.addEventListener('change',()=>{
    if(tiAutoTimer)clearTimeout(tiAutoTimer);
    tiAutoTimer=setTimeout(()=>{tiAutoTimer=null;void persistTiInterval({auto:true})},650);
  });
}

async function persistTiInterval(options={}){
  const select=byId('tiInterval');
  const statusEl=byId('tiIntervalStatus');
  const button=byId('tiIntervalSave');
  const minutes=Number(select?.value||0);
  if(!Number.isInteger(minutes)||minutes<tiPollingBounds.min||minutes>tiPollingBounds.max){
    setFormStatus(statusEl,`Intervall muss zwischen ${tiPollingBounds.min} und ${tiPollingBounds.max} Minuten liegen.`,'bad');
    return;
  }
  let reason=String(options.reason||'').trim();
  if(!reason&&!options.auto){
    reason=await requestReason({
      title:'Threat-Intelligence-Intervall speichern',
      text:`Der automatische Feed-Abruf wird auf ${minutes} Minuten gesetzt. Die Control Plane validiert die Grenzen und protokolliert die Änderung.`,
      label:'Begründung der Intervalländerung',
      confirmLabel:'Intervall speichern',
    })||'';
  }
  if(options.auto&&!reason)reason=`Automatische Änderung des Threat-Intelligence-Abrufintervalls auf ${minutes} Minuten über die Operator-Oberfläche`;
  if(!reason){
    setFormStatus(statusEl,'Nicht gespeichert: keine Begründung angegeben.','');
    return;
  }
  if(button){button.disabled=true;button.classList.add('loading');button.textContent='Speichere …'}
  setFormStatus(statusEl,options.auto?'Intervall wird automatisch gespeichert …':'Intervall wird an die Control Plane übergeben …','');
  try{
    const result=await saveThreatIntelSettings({pollIntervalMinutes:minutes,reason});
    if(result.ok){
      localTiInterval=null;
      tiServerInterval=minutes;
      setFormStatus(statusEl,options.auto?`Intervall automatisch gespeichert: ${minutes} Minuten.`:`Intervall serverseitig gespeichert: ${minutes} Minuten.`,'good');
      if(!options.auto)toast('Threat-Intelligence-Intervall gespeichert.','good');
      await loadThreatIntelSettingsPanel();
    }else if(result.unavailable){
      localTiInterval=minutes;
      setFormStatus(statusEl,`Nicht persistiert: ${result.message}. Auswahl gilt nur lokal in dieser Sitzung.`,'bad');
      toast('Intervall nur lokal gesetzt – Settings-API nicht verfügbar.','warn');
    }else{
      setFormStatus(statusEl,`Abgelehnt: ${result.message}`,'bad');
    }
  }finally{
    if(button){button.disabled=false;button.classList.remove('loading');button.textContent='Intervall speichern'}
  }
}

export function localThreatIntelInterval(){return localTiInterval}

/* ------------------------------------------------------------------ */
/* Threat-Intelligence per-feed authority                              */
/* ------------------------------------------------------------------ */
const FEED_ACTION_LABEL={
  DEFAULT:'Katalog-Standard',
  BLOCK:'Blockieren',
  CORRELATE_ONLY:'Nur korrelieren',
  ANNOTATE_ONLY:'Nur annotieren',
};
let feedPolicyBound=false;
let feedPolicySnapshot=null;

function feedRoleChip(action){
  const role=String(action||'DEFAULT');
  const chip=node('span','feed-role');
  chip.dataset.role=role;
  chip.append(node('i','feed-role-dot'),document.createTextNode(FEED_ACTION_LABEL[role]||role));
  return chip;
}

export async function loadFeedPolicyPanel(){
  const host=byId('tiFeedPolicyList');
  if(!host)return;
  bindFeedPolicyPanel();
  const result=await getFeedPolicy();
  const state=byId('tiFeedPolicyState');
  const status=byId('tiFeedPolicyStatus');
  if(!result.ok){
    feedPolicySnapshot=null;
    host.replaceChildren(node('div','empty-state','Feed-Autorität ist in diesem Build nicht verfügbar.'));
    if(state)replaceNotice(state,{tone:'warn',title:'Feed-Autorität nicht abrufbar',body:result.message});
    setPill('tiFeedPolicyStore','NICHT VERFÜGBAR','warn');
    setPill('tiFeedPolicyPending', '—','info');
    if(status)setFormStatus(status,'Keine Änderung möglich.','bad');
    return;
  }
  feedPolicySnapshot=asObject(result.data);
  if(state)clear(state);
  const snapshot=feedPolicySnapshot;
  const store=String(snapshot.storeState||'DEFAULT').toUpperCase();
  const storeLabel=store==='PERSISTED'?'PERSISTIERT':store==='INVALID_DEFAULT'?'STORE FEHLERHAFT':'KATALOG';
  setPill('tiFeedPolicyStore',storeLabel,store==='INVALID_DEFAULT'?'bad':store==='PERSISTED'?'good':'info');
  const pending=snapshot.pending===true;
  const pendingBadge=byId('tiFeedPolicyPending');
  if(pendingBadge)pendingBadge.hidden=false;
  setPill('tiFeedPolicyPending',pending?'WFP AUSSTEHEND':snapshot.wfpVerified===true?'WFP VERIFIZIERT':'WFP UNGEPRÜFT',pending?'warn':snapshot.wfpVerified===true?'good':'info');
  if(snapshot.wfpVerified===false&&!pending){
    if(state)replaceNotice(state,{tone:'warn',title:'Keine verifizierte WFP-Generation',body:'Feed-Rollen können gespeichert werden, gelten aber erst nach einer verifizierten WFP-Anwendung als aktive Sperrautorität.'});
  }
  if(snapshot.storeError&&state)replaceNotice(state,{tone:'bad',title:'Feed-Policy-Store nicht lesbar',body:'Die Katalog-Autorität bleibt aktiv. Der Store wurde unverändert für die Forensik belassen. '+String(snapshot.storeError)});
  if(Array.isArray(snapshot.warnings)&&snapshot.warnings.length&&state&&!snapshot.storeError){
    replaceNotice(state,{tone:'warn',title:'Hinweise der Control Plane',body:snapshot.warnings.map(String).join(' · ')});
  }
  host.replaceChildren();
  const feeds=Array.isArray(snapshot.feeds)?snapshot.feeds:[];
  if(!feeds.length){
    host.append(node('div','empty-state','Noch keine Feed-Autorität verfügbar.'));
    return;
  }
  for(const feed of feeds){
    const configured=String(feed.configuredAction||feed.effectiveAction||'DEFAULT');
    const defaultAction=String(feed.defaultAction||'DEFAULT');
    const displayAction=String(feed.effectiveAction||configured);
    const row=node('div','feed-policy-row');
    row.dataset.feedId=String(feed.feedId||'');
    row.dataset.defaultAction=defaultAction;
    const main=node('div','feed-policy-main');
    const nameLine=node('div','feed-policy-name');
    nameLine.append(node('strong','',String(feed.name||feed.feedId||'Feed')));
    const role=feedRoleChip(displayAction);
    role.dataset.roleChip='true';
    nameLine.append(role);
    if(String(feed.actionSource||'').toUpperCase()==='OVERRIDE')nameLine.append(node('span','mode-caption','OPERATOR-OVERRIDE'));
    main.append(nameLine);
    const meta=node('div','feed-policy-meta');
    meta.append(node('span','',`Standard: ${FEED_ACTION_LABEL[String(feed.defaultAction||'DEFAULT')]||String(feed.defaultAction||'—')}`));
    meta.append(node('span','feed-state',String(feed.feedState||'UNBEKANNT')));
    meta.append(node('span','',`Enforcement: ${String(feed.enforcement||'—')}`));
    main.append(meta);
    const count=node('div','feed-policy-count');
    count.append(document.createTextNode(formatNumber(feed.indicators)),node('small','','Indikatoren'));
    const select=document.createElement('select');
    select.className='feed-policy-select';
    select.dataset.original=configured;
    select.dataset.feedId=String(feed.feedId||'');
    select.setAttribute('aria-label',`Rolle für ${String(feed.name||feed.feedId||'Feed')}`);
    const options=[['DEFAULT',`Standard (${FEED_ACTION_LABEL[String(feed.defaultAction||'DEFAULT')]||String(feed.defaultAction||'—')})`],['BLOCK',FEED_ACTION_LABEL.BLOCK],['CORRELATE_ONLY',FEED_ACTION_LABEL.CORRELATE_ONLY],['ANNOTATE_ONLY',FEED_ACTION_LABEL.ANNOTATE_ONLY]];
    for(const [value,label] of options){
      const option=document.createElement('option');
      option.value=value;
      option.textContent=label;
      select.append(option);
    }
    select.value=configured;
    select.addEventListener('change',()=>{
      select.dataset.dirty=select.value!==select.dataset.original?'true':'false';
      const chip=row.querySelector('[data-role-chip="true"]');
      if(chip){
        const effective=select.value==='DEFAULT'?row.dataset.defaultAction:select.value;
        chip.dataset.role=effective;
        chip.replaceChildren(node('i','feed-role-dot'),document.createTextNode(FEED_ACTION_LABEL[effective]||effective));
      }
      refreshFeedPolicyApplyState();
      scheduleFeedPolicyAutoSave();
    });
    row.append(main,count,select);
    host.append(row);
  }
  refreshFeedPolicyApplyState();
}

function refreshFeedPolicyApplyState(){
  const button=byId('tiFeedPolicyApply');
  if(!button)return;
  const dirty=[...document.querySelectorAll('.feed-policy-select')].filter(select=>select.value!==select.dataset.original);
  button.disabled=dirty.length===0;
  if(dirty.length)setFormStatus(byId('tiFeedPolicyStatus'),`${dirty.length} Rolle${dirty.length===1?'':'n'} geändert – noch nicht angewendet.`,'');
}

function bindFeedPolicyPanel(){
  if(feedPolicyBound)return;
  feedPolicyBound=true;
  byId('tiFeedPolicyReload')?.addEventListener('click',()=>{void loadFeedPolicyPanel()});
  byId('tiFeedPolicyApply')?.addEventListener('click',()=>{void applyFeedPolicyChanges()});
}

let feedPolicyAutoTimer=null;

function scheduleFeedPolicyAutoSave(){
  if(!feedPolicySnapshot)return;
  if(feedPolicyAutoTimer)clearTimeout(feedPolicyAutoTimer);
  feedPolicyAutoTimer=setTimeout(()=>{feedPolicyAutoTimer=null;void applyFeedPolicyChanges({auto:true})},900);
}

async function applyFeedPolicyChanges(options={}){
  const selects=[...document.querySelectorAll('.feed-policy-select')];
  const changes=selects.filter(select=>select.value!==select.dataset.original).map(select=>({feedId:select.dataset.feedId,action:select.value}));
  const status=byId('tiFeedPolicyStatus');
  const button=byId('tiFeedPolicyApply');
  if(!changes.length){setFormStatus(status,'Keine Änderung ausgewählt.','');return}
  let reason=String(options.reason||'').trim();
  if(!reason&&!options.auto){
    reason=await requestReason({
      title:'Feed-Autorität ändern',
      text:`${changes.length} Feed-Rolle${changes.length===1?'':'n'} werden serverseitig validiert und als Sicherheits-Transaktion protokolliert. BLOCK ist eine echte Firewall-Autorität; bei fehlender verifizierter WFP-Generation bleibt die Änderung ausdrücklich ausstehend.`,
      label:'Begründung der Feed-Rollen-Änderung',
      confirmLabel:'Feed-Rollen anwenden',
    })||'';
  }
  if(options.auto&&!reason)reason='Automatische Feed-Rollen-Änderung über die Operator-Oberfläche';
  if(!reason){setFormStatus(status,'Nicht angewendet: keine Begründung angegeben.','');return}
  if(button){button.disabled=true;button.classList.add('loading');button.textContent='Validiere Feed-Rollen …'}
  setFormStatus(status,options.auto?'Feed-Rollen werden automatisch gespeichert und validiert …':'Feed-Rollen werden geprüft und angewendet …','');
  try{
    const result=await setFeedPolicy({feeds:changes,reason});
    if(result.ok){
      const snapshot=asObject(result.data);
      const pending=snapshot.pending===true;
      const changed=snapshot.enforcementChanged===true;
      setFormStatus(status,pending?'Feed-Rollen automatisch gespeichert – WFP-Generation ist noch ausstehend.':options.auto?'Feed-Rollen automatisch gespeichert und serverseitig übernommen.':'Feed-Rollen gespeichert und serverseitig übernommen.',pending?'warn':'good');
      if(!options.auto)toast(pending?'Feed-Rollen gespeichert; WFP-Verifikation ausstehend.':'Feed-Rollen gespeichert.','good');
      await loadFeedPolicyPanel();
      if(changed)toast('Die kompilierte Enforcement-Generation wurde geändert.','info');
    }else{
      setFormStatus(status,`Abgelehnt: ${result.message}`,'bad');
      toast(`Feed-Rollen abgelehnt: ${result.message}`,'bad');
    }
  }finally{
    if(button){button.classList.remove('loading');button.textContent='Feed-Rollen anwenden'}
    refreshFeedPolicyApplyState();
  }
}
