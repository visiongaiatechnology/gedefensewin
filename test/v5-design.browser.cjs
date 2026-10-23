// STATUS: PLATIN
// Isolated visual-regression fixture for the GeDefense Windows V5 shell.
// Verifies composition/alignment invariants and captures full-page screenshots
// at desktop 1440, wide 1920 and mobile 390 for every operational view.
const fs = require('node:fs/promises');
const path = require('node:path');
const http = require('node:http');
const {createRequire} = require('node:module');
const runtimeRequire = process.env.CODEX_NODE_MODULES
  ? createRequire(path.join(path.resolve(process.env.CODEX_NODE_MODULES), 'package.json'))
  : require;
const {chromium} = runtimeRequire('playwright');

const root = path.resolve(__dirname, '../src/GeDefense/windows/internal/server/web');
const output = path.resolve(__dirname, '../work/verification/v5-design');

const protection = {Defender:true,DefenderService:true,RealTimeProtection:true,BehaviorProtection:true,IOAVProtection:true,CloudProtection:true,NetworkProtection:true,TamperProtection:true,Firewall:true,SecureBoot:true,Tpm:true,BitLocker:true,Vbs:true,CredentialGuard:true,MemoryIntegrity:true,LsaProtection:true,SmbHardening:true,PowerShellLogging:true,UsbStorageBlocked:true,RemoteDesktopDisabled:true,WindowsUpdate:true};
const components = [
 ['ASR','Attack Surface Reduction','DEFENDER',true],['DefenderCloud','Defender Cloud & Network','DEFENDER',true],
 ['Firewall','Windows Firewall','NETZWERK',true],['ControlledFolderAccess','Controlled Folder Access','RANSOMWARE',true],
 ['CredentialGuard','Credential Guard','ISOLATION',true],['MemoryIntegrity','Memory Integrity / HVCI','KERNEL',true],
 ['LSASS','LSASS Protected Process','IDENTITÄT',true],['SMB','SMB-Härtung','NETZWERK',true],
 ['PowerShellLogging','PowerShell & Process Audit','TELEMETRIE',true],['UAC','UAC Secure Desktop','IDENTITÄT',true],
 ['USBStorage','USB-Massenspeicher sperren','ISOLATION',false],['RemoteDesktop','Remote Desktop deaktivieren','NETZWERK',true],
].map(([id,name,category,active],index)=>({id,name,category,active,rebootRequired:index%3===0,description:`Gemessene Schutzfunktion ${index+1} für die Windows-Sicherheitslage.`}));
const hardeningCatalog = components.map((item,index)=>({
  ...item,label:item.name,configurable:item.id==='DefenderCloud'||item.id==='Firewall',
  fields:item.id==='DefenderCloud'?[
    {key:'defender.cloudBlockLevel',label:'Cloud-Block-Level',type:'enum',values:['Default','Normal','High','HighPlus','ZeroTolerance']},
    {key:'defender.networkProtection',label:'Netzwerkschutz',type:'enum',values:['Enabled','AuditMode','Disabled']},
    {key:'defender.puaProtection',label:'PUA-Schutz',type:'enum',values:['Enabled','AuditMode','Disabled']},
  ]:[]
}));
const status = () => ({
  version:'5.0.0',platform:'Windows 11 Enterprise LTSC 2024',
  protection,
  mhx:{protectionMode:'guarded',protectionHealth:'VERIFIED',protectionVerifiedUtc:'2026-10-22T08:54:43Z',realtime:true,realtimeProtection:true,telemetry:'WMI_PROCESS_START_TRACE',telemetryHeartbeatUtc:new Date().toISOString(),networkRealtime:true,wfpRealtime:true,appControl:'AUDIT',kernelEnforcement:false,eventsEvaluated:12453,eventsBlocked:3,wfpBlockedEvents:133916,networkTelemetry:'NATIVE_TCP_OWNER_PID',wfpBlockTelemetry:'SECURITY_5157_OBSERVED',threatNetworkHits:128,attackStories:4,threatIntelligence:{state:'CURRENT',indicators:133916,blockingIndicators:52840,correlationIndicators:81076,annotationIndicators:3422,protectedPrefixes:2,blockingFeedsReady:4,blockingFeedsTotal:4,enforcementGenerationSha256:'b1b2c3d4e5f6',lastSuccessUtc:'2026-10-22T08:50:00Z',nextSyncUtc:'2026-10-22T20:50:00Z',feeds:[]},threatEnforcement:{state:'VERIFIED',activeGenerationSha256:'b1b2c3d4e5f6',indicators:52840,rules:52840},traffic:{state:'LIVE',receivedBytesPerSec:128430, sentBytesPerSec:84210, observedUtc:new Date().toISOString()},kineticArmed:false,kineticReadiness:{threatRules:'GENERATION_VERIFIED',wfpAudit:'BLOCK_EVENTS_OBSERVED',mode:'OBSERVE_ONLY'},kinetic:{mode:'OBSERVE_ONLY',burstCandidates:2,trackedSources:9,capacity:2048,blocksObserved:133916},kineticSources:[],kineticIncidents:[],kineticThreatCorrelations:2,kineticBlockedCorrelations:1,uncorrelatedThreatHits:0},
  integrity:{healthy:true},
});
const map = {sources:[
 {ip:'198.51.100.24',country_code:'DE',country:'Germany',latitude:51.1,longitude:10.4,asn:'AS64500',as_name:'Fixture Network',area:'kinetic',areas:['kinetic'],direction:'inbound',blocked:true,severity:'HIGH',hits:24,last_seen:'2026-10-22T08:50:00Z'},
 {ip:'203.0.113.18',country_code:'US',country:'United States',latitude:38.9,longitude:-77,asn:'AS64501',as_name:'Fixture Cloud',area:'xdr',areas:['xdr','ti'],direction:'inbound',blocked:false,severity:'LOW',hits:9,last_seen:'2026-10-22T08:49:00Z'},
 {ip:'192.0.2.33',country_code:'FR',country:'France',latitude:48.8,longitude:2.3,asn:'AS64502',as_name:'Fixture Telecom',area:'kinetic',areas:['kinetic','ti'],direction:'inbound',blocked:true,severity:'HIGH',hits:12,last_seen:'2026-10-22T08:48:00Z'}
],recent:[],origin:{known:true,lat:50.1,lon:8.6,ip:'203.0.113.1',country:'Fixture Host'},geo:{loaded:true,entries:950000},generated:new Date().toISOString(),totals:{sources:3,placed:3,blocked:2,countries:3,kinetic:2,ti:2,xdr:1}};
map.recent = map.sources.map((source,index)=>({id:'fixture-'+index,remote:source.ip,time:source.last_seen,area:source.area,country_code:source.country_code,blocked:source.blocked,severity:source.severity,summary:'Fixture WFP observation',process:index===0?'fixture-host.exe':'',path:'Lokaler Port '+(440+index),decision:source.blocked?'WFP_BLOCK_OBSERVED':'CORRELATED_ONLY'}));

const analyses = Array.from({length:45},(_,index)=>({
  id:'analysis-'+index,
  timestampUtc:new Date(Date.now()-index*60000).toISOString(),
  effectiveSeverity:index%7===0?'CRITICAL':index%4===0?'HIGH':index%3===0?'MEDIUM':'LOW',
  disposition:index%5===0?'BLOCK':index%3===0?'AUDIT':'ALLOW',
  detection:index%4===0?'MHX.Suspicious.PowerShell':'MHX.Contextual.Signed',
  image:index%2===0?'powershell.exe':'rundll32.exe',
  pid:4000+index,
  signalCategories:index%2===0?['ENCODED_COMMAND','TI_NETWORK_MATCH']:['SIGNED_KNOWN'],
}));
const evidence = Array.from({length:23},(_,index)=>({
  sequence:9000-index,
  timestamp:new Date(Date.now()-index*300000).toISOString(),
  kind:index%3===0?'protection.transition':index%3===1?'threat-intelligence.policy':'hardening.component',
  action:index%2===0?'guarded':'verified',
  result:index%6===0?'denied':'recorded',
}));
const network = Array.from({length:8},(_,index)=>({
  id:'network-'+index,
  timestampUtc:new Date(Date.now()-index*120000).toISOString(),
  pid:4100+index,
  image:index%2===0?'powershell.exe':'msedge.exe',
  remoteIp:'203.0.113.'+(10+index),
  remotePort:443,
  localPort:51000+index,
  threatIntel:index%3!==0,
  threatAction:index%3===0?'BLOCK':'CORRELATE_ONLY',
  threatSources:['feodo','spamhaus'],
  severity:index%3===0?'HIGH':'MEDIUM',
  response:index%3===0?'BLOCKED_BY_WFP':'AUDIT',
}));
const stories = [
  {id:'story-1',startedUtc:'2026-10-22T08:40:00Z',updatedUtc:'2026-10-22T08:45:00Z',pid:4100,image:'powershell.exe',severity:'HIGH',signals:['UNSIGNED_CHILD','ENCODED_COMMAND','TI_NETWORK_MATCH'],remoteIp:'203.0.113.10',remotePort:443,response:'HOST_RESPONSE_BLOCK'},
  {id:'story-2',startedUtc:'2026-10-22T08:20:00Z',updatedUtc:'2026-10-22T08:30:00Z',pid:4200,image:'rundll32.exe',severity:'MEDIUM',signals:['SUSPICIOUS_PARENT'],remoteIp:'203.0.113.14',remotePort:443,response:'CORRELATED'},
];
const notifications = [
  {id:'notification-1',timestampUtc:new Date(Date.now()-60000).toISOString(),kind:'kinetic.burst',severity:'HIGH',title:'Kinetic Burst korreliert',detail:'203.0.113.7:443 · WFP-5157-Serie mit Feed-Match'},
  {id:'notification-2',timestampUtc:new Date(Date.now()-180000).toISOString(),kind:'network.threat-intel',severity:'HIGH',title:'Threat-IP-Treffer blockiert',detail:'powershell.exe → 203.0.113.7:443'},
  {id:'notification-3',timestampUtc:new Date(Date.now()-420000).toISOString(),kind:'protection.policy',severity:'LOW',title:'Schutzrichtlinie verifiziert',detail:'Generation aktiv und zur Datenbasis passend'},
  {id:'notification-4',timestampUtc:new Date(Date.now()-900000).toISOString(),kind:'xdr.finding',severity:'MEDIUM',title:'Persistenz-Finding',detail:'Autostart-Eintrag mit ungewöhnlichem Ziel'},
];
const settingsProfiles = {
  profiles:[
    {id:'monitor',name:'Nur Überwachung',description:'Standardprofil Monitor.',level:'monitor',builtIn:true,values:{defender:{cloudBlockLevel:'Normal'}}},
    {id:'guarded',name:'Guarded',description:'Standardprofil Guarded.',level:'guarded',builtIn:true,values:{defender:{cloudBlockLevel:'High'}}},
    {id:'sovereign',name:'Sovereign',description:'Standardprofil Sovereign.',level:'sovereign',builtIn:true,values:{defender:{cloudBlockLevel:'ZeroTolerance'}}},
    {id:'lab-profile',name:'Werkstatt-PC',description:'Operator-Profil',level:'guarded',builtIn:false,values:{defender:{cloudBlockLevel:'High'}}},
  ],
  levels:[
    {id:'monitor',label:'Nur Überwachung',description:'Nur erkennen und protokollieren.',risk:'MEDIUM'},
    {id:'guarded',label:'Guarded',description:'Verifizierte Standardverteidigung.',risk:'HIGH'},
    {id:'sovereign',label:'Sovereign',description:'Maximalprofil mit Enforcement.',risk:'CRITICAL'},
    {id:'custom',label:'Benutzerdefiniert',description:'Operator-definiert.',risk:'HIGH'},
  ],
  activeProfileId:'guarded',activeLevel:'guarded',protectionLevel:'guarded',state:'READY',applierReady:true,
};
const settingsCatalog = {
  schemaVersion:1,catalogVersion:'fixture',
  controls:[
    {id:'defender.cloudBlockLevel',key:'defender.cloudBlockLevel',section:'defender',label:'Cloud-Block-Level',description:'Aggressivität der Cloud-Entscheidung.',type:'enum',values:['Default','Normal','High','HighPlus','ZeroTolerance'],default:'High'},
    {id:'defender.networkProtection',key:'defender.networkProtection',section:'defender',label:'Defender Netzwerkschutz',description:'Blockiert schädliche Verbindungen.',type:'enum',values:['Enabled','AuditMode','Disabled'],default:'Enabled'},
    {id:'defender.puaProtection',key:'defender.puaProtection',section:'defender',label:'PUA-Schutz',description:'Blockiert unerwünschte Anwendungen.',type:'enum',values:['Enabled','AuditMode','Disabled'],default:'Enabled'},
  ],
  sections:[{id:'defender',label:'Microsoft Defender',description:'Defender-Einstellungen'}],
  levels:settingsProfiles.levels,
};
const mhxSettings = {schemaVersion:1,aggressiveness:{process:'guarded',network:'guarded',application:'guarded'},autoResponse:{terminate:true,correlatedNetworkResponse:true,minimumSeverity:'LOW'},notifications:{events:true,blockEvents:true,critical:true,windowsToasts:true,toastMinimumSeverity:'LOW'},applicationNetworkRestrictions:{unknownPolicy:'audit',allowListEnforced:true,denyListSupported:true},autoDisarmMinutes:0,source:'PROTECTION_MODE',warnings:['Per-domain aggressiveness shares one verified protection profile.'],readOnly:{process:{supported:false,reason:'Nicht unabhängig durchsetzbar'},application:{denyListSupported:true,allowListEnforced:true,enforcedBy:'Windows Firewall'},network:{enforcedBy:'WFP + Threat-IP'}}};
const kineticSettings = {schemaVersion:1,armed:false,observe:true,desiredArmed:false,persisted:true,mode:'OBSERVE_ONLY',source:'PERSISTED',persistenceSource:'OPERATOR_OBSERVE',thresholds:{windowSeconds:10,minEvents:12,minDistinctPorts:3,autoDisarmSeconds:0},limits:{},requirements:{threatRulesVerified:true,wfpAuditVerified:true},autoRearm:{requested:false,state:'IDLE'},rearmedAfterRestart:false};
const mhxLive=JSON.parse(JSON.stringify(mhxSettings));
const kineticLive=JSON.parse(JSON.stringify(kineticSettings));
let lastKineticWrite=null;

function readJSON(req){
  return new Promise(resolve=>{
    let body='';
    req.on('data',chunk=>{if(body.length<32768)body+=chunk});
    req.on('end',()=>{try{resolve(JSON.parse(body||'{}'))}catch{resolve({})}});
  });
}
const tiStatus = {state:'CURRENT',indicators:133916,blockingIndicators:52840,correlationIndicators:81076,annotationIndicators:3422,blockingFeedsReady:4,blockingFeedsTotal:4,lastAttemptUtc:'2026-10-22T08:50:00Z',lastSuccessUtc:'2026-10-22T08:50:00Z',nextSyncUtc:'2026-10-22T20:50:00Z',pollIntervalMinutes:720,pollingSource:'PERSISTED',minIntervalSeconds:300,maxIntervalSeconds:86400,error:'',feeds:[
  {key:'feodo',name:'Feodo Tracker',action:'BLOCK',state:'CURRENT',indicators:1240,lastSuccessUtc:'2026-10-22T08:50:00Z'},
  {key:'spamhaus4',name:'Spamhaus DROP IPv4',action:'BLOCK',state:'CURRENT',indicators:42100,lastSuccessUtc:'2026-10-22T08:50:00Z'},
  {key:'blocklist',name:'Blocklist.de',action:'CORRELATE_ONLY',state:'CURRENT',indicators:52100,lastSuccessUtc:'2026-10-22T08:50:00Z'},
],threatEnforcement:{state:'VERIFIED',activeGenerationSha256:'b1b2c3d4e5f6'}};
const feedPolicy = {
  schemaVersion:1,storeState:'PERSISTED',generationSha256:'b'.repeat(64),enforcementGenerationSha256:'b1b2c3d4e5f6',activeEnforcementGenerationSha256:'b1b2c3d4e5f6',
  enforcementState:'VERIFIED',wfpVerified:true,pending:false,warnings:[],enforcementChanged:false,
  limits:{maxUpdates:16,maxOverrides:9,maximumFeedIdBytes:32,minimumReasonBytes:8,maximumReasonBytes:512,allowedActions:['BLOCK','CORRELATE_ONLY','ANNOTATE_ONLY']},
  feeds:[
    {feedId:'feodo',name:'Feodo Tracker C2',defaultAction:'BLOCK',configuredAction:'BLOCK',effectiveAction:'BLOCK',actionSource:'DEFAULT',blocking:true,indicators:1240,ready:true,feedState:'CURRENT',enforcementImpact:'NONE',enforcement:'VERIFIED_BLOCK'},
    {feedId:'spamhaus_drop_v4',name:'Spamhaus DROP IPv4',defaultAction:'BLOCK',configuredAction:'BLOCK',effectiveAction:'BLOCK',actionSource:'DEFAULT',blocking:true,indicators:42100,ready:true,feedState:'CURRENT',enforcementImpact:'NONE',enforcement:'VERIFIED_BLOCK'},
    {feedId:'spamhaus_drop_v6',name:'Spamhaus DROP IPv6',defaultAction:'BLOCK',configuredAction:'BLOCK',effectiveAction:'BLOCK',actionSource:'DEFAULT',blocking:true,indicators:91,ready:true,feedState:'CURRENT',enforcementImpact:'NONE',enforcement:'VERIFIED_BLOCK'},
    {feedId:'cins_army',name:'CINS Army Badguys',defaultAction:'CORRELATE_ONLY',configuredAction:'CORRELATE_ONLY',effectiveAction:'CORRELATE_ONLY',actionSource:'DEFAULT',blocking:false,indicators:15000,ready:true,feedState:'CURRENT',enforcementImpact:'NONE',enforcement:'NOT_BLOCKING'},
    {feedId:'blocklist_de',name:'blocklist.de All',defaultAction:'CORRELATE_ONLY',configuredAction:'BLOCK',effectiveAction:'BLOCK',actionSource:'OVERRIDE',updatedUtc:'2026-10-22T08:20:00Z',blocking:true,indicators:28493,ready:true,feedState:'CURRENT',enforcementImpact:'ADDS_BLOCK',enforcement:'VERIFIED_BLOCK'},
    {feedId:'emerging_threats',name:'Emerging Threats Block IPs',defaultAction:'CORRELATE_ONLY',configuredAction:'CORRELATE_ONLY',effectiveAction:'CORRELATE_ONLY',actionSource:'DEFAULT',blocking:false,indicators:1769,ready:true,feedState:'CURRENT',enforcementImpact:'NONE',enforcement:'NOT_BLOCKING'},
    {feedId:'ipsum',name:'IPsum Level 1+',defaultAction:'CORRELATE_ONLY',configuredAction:'CORRELATE_ONLY',effectiveAction:'CORRELATE_ONLY',actionSource:'DEFAULT',blocking:false,indicators:125460,ready:true,feedState:'CURRENT',enforcementImpact:'NONE',enforcement:'NOT_BLOCKING'},
    {feedId:'firehol_l1',name:'FireHOL Level 1',defaultAction:'BLOCK',configuredAction:'BLOCK',effectiveAction:'BLOCK',actionSource:'DEFAULT',blocking:true,indicators:4626,ready:true,feedState:'CURRENT',enforcementImpact:'NONE',enforcement:'VERIFIED_BLOCK'},
    {feedId:'tor_exit',name:'Tor Exit Nodes',defaultAction:'ANNOTATE_ONLY',configuredAction:'ANNOTATE_ONLY',effectiveAction:'ANNOTATE_ONLY',actionSource:'DEFAULT',blocking:false,indicators:1229,ready:true,feedState:'CURRENT',enforcementImpact:'NONE',enforcement:'NOT_BLOCKING'}
  ]
};
const defenderTelemetry = {Available:true,CapturedUtc:new Date().toISOString(),SourcesAttempted:['Get-MpComputerStatus','Get-MpPreference'],ComputerStatusAvailable:true,PreferenceAvailable:true,Status:{AntivirusEnabled:true,RealTimeProtectionEnabled:true,BehaviorMonitorEnabled:true,IsTamperProtected:true,AntivirusSignatureAge:1,AntivirusSignatureVersion:'1.461.119.0',AntivirusSignatureLastUpdated:new Date().toISOString()},Preference:{CloudBlockLevel:'High',MAPSReporting:'Advanced',PUAProtection:'Enabled',NetworkProtection:'Enabled',SubmitSamplesConsent:'SendSafeSamples',ControlledFolderAccess:'Enabled'},AttackSurfaceReduction:{Available:true,ConfiguredCount:11,EnabledCount:11,AuditCount:0,WarnCount:0,RecommendedMissing:[]},Exclusions:{Available:true,PathCount:2,ProcessCount:1,ExtensionCount:3},Threats:{Available:true,DetectionCount:0,ActiveThreatCount:0},Firewall:{Available:true,ProfileCount:3,EnabledProfileCount:3,Profiles:[{Name:'Domain',Enabled:true},{Name:'Private',Enabled:true},{Name:'Public',Enabled:true}]}};
const integrityStatus = {state:'IDLE',running:false,generatedUtc:new Date().toISOString(),filesHashed:12840,bytesHashed:734003200,added:1,modified:2,deleted:0,readErrors:0,generation:'g-2026-10-22',enabled:true,intervalHours:24,nextScanUtc:new Date(Date.now()+43200000).toISOString()};
const integrityChanges = [
  {kind:'MODIFIED',path:'C:\\Program Files\\VGT\\GeDefense\\bin\\gedefense-service.exe',oldSha256:'d'.repeat(64),newSha256:'e'.repeat(64),size:18432000},
  {kind:'ADDED',path:'C:\\ProgramData\\VGT\\GeDefense\\config.json',oldSha256:'',newSha256:'f'.repeat(64),size:2048},
  {kind:'MODIFIED',path:'C:\\ProgramData\\VGT\\GeDefense\\policy.json',oldSha256:'a'.repeat(64),newSha256:'b'.repeat(64),size:4096},
];
const applications = {TimestampUtc:new Date().toISOString(),Entries:[
  {path:'C:\\Program Files\\VGT\\GeDefense\\gedefense-ui.exe',sha256:'abcdef',signer:'VisionGaiaTechnology',addedUtc:'2026-10-20T10:00:00Z',rule:'Allow'},
  {path:'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe',sha256:'123456',signer:'Microsoft Corporation',addedUtc:'2026-10-19T10:00:00Z',rule:'Allow'},
],Count:2};
const denies = {Entries:[
  {path:'C:\\Users\\Public\\update.exe',sha256:'aa11bb22cc33',rule:'Block',addedUtc:'2026-10-21T10:00:00Z'},
],Count:1};

const pagesToCapture = ['overview','protection','hardening','audit','evidence','threat-intel','xdr','network','kinetic','integrity'];

function jsonSafe(value){return JSON.stringify(value)}

async function main(){
  await fs.mkdir(output,{recursive:true});
  const server=http.createServer(async(req,res)=>{
    const url=new URL(req.url,'http://localhost');
    try{
      if(url.pathname.startsWith('/api/')){
        res.setHeader('Content-Type','application/json');
        if(url.pathname==='/api/v1/startup/state')return res.end('{"required":false,"reason":"","version":"5.0.0","currentVersion":"5.0.0"}');
        if(url.pathname==='/api/v1/status')return res.end(jsonSafe(status()));
        if(url.pathname==='/api/v1/mhx/status')return res.end(jsonSafe(status().mhx));
        if(url.pathname==='/api/v1/mhx/stories')return res.end(jsonSafe(stories));
        if(url.pathname==='/api/v1/mhx/analyses')return res.end(jsonSafe(analyses));
        if(url.pathname==='/api/v1/mhx/network')return res.end(jsonSafe(network));
        if(url.pathname==='/api/v1/xdr/findings')return res.end('{"Findings":[],"Items":[]}');
        if(url.pathname==='/api/v1/overview/threat-map')return res.end(jsonSafe(map));
        if(url.pathname==='/api/v1/mhx/geo')return res.end(jsonSafe({database:{loaded:true,entries:950000},sources:map.sources}));
        if(url.pathname==='/api/v1/hardening/components')return res.end(jsonSafe(components));
        if(url.pathname==='/api/v1/hardening/catalog')return res.end(jsonSafe(hardeningCatalog));
        if(url.pathname==='/api/v1/defender/telemetry')return res.end(jsonSafe(defenderTelemetry));
        if(url.pathname==='/api/v1/evidence/page')return res.end(jsonSafe({items:evidence.slice(0,20),total:evidence.length,offset:0,limit:20}));
        if(url.pathname==='/api/v1/evidence')return res.end(jsonSafe(evidence));
        if(url.pathname==='/api/v1/integrity/status')return res.end(jsonSafe(integrityStatus));
        if(url.pathname==='/api/v1/integrity/changes')return res.end(jsonSafe(integrityChanges));
        if(url.pathname==='/api/v1/protection/readiness')return res.end('{"target":"guarded","currentMode":"guarded","ready":true,"blockers":[],"consequences":["Kontextuelle Response nach erneuter Identitätsprüfung."]}');
        if(url.pathname==='/api/v1/health/refresh'||url.pathname==='/api/v1/health/status')return res.end(jsonSafe({checkedUtc:new Date().toISOString(),healthy:true,checks:[['policy','Schutzrichtlinie'],['defender','Microsoft Defender'],['firewall','Windows Firewall'],['telemetry','Prozess- und Netzwerk-Telemetrie'],['intelligence','Threat Intelligence'],['enforcement','Threat-IP-Firewallregeln'],['evidence','Evidenz und Audit-Kette']].map(([id,label])=>({id,label,state:'healthy',detail:'Aktueller Zustand verifiziert.'}))}));
        if(url.pathname==='/api/v1/settings')return res.end(jsonSafe({schemaVersion:1,updatedUtc:new Date().toISOString(),activeProfileId:'guarded',activeLevel:'guarded',protectionLevel:'guarded',state:'READY',applierReady:true,values:{},settings:{},profiles:settingsProfiles.profiles,levels:settingsProfiles.levels}));
        if(url.pathname==='/api/v1/settings/catalog')return res.end(jsonSafe(settingsCatalog));
        if(url.pathname==='/api/v1/settings/profiles')return res.end(jsonSafe(settingsProfiles));
        if(url.pathname==='/api/v1/mhx/settings'&&req.method==='GET')return res.end(jsonSafe(mhxLive));
        if(url.pathname==='/api/v1/mhx/settings'&&req.method==='POST'){
          const body=await readJSON(req);
          if(body.notifications)Object.assign(mhxLive.notifications,body.notifications);
          if(body.autoResponse)Object.assign(mhxLive.autoResponse,body.autoResponse);
          if(body.aggressiveness)Object.assign(mhxLive.aggressiveness,body.aggressiveness);
          mhxLive.source='PERSISTED';
          return res.end(jsonSafe(mhxLive));
        }
        if(url.pathname==='/api/v1/kinetic/settings'&&req.method==='GET')return res.end(jsonSafe(kineticLive));
        if(url.pathname==='/api/v1/kinetic/settings'&&req.method==='POST'){
          const body=await readJSON(req);
          lastKineticWrite=body;
          if(body.thresholds)Object.assign(kineticLive.thresholds,body.thresholds);
          if(Object.prototype.hasOwnProperty.call(body,'armedAfterRestart')){
            kineticLive.armedAfterRestart=Boolean(body.armedAfterRestart);
            kineticLive.desiredArmed=Boolean(body.armedAfterRestart);
            kineticLive.persisted=Boolean(body.armedAfterRestart);
          }
          if(body.notifications&&Object.prototype.hasOwnProperty.call(body.notifications,'enabled'))kineticLive.notifications={enabled:Boolean(body.notifications.enabled)};
          kineticLive.source='PERSISTED';
          return res.end(jsonSafe(kineticLive));
        }
        if(url.pathname==='/api/v1/threat-intel/status')return res.end(jsonSafe(tiStatus));
        if(url.pathname==='/api/v1/mhx/threat-intelligence/feed-policy'&&req.method==='GET')return res.end(jsonSafe(feedPolicy));
        if(url.pathname==='/api/v1/mhx/threat-intelligence/feed-policy'&&req.method==='POST')return res.end(jsonSafe({...feedPolicy,enforcementChanged:true,pending:false}));
        if(url.pathname==='/api/v1/notifications')return res.end(jsonSafe(notifications));
        if(url.pathname==='/api/v1/mhx/applications')return res.end(jsonSafe(applications));
        if(url.pathname==='/api/v1/mhx/application-denies')return res.end(jsonSafe(denies));
        if(url.pathname==='/api/v1/mhx/threat-intelligence/protected-networks')return res.end(jsonSafe({prefixes:['198.20.30.40/32'],generationSha256:'c'.repeat(64),updatedUtc:new Date().toISOString()}));
        if(url.pathname==='/api/v1/window/state')return res.end('{"handled":false,"state":"normal"}');
        res.statusCode=404;return res.end('{"error":"fixture route missing"}');
      }
      const name=url.pathname==='/'?'index.html':url.pathname.replace(/^\/assets\//,'');
      const resolved=path.resolve(root,name);
      if(!resolved.startsWith(root+path.sep)){res.statusCode=403;return res.end()}
      res.setHeader('Content-Type',name.endsWith('.js')?'text/javascript':name.endsWith('.css')?'text/css':name.endsWith('.png')?'image/png':'text/html; charset=utf-8');
      res.end(await fs.readFile(resolved));
    }catch(error){res.statusCode=500;res.end(String(error))}
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  const browser=await chromium.launch({executablePath:path.join(process.env.ProgramFiles,'Google/Chrome/Application/chrome.exe'),headless:true});
  const reports={};
  try{
    for(const viewport of [{name:'desktop',width:1440,height:1000},{name:'wide',width:1920,height:1080},{name:'ultrawide',width:2194,height:1146},{name:'mobile',width:390,height:844}]){
      const page=await browser.newPage({viewport:{width:viewport.width,height:viewport.height},reducedMotion:'reduce'});
      const errors=[];const consoleErrors=[];
      page.on('pageerror',error=>errors.push(error.message));
      page.on('console',message=>{if(message.type()==='error')consoleErrors.push(message.text())});
      await page.goto('http://127.0.0.1:'+server.address().port);
      await page.waitForTimeout(1200);
      const viewportReport={viewport,layout:null,pages:{}};
      for(const view of pagesToCapture){
        if(view!=='overview'){
          await page.evaluate(target=>document.querySelector(`[data-view="${target}"]`).click(),view);
          await page.waitForTimeout(view==='xdr'||view==='threat-intel'?1400:900);
        }
        const metrics=await page.evaluate(()=>{
          const rect=selector=>{const el=document.querySelector(selector);return el?el.getBoundingClientRect().toJSON():null};
          const style=selector=>{const el=document.querySelector(selector);return el?getComputedStyle(el):null};
          const int=value=>Number.parseFloat(value)||0;
          const activeView=document.querySelector('.view.active')?.dataset.page||'';
          const topbar=rect('.topbar');
          const title=rect('#viewTitle');
          const topbarStyle=style('.topbar');
          const actionHeights=['#healthRefreshButton','#notificationButton','#authButton']
            .map(selector=>{const item=rect(selector);return item?Math.round(item.height):0})
            .filter(height=>height>0);
          const metricFirst=document.querySelector('.view.active .metric-grid .metric-card');
          const walker=document.createTreeWalker(document.body,NodeFilter.SHOW_TEXT,{acceptNode:node=>{
            if(!node.nodeValue.trim())return NodeFilter.FILTER_REJECT;
            const parent=node.parentElement;
            return parent&&parent.offsetParent!==null?NodeFilter.FILTER_ACCEPT:NodeFilter.FILTER_REJECT;
          }});
          let nonWhiteText=0;
          const nonWhiteTextDetails=[];
          while(walker.nextNode()){
            const parent=walker.currentNode.parentElement;
            const color=parent?getComputedStyle(parent).color:'';
            if(parent&&color!=='rgb(255, 255, 255)'){
              nonWhiteText++;
              if(nonWhiteTextDetails.length<10)nonWhiteTextDetails.push({tag:parent.tagName,cls:parent.className||'',text:walker.currentNode.nodeValue.trim().slice(0,60),color});
            }
          }
          const pageMetrics={
            activeView,
            inner:innerWidth,
            scroll:document.documentElement.scrollWidth,
            topbarHeight:topbar?Math.round(topbar.height):0,
            topbarPadTop:topbarStyle?int(topbarStyle.paddingTop):0,
            topbarPadBottom:topbarStyle?int(topbarStyle.paddingBottom):0,
            titleOffset:topbar&&title?Math.round(title.top-topbar.top):0,
            actionHeights,
            firstMetricPadLeft:metricFirst?int(getComputedStyle(metricFirst).paddingLeft):0,
            viewPadTop:activeView?int(getComputedStyle(document.querySelector(`.view[data-page="${activeView}"]`)).paddingTop):0,
            nonWhiteText,
            nonWhiteTextDetails,
          };
          if(activeView==='overview'){
            const subtitle=rect('.overview-threat-title p');
            const chips=rect('.overview-threat-chips');
            const canvas=rect('.overview-threat-canvas');
            const chart=rect('#trafficGraph');
            const layout=rect('.traffic-layout');
            const chartElement=document.querySelector('#trafficGraph');
            pageMetrics.mapSubtitleToChips=subtitle&&chips?Math.round(chips.top-subtitle.bottom):0;
            pageMetrics.mapCanvasHeight=canvas?Math.round(canvas.height):0;
            pageMetrics.trafficChartWidth=chart?Math.round(chart.width):0;
            pageMetrics.trafficLayoutWidth=layout?Math.round(layout.width):0;
            pageMetrics.trafficChartHeight=chart?Math.round(chart.height):0;
            pageMetrics.preserveAspect=chartElement?chartElement.getAttribute('preserveAspectRatio'):null;
            pageMetrics.storyEmptyHeight=Math.round(rect('#overviewStories')?.height||0);
          }
          if(activeView==='hardening'){
            const count=rect('#hardeningCount');
            const firstCard=rect('#hardeningComponents .component-card');
            pageMetrics.catalogCountGap=count&&firstCard?Math.round(firstCard.top-count.bottom):0;
            pageMetrics.cardCount=document.querySelectorAll('#hardeningComponents .component-card').length;
          }
          if(activeView==='audit'){
            const hero=rect('.audit-hero');
            const heroStyle=style('.audit-hero');
            pageMetrics.auditHeroPadLeft=heroStyle?int(heroStyle.paddingLeft):0;
            pageMetrics.auditHeroHeight=hero?Math.round(hero.height):0;
            pageMetrics.auditMetricCards=document.querySelectorAll('#auditMetrics .metric-card').length;
          }
          if(activeView==='xdr'){
            pageMetrics.xdrGroups=document.querySelectorAll('#xdrMetrics .xdr-status-group').length;
            pageMetrics.xdrGroupPad=style('#xdrMetrics .xdr-status-group .xdr-status-body')?int(style('#xdrMetrics .xdr-status-group .xdr-status-body').paddingLeft):0;
            pageMetrics.allowListIsCard=Boolean(document.querySelector('#mhxAllowCard')?.classList.contains('section-card'));
            pageMetrics.analysisRows=document.querySelectorAll('#analysisRows tr').length;
            pageMetrics.analysisPageInfo=document.getElementById('analysisPageInfo')?.textContent||'';
            pageMetrics.analysisPager=Boolean(document.getElementById('analysisPrev')&&document.getElementById('analysisNext'));
            pageMetrics.controlSurfaces=document.querySelectorAll('#mhxSettingsForm .control-surface').length;
            pageMetrics.domainControls=document.querySelectorAll('#mhxSettingsForm .domain-control').length;
          }
          if(activeView==='kinetic'){
            const track=rect('.view.active .switch-track');
            const trackStyle=style('.view.active .switch-track');
            const knob=trackStyle?getComputedStyle(document.querySelector('.view.active .switch-track'),'::after'):null;
            pageMetrics.switchTrackWidth=track?Math.round(track.width):0;
            pageMetrics.switchTrackHeight=track?Math.round(track.height):0;
            pageMetrics.switchKnobWidth=knob?int(knob.width):0;
            pageMetrics.controlSurfaces=document.querySelectorAll('#kineticSettingsForm .control-surface').length;
            pageMetrics.thresholdFields=document.querySelectorAll('#kineticSettingsForm .threshold-grid label').length;
          }
          if(activeView==='network')pageMetrics.networkRows=document.querySelectorAll('#networkRows tr').length;
          if(activeView==='integrity')pageMetrics.integrityRows=document.querySelectorAll('#integrityRows tr').length;
          return pageMetrics;
        });
        viewportReport.pages[view]=metrics;
        await page.screenshot({path:path.join(output,`${view}-${viewport.name}.png`),fullPage:true});
        if(viewport.name==='desktop'&&view==='xdr'){
          const before=await page.evaluate(()=>document.querySelector('#mhxAutoTerminate')?.checked);
          if(typeof before==='boolean'){
            await page.evaluate(()=>{const el=document.querySelector('#mhxAutoTerminate');el.checked=!el.checked;el.dispatchEvent(new Event('change',{bubbles:true}))});
            await page.waitForTimeout(1800);
            const after=await page.evaluate(()=>document.querySelector('#mhxAutoTerminate')?.checked);
            const status=await page.evaluate(()=>document.querySelector('#mhxSettingsStatus')?.textContent||'');
            await page.waitForTimeout(6600);
            const afterRefresh=await page.evaluate(()=>document.querySelector('#mhxAutoTerminate')?.checked);
            viewportReport.autoSaveXdr={before,after,status,afterRefresh};
          }
        }
        if(viewport.name==='desktop'&&view==='kinetic'){
          const before=await page.evaluate(()=>document.querySelector('#kineticPersistArmed')?.checked);
          if(typeof before==='boolean'){
            await page.evaluate(()=>{const el=document.querySelector('#kineticPersistArmed');el.checked=!el.checked;el.dispatchEvent(new Event('change',{bubbles:true}))});
            await page.waitForTimeout(1800);
            const after=await page.evaluate(()=>document.querySelector('#kineticPersistArmed')?.checked);
            const status=await page.evaluate(()=>document.querySelector('#kineticSettingsStatus')?.textContent||'');
            await page.waitForTimeout(6600);
            const afterRefresh=await page.evaluate(()=>document.querySelector('#kineticPersistArmed')?.checked);
            viewportReport.autoSaveKinetic={before,after,status,afterRefresh};
            viewportReport.kineticWrite=lastKineticWrite;
          }
        }
      }
      viewportReport.layout=viewportReport.pages.overview;
      viewportReport.errors=errors;
      viewportReport.consoleErrors=consoleErrors;
      reports[viewport.name]=viewportReport;
      await fs.writeFile(path.join(output,`design-report-${viewport.name}.json`),JSON.stringify(viewportReport,null,2));
      await fs.writeFile(path.join(output,`errors-${viewport.name}.json`),JSON.stringify({pageErrors:errors,consoleErrors},null,2));
      assertDesign(viewport.name,viewportReport);
      process.stdout.write(`PASS ${viewport.name} pages=${pagesToCapture.length} errors=${errors.length} consoleErrors=${consoleErrors.length}\n`);
      await page.close();
    }
  }finally{await browser.close();await new Promise(resolve=>server.close(resolve))}
  process.stdout.write('PASS v5-design all viewports\n');
}

function assertDesign(viewportName,report){
  const desktop=viewportName!=='mobile';
  const fail=message=>{throw new Error(`[${viewportName}] ${message}`)};
  const overview=report.pages.overview;
  if(desktop){
    if(viewportName==='desktop'){
      for(const key of ['autoSaveXdr','autoSaveKinetic']){
        const saved=report[key];
        if(!saved)fail(`${key} was not exercised`);
        if(saved.after===saved.before)fail(`${key} value did not change`);
        if(saved.afterRefresh!==saved.after)fail(`${key} reverted after the live-refresh interval (${saved.afterRefresh} != ${saved.after})`);
        if(!/automatisch gespeichert/i.test(saved.status))fail(`${key} did not report automatic save: ${saved.status}`);
      }
      const write=report.kineticWrite;
      if(!write||typeof write.thresholds?.minDistinctPorts!=='number')fail('Kinetic auto-save omitted thresholds.minDistinctPorts');
      if(!Object.prototype.hasOwnProperty.call(write,'autoDisarmMinutes'))fail('Kinetic auto-save omitted autoDisarmMinutes');
    }
    if(overview.topbarHeight<78)fail(`topbar height ${overview.topbarHeight} < 78`);
    if(overview.topbarPadTop<12)fail(`topbar padding-top ${overview.topbarPadTop} < 12`);
    if(overview.topbarPadBottom<12)fail(`topbar padding-bottom ${overview.topbarPadBottom} < 12`);
    if(overview.titleOffset<18)fail(`title offset from window edge ${overview.titleOffset} < 18`);
    if(overview.actionHeights.some(height=>height<44||height>60))fail(`action heights ${overview.actionHeights.join('/')} outside 44-60px`);
  }else{
    if(overview.topbarHeight<58)fail(`mobile topbar height ${overview.topbarHeight} < 58`);
    if(overview.titleOffset<10)fail(`mobile title offset ${overview.titleOffset} < 10`);
  }
  if(overview.mapSubtitleToChips<(desktop?18:10))fail(`map subtitle/chips spacing ${overview.mapSubtitleToChips}px too tight`);
  if(overview.mapCanvasHeight>(desktop?420:320))fail(`map canvas ${overview.mapCanvasHeight}px too tall`);
  if(overview.preserveAspect!=='none')fail('traffic SVG must use preserveAspectRatio="none" to fill the chart column');
  if(overview.trafficChartWidth<Math.round(overview.trafficLayoutWidth*(desktop?0.62:0.9)))fail(`traffic chart ${overview.trafficChartWidth}px does not fill its column (${overview.trafficLayoutWidth}px)`);
  if(overview.firstMetricPadLeft<12)fail(`first metric padding-left ${overview.firstMetricPadLeft}px flush`);
  for(const [page,metrics] of Object.entries(report.pages)){
    if(metrics.scroll>metrics.inner+1)fail(`${page} horizontal overflow ${metrics.scroll}>${metrics.inner}`);
    if(metrics.nonWhiteText!==0)fail(`${page} still has ${metrics.nonWhiteText} non-white text nodes: ${JSON.stringify(metrics.nonWhiteTextDetails)}`);
  }
  const hardening=report.pages.hardening;
  if(hardening.catalogCountGap<12)fail(`hardening count/cards gap ${hardening.catalogCountGap}px too tight`);
  if(hardening.cardCount!==12)fail(`hardening catalog rendered ${hardening.cardCount} cards`);
  const audit=report.pages.audit;
  if(desktop&&audit.auditHeroPadLeft<16)fail(`audit hero padding-left ${audit.auditHeroPadLeft}px`);
  if(audit.auditMetricCards<3)fail('audit readiness row does not render 3 intentional metrics');
  const xdr=report.pages.xdr;
  if(xdr.xdrGroups<3)fail(`xdr status groups ${xdr.xdrGroups} < 3`);
  if(!xdr.allowListIsCard)fail('application allowlist is not its own spaced card');
  if(!xdr.analysisPager)fail('analysis pager missing');
  if(xdr.analysisRows<1||xdr.analysisRows>20)fail(`analysis page renders ${xdr.analysisRows} rows (expected 1-20)`);
  if(!/Seite 1 von 3/.test(xdr.analysisPageInfo))fail(`analysis pager info "${xdr.analysisPageInfo}"`);
  if(xdr.controlSurfaces<3)fail(`xdr policy control surfaces ${xdr.controlSurfaces} < 3`);
  if(xdr.domainControls!==3)fail(`xdr domain controls ${xdr.domainControls} != 3`);
  const kinetic=report.pages.kinetic;
  if(kinetic.switchTrackWidth<42||kinetic.switchTrackHeight<22)fail(`switch track ${kinetic.switchTrackWidth}x${kinetic.switchTrackHeight} too small`);
  if(kinetic.switchKnobWidth<16)fail(`switch knob ${kinetic.switchKnobWidth}px too small`);
  if(kinetic.controlSurfaces<3)fail(`kinetic control surfaces ${kinetic.controlSurfaces} < 3`);
  if(kinetic.thresholdFields!==4)fail(`kinetic threshold fields ${kinetic.thresholdFields} != 4`);
}
main().catch(error=>{process.stderr.write(error.stack+'\n');process.exitCode=1});
