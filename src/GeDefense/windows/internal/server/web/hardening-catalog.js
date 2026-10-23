// STATUS: DIAMANT VGT SUPREME
'use strict';
/** Static hardening catalog for the first paint of the V5 hardening page.
 *
 *  The IDs, names, categories and descriptions mirror the measured component
 *  catalog of the local Go hardening engine. The static copy only describes
 *  intended scope; it never claims a control is active. Live state arrives from
 *  GET /api/v1/hardening/components (or /api/v1/hardening/catalog for extended
 *  metadata). Until then every card is explicitly marked "Status unbekannt".
 */
export const HARDENING_CATALOG=[
  {
    id:'DefenderCloud',name:'Defender Cloud & Network',category:'DEFENDER',rebootRequired:false,configurable:true,
    description:'Cloudbasierter Blockschutz, PUA-Schutz, sichere Samples und Netzwerkinspektion.',
    fields:[
      {key:'defender.cloudBlockLevel',label:'Cloud-Block-Level',type:'enum',description:'Aggressivität der cloudbasierten Blockentscheidung.',values:['Default','Normal','High','HighPlus','ZeroTolerance']},
      {key:'defender.mapsReporting',label:'Cloud-Schutz (MAPS)',type:'enum',description:'Mitgliedschaft in Microsoft Advanced Protection Service.',values:['Disabled','Basic','Advanced']},
      {key:'defender.submitSamplesConsent',label:'Sample-Übermittlung',type:'enum',description:'Zustimmung zur Übermittlung verdächtiger Dateien.',values:['AlwaysPrompt','SendSafeSamples','NeverSend','SendAllSamples']},
      {key:'defender.networkProtection',label:'Netzwerkschutz',type:'enum',description:'Blockiert schädliche Verbindungen auf Basis der Defender-Intelligenz.',values:['Enabled','AuditMode','Disabled']},
      {key:'defender.puaProtection',label:'PUA-Schutz',type:'enum',description:'Blockiert potenziell unerwünschte Anwendungen.',values:['Enabled','AuditMode','Disabled']},
    ],
  },
  {
    id:'ASR',name:'Attack Surface Reduction',category:'DEFENDER',rebootRequired:false,configurable:true,
    description:'Elf priorisierte ASR-Regeln im Blockmodus.',
    fields:[{key:'defender.asrRules',label:'ASR-Regelaktionen',type:'array',description:'Aktion pro unterstützter ASR-Regel; wird als Liste validiert.'}],
  },
  {
    id:'ControlledFolderAccess',name:'Controlled Folder Access',category:'RANSOMWARE',rebootRequired:false,configurable:true,
    description:'Schreibzugriffe auf geschützte Ordner werden durch Defender kontrolliert.',
    fields:[{key:'defender.controlledFolderAccess',label:'Controlled Folder Access',type:'enum',description:'Block- oder Auditmodus für geschützte Ordner.',values:['Enabled','AuditMode','Disabled']}],
  },
  {
    id:'Firewall',name:'Windows Firewall',category:'NETZWERK',rebootRequired:false,configurable:true,
    description:'Alle Profile aktiv; eingehende Verbindungen standardmäßig blockiert.',
    fields:[{key:'firewall.profiles',label:'Firewall-Profile',type:'array',description:'Pro Profil nur die ausdrücklich angegebenen Einstellungen ändern.'}],
  },
  {
    id:'CredentialGuard',name:'Credential Guard',category:'ISOLATION',rebootRequired:true,configurable:false,
    description:'Anmeldegeheimnisse werden in VBS-isolierter Umgebung geschützt.',
  },
  {
    id:'MemoryIntegrity',name:'Memory Integrity / HVCI',category:'KERNEL',rebootRequired:true,configurable:false,
    description:'Hypervisor-gestützte Codeintegrität und Microsoft-Treiberblockliste.',
  },
  {
    id:'LSASS',name:'LSASS Protected Process',category:'IDENTITÄT',rebootRequired:true,configurable:false,
    description:'LSASS läuft als geschützter Prozess; WDigest-Credentials bleiben deaktiviert.',
  },
  {
    id:'SMB',name:'SMB-Härtung',category:'NETZWERK',rebootRequired:true,configurable:false,
    description:'SMB1 deaktiviert und Signierung für Client und Server erzwungen.',
  },
  {
    id:'PowerShellLogging',name:'PowerShell & Process Audit',category:'TELEMETRIE',rebootRequired:false,configurable:false,
    description:'ScriptBlock-, Modul- und Prozessbefehlszeilen-Protokollierung.',
  },
  {
    id:'UAC',name:'UAC Secure Desktop',category:'IDENTITÄT',rebootRequired:false,configurable:false,
    description:'Admin-Zustimmung und Secure Desktop sind erzwungen.',
  },
  {
    id:'USBStorage',name:'USB-Massenspeicher sperren',category:'ISOLATION',rebootRequired:false,configurable:false,
    description:'USBSTOR wird vollständig deaktiviert.',
  },
  {
    id:'RemoteDesktop',name:'Remote Desktop deaktivieren',category:'NETZWERK',rebootRequired:false,configurable:false,
    description:'Eingehende RDP-Sitzungen werden blockiert.',
  },
];

export function hardeningCatalogById(){
  return new Map(HARDENING_CATALOG.map(component=>[component.id,component]));
}

/** Merge live component data over the static catalog. Live fields win; the
 *  static text only stays where the backend does not deliver metadata. */
export function mergeHardeningCatalog(liveComponents,extendedCatalog){
  const base=hardeningCatalogById();
  const extended=new Map();
  if(Array.isArray(extendedCatalog))for(const item of extendedCatalog)if(item?.id)extended.set(item.id,item);
  const live=new Map();
  if(Array.isArray(liveComponents))for(const item of liveComponents)if(item?.id)live.set(item.id,item);
  const ids=new Set([...base.keys(),...extended.keys(),...live.keys()]);
  const result=[];
  for(const id of ids){
    const fallback=base.get(id)||{};
    const meta=extended.get(id)||{};
    const status=live.get(id)||null;
    result.push({
      id,
      name:String(status?.name||meta.name||fallback.name||id),
      category:String(status?.category||meta.category||fallback.category||'SECURITY').toUpperCase(),
      description:String(status?.description||meta.description||fallback.description||''),
      rebootRequired:Boolean(status?.rebootRequired??meta.rebootRequired??fallback.rebootRequired),
      configurable:Boolean(status?.configurable??meta.configurable??fallback.configurable),
      fields:Array.isArray(meta.fields)?meta.fields:(Array.isArray(fallback.fields)?fallback.fields:[]),
      active:typeof status?.active==='boolean'?status.active:null,
      measured:Boolean(status),
    });
  }
  result.sort((a,b)=>(a.category===b.category?a.name.localeCompare(b.name,'de'):a.category.localeCompare(b.category,'de')));
  return result;
}
