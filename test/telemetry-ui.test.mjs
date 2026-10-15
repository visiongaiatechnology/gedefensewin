import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
const here = path.dirname(fileURLToPath(import.meta.url));
const web = path.resolve(here, '../src/GeDefense/windows/internal/server/web');
class Element {
  constructor(tag = 'div') { this.tag=tag; this.children=[]; this.style={}; this.dataset={}; this.className=''; this.textContent=''; this.id=''; }
  append(...children){ this.children.push(...children); }
  replaceChildren(...children){ this.children = children; }
}
const elements=new Map();
globalThis.document={
  getElementById(id){if(!elements.has(id))elements.set(id,new Element());return elements.get(id);},
  createElement(tag){return new Element(tag);},
};
const {renderStatus,renderKinetic} = await import('../src/GeDefense/windows/internal/server/web/views.js');
const id=x=>globalThis.document.getElementById(x);
const defaults={
  version:'4.1.0',platform:'Windows 10',protection:{},mhx:{
    realtime:true,protectionMode:'guarded',protectionHealth:'VERIFIED',eventsEvaluated:100,
    eventsBlocked:0,wfpBlockedEvents:8,threatNetworkHits:0,attackStories:0,
    networkTelemetry:'NATIVE_TCP_OWNER_PID',wfpBlockTelemetry:'SECURITY_5157_FAILURE_AUDIT',
    threatIntelligence:{indicators:137444,blockingIndicators:50000,enforcementGenerationSha256:'expected-hash'},
    threatEnforcement:{state:'DEGRADED',activeGenerationSha256:'',error:'firewall enforcement verification failed'}
  }
};
test('overview distinguishes observed Windows firewall blocks from MHX process terminations',()=>{
  renderStatus(structuredClone(defaults));
  assert.equal(id('mhxBlocked').textContent,'0');
  assert.equal(id('wfpBlocks').textContent,'8');
  assert.equal(id('networkHits').textContent,'0');
  assert.equal(id('storyCount').textContent,'0');
  assert.match(id('telemetryHealth').textContent,/firewall enforcement verification failed/);
});
test('overview refuses OPTIMAL while WFP generation is unverified',()=>{
  renderStatus(structuredClone(defaults));
  assert.match(id('titlePulseBadge').textContent,/WFP UNVERIFIED/);
  assert.notEqual(id('titlePulseBadge').style.color,'#31d0aa');
});
test('overview accepts verified generation matched to feed hash',()=>{
  const data=structuredClone(defaults);
  data.mhx.threatEnforcement={state:'VERIFIED',activeGenerationSha256:'expected-hash'};
  renderStatus(data);
  assert.match(id('titlePulseBadge').textContent,/OPTIMAL/);
  assert.equal(id('titlePulseBadge').style.color,'#31d0aa');
});
test('new diagnostic panel is actually linked to the HTML',()=>{
  const html=fs.readFileSync(path.join(web,'index.html'),'utf8');
  for (const key of ['wfpBlocks','telemetryHealth','mhxBlocked','networkHits','storyCount'])
    assert.match(html,new RegExp(`id="${key}"`));
  assert.match(html,/Zähler seit Dienststart/);
});

test('native traffic sample reports real rates rather than fabricating data',()=>{
 const d=structuredClone(defaults);d.mhx.traffic={state:'LIVE',receivedBytesPerSec:20480,sentBytesPerSec:10240,observedUtc:'2026-10-15T10:00:00Z'};renderStatus(d);
 assert.match(id('trafficRx').textContent,/KiB\/s/);assert.match(id('trafficTx').textContent,/KiB\/s/);assert.equal(id('trafficState').textContent,'LIVE');
 d.mhx.traffic={state:'UNAVAILABLE'};renderStatus(d);assert.equal(id('trafficRx').textContent,'--');
});
test('kinetic arming never claims separate dynamic WFP blocking',()=>{
 renderKinetic({kineticArmed:true,kineticReadiness:{threatRules:'UNVERIFIED',wfpAudit:'POLLING_AUDIT_NOT_VERIFIED',ingress:'UNVERIFIED_NO_RAW_INGRESS_SENSOR'},kinetic:{blocksObserved:23,burstCandidates:1,trackedSources:4,capacity:2048},kineticThreatCorrelations:1,kineticBlockedCorrelations:0,kineticIncidents:[{remoteIp:'203.0.113.4',localPort:8080,timestampUtc:'2026-10-15T10:00:00Z',threatMatched:true,verifiedWfpBlock:false,threatSources:['feed-a']}]});
 assert.match(id('kineticState').textContent,/DEGRADED/);assert.equal(id('kineticTitle').textContent,'Korrelation angefordert, Durchsetzung nicht bestätigt');assert.equal(id('kineticTimeline').children.length,1);
});
test('overview and kinetic navigation have their own live surfaces',()=>{
 const html=fs.readFileSync(path.join(web,'index.html'),'utf8');
 for(const key of ['trafficGraph','trafficRx','trafficTx','kineticState','kineticTimeline','kineticArm','kineticDisarm','kineticDialog'])assert.match(html,new RegExp(`id="${key}"`));
 assert.match(html,/data-view="kinetic"/);assert.match(html,/data-page="kinetic"/);
});
