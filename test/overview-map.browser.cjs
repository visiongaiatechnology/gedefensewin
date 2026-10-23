// STATUS: PLATIN
// Isolated fixture peer; never contacts or mutates the installed Windows service.
const assert=require('node:assert/strict');
const fs=require('node:fs/promises');
const path=require('node:path');
const http=require('node:http');
const {createRequire}=require('node:module');
const runtimeRequire=process.env.CODEX_NODE_MODULES?createRequire(path.join(path.resolve(process.env.CODEX_NODE_MODULES),'package.json')):require;
const {chromium}=runtimeRequire('playwright');
const root=path.resolve(__dirname,'../src/GeDefense/windows/internal/server/web');
const output=path.resolve(__dirname,'../work/verification/overview-map');
const checks=[];
const definitions=[['policy','Schutzrichtlinie'],['defender','Microsoft Defender'],['firewall','Windows Firewall'],['telemetry','Telemetrie'],['intelligence','Threat Intelligence'],['enforcement','Threat-IP-Firewallregeln'],['evidence','Evidenz']];
const places=[['CN',39.9,116.4],['CN',39.9,116.4],['US',38.9,-77],['RU',55.7,37.6],['BR',-23.5,-46.6],['SG',1.3,103.8]];
const now='2026-10-17T12:35:00Z';
const baseMap={sources:places.map(([country_code,latitude,longitude],i)=>({ip:`198.51.100.${10+i}`,
 country_code,country:country_code,latitude,longitude,asn:'AS'+(100+i),as_name:'Isolated fixture network',
 area:i===4?'xdr':'kinetic',areas:i===4?['kinetic','ti','xdr']:['kinetic'],direction:'inbound',
 blocked:i%3===0,severity:i%3===1?'HIGH':'LOW',hits:i+1,last_seen:now,
 summary:i===0?'<img src=x onerror="window.__injected=1">':'Fixture: genuine-shaped WFP observation'})),
 recent:[],origin:{known:true,lat:50.1,lon:8.6,ip:'203.0.113.1',country:'Test host'},geo:{loaded:true,entries:950000},
 generated:now,totals:{sources:6,placed:6,blocked:2,countries:5,kinetic:6,ti:1,xdr:1}};
baseMap.recent=baseMap.sources.map((s,i)=>({id:'fixture-'+i,remote:s.ip,time:now,area:s.area,country_code:s.country_code,
 blocked:s.blocked,severity:s.severity,summary:s.summary,process:i===4?'fixture-process.exe':'',path:i===0?'Kein Transportport gemeldet':'Lokaler Port 443',decision:s.blocked?'WFP_BLOCK_OBSERVED':'CORRELATED_ONLY'}));
let map=structuredClone(baseMap),mapFailure=false,geoFailure=false,requests=0;
const mhxStatus=()=>({protectionMode:'guarded',protectionHealth:'VERIFIED',realtime:true,eventsEvaluated:0,
 networkTelemetry:'NATIVE_TCP_OWNER_PID',wfpBlockTelemetry:'POLLING_5157_AUDIT_UNVERIFIED',
 wfpBlockedEvents:20,kinetic:{blocksObserved:20,burstCandidates:0,trackedSources:6,capacity:2048},
 kineticSources:[],kineticIncidents:[],kineticReadiness:{threatRules:'GENERATION_VERIFIED',wfpAudit:'BLOCK_EVENTS_OBSERVED'},
 threatIntelligence:{state:'CURRENT',indicators:100,blockingFeedsReady:1,blockingFeedsTotal:1},
 threatEnforcement:{state:'VERIFIED'},traffic:{state:'UNAVAILABLE'}});
async function main(){
 await fs.mkdir(output,{recursive:true});
 const server=http.createServer(async(req,res)=>{
  const url=new URL(req.url,'http://localhost');
  try{
   if(url.pathname.startsWith('/api/')){
    res.setHeader('Content-Type','application/json');
    if(url.pathname==='/api/v1/startup/state')return res.end(JSON.stringify({required:true,reason:'reboot',version:'isolated-test',currentVersion:'isolated-test'}));
    if(url.pathname==='/api/v1/startup/ack')return res.end(JSON.stringify({required:false,reason:'',version:'isolated-test',currentVersion:'isolated-test'}));
    if(url.pathname==='/api/v1/status')return res.end(JSON.stringify({version:'isolated-test',platform:'Windows fixture',protection:{Defender:true,DefenderService:true,RealTimeProtection:true,Firewall:true},mhx:mhxStatus(),integrity:{}}));
    if(url.pathname==='/api/v1/mhx/status')return res.end(JSON.stringify(mhxStatus()));
    if(url.pathname==='/api/v1/overview/threat-map'){
     requests++;res.statusCode=mapFailure?503:200;return res.end(JSON.stringify(mapFailure?{error:'Fixture failure'}:map));
    }
    if(url.pathname==='/api/v1/mhx/geo'){
     res.statusCode=geoFailure?503:200;
     return res.end(JSON.stringify(geoFailure?{error:'Fixture geo failure'}:{database:map.geo,sources:map.sources,countries:[],unknown:0}));
    }
    if(url.pathname==='/api/v1/health/refresh'||url.pathname==='/api/v1/health/status')return res.end(JSON.stringify({healthy:true,checkedUtc:now,checks:definitions.map(([id,label])=>({id,label,state:'healthy',detail:'Isolated test fixture'}))}));
    if(url.pathname==='/api/v1/window/state')return res.end('{"handled":false,"state":"normal"}');
    if(url.pathname==='/api/v1/mhx/stories')return res.end('[]');
    if(url.pathname==='/api/v1/mhx/policy/reconcile'||url.pathname==='/api/v1/mhx/feeds/sync')return res.end('{}');
    res.statusCode=404;return res.end('{"error":"Unexpected isolated test route"}');
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
 const failures=[];
 const check=async(name,fn)=>{assert.ok(await fn(),name);checks.push(name)};
 try{
  const page=await browser.newPage({viewport:{width:1600,height:1200},reducedMotion:'no-preference'});
  page.on('pageerror',error=>failures.push(error.message));
  await page.goto('http://127.0.0.1:'+server.address().port);
  await page.getByRole('button',{name:'Zum Security Center',exact:true}).waitFor();
  await page.getByRole('button',{name:'Zum Security Center',exact:true}).click();
  await page.locator('.overview-threat-marker').first().waitFor();
  await page.locator('#overviewThreatPanel').scrollIntoViewIfNeeded();
  await check('all 176 local countries render',async()=>await page.locator('.overview-world-country').count()===176);
  await check('one marker per position; shared sources form cluster',async()=>await page.locator('.overview-threat-marker').count()===5 && await page.locator('.overview-cluster-count').count()===1);
  await check('all genuine-shaped source trajectories reach the configured host',async()=>await page.locator('animateMotion').count()===6);
  await check('six telemetry columns and ASN context render',async()=>await page.locator('.overview-threat-stream-table th').count()===6 && (await page.locator('#overviewMapFeedList').textContent()).includes('AS100'));
  await check('hostile strings remain inert text',async()=>!await page.evaluate(()=>window.__injected) && await page.locator('#overviewMapFeedList img').count()===0);
  const x=await page.locator('.overview-threat-projectile').first().evaluate(node=>node.getCTM().e);
  await page.waitForTimeout(450);
  await check('SMIL projectile actually moves',async()=>Math.abs(await page.locator('.overview-threat-projectile').first().evaluate(node=>node.getCTM().e)-x)>.1);
  await page.locator('[data-filter="blocked"]').click();
  await check('blocked filter uses witnessed blocks',async()=>await page.locator('#overviewMapFeedList tr').count()===2);
  await page.locator('[data-filter="suspicious"]').click();
  await check('uppercase Windows severity is normalized for correlation filter',async()=>await page.locator('#overviewMapFeedList tr').count()===2);
  await page.locator('[data-filter="all"]').click();
  await page.locator('.overview-source-button').first().click();
  await check('table opens persistent source details',async()=>await page.locator('#overviewMapCard').isVisible());
  await page.keyboard.press('Escape');
  await check('Escape restores source keyboard focus',async()=>await page.locator('.overview-source-button').first().evaluate(node=>node===document.activeElement));
  await page.locator('.overview-threat-marker').first().focus();
  await page.keyboard.press('Enter');
  await check('keyboard activation reveals cluster members',async()=>await page.locator('#overviewCardCluster>div').count()===1);
  await page.keyboard.press('Escape');
  await page.locator('#overviewMapZoomIn').click();
  await check('zoom transforms complete SVG',async()=>(await page.locator('.overview-world-map>g').getAttribute('transform')).includes('scale(1.35)'));
  await page.locator('#overviewMapZoomReset').click();
  await page.locator('#overviewMapPause').click();
  const pausedRequests=requests;
  await page.waitForTimeout(5400);
  await check('operator pause freezes motion and network polling',async()=>requests===pausedRequests && await page.locator('.overview-world-map').evaluate(node=>node.animationsPaused()));
  await page.locator('#overviewMapPause').click();
  await page.waitForTimeout(300);
  await check('resume fetches current data',async()=>requests>pausedRequests);
  for(const[name,width,height]of[['ultrawide',2560,1389],['desktop',1600,1200],['tablet',1000,1100],['mobile',390,1000]]){
   await page.setViewportSize({width,height});
   await page.locator('#overviewThreatPanel').evaluate(node=>node.scrollIntoView({block:'start'}));
   await check(name+' has no page overflow',async()=>await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));
   await check(name+' map stage stays inside its panel',async()=>await page.evaluate(()=>{
     const panel=document.querySelector('#overviewThreatPanel');
     const stage=document.querySelector('.overview-threat-stage');
     const feed=document.querySelector('.overview-threat-feed');
     if(!panel||!stage||!feed)return false;
     const panelBox=panel.getBoundingClientRect();
     const stageBox=stage.getBoundingClientRect();
     const feedBox=feed.getBoundingClientRect();
     return stageBox.right<=panelBox.right-10
       && Math.abs(stageBox.width-feedBox.width)<=1
       && panel.scrollWidth<=panel.clientWidth+1;
   }));
   await page.screenshot({path:path.join(output,name+'.png')});
  }
  await page.emulateMedia({reducedMotion:'reduce'});
  await check('reduced motion freezes CSS and SVG decoration',async()=>await page.locator('.overview-threat-projectile').first().evaluate(node=>getComputedStyle(node).display==='none') && await page.locator('.overview-threat-arc').first().evaluate(node=>getComputedStyle(node).animationName==='none'));
  await page.emulateMedia({reducedMotion:'no-preference'});
  const redraw=async()=>{
   await page.evaluate(async()=>{const m=await import('/assets/overview-map.js');m.stopOverviewThreatMap();m.startOverviewThreatMap()});
   await page.waitForTimeout(400);
  };
  map={...structuredClone(baseMap),origin:{known:false}};
  await redraw();
  await check('unknown NAT host never creates invented destination arcs',async()=>await page.locator('animateMotion').count()===0 && await page.locator('.overview-threat-marker').count()===5);
  map={...structuredClone(baseMap),geo:{loaded:false,entries:0},sources:baseMap.sources.map(s=>({...s,latitude:null,longitude:null}))};
  await redraw();
  await check('missing CSV retains real telemetry without geographic pins',async()=>await page.locator('.overview-threat-marker').count()===0 && await page.locator('#overviewMapFeedList tr').count()===6);
  await page.evaluate(()=>document.querySelector('[data-view="kinetic"]').click());
  await page.locator('#kineticMetrics .metric-card').first().waitFor();
  await check('Kinetic shows counted blocks even without a burst',async()=>(await page.locator('#kineticTimeline').textContent()).includes('20') && (await page.locator('#kineticMetrics').textContent()).includes('20'));
  await check('Kinetic source table survives CSV failure',async()=>await page.locator('#kineticGeoRows tr').count()===6);
  geoFailure=true;
  await page.evaluate(async()=>{await(await import('/assets/views.js')).loadKinetic()});
  await check('failed GeoIP request cannot suppress Kinetic status',async()=>(await page.locator('#kineticGeoSummary').textContent()).includes('unabhängig') && (await page.locator('#kineticMetrics').textContent()).includes('20'));
  await page.screenshot({path:path.join(output,'kinetic.png')});
  geoFailure=false;
  await page.evaluate(()=>document.querySelector('[data-view="overview"]').click());
  await page.locator('#overviewThreatPanel').evaluate(node=>node.scrollIntoView({block:'start'}));
  map={...structuredClone(baseMap),sources:[],recent:[],totals:{}};
  await redraw();
  await check('empty snapshot clears all previous map and table data',async()=>await page.locator('.overview-threat-marker').count()===0 && await page.locator('#overviewMapFeedList tr').count()===0 && await page.locator('#overviewMapClean').isVisible());
  mapFailure=true;
  await redraw();
  await check('API failure is visibly stale rather than a safe empty state',async()=>await page.locator('#overviewMapStatus').getAttribute('data-state')==='failed' && !await page.locator('#overviewMapClean').isVisible());
  mapFailure=false;map=structuredClone(baseMap);await redraw();
  await check('successful retry clears stale state',async()=>await page.locator('#overviewMapStatus').getAttribute('data-state')==='live');
  await check('no uncaught browser exceptions',async()=>failures.length===0);
  await fs.writeFile(path.join(output,'report.json'),JSON.stringify({checks,failures,viewportEvidence:['desktop.png','tablet.png','mobile.png','kinetic.png']},null,2));
  console.log('PASS: '+checks.length+' browser checks; '+output);
 }finally{await browser.close();server.closeAllConnections();await new Promise(resolve=>server.close(resolve))}
}
main().catch(error=>{console.error(error);process.exitCode=1});
