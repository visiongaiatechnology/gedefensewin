// STATUS: PLATIN
// Isolated browser regression fixtures; never connect to the installed service.
const assert=require('node:assert/strict');
const fs=require('node:fs/promises');
const path=require('node:path');
const http=require('node:http');
const {createRequire}=require('node:module');
const runtimeRequire=process.env.CODEX_NODE_MODULES?createRequire(path.join(path.resolve(process.env.CODEX_NODE_MODULES),'package.json')):require;
const {chromium}=runtimeRequire('playwright');
const root=path.resolve(__dirname,'../src/GeDefense/windows/internal/server/web');
const output=path.resolve(__dirname,'../work/verification');
const definitions=[['policy','Schutzrichtlinie'],['defender','Microsoft Defender'],['firewall','Windows Firewall'],['telemetry','Prozess- und Netzwerk-Telemetrie'],['intelligence','Threat Intelligence'],['enforcement','Threat-IP-Firewallregeln'],['evidence','Evidenz und Audit-Kette']];

async function main(){
 await fs.mkdir(output,{recursive:true});
 let scenario='healthy';
 let reconciled=false;
 let feedReady=false;
 let calls=[];
 const status=()=>({version:'test',platform:'Windows · Test fixture',protection:{Defender:true,DefenderService:true,RealTimeProtection:true,Firewall:true},mhx:{protectionMode:'guarded',protectionHealth:reconciled?'VERIFIED':'STARTING',realtime:true,threatIntelligence:feedReady?{state:'CURRENT',indicators:123,blockingFeedsReady:1,blockingFeedsTotal:1,enforcementGenerationSha256:'generation'}:{state:'STARTING'},threatEnforcement:feedReady?{state:'VERIFIED',activeGenerationSha256:'generation'}:{state:'UNVERIFIED'},traffic:{}},integrity:{}});
 const server=http.createServer(async(req,res)=>{
  const target=new URL(req.url,'http://localhost');
  try{
   if(target.pathname.startsWith('/api/')){
    calls.push(target.pathname);
    res.setHeader('Content-Type','application/json');
    if(target.pathname==='/api/v1/status')return res.end(JSON.stringify(status()));
    if(target.pathname==='/api/v1/mhx/stories')return res.end('[]');
    if(target.pathname==='/api/v1/mhx/status')return res.end(JSON.stringify(status().mhx));
    if(target.pathname==='/api/v1/window/state')return res.end('{"handled":false,"state":"normal"}');
    if(target.pathname==='/api/v1/mhx/policy/reconcile'){
     await new Promise(resolve=>setTimeout(resolve,150));
     if(scenario==='error'){res.statusCode=409;return res.end('{"error":"Policy konnte nicht verifiziert werden."}')}
     reconciled=true;return res.end('{}');
    }
    if(target.pathname==='/api/v1/mhx/feeds/sync'){feedReady=true;return res.end('{}')}
    if(target.pathname==='/api/v1/health/refresh'){
     const checks=definitions.map(([id,label])=>({id,label,state:(scenario==='attention'&&id==='defender')||(!reconciled&&id==='policy')?'attention':'healthy',detail:scenario==='attention'&&id==='defender'?'Defender oder Echtzeitschutz ist nicht aktiv. Windows-Sicherheit prüfen.':'Aktueller Zustand verifiziert.'}));
     if(scenario==='malformed')checks[0].id='unexpected';
     return res.end(JSON.stringify({healthy:scenario!=='attention'&&reconciled,checkedUtc:new Date().toISOString(),checks}));
    }
    res.statusCode=404;return res.end('{"error":"Unexpected test route"}');
   }
   const name=target.pathname==='/'?'index.html':target.pathname.replace(/^\/assets\//,'');
   const resolved=path.resolve(root,name);
   if(!resolved.startsWith(root+path.sep)){res.statusCode=403;return res.end()}
   res.setHeader('Content-Type',name.endsWith('.js')?'text/javascript':name.endsWith('.css')?'text/css':name.endsWith('.png')?'image/png':'text/html; charset=utf-8');
   res.end(await fs.readFile(resolved));
  }catch(error){res.statusCode=500;res.end(String(error))}
 });
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 const browser=await chromium.launch({executablePath:path.join(process.env.ProgramFiles,'Google/Chrome/Application/chrome.exe'),headless:true});
 try{
  for(const test of [{name:'desktop',width:1440,height:1000,scenario:'healthy'},{name:'narrow',width:800,height:900,scenario:'healthy'},{name:'mobile',width:390,height:844,scenario:'healthy'},{name:'attention',width:1100,height:900,scenario:'attention'},{name:'error',width:1100,height:900,scenario:'error'},{name:'malformed',width:1100,height:900,scenario:'malformed'}]){
   scenario=test.scenario;reconciled=false;feedReady=false;calls=[];
   const page=await browser.newPage({viewport:{width:test.width,height:test.height},reducedMotion:'reduce'});
   const failures=[];page.on('pageerror',error=>failures.push(error.message));
   await page.goto('http://127.0.0.1:'+server.address().port);
   await page.locator('#startupDialog[open]').waitFor();
   await page.getByRole('button',{name:'Zum Security Center',exact:true}).waitFor();
   assert.equal(failures.length,0,failures.join('\n'));
   assert.equal(await page.locator('#startupChecks li').count(),7);
   if(test.scenario==='healthy'){
    assert.equal(await page.locator('#startupChecks [data-state="healthy"]').count(),7);
    await page.getByRole('heading',{name:'GeDefense ist bereit',exact:true}).waitFor();
    assert.equal(await page.locator('#startupRetry').isVisible(),false);
   }else{
    assert.equal(await page.locator('#startupRetry').isVisible(),true);
    if(test.scenario==='attention')assert.equal(await page.locator('#startupChecks [data-state="attention"]').count(),1);
    if(test.scenario==='malformed')await page.getByRole('heading',{name:'Startcheck konnte nicht abgeschlossen werden'}).waitFor();
   }
   assert.equal(calls.filter(route=>route==='/api/v1/mhx/policy/reconcile').length,1);
   assert.equal(calls.filter(route=>route==='/api/v1/mhx/feeds/sync').length,1);
   const dimensions=await page.evaluate(()=>({body:document.documentElement.scrollWidth,width:innerWidth,dialog:document.querySelector('#startupDialog').getBoundingClientRect().width}));
   assert.ok(dimensions.body<=dimensions.width,'horizontal page overflow');
   assert.ok(dimensions.dialog<=dimensions.width,'dialog overflows viewport');
   await page.screenshot({path:path.join(output,'startup-'+test.name+'.png')});
   if(test.scenario==='attention'){
    scenario='healthy';
    await page.getByRole('button',{name:'Erneut synchronisieren'}).click();
    await page.getByRole('heading',{name:'GeDefense ist bereit',exact:true}).waitFor();
   }
   await page.getByRole('button',{name:'Zum Security Center',exact:true}).click();
   assert.equal(await page.locator('#startupDialog').isVisible(),false);
   await page.close();
   process.stdout.write('PASS '+test.name+'\n');
  }
 }finally{await browser.close();await new Promise(resolve=>server.close(resolve))}
}
main().catch(error=>{process.stderr.write(error.stack+'\n');process.exitCode=1});
