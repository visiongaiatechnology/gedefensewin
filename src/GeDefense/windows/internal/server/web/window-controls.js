// STATUS: PLATIN
'use strict';
import {api} from './api.js';
import {byId,toast} from './dom.js';

let initialized=false;
export function initWindowControls(){
 if(initialized)return;
 initialized=true;
 const buttons=[byId('winMin'),byId('winMax'),byId('winClose')].filter(Boolean);
 let connected=false;
 let busy=false;
 function update(status){
  connected=status?.handled===true;
  for(const button of buttons)button.disabled=!connected||busy;
  const max=byId('winMax');
  const maximized=status?.state==='maximized';
  max.title=maximized?'Wiederherstellen':'Maximieren';
  max.setAttribute('aria-label',max.title);
  byId('winMaxIcon').replaceChildren();
  const rect=document.createElementNS(byId('winMaxIcon').namespaceURI,'rect');
  for(const [key,value]of Object.entries({x:'0.5',y:'0.5',width:maximized?'7':'9',height:maximized?'7':'9',fill:'none',stroke:'currentColor','stroke-width':'1.2'}))rect.setAttribute(key,value);
  byId('winMaxIcon').append(rect);
 }
 async function refresh(){
  try{update(await api('/api/v1/window/state',{signal:AbortSignal.timeout(4000)}))}
  catch{update({handled:false})}
 }
 async function command(action){
  if(!connected||busy)return;
  busy=true;
  for(const button of buttons)button.disabled=true;
  try{await api('/api/v1/window/'+action,{method:'POST',json:{},signal:AbortSignal.timeout(4000)})}
  catch(error){toast(error.message||'Fenstersteuerung nicht erreichbar.','bad')}
  finally{busy=false;await refresh()}
 }
 byId('winMin').addEventListener('click',()=>{void command('minimize')});
 byId('winMax').addEventListener('click',()=>{void command('maximize')});
 byId('winClose').addEventListener('click',()=>{void command('close')});
 const topbar=document.querySelector('.topbar');
 topbar.addEventListener('dblclick',event=>{
  if(event.target.closest('button,input,a,.top-actions'))return;
  void command('maximize');
 });
 topbar.addEventListener('pointerdown',event=>{
  if(event.button!==0||!connected||event.target.closest('button,input,a,.top-actions'))return;
  void api('/api/v1/window/drag',{method:'POST',json:{},signal:AbortSignal.timeout(2000)}).catch(()=>{toast('Fenster konnte nicht verschoben werden.','bad')});
 });
 void refresh();
 globalThis.setInterval(()=>{if(!document.hidden)void refresh()},1500);
}
