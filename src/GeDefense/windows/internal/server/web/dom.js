// STATUS: DIAMANT VGT SUPREME
'use strict';

import {locale} from './i18n.js';

/** Small, dependency-free DOM helpers. All rendering is textContent/DOM
 *  construction; untrusted server strings never reach innerHTML. */

export const byId=id=>document.getElementById(id);

export function setText(id,value){
  const node=byId(id);
  if(node)node.textContent=String(value??'---');
}

export function node(tag,className,text){
  const item=document.createElement(tag);
  if(className)item.className=className;
  if(text!==undefined)item.textContent=String(text);
  return item;
}

export const el=node;

export function clear(target){
  const element=typeof target==='string'?byId(target):target;
  if(element)element.replaceChildren();
  return element;
}

export function pill(text,tone='info'){
  return node('span',`status-pill ${tone}`,text);
}

export function severity(text){
  return node('span',`severity ${String(text||'').toLowerCase()}`,text||'---');
}

export function metric(label,value,detail='',tone=''){
  const article=node('article','metric-card');
  article.append(node('span','',label),node('strong','',value));
  if(detail)article.append(node('small','',detail));
  if(tone)article.dataset.tone=tone;
  return article;
}

export function formatNumber(value){
  const number=Number(value);
  return Number.isFinite(number)?number.toLocaleString(locale()):'---';
}

export function formatPercent(value,digits=0){
  const number=Number(value);
  return Number.isFinite(number)?`${number.toFixed(digits)}%`:'---';
}

export function formatBytes(value){
  let n=Number(value||0);
  if(!Number.isFinite(n)||n<0)return '0 B';
  const units=['B','KiB','MiB','GiB','TiB'];
  let i=0;
  while(n>=1024&&i<units.length-1){n/=1024;i++}
  return `${n.toFixed(i?1:0)} ${units[i]}`;
}

export function formatTime(value){
  if(!value)return '---';
  const date=new Date(value);
  if(Number.isNaN(date.getTime()))return '---';
  if(date.getTime()<=0)return '---';
  return date.toLocaleString(locale());
}

export function formatClock(value){
  if(!value)return '---';
  const date=new Date(value);
  if(Number.isNaN(date.getTime())||date.getTime()<=0)return '---';
  return date.toLocaleTimeString(locale(),{hour12:false});
}

export function relativeDuration(targetUtc,now=Date.now()){
  const target=new Date(targetUtc).getTime();
  if(!Number.isFinite(target)||target<=0)return '';
  const delta=target-now;
  const abs=Math.abs(delta);
  const minutes=Math.round(abs/60000);
  if(minutes<1)return delta>=0?'in weniger als 1 Min.':'vor weniger als 1 Min.';
  const hours=Math.floor(minutes/60);
  const days=Math.floor(hours/24);
  const label=days>0?`${days} T ${hours%24} Std.`:hours>0?`${hours} Std. ${minutes%60} Min.`:`${minutes} Min.`;
  return delta>=0?`in ${label}`:`vor ${label}`;
}

export function toast(message,tone=''){
  const root=byId('toasts');
  if(!root)return;
  const item=node('div',`toast ${tone}`.trim(),message);
  root.append(item);
  globalThis.setTimeout(()=>item.remove(),6000);
}

export function announce(message){
  const live=byId('pageLive');
  if(live)live.textContent=String(message||'');
}

export function emptyRow(columns,text){
  const row=node('tr');
  const cell=node('td','',text);
  cell.colSpan=columns;
  row.append(cell);
  return row;
}

export function emptyState(title,body=''){
  const wrap=node('div','empty-state');
  wrap.append(node('strong','',title));
  if(body)wrap.append(node('span','',body));
  return wrap;
}

export function bar(label,active,total){
  const wrap=node('div');
  const head=node('div','bar-head');
  const percent=total>0?Math.round((active/total)*100):0;
  head.append(node('span','',label),node('strong','',`${percent}%`));
  const track=node('div','bar-track');
  const fill=node('div','bar-fill');
  fill.style.width=`${percent}%`;
  track.append(fill);
  wrap.append(head,track);
  return wrap;
}

export function setPill(target,text,tone='info'){
  const element=typeof target==='string'?byId(target):target;
  if(!element)return;
  element.textContent=String(text??'---');
  element.className=`status-pill ${tone}`;
}

export function setBusy(button,busy,label=''){
  if(!button)return;
  button.disabled=Boolean(busy);
  button.classList.toggle('loading',Boolean(busy));
  if(label)button.textContent=label;
}

export function setProgress(target,percent,indeterminate=false){
  const element=typeof target==='string'?byId(target):target;
  if(!element)return;
  const track=element.closest?.('.progress')||element.parentElement;
  if(indeterminate){element.style.width='';if(track)track.dataset.indeterminate='true';return}
  if(track)delete track.dataset.indeterminate;
  const value=Math.max(0,Math.min(100,Number(percent)||0));
  element.style.width=`${value}%`;
}

/**
 * Render an honest notice into a host element (or id).
 * options: {tone:'info'|'warn'|'bad'|'good', title, body, icon, actions:[{label,onClick,variant,disabled}], id}
 * Returns the notice element.
 */
export function notice(host,options={}){
  const parent=typeof host==='string'?byId(host):host;
  if(!parent)return null;
  const tone=options.tone||'info';
  const card=node('div','notice');
  card.dataset.tone=tone;
  if(options.id)card.id=options.id;
  const icon=node('span','notice-icon',options.icon||(tone==='bad'?'!':tone==='warn'?'!':tone==='good'?'✓':'i'));
  icon.setAttribute('aria-hidden','true');
  const body=node('div','notice-content');
  if(options.title)body.append(node('p','notice-title',options.title));
  if(options.body)body.append(node('p','notice-body',options.body));
  if(Array.isArray(options.actions)&&options.actions.length){
    const actions=node('div','notice-actions');
    for(const action of options.actions){
      if(!action)continue;
      const button=node('button',`button ${action.variant||'ghost'} small`,action.label);
      button.type='button';
      if(action.disabled)button.disabled=true;
      if(typeof action.onClick==='function')button.addEventListener('click',action.onClick);
      actions.append(button);
    }
    body.append(actions);
  }
  card.append(icon,body);
  parent.append(card);
  return card;
}

/** Replace a host with a single notice. */
export function replaceNotice(host,options={}){
  const parent=typeof host==='string'?byId(host):host;
  if(!parent)return null;
  parent.replaceChildren();
  return notice(parent,options);
}

/**
 * Confirm dialog helper. Resolves true only for the explicit confirm action.
 * Safe when the dialog is missing (returns false).
 */
export function requestConfirm({title,text,label='Ausführen',tone='danger'}={}){
  const dialog=byId('confirmDialog');
  if(!dialog||typeof dialog.showModal!=='function')return Promise.resolve(false);
  if(dialog.open)return Promise.resolve(false);
  setText('confirmTitle',title||'Aktion bestätigen');
  setText('confirmText',text||'');
  const confirm=byId('confirmAction');
  const cancel=dialog.querySelector('button[value="cancel"]');
  if(confirm){confirm.textContent=label||'Ausführen';confirm.className=`button ${tone==='primary'?'primary':'danger'}`;confirm.value='confirm'}
  if(cancel)cancel.value='cancel';
  return new Promise(resolve=>{
    const onClose=()=>{dialog.removeEventListener('close',onClose);resolve(dialog.returnValue==='confirm')};
    dialog.addEventListener('close',onClose);
    dialog.returnValue='';
    try{dialog.showModal()}catch{dialog.removeEventListener('close',onClose);resolve(false)}
  });
}

/**
 * Reason dialog helper. Security transactions require an explicit operator
 * reason (>= 8 chars, server-side floor). Resolves the trimmed reason or null.
 */
export function requestReason({title,text,label='Begründung',confirmLabel='Bestätigen',tone='primary'}={}){
  const dialog=byId('reasonDialog');
  if(!dialog||typeof dialog.showModal!=='function')return Promise.resolve(null);
  if(dialog.open)return Promise.resolve(null);
  setText('reasonDialogTitle',title||'Änderung bestätigen');
  setText('reasonDialogText',text||'');
  setText('reasonDialogLabel',label);
  const input=byId('reasonDialogReason');
  if(input){input.value='';input.placeholder='Mindestens 8 Zeichen'}
  const confirm=byId('reasonDialogConfirm');
  if(confirm){confirm.textContent=confirmLabel||'Bestätigen';confirm.className=`button ${tone==='danger'?'danger':'primary'}`;confirm.value='confirm'}
  const cancel=dialog.querySelector('button[value="cancel"]');
  if(cancel)cancel.value='cancel';
  return new Promise(resolve=>{
    let settled=false;
    const finish=value=>{
      if(settled)return;
      settled=true;
      confirm?.removeEventListener('click',onConfirm);
      dialog.removeEventListener('close',onClose);
      resolve(value);
    };
    const onConfirm=event=>{
      event.preventDefault();
      const reason=String(input?.value||'').trim();
      if(reason.length<8){
        toast('Bitte eine Begründung mit mindestens 8 Zeichen angeben.','bad');
        input?.focus();
        return;
      }
      dialog.returnValue='confirm';
      dialog.close('confirm');
      finish(reason);
    };
    const onClose=()=>finish(null);
    confirm?.addEventListener('click',onConfirm);
    dialog.addEventListener('close',onClose);
    dialog.returnValue='';
    try{dialog.showModal()}catch{
      finish(null);
      return;
    }
    input?.focus();
  });
}

export function openDialog(id){
  const dialog=byId(id);
  if(!dialog)return null;
  try{if(!dialog.open)dialog.showModal()}catch{return null}
  return dialog;
}

export function closeDialog(id){
  const dialog=byId(id);
  if(dialog?.open)dialog.close();
}
