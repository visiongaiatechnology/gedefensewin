// STATUS: DIAMANT VGT SUPREME
'use strict';
export const byId=id=>document.getElementById(id);
export function setText(id,value){const node=byId(id);if(node)node.textContent=String(value??'---')}
export function node(tag,className,text){const item=document.createElement(tag);if(className)item.className=className;if(text!==undefined)item.textContent=String(text);return item}
export function clear(target){const element=typeof target==='string'?byId(target):target;if(element)element.replaceChildren();return element}
export function pill(text,tone='info'){return node('span',`status-pill ${tone}`,text)}
export function severity(text){return node('span',`severity ${String(text||'').toLowerCase()}`,text||'---')}
export function metric(label,value,detail=''){const article=node('article','glass metric-card');article.append(node('span','',label),node('strong','',value));if(detail)article.append(node('small','',detail));return article}
export function formatNumber(value){return Number(value||0).toLocaleString('de-DE')}
export function formatBytes(value){let n=Number(value||0);if(!Number.isFinite(n)||n<0)return '0 B';const units=['B','KiB','MiB','GiB','TiB'];let i=0;while(n>=1024&&i<units.length-1){n/=1024;i++}return `${n.toFixed(i?1:0)} ${units[i]}`}
export function formatTime(value){if(!value)return '---';const d=new Date(value);return Number.isNaN(d.getTime())?'---':d.toLocaleString('de-DE')}
export function toast(message,tone=''){const root=byId('toasts');if(!root)return;const item=node('div',`toast ${tone}`.trim(),message);root.append(item);globalThis.setTimeout(()=>item.remove(),6000)}
export function emptyRow(columns,text){const row=node('tr');const cell=node('td','',text);cell.colSpan=columns;row.append(cell);return row}
export function bar(label,active,total){const wrap=node('div');const head=node('div','bar-head');const percent=total>0?Math.round((active/total)*100):0;head.append(node('span','',label),node('strong','',`${percent}%`));const track=node('div','bar-track');const fill=node('div','bar-fill');fill.style.width=`${percent}%`;track.append(fill);wrap.append(head,track);return wrap}
