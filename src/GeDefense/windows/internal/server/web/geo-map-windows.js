// GeDefense Windows / Kinetic offline world map. Local SVG, no network calls.
import world from './world-merc.js';
import {locale} from './i18n.js';
const ns='ht'+'tp://www.w3.org/2000/svg';
let svg, countriesLayer, markersLayer, rowsLayer;let rendered=false;
const node=(tag,attrs={})=>{const el=document.createElementNS(ns,tag);for(const [k,v]of Object.entries(attrs))el.setAttribute(k,String(v));return el};
function position(lat,lon){
 if(!Number.isFinite(lat)||!Number.isFinite(lon)||Math.abs(lat)>89||Math.abs(lon)>180)return null;
 const inset=world.insets[0],a=inset.bbox[0],b=inset.bbox[1];
 const radius=6378137,rad=Math.PI/180;
 const x=radius*(lon-world.projection.centralMeridian)*rad;
 const y=-radius*Math.log(Math.tan(Math.PI/4+(lat*rad)/2));
 const px=(x-a.x)/(b.x-a.x)*inset.width,py=(y-a.y)/(b.y-a.y)*inset.height;
 return px>=0&&px<=world.width&&py>=0&&py<=world.height?[px,py]:null;
}
function init(){
 const host=document.getElementById('kineticGeoMap');if(!host)return false;
 if(rendered&&svg?.isConnected)return true;
 svg=node('svg',{viewBox:`0 0 ${world.width} ${world.height}`,role:'img','aria-label':'Kinetic Netzwerkereignisse auf einer Weltkarte'});
 svg.classList.add('kinetic-world-svg');host.replaceChildren(svg);
 const land=node('g',{class:'geo-land'});
 for(const [code,item]of Object.entries(world.paths)){
  const p=node('path',{d:item.path,'data-country':code,fill:'#0a3145',stroke:'#35607e','stroke-width':'.65'});
  const label=node('title');label.textContent=item.name||code;p.append(label);land.append(p);
 }
 svg.append(land);countriesLayer=land;markersLayer=node('g',{class:'geo-markers'});svg.append(markersLayer);rendered=true;return true;
}
export function updateGeoMap(payload){
 if(!init())return;
 const meta=document.getElementById('kineticGeoSummary');const status=payload?.database||{};
 if(!status.loaded){markersLayer.replaceChildren()}
 const countries=(payload.countries||[]).slice(0,64), sources=(payload.sources||[]).slice(0,96);
 const heat=new Map(countries.map(c=>[c.code,c]));const max=Math.max(1,...countries.map(c=>c.hits||0));
 for(const p of countriesLayer.children){const c=heat.get(p.dataset.country||p.getAttribute('data-country'));let fill='#0a3145';if(c){const k=Math.min(1,(c.hits||0)/max);fill=`rgb(${Math.round(16+k*175)},${Math.round(63-k*17)},${Math.round(84+k*15)})`}p.setAttribute('fill',fill)}
 markersLayer.replaceChildren();let placed=0;
 for(const s of sources){const lat=Number(s.latitude),lon=Number(s.longitude);if(s.latitude==null||s.longitude==null)continue;const xy=position(lat,lon);if(!xy)continue;
  const circle=node('circle',{cx:xy[0],cy:xy[1],r:s.blocked?4.5:3,fill:s.blocked?'#ff527b':'#42dded',stroke:'#081525','stroke-width':1.1});
  const title=node('title');title.textContent=`${s.ip} · ${s.country||'Unbekannt'} · ${s.asn||'ASN unbekannt'} ${s.as_name||''} · ${s.state}`;circle.append(title);markersLayer.append(circle);placed++
 }
 if(meta)meta.textContent=`${status.loaded?'': 'GeoIP nicht geladen · keine geografischen Pins · '}${Number(status.entries||0).toLocaleString(locale())} CIDR-Netze geladen · ${sources.length} beobachtete Quell-IP-Adressen · ${placed} geografisch zugeordnet · ${payload.unknown||0} unbekannt. Standort = ungefähre Netzzuordnung.`;
 const body=document.getElementById('kineticGeoRows');if(body){body.replaceChildren();for(const s of sources.slice(0,64)){
  const tr=document.createElement('tr');for(const val of[s.ip,s.country||'Unbekannt',s.asn||'—',s.as_name||'—',s.state]){const td=document.createElement('td');td.textContent=String(val);tr.append(td)}body.append(tr)
 }if(!body.children.length){const td=document.createElement('td');td.colSpan=5;td.textContent='Noch keine passenden Netzwerkereignisse.';const tr=document.createElement('tr');tr.append(td);body.append(tr)}}
}
