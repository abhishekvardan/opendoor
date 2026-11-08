import { escapeHtml } from "./security.js";

/**
 * Built-in, dependency-free pages so an existing site needs no frontend work:
 *   {basePath}            Connected agents: connect with a token, edit permissions, revoke, activity log
 *   {basePath}/authorize  OAuth consent screen
 * Everything dynamic is rendered client-side with textContent-safe escaping.
 */
const CSS = `
:root{--ink:#1c1917;--muted:#78716c;--line:#e7e5e4;--bg:#fafaf9;--accent:var(--od-accent,#1c1917);--ok:#047857;--bad:#be123c;--warn:#b45309}
*{box-sizing:border-box}input[type=checkbox]{accent-color:var(--accent);width:16px;height:16px;flex:none;margin-top:2px}body{margin:0;font:15px/1.5 Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;color:var(--ink);background:var(--bg)}
a{color:inherit}.wrap{max-width:1040px;margin:0 auto;padding:32px 20px 80px}.top{display:flex;align-items:center;gap:10px;font-weight:600}
.logo{display:grid;place-items:center;width:30px;height:30px;border-radius:9px;background:var(--accent);color:#fff;font-size:14px;font-weight:700}
h1{font-size:30px;letter-spacing:-.02em;margin:28px 0 6px}h2{font-size:18px;margin:36px 0 12px}.sub{color:var(--muted);margin:0 0 20px;max-width:680px}
.card{background:#fff;border:1px solid var(--line);border-radius:16px;padding:20px}.grid{display:grid;gap:14px}.row{display:flex;gap:12px;align-items:center;flex-wrap:wrap}
.btn{display:inline-flex;align-items:center;gap:6px;border-radius:999px;padding:9px 18px;font:inherit;font-weight:500;cursor:pointer;border:1px solid var(--line);background:#fff;color:var(--ink)}
.btn:hover{border-color:#a8a29e}.btn.primary{background:var(--accent);border-color:var(--accent);color:#fff}.btn.danger{color:var(--bad);border-color:#fecdd3}.btn.sm{padding:5px 12px;font-size:13px}
.btn:disabled{opacity:.5;cursor:not-allowed}input[type=text],input[type=number],select{font:inherit;border:1px solid #d6d3d1;border-radius:10px;padding:8px 11px;background:#fff;width:100%}
label.scope{display:flex;gap:10px;padding:12px 14px;border-top:1px solid var(--line);cursor:pointer}label.scope:first-child{border-top:0}.scopes{border:1px solid var(--line);border-radius:12px;overflow:hidden;background:#fff}
.scope b{font-weight:600}.scope small{display:block;color:var(--muted)}code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px}
.chip{display:inline-block;border-radius:6px;background:#f5f5f4;padding:2px 7px;margin:2px 4px 2px 0;font-family:ui-monospace,monospace;font-size:12px;color:#57534e}
.pill{display:inline-flex;align-items:center;gap:5px;border-radius:999px;padding:1px 9px;font-size:12px;font-weight:600;border:1px solid}
.pill.success{color:var(--ok);border-color:#a7f3d0;background:#ecfdf5}.pill.denied{color:var(--warn);border-color:#fde68a;background:#fffbeb}.pill.error{color:var(--bad);border-color:#fecdd3;background:#fff1f2}
.risk-high{color:var(--bad);font-size:11px;font-weight:700}.risk-medium{color:var(--warn);font-size:11px;font-weight:700}
.muted{color:var(--muted)}.small{font-size:13px}.note{border-radius:12px;padding:10px 14px;background:#fffbeb;border:1px solid #fde68a;color:#78350f;font-size:14px}
.err{border-radius:12px;padding:10px 14px;background:#fff1f2;border:1px solid #fecdd3;color:var(--bad);font-size:14px;display:none}
table{width:100%;border-collapse:collapse;font-size:13.5px}th{text-align:left;color:var(--muted);font-weight:500;padding:10px 12px;border-bottom:1px solid var(--line)}
td{padding:10px 12px;border-bottom:1px solid #f5f5f4;vertical-align:top}.copy{display:flex;border:1px solid #d6d3d1;border-radius:10px;overflow:hidden}
.copy code{flex:1;padding:9px 12px;background:#f5f5f4;overflow-x:auto;white-space:nowrap}.copy button{border:0;border-left:1px solid #d6d3d1;background:#fff;padding:0 12px;cursor:pointer;font:inherit;font-size:13px}
pre.code{background:#1c1917;color:#f5f5f4;border-radius:12px;padding:14px;overflow-x:auto;font-size:12.5px}
.consent{max-width:520px;margin:40px auto}.center{text-align:center}dl.kv{display:grid;grid-template-columns:auto 1fr;gap:4px 14px;background:#f5f5f4;border-radius:12px;padding:12px 14px;font-size:13px;margin:16px 0}
dl.kv dt{color:var(--muted)}dl.kv dd{margin:0;overflow:hidden;text-overflow:ellipsis}
`;

const json = (v) => JSON.stringify(v).replace(/</g, "\\u003c");

function page({ title, site, accent, body, data, script }) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer"><title>${escapeHtml(title)}</title><style>${CSS}${accent ? `:root{--od-accent:${escapeHtml(accent)}}` : ""}</style></head>
<body>${body}<script>const OD=${json(data)};
const esc=(s)=>String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"})[c]);
const $=(s,r=document)=>r.querySelector(s);
async function api(path,opts={}){const r=await fetch(OD.api+path,{method:opts.method||"GET",headers:opts.body?{"Content-Type":"application/json"}:{},body:opts.body?JSON.stringify(opts.body):undefined,credentials:"same-origin"});
const d=await r.json().catch(()=>({}));if(!r.ok)throw new Error(d.error?.message||("Request failed ("+r.status+")"));return d;}
function showErr(el,msg){el.textContent=msg;el.style.display=msg?"block":"none";}
function fmtLimit(key,v){const d=OD.limits[key];return d&&d.format==="usd_cents"?"$"+(v/100).toFixed(2):String(v);}
function scopeList(allowed,checked,prefix){return '<div class="scopes">'+Object.entries(OD.scopes).filter(([k])=>!allowed||allowed.includes(k)).map(([k,s])=>
'<label class="scope"><input type="checkbox" name="'+prefix+'scope" value="'+esc(k)+'"'+(checked.includes(k)?" checked":"")+'><span><b>'+esc(s.label||k)+'</b> <code class="chip">'+esc(k)+'</code>'+
(s.risk==="high"?' <span class="risk-high">HIGH RISK</span>':s.risk==="medium"?' <span class="risk-medium">MEDIUM RISK</span>':"")+'<small>'+esc(s.description||"")+'</small></span></label>').join("")+'</div>';}
function limitInputs(prefix,values){return Object.entries(OD.limits).map(([k,d])=>'<div class="limit" data-scope="'+esc(d.scope||"")+'" style="margin-top:12px"><label class="small"><b>'+esc(d.label||k)+'</b> <span class="muted">(empty = no limit'+(d.format==="usd_cents"?", in dollars":"")+')</span></label><input type="number" min="0" step="any" name="'+prefix+'limit-'+esc(k)+'" value="'+(values&&values[k]!=null?(d.format==="usd_cents"?values[k]/100:values[k]):"")+'"></div>').join("");}
function readForm(root,prefix){const scopes=[...root.querySelectorAll('input[name="'+prefix+'scope"]:checked')].map(i=>i.value);const limits={};
for(const [k,d] of Object.entries(OD.limits)){const i=root.querySelector('[name="'+prefix+'limit-'+k+'"]');if(!i||i.value===""||(d.scope&&!scopes.includes(d.scope)))continue;limits[k]=d.format==="usd_cents"?Math.round(Number(i.value)*100):Math.floor(Number(i.value));}
return {scopes,limits};}
function syncLimits(root,prefix){const scopes=readForm(root,prefix).scopes;root.querySelectorAll(".limit").forEach(el=>{el.style.display=!el.dataset.scope||scopes.includes(el.dataset.scope)?"block":"none";});}
${script}</script></body></html>`;
}

const header = (site) => `<div class="top"><span class="logo">${escapeHtml(site.slice(0, 1).toUpperCase())}</span>${escapeHtml(site)}</div>`;

export function consentPage(door, req) {
  const { config } = door;
  return page({
    title: `Connect an agent · ${config.name}`,
    accent: config.accentColor,
    data: { api: door.apiBase, scopes: config.scopes, limits: config.limits ?? {}, query: req.query },
    body: `<div class="consent">${header(config.name)}<div class="card" style="margin-top:20px;padding:28px" id="box"><p class="muted">Loading…</p></div></div>`,
    script: `
(async()=>{const box=$("#box");let r;try{r=await api("/oauth/request?"+new URLSearchParams(OD.query));}catch(e){box.innerHTML='<h1 style="font-size:22px;margin:0">This request can\\'t be completed</h1><p class="muted">'+esc(e.message)+'</p>';return;}
const pre=r.existing_grant?r.existing_grant.scopes.filter(s=>r.requested_scopes.includes(s)):r.requested_scopes.filter(s=>OD.scopes[s]?.risk!=="high");
box.innerHTML='<h1 style="font-size:22px;margin:0" class="center">'+esc(r.agent.name)+' wants to access your '+esc(r.site)+' account</h1>'+
'<p class="muted center small" style="margin:6px 0 0">Signed in as '+esc(r.user.email||r.user.name||"you")+'</p>'+
'<dl class="kv"><dt>Agent ID</dt><dd class="mono">'+esc(r.agent.id)+'</dd><dt>Registered</dt><dd>'+(r.agent.registered_via==="oauth_dcr"?"Self-registered via OAuth":"Registered on this site")+'</dd><dt>Returns to</dt><dd class="mono">'+esc(r.redirect_host)+'</dd></dl>'+
(r.agent.registered_via==="oauth_dcr"?'<p class="muted small">The name above is supplied by the agent. Only continue if you started this connection from '+esc(r.redirect_host)+'.</p>':"")+
'<p style="font-weight:600;margin:18px 0 8px">Allow it to:</p>'+scopeList(r.requested_scopes,pre,"")+limitInputs("",r.existing_grant?.limits)+
(r.existing_grant?'<p class="muted small">This agent is already connected. Approving replaces its permissions.</p>':"")+
'<div class="err" id="err" style="margin-top:14px"></div><div class="row" style="margin-top:20px"><button class="btn" id="deny" style="flex:1;justify-content:center">Deny</button><button class="btn primary" id="allow" style="flex:1;justify-content:center">Allow access</button></div>'+
'<p class="muted small center" style="margin-top:14px">The agent never sees your password. You can revoke access at any time.</p>';
syncLimits(box,"");box.addEventListener("change",()=>syncLimits(box,""));
const decide=async(approve)=>{const f=readForm(box,"");if(approve&&!f.scopes.length)return showErr($("#err"),"Select at least one permission.");
$("#allow").disabled=$("#deny").disabled=true;try{const d=await api("/oauth/consent",{method:"POST",body:{params:OD.query,approve,scopes:f.scopes,limits:f.limits}});location.assign(d.redirect);}
catch(e){showErr($("#err"),e.message);$("#allow").disabled=$("#deny").disabled=false;}};
$("#allow").onclick=()=>decide(true);$("#deny").onclick=()=>decide(false);})();`,
  });
}

export function dashboardPage(door, req) {
  const { config } = door;
  const meta = door.meta(req);
  return page({
    title: `Connected agents · ${config.name}`,
    accent: config.accentColor,
    data: { api: door.apiBase, scopes: config.scopes, limits: config.limits ?? {}, defaults: door.defaultScopes, meta },
    body: `<div class="wrap">${header(config.name)}
<h1>Connected agents</h1><p class="sub">Let Claude, ChatGPT or your own AI agent act on your ${escapeHtml(config.name)} account. You choose what each agent may do, and you can revoke access at any time.</p>
<div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(300px,1fr))">
<div class="card"><b>Connect with OAuth</b><p class="muted small">For Claude, ChatGPT, Cursor and other MCP apps: add this URL as a custom connector, then approve here.</p><div class="copy"><code id="mcpurl"></code><button data-copy="#mcpurl">Copy</button></div></div>
<div class="card"><b>Connect with an Agent ID</b><p class="muted small">For scripts and custom agents: register an Agent ID and get a scoped token.</p><button class="btn primary" id="open-connect">Connect an agent</button></div></div>
<div class="card" id="connect" style="display:none;margin-top:14px"></div>
<h2>Your agents</h2><div class="grid" id="grants"><p class="muted">Loading…</p></div>
<h2>Activity</h2><div class="card" style="padding:0;overflow-x:auto"><table><thead><tr><th>Time</th><th>Agent</th><th>Action</th><th>Permission</th><th>Result</th><th>Details</th></tr></thead><tbody id="log"></tbody></table></div>
</div>`,
    script: `
$("#mcpurl").textContent=OD.meta.mcp_url;
document.addEventListener("click",e=>{const b=e.target.closest("[data-copy]");if(b){navigator.clipboard.writeText($(b.dataset.copy).textContent);b.textContent="Copied";setTimeout(()=>b.textContent="Copy",1500);}});
const ago=d=>{if(!d)return"never";const s=(Date.now()-new Date(d))/1000;return s<60?"just now":s<3600?Math.round(s/60)+" min ago":s<86400?Math.round(s/3600)+" h ago":new Date(d).toLocaleDateString();};
async function loadGrants(){const {grants}=await api("/grants");const el=$("#grants");if(!grants.length){el.innerHTML='<div class="card muted">No agents connected yet.</div>';return;}
el.innerHTML=grants.map(g=>'<div class="card" data-id="'+esc(g.id)+'"><div class="row" style="justify-content:space-between"><div><b>'+esc(g.agent.name)+'</b> <span class="pill '+(g.status==="active"?"success":"error")+'">'+esc(g.status)+'</span> <span class="muted small">'+(g.method==="oauth"?"OAuth":"Access token")+'</span>'+
'<div class="mono muted">Agent ID: '+esc(g.agent.id)+'</div></div>'+(g.status==="active"?'<div class="row"><button class="btn sm" data-act="edit">Permissions</button>'+(g.method==="token"?'<button class="btn sm" data-act="rotate">New token</button>':"")+'<button class="btn sm danger" data-act="revoke">Revoke</button></div>':"")+'</div>'+
'<div style="margin-top:8px">'+g.scopes.map(s=>'<span class="chip">'+esc(s)+'</span>').join("")+'</div><div class="muted small" style="margin-top:6px">Last used '+ago(g.last_used_at)+' · '+g.calls_24h+' calls in 24 h'+
Object.entries(g.limits_display||{}).map(([k,v])=>' · '+esc(OD.limits[k]?.label||k)+': '+esc(v)).join("")+'</div><div class="editor"></div></div>').join("");}
$("#grants").addEventListener("click",async e=>{const b=e.target.closest("[data-act]");if(!b)return;const card=b.closest("[data-id]");const id=card.dataset.id;const {grants}=await api("/grants");const g=grants.find(x=>x.id===id);
if(b.dataset.act==="revoke"){if(!confirm("Revoke "+g.agent.name+"'s access? Its tokens stop working immediately."))return;await api("/grants/"+id+"/revoke",{method:"POST",body:{}});refresh();}
if(b.dataset.act==="rotate"){if(!confirm("Issue a new token? The current one stops working."))return;const r=await api("/grants/"+id+"/token",{method:"POST",body:{expires_in_days:30}});showToken(r,g.agent.name);refresh();}
if(b.dataset.act==="edit"){const ed=card.querySelector(".editor");ed.innerHTML='<div style="margin-top:14px">'+scopeList(null,g.scopes,"e")+limitInputs("e",g.limits)+'<div class="err"></div><div class="row" style="margin-top:12px"><button class="btn primary sm" data-save>Save</button><button class="btn sm" data-cancel>Cancel</button></div></div>';syncLimits(ed,"e");ed.onchange=()=>syncLimits(ed,"e");
ed.querySelector("[data-cancel]").onclick=()=>ed.innerHTML="";ed.querySelector("[data-save]").onclick=async()=>{try{await api("/grants/"+id,{method:"PATCH",body:readForm(ed,"e")});refresh();}catch(err){showErr(ed.querySelector(".err"),err.message);}};}});
async function loadLog(){const {entries}=await api("/activity?limit=50");$("#log").innerHTML=entries.length?entries.map(e=>'<tr><td class="muted">'+new Date(e.created_at).toLocaleString()+'</td><td>'+esc(e.agent_name||"")+'<div class="mono muted">'+esc(e.agent_id||"")+'</div></td><td><code>'+esc(e.action)+'</code> <span class="muted small">'+esc(e.transport)+'</span></td><td><code>'+esc(e.required_scope||"—")+'</code></td><td><span class="pill '+esc(e.status)+'">'+esc(e.status)+'</span></td><td>'+esc(e.error_message||e.result_summary||"")+'</td></tr>').join(""):'<tr><td colspan="6" class="muted">No activity yet.</td></tr>';}
function showToken(r,name){const c=$("#connect");c.style.display="block";const t=r.access_token;
c.innerHTML='<b>'+esc(name)+' is connected</b><p class="note" style="margin-top:10px">Copy this token now. Only a hash is stored, so it can\\'t be shown again.</p><div class="copy"><code id="tok">'+esc(t)+'</code><button data-copy="#tok">Copy</button></div>'+
'<pre class="code">'+esc('# MCP (Streamable HTTP)\\nURL:    '+OD.meta.mcp_url+'\\nHeader: Authorization: Bearer '+t+'\\n\\n# REST\\ncurl -X POST '+OD.meta.rest_actions_url+'/'+(OD.meta.actions[0]?.name||"")+' \\\\\\n  -H "Authorization: Bearer '+t+'" -H "Content-Type: application/json" -d \\'{}\\'')+'</pre><button class="btn sm" id="done">Done</button>';$("#done").onclick=()=>{c.style.display="none";};}
$("#open-connect").onclick=()=>{const c=$("#connect");c.style.display="block";c.innerHTML='<b>Connect an agent</b><div class="grid" style="grid-template-columns:1fr 1fr;margin-top:12px"><div><label class="small">Display name</label><input type="text" id="c-name" placeholder="My agent"></div><div><label class="small">Agent ID</label><input type="text" id="c-id" class="mono" value="agent-'+Math.random().toString(36).slice(2,8)+'"></div></div>'+
'<p class="small" style="margin:16px 0 8px"><b>Permissions</b> <span class="muted">(high-risk ones are off by default)</span></p>'+scopeList(null,OD.defaults,"c")+limitInputs("c",null)+
'<div class="row" style="margin-top:12px"><label class="small">Token lifetime</label><select id="c-days" style="width:auto"><option value="7">7 days</option><option value="30" selected>30 days</option><option value="90">90 days</option></select></div>'+
'<label class="row small" style="margin-top:14px"><input type="checkbox" id="c-consent"> I authorize this agent to act on my account with these permissions until the token expires or I revoke it.</label><div class="err" style="margin-top:10px"></div>'+
'<div class="row" style="margin-top:14px"><button class="btn primary" id="c-go">Authorize &amp; create token</button><button class="btn" id="c-cancel">Cancel</button></div>';syncLimits(c,"c");c.onchange=()=>syncLimits(c,"c");
$("#c-cancel").onclick=()=>{c.style.display="none";};$("#c-go").onclick=async()=>{const f=readForm(c,"c");try{const r=await api("/connect",{method:"POST",body:{name:$("#c-name").value.trim(),agent_id:$("#c-id").value.trim(),kind:"custom",scopes:f.scopes,limits:f.limits,expires_in_days:Number($("#c-days").value),consent:$("#c-consent").checked||undefined}});showToken(r,$("#c-name").value.trim());refresh();}catch(err){showErr(c.querySelector(".err"),err.message);}};};
function refresh(){loadGrants().catch(()=>{});loadLog().catch(()=>{});}refresh();setInterval(()=>loadLog().catch(()=>{}),5000);`,
  });
}
