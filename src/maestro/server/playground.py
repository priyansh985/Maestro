"""Self-contained model-testing dashboard served at ``/playground``.

Single-file HTML + CSS + vanilla JS (no build step, no external assets) so it
works offline and matches the repo's existing FastAPI-served dashboard. It
drives the ``/api`` router in :mod:`maestro.server.connectors_api`.
"""
from __future__ import annotations

PLAYGROUND_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Maestro Model Connector Playground</title>
<style>
 :root {
   --bg:#f7f7f8; --panel:#ffffff; --border:#e2e2e6; --text:#1a1a1f;
   --muted:#6b6b76; --accent:#3b5bdb; --ok:#2b8a3e; --err:#c92a2a;
   --chip:#eef0f6;
 }
 @media (prefers-color-scheme: dark) {
   :root { --bg:#16161a; --panel:#1e1e24; --border:#2e2e37; --text:#ececf1;
     --muted:#9a9aa7; --accent:#748ffc; --ok:#51cf66; --err:#ff6b6b; --chip:#2a2a33; }
 }
 :root[data-theme="light"] { --bg:#f7f7f8; --panel:#fff; --border:#e2e2e6; --text:#1a1a1f;
   --muted:#6b6b76; --accent:#3b5bdb; --ok:#2b8a3e; --err:#c92a2a; --chip:#eef0f6; }
 :root[data-theme="dark"] { --bg:#16161a; --panel:#1e1e24; --border:#2e2e37; --text:#ececf1;
   --muted:#9a9aa7; --accent:#748ffc; --ok:#51cf66; --err:#ff6b6b; --chip:#2a2a33; }
 * { box-sizing:border-box; }
 body { margin:0; font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
   background:var(--bg); color:var(--text); font-size:14px; line-height:1.45; }
 header { display:flex; align-items:center; gap:12px; padding:12px 20px;
   background:var(--panel); border-bottom:1px solid var(--border); position:sticky; top:0; z-index:5; }
 header h1 { font-size:16px; margin:0; font-weight:650; }
 header .sub { color:var(--muted); font-size:12px; }
 header .spacer { flex:1; }
 main { display:grid; grid-template-columns:320px 1fr; gap:16px; padding:16px;
   max-width:1500px; margin:0 auto; align-items:start; }
 @media (max-width:900px){ main { grid-template-columns:1fr; } }
 .panel { background:var(--panel); border:1px solid var(--border); border-radius:10px; padding:14px; }
 .panel h2 { font-size:13px; text-transform:uppercase; letter-spacing:.04em; color:var(--muted);
   margin:0 0 10px; }
 label { display:block; font-size:12px; color:var(--muted); margin:8px 0 3px; }
 input,select,textarea,button { font:inherit; color:var(--text); background:var(--bg);
   border:1px solid var(--border); border-radius:7px; padding:7px 9px; width:100%; }
 textarea { resize:vertical; min-height:70px; }
 button { cursor:pointer; background:var(--accent); color:#fff; border:none; font-weight:600; width:auto; }
 button.secondary { background:var(--chip); color:var(--text); }
 button.small { padding:4px 8px; font-size:12px; }
 button:disabled { opacity:.5; cursor:not-allowed; }
 .row { display:flex; gap:8px; align-items:center; flex-wrap:wrap; }
 .row > * { width:auto; }
 .grid3 { display:grid; grid-template-columns:1fr 1fr 1fr; gap:8px; }
 .conn { display:flex; align-items:center; gap:8px; padding:7px 0; border-top:1px solid var(--border); }
 .conn:first-of-type { border-top:none; }
 .conn .meta { flex:1; min-width:0; }
 .conn .name { font-weight:600; }
 .conn .prov { color:var(--muted); font-size:12px; }
 .dot { width:9px; height:9px; border-radius:50%; flex:none; }
 .dot.on { background:var(--ok); } .dot.off { background:var(--muted); opacity:.5; }
 .chip { display:inline-block; background:var(--chip); border-radius:20px; padding:1px 8px;
   font-size:11px; color:var(--muted); }
 .results { display:grid; grid-template-columns:repeat(auto-fit,minmax(300px,1fr)); gap:12px; }
 .card { background:var(--panel); border:1px solid var(--border); border-radius:10px; padding:12px; }
 .card.err { border-color:var(--err); }
 .card .head { display:flex; align-items:center; gap:8px; margin-bottom:8px; }
 .card .text { white-space:pre-wrap; background:var(--bg); border-radius:7px; padding:10px;
   font-size:13px; max-height:280px; overflow:auto; }
 .metrics { display:flex; gap:14px; margin-top:9px; flex-wrap:wrap; }
 .metric { }
 .metric .v { font-weight:700; font-size:15px; } .metric .k { color:var(--muted); font-size:11px; }
 table { width:100%; border-collapse:collapse; font-size:12.5px; }
 th,td { text-align:left; padding:6px 8px; border-bottom:1px solid var(--border); vertical-align:top; }
 th { color:var(--muted); font-weight:600; }
 .muted { color:var(--muted); }
 .ok { color:var(--ok); } .bad { color:var(--err); }
 .full { width:100%; }
 details summary { cursor:pointer; color:var(--muted); font-size:12px; }
</style>
</head>
<body>
<header>
  <h1>Maestro <span class="muted">·</span> Model Connector Playground</h1>
  <span class="sub">test &amp; compare LLM backends</span>
  <span class="spacer"></span>
  <button class="secondary small" id="token">🔑 token</button>
  <button class="secondary small" id="theme">◐ theme</button>
</header>
<main>
  <!-- LEFT: connectors -->
  <section>
    <div class="panel">
      <h2>Connectors</h2>
      <div id="connectors"></div>
    </div>
    <div class="panel" style="margin-top:16px">
      <h2>Register provider</h2>
      <div class="row"><input id="r_name" placeholder="name" style="flex:1">
        <select id="r_provider" style="flex:1">
          <option>custom</option><option>openai</option><option>anthropic</option>
          <option>ollama</option><option>stub</option>
        </select></div>
      <label>model</label><input id="r_model" placeholder="e.g. gpt-4o-mini" class="full">
      <label>base url (optional)</label><input id="r_base" placeholder="https://api.example.com/v1" class="full">
      <label>api key (optional)</label><input id="r_key" type="password" class="full">
      <label>auth header (custom)</label><input id="r_auth" placeholder="authorization or x-api-key" class="full">
      <div style="margin-top:10px"><button id="r_add">Add connector</button></div>
    </div>
  </section>

  <!-- RIGHT: run + results -->
  <section>
    <div class="panel">
      <h2>Prompt</h2>
      <label>system (optional)</label>
      <textarea id="system" placeholder="System prompt / agent role…"></textarea>
      <label>prompt</label>
      <textarea id="prompt" placeholder="Ask the model something…">Say hello in one short sentence.</textarea>
      <div class="grid3" style="margin-top:8px">
        <div><label>temperature <span id="t_val" class="chip">0.7</span></label>
          <input id="temperature" type="range" min="0" max="2" step="0.05" value="0.7"></div>
        <div><label>max tokens</label><input id="max_tokens" type="number" value="256" min="1" max="8192"></div>
        <div><label>top_p (optional)</label><input id="top_p" type="number" step="0.05" min="0" max="1" placeholder="—"></div>
      </div>
      <label>connector</label>
      <select id="connector"></select>
      <div class="row" style="margin-top:10px">
        <label class="row" style="margin:0"><input type="checkbox" id="fallback" style="width:auto"> &nbsp;fallback</label>
        <label class="row" style="margin:0"><input type="checkbox" id="compare" style="width:auto"> &nbsp;compare all enabled</label>
        <span class="spacer" style="flex:1"></span>
        <button id="run">▶ Run</button>
        <button class="secondary" id="save">＋ Save test case</button>
      </div>
    </div>

    <div class="panel" style="margin-top:16px">
      <h2>Results</h2>
      <div class="results" id="results"><span class="muted">Run a prompt to see responses.</span></div>
    </div>

    <div class="panel" style="margin-top:16px">
      <h2>Test cases</h2>
      <div id="testcases"><span class="muted">No saved test cases.</span></div>
    </div>

    <div class="panel" style="margin-top:16px">
      <div class="row"><h2 style="margin:0;flex:1">Logs</h2>
        <button class="secondary small" id="reload_logs">refresh</button>
        <button class="secondary small" id="clear_logs">clear</button></div>
      <div style="overflow:auto;margin-top:8px"><table id="logs"></table></div>
    </div>
  </section>
</main>
<script>
const $ = (id) => document.getElementById(id);
const api = async (path, opts) => {
  const headers = {'content-type':'application/json'};
  const tok = localStorage.getItem('maestro_token');
  if (tok) headers['authorization'] = 'Bearer ' + tok;
  const r = await fetch(path, {headers, ...opts});
  if (!r.ok) { let d; try { d = await r.json(); } catch(e){ d = {detail:r.statusText}; }
    throw new Error(d.detail || ('HTTP '+r.status)); }
  return r.json();
};
$('token').onclick = () => {
  const cur = localStorage.getItem('maestro_token') || '';
  const v = prompt('API token (blank to clear; needed only when the server sets MAESTRO_API_TOKEN):', cur);
  if (v === null) return;
  if (v) localStorage.setItem('maestro_token', v); else localStorage.removeItem('maestro_token');
  loadConnectors(); loadLogs();
};
const esc = (s) => (s??'').toString().replace(/[&<>]/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));

// theme toggle
$('theme').onclick = () => {
  const cur = document.documentElement.getAttribute('data-theme');
  const next = cur === 'dark' ? 'light' : (cur === 'light' ? 'dark' : 'dark');
  document.documentElement.setAttribute('data-theme', next);
};
$('temperature').oninput = e => $('t_val').textContent = e.target.value;

let connectors = [];
async function loadConnectors() {
  const d = await api('/api/connectors');
  connectors = d.connectors;
  const box = $('connectors'); box.innerHTML = '';
  const sel = $('connector'); sel.innerHTML = '';
  connectors.forEach(c => {
    const el = document.createElement('div'); el.className = 'conn';
    el.innerHTML = `<span class="dot ${c.enabled?'on':'off'}"></span>
      <div class="meta"><div class="name">${esc(c.name)} ${c.default?'<span class="chip">default</span>':''}</div>
      <div class="prov">${esc(c.provider)} · ${esc(c.model)}</div></div>`;
    const acts = document.createElement('div'); acts.className='row';
    const mk = (t,fn,cls='secondary') => { const b=document.createElement('button');
      b.className='small '+cls; b.textContent=t; b.onclick=fn; return b; };
    acts.appendChild(mk(c.enabled?'disable':'enable', async()=>{
      await api(`/api/connectors/${c.name}/${c.enabled?'disable':'enable'}`,{method:'POST'}); loadConnectors();}));
    acts.appendChild(mk('health', async()=>{ try{ const h=await api(`/api/connectors/${c.name}/health`,{method:'POST'});
      alert(`${c.name}: ${h.ok?'healthy ✓':'unhealthy ✗'}`);}catch(e){alert(e.message);} }));
    if (!c.default) acts.appendChild(mk('default', async()=>{
      await api(`/api/connectors/${c.name}/default`,{method:'POST'}); loadConnectors();}));
    acts.appendChild(mk('✕', async()=>{ if(confirm(`Remove ${c.name}?`)){
      await api(`/api/connectors/${c.name}`,{method:'DELETE'}); loadConnectors(); }}));
    el.appendChild(acts); box.appendChild(el);
    const o = document.createElement('option'); o.value=c.name;
    o.textContent = c.name + (c.enabled?'':' (disabled)'); if(c.default) o.selected=true;
    sel.appendChild(o);
  });
}

$('r_add').onclick = async () => {
  const body = { name:$('r_name').value.trim(), provider:$('r_provider').value,
    model:$('r_model').value.trim(), base_url:$('r_base').value.trim()||null,
    api_key:$('r_key').value||null, auth_header:$('r_auth').value.trim()||null };
  if (!body.name || !body.model) { alert('name and model are required'); return; }
  try { await api('/api/connectors',{method:'POST',body:JSON.stringify(body)});
    ['r_name','r_model','r_base','r_key','r_auth'].forEach(i=>$(i).value=''); loadConnectors();
  } catch(e){ alert(e.message); }
};

function paramsBody() {
  const tp = $('top_p').value; const b = {
    temperature: parseFloat($('temperature').value),
    max_tokens: parseInt($('max_tokens').value)||256 };
  if (tp!=='') b.top_p = parseFloat(tp);
  return b;
}
function requestBody() {
  const b = { prompt:$('prompt').value, system:$('system').value||null, params:paramsBody() };
  if ($('compare').checked) b.compare = connectors.filter(c=>c.enabled).map(c=>c.name);
  else { b.connector = $('connector').value; if ($('fallback').checked) b.fallback = true; }
  return b;
}

function renderResults(results) {
  const box = $('results'); box.innerHTML = '';
  if (!results.length) { box.innerHTML='<span class="muted">No results.</span>'; return; }
  results.forEach(r => {
    const card = document.createElement('div'); card.className = 'card'+(r.ok?'':' err');
    if (r.ok) {
      const resp = r.response;
      card.innerHTML = `<div class="head"><b>${esc(r.connector)}</b>
        <span class="chip">${esc(resp.provider)} · ${esc(resp.model)}</span>
        ${r.via_fallback?'<span class="chip">fallback</span>':''}</div>
        <div class="text">${esc(resp.text)}</div>
        <div class="metrics">
          <div class="metric"><div class="v">${resp.latency_ms} ms</div><div class="k">latency</div></div>
          <div class="metric"><div class="v">${resp.usage.total_tokens}</div><div class="k">tokens${resp.usage.estimated?' (est)':''}</div></div>
          <div class="metric"><div class="v">${resp.usage.prompt_tokens}/${resp.usage.completion_tokens}</div><div class="k">in/out</div></div>
        </div>`;
      if (r.log_id) { const v=document.createElement('label'); v.className='row'; v.style.marginTop='8px';
        v.innerHTML=`<input type="checkbox" style="width:auto"> verified`;
        v.querySelector('input').onchange = e =>
          api(`/api/logs/${r.log_id}/verify`,{method:'POST',body:JSON.stringify({verified:e.target.checked})}).then(loadLogs);
        card.appendChild(v); }
    } else {
      card.innerHTML = `<div class="head"><b>${esc(r.connector)}</b>
        <span class="chip bad">${esc(r.error.type)}</span></div>
        <div class="text bad">${esc(r.error.message)}</div>`;
    }
    box.appendChild(card);
  });
}

$('run').onclick = async () => {
  $('run').disabled = true; $('results').innerHTML='<span class="muted">Running…</span>';
  try { const d = await api('/api/chat',{method:'POST',body:JSON.stringify(requestBody())});
    renderResults(d.results); loadLogs();
  } catch(e){ $('results').innerHTML = `<span class="bad">${esc(e.message)}</span>`; }
  finally { $('run').disabled = false; }
};

$('save').onclick = async () => {
  const name = prompt('Test case name:'); if(!name) return;
  const body = { name, prompt:$('prompt').value, system:$('system').value||null,
    connector:$('compare').checked?null:$('connector').value, params:paramsBody() };
  await api('/api/testcases',{method:'POST',body:JSON.stringify(body)}); loadTestcases();
};

async function loadTestcases() {
  const d = await api('/api/testcases'); const box = $('testcases');
  if (!d.testcases.length){ box.innerHTML='<span class="muted">No saved test cases.</span>'; return; }
  box.innerHTML=''; d.testcases.forEach(tc => {
    const el=document.createElement('div'); el.className='conn';
    el.innerHTML=`<div class="meta"><div class="name">${esc(tc.name)}</div>
      <div class="prov">${esc((tc.connector||'default'))} · ${esc(tc.prompt.slice(0,60))}</div></div>`;
    const acts=document.createElement('div'); acts.className='row';
    const replay=document.createElement('button'); replay.className='small'; replay.textContent='▶ replay';
    replay.onclick=async()=>{ const r=await api(`/api/testcases/${tc.id}/replay`,{method:'POST'});
      renderResults(r.results); loadLogs(); };
    const del=document.createElement('button'); del.className='small secondary'; del.textContent='✕';
    del.onclick=async()=>{ await api(`/api/testcases/${tc.id}`,{method:'DELETE'}); loadTestcases(); };
    acts.appendChild(replay); acts.appendChild(del); el.appendChild(acts); box.appendChild(el);
  });
}

async function loadLogs() {
  const d = await api('/api/logs?limit=50'); const t=$('logs');
  t.innerHTML='<tr><th>#</th><th>connector</th><th>prompt</th><th>latency</th><th>tokens</th><th>status</th><th>✓</th></tr>';
  d.logs.forEach(l=>{
    const tr=document.createElement('tr');
    const lat=l.ok?l.response.latency_ms+' ms':'—';
    const tok=l.ok?l.response.usage.total_tokens:'—';
    const status=l.ok?'<span class="ok">ok</span>':`<span class="bad">${esc(l.error?.type||'error')}</span>`;
    tr.innerHTML=`<td>${l.id}</td><td>${esc(l.connector)}</td>
      <td title="${esc(l.prompt)}">${esc((l.prompt||'').slice(0,40))}</td>
      <td>${lat}</td><td>${tok}</td><td>${status}</td>
      <td><input type="checkbox" ${l.verified?'checked':''} style="width:auto"></td>`;
    tr.querySelector('input').onchange = e =>
      api(`/api/logs/${l.id}/verify`,{method:'POST',body:JSON.stringify({verified:e.target.checked})});
    t.appendChild(tr);
  });
}
$('reload_logs').onclick = loadLogs;
$('clear_logs').onclick = async()=>{ await api('/api/logs',{method:'DELETE'}); loadLogs(); };

loadConnectors(); loadTestcases(); loadLogs();
</script>
</body>
</html>
"""
