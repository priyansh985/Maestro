"""Remote Operator Dashboard (Sec 3.1 Interactive Dashboard).

Events streamed over WebSocket from the backend (``server.py``). This
template is rendered by FastAPI at ``/`` and receives a JSON stream of
:obj:`Snapshot`. Real-time updates use Sec 6.2 baseline interval (~7s).
"""
from __future__ import annotations

DASHBOARD_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>MAESTRO Network Monitoring Agent - Repro of arXiv:2508.10043</title>
<style>
 body { font-family: -apple-system, sans-serif; margin: 0; }
 header { background: #111; color: #eee; padding: 12px 20px; }
 main { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; padding: 12px; }
 .card { border: 1px solid #ddd; border-radius: 6px; padding: 10px; }
 pre { background: #f8f8f8; padding: 8px; overflow: auto; }
 .delta { color: #c00; font-weight: bold; }
 #telemetry, #alerts, #plan { font-family: monospace; min-height: 80px; }
</style>
</head>
<body>
<header>
 <b>MAESTRO</b> Network Monitoring Agent — reproduction of
 arXiv:2508.10043 (Sec 3.1 dashboard, Sec 6.2 telemetry interval)
</header>
<main>
 <div class="card"><b>Telemetry (Sec 3.1 Performance Analysis)</b>
  <pre id="telemetry">_connecting_</pre></div>
 <div class="card"><b>Alerts (Sec 3.1 Security Detection)</b>
  <pre id="alerts">_connecting_</pre></div>
 <div class="card"><b>Plan (Sec 3.1 LLM Reasoning -> L3 Planner)</b>
  <pre id="plan">_connecting_</pre></div>
 <div class="card"><b>MAESTRO Risk Matrix (Sec 4.3.2 Table 4)</b>
  <pre id="risk">_waiting_</pre></div>
</main>
<script>
const ws = new WebSocket(((location.protocol === 'https:') ? 'wss://' : 'ws://') +
                        location.host + '{{ ws_path }}');
ws.onmessage = (ev) => {
  const m = JSON.parse(ev.data);
  if (m.kind === 'telemetry') document.getElementById('telemetry').textContent = JSON.stringify(m, null, 2);
  if (m.kind === 'alert')     document.getElementById('alerts').textContent = JSON.stringify(m, null, 2);
  if (m.kind === 'plan')      document.getElementById('plan').textContent = JSON.stringify(m, null, 2);
  if (m.kind === 'risk')      document.getElementById('risk').textContent = JSON.stringify(m, null, 2);
};
ws.onopen = () => { document.getElementById('telemetry').textContent = 'connected'; };
ws.onclose = () => { document.getElementById('telemetry').textContent = 'disconnected'; };
</script>
</body>
</html>
"""
