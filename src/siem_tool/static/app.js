/* ╔══════════════════════════════════════════════════════════╗
   ║  SIEM Dashboard – app.js                                ║
   ╚══════════════════════════════════════════════════════════╝ */
(function () {
  'use strict';

  /* ═══════════════════════ State ═══════════════════════════ */
  const S = {
    devices: [], bluetooth: [], alerts: [], connections: [], packets: [], events: [],
    agents: [], agentEvents: [],
    packetFlows: [], packetConversations: [],
    incidents: [],
    firewallBlocks: [],
    networkHealth: null,
    aiMessages: [],
    aiContext: null,   // { type: 'alert'|'event'|'device', items: [...] }
    settings: {},
    selectedPacketKey: '',
    selectedPacket: null,
    packetsPaused: false,
    systemStatus: null,
    hostRisk: [],
    attackChains: [],
    savedViews: [],
    incidentTicketTab: 'open',
  };

  /* ═══════════════════════ Utilities ════════════════════════ */
  function fmt_bytes(bps) {
    bps = bps || 0;
    if (bps >= 1e6)  return (bps / 1e6).toFixed(2) + ' MB/s';
    if (bps >= 1e3)  return (bps / 1e3).toFixed(1) + ' KB/s';
    return bps.toFixed(0) + ' B/s';
  }

  function fmt_dt(iso) {
    if (!iso) return '—';
    const d = new Date(iso);
    return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' }) + ' ' +
           d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  }

  function fmt_uptime(seconds) {
    const s = Math.max(0, parseInt(seconds || 0, 10));
    const h = Math.floor(s / 3600);
    const m = Math.floor((s % 3600) / 60);
    const sec = s % 60;
    return `${h}h ${m}m ${sec}s`;
  }

  function esc(val) {
    const d = document.createElement('div');
    d.textContent = String(val ?? '');
    return d.innerHTML;
  }

  function isNoisyBluetoothRow(row) {
    const n = String(row?.name || '').toLowerCase();
    const noisy = [
      'generic attribute profile',
      'generic access profile',
      'bluetooth le generic attribute service',
      'microsoft bluetooth enumerator',
      'microsoft bluetooth le enumerator',
      'service discovery service',
      'wireless bluetooth',
      'avrcp transport',
      'rfcomm',
    ];
    return noisy.some(token => n.includes(token));
  }

  function sev_pill(sev) {
    const s = (sev || '').toLowerCase();
    return `<span class="pill pill-${esc(s)}">${esc(sev)}</span>`;
  }

  function toast(msg, type = 'info') {
    const el = document.createElement('div');
    el.className = `toast ${type}`;
    el.textContent = msg;
    document.getElementById('toast-container').appendChild(el);
    setTimeout(() => { el.style.opacity = '0'; setTimeout(() => el.remove(), 300); }, 3200);
  }

  async function apiFetch(method, path, body) {
    const opts = { method, headers: { 'Content-Type': 'application/json' } };
    if (body !== undefined) opts.body = JSON.stringify(body);
    const res = await fetch(path, opts);
    if (!res.ok) {
      let detail = `${res.status} ${res.statusText}`;
      try {
        const json = await res.json();
        detail = json.detail || json.message || detail;
      } catch (_) {}
      throw new Error(detail);
    }
    return res.json();
  }

  /* ═══════════════════════ Navigation ══════════════════════ */
  function initNav() {
    document.querySelectorAll('[data-view]').forEach(el => {
      el.addEventListener('click', e => { e.preventDefault(); switchView(el.dataset.view); });
    });
  }

  function switchView(name) {
    document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
    document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
    const v = document.getElementById(`view-${name}`);
    const n = document.querySelector(`.nav-link[data-view="${name}"]`);
    if (v) v.classList.add('active');
    if (n) n.classList.add('active');
    const TITLES = {
      overview: 'Overview', devices: 'Network Devices', agents: 'Endpoint Agents', bluetooth: 'Bluetooth Devices', alerts: 'Alerts',
      incidents: 'Correlated Incidents',
      risk: 'Host Risk',
      chains: 'Attack Chains',
      health: 'Network Health',
      firewall: 'Firewall Blocks',
      traffic: 'Active Connections', packets: 'Packet Stream', setup: 'Setup Wizard', settings: 'Settings & Logs', ai: 'AI Analyzer',
    };
    document.getElementById('page-title').textContent = TITLES[name] ?? name;
    if (name === 'devices')  fetchDevices();
    if (name === 'agents') { fetchAgents(); fetchAgentEvents(); }
    if (name === 'bluetooth') fetchBluetooth();
    if (name === 'alerts')   fetchAlerts();
    if (name === 'incidents') fetchIncidents();
    if (name === 'risk') fetchHostRisk();
    if (name === 'chains') fetchAttackChains();
    if (name === 'health')   fetchNetworkHealth();
    if (name === 'firewall') fetchFirewallBlocks();
    if (name === 'traffic')  fetchConnections();
    if (name === 'packets')  fetchPackets();
    if (name === 'setup') fetchSetupWizard();
    if (name === 'settings') fetchSettings();
    if (name === 'incidents') fetchSavedViews();
  }

  async function fetchSetupWizard() {
    try {
      const [w, d] = await Promise.all([
        apiFetch('GET', '/api/setup/wizard'),
        apiFetch('GET', '/api/startup/diagnostics'),
      ]);
      renderSetupWizard(w, d);
    } catch (e) {
      const status = document.getElementById('setup-ready-status');
      if (status) status.textContent = 'Setup checks unavailable: ' + e.message;
    }
  }

  function renderSetupWizard(wizard, diag) {
    const status = document.getElementById('setup-ready-status');
    const steps = document.getElementById('setup-steps-feed');
    const blockers = document.getElementById('setup-blockers-feed');
    const suggestions = document.getElementById('setup-suggestions-feed');
    if (!status || !steps || !blockers || !suggestions) return;
    status.textContent = wizard.ready ? 'Ready for monitoring' : 'Setup requires attention';
    steps.innerHTML = (wizard.steps || []).map((s) => `
      <li class="feed-item">
        <span class="feed-sev ${s.ok ? 'sev-low' : 'sev-high'}">${s.ok ? 'OK' : 'FIX'}</span>
        <div class="feed-body"><div class="feed-msg">${esc(s.title || s.id || 'step')}</div></div>
      </li>`).join('') || '<li class="feed-empty">No setup steps</li>';
    blockers.innerHTML = (diag.blockers || []).map((b) => `
      <li class="feed-item"><span class="feed-sev sev-high">BLOCKER</span><div class="feed-body"><div class="feed-msg">${esc(b)}</div></div></li>
    `).join('') || '<li class="feed-empty">No blockers</li>';
    suggestions.innerHTML = (diag.suggestions || []).map((s) => `
      <li class="feed-item"><span class="feed-sev sev-medium">FIX</span><div class="feed-body"><div class="feed-msg">${esc(s)}</div></div></li>
    `).join('') || '<li class="feed-empty">No suggestions</li>';
  }

  /* ═══════════════════════ Stats + Bandwidth ════════════════ */
  async function fetchStats() {
    try {
      const s = await apiFetch('GET', '/api/stats');
      document.getElementById('stat-devices').textContent = s.device_count;
      const agentStat = document.getElementById('stat-agents');
      if (agentStat) agentStat.textContent = `${s.agent_count_online || 0}/${s.agent_count || 0}`;
      document.getElementById('stat-high').textContent    = s.alert_count_high;
      document.getElementById('stat-med').textContent     = s.alert_count_medium;
      const bw = (s.network_bandwidth_bps ?? s.recent_bandwidth_bps ?? 0);
      document.getElementById('stat-bw').textContent      = fmt_bytes(bw);
      const capturedEl = document.getElementById('stat-bw-captured');
      if (capturedEl) capturedEl.textContent = fmt_bytes(s.captured_bandwidth_bps || 0);
      const ppsEl = document.getElementById('stat-pps');
      if (ppsEl) ppsEl.textContent = `${(s.captured_packet_rate_pps || 0).toFixed(1)} pps`;
      const bwLabel = document.getElementById('stat-bw-label');
      if (bwLabel) {
        bwLabel.textContent = s.capture_mode === 'pcap'
          ? 'Network Throughput (Captured)'
          : 'Host Throughput';
      }
      document.getElementById('last-updated').textContent = 'Updated ' + new Date().toLocaleTimeString();
    } catch (_) {}
  }

  async function fetchSystemStatus() {
    try {
      S.systemStatus = await apiFetch('GET', '/api/system/status');
      renderSystemStatus();
    } catch (_) {}
  }

  async function fetchNetworkHealth() {
    try {
      S.networkHealth = await apiFetch('GET', '/api/network/health');
      renderNetworkHealth();
      renderHealthTab();
    } catch (e) {
      S.networkHealth = {
        status: 'unknown',
        reason: 'Network health API unavailable: ' + (e?.message || 'request failed'),
      };
      renderNetworkHealth();
      renderHealthTab();
    }
  }

  function renderSystemStatus() {
    const feed = document.getElementById('overview-system-feed');
    if (!feed) return;
    const s = S.systemStatus;
    if (!s) {
      feed.innerHTML = '<li class="feed-empty">No status available</li>';
      return;
    }

    const rows = [
      { label: `Mode: ${s.capture_mode || 'host'}`, ok: true },
      { label: `Interface: ${s.capture_interface || 'auto'}`, ok: true },
      { label: `Filter: ${s.capture_filter || 'ip or ip6'}`, ok: true },
      { label: `Packet buffer: ${s.packet_buffer_size || 0}`, ok: true },
      { label: `Packet rate: ${(s.recent_packet_rate_pps || 0).toFixed(1)} pps`, ok: true },
      { label: `Status: ${s.status || 'unknown'}`, ok: true },
    ];

    const checks = s.sensor_checks || {};
    const checkRows = [
      { key: 'capture_mode_ok', name: 'Capture mode' },
      { key: 'pcap_dependency_ok', name: 'Scapy dependency' },
      { key: 'pcap_runtime_ok', name: 'Npcap runtime' },
      { key: 'packet_flow_ok', name: 'Packet flow' },
      { key: 'network_health_probe_ok', name: 'Health probes' },
      { key: 'firewall_log_ok', name: 'Firewall logging' },
    ].map(c => {
      const item = checks[c.key];
      if (!item) return null;
      return {
        label: `${c.name}: ${item.detail || 'unknown'}`,
        ok: !!item.ok,
      };
    }).filter(Boolean);

    const allRows = rows.concat(checkRows);
    feed.innerHTML = allRows.map(r => `
      <li class="feed-item">
        <span class="feed-sev ${r.ok ? 'sev-low' : 'sev-high'}">${r.ok ? 'OK' : 'FAIL'}</span>
        <div class="feed-body"><div class="feed-msg">${esc(r.label)}</div></div>
      </li>`).join('');

    renderFirewallLoggingStatus(s.firewall_logging);
  }

  function renderNetworkHealth() {
    const h = S.networkHealth;
    const stat = document.getElementById('stat-health');
    const card = document.getElementById('stat-card-health');
    const feed = document.getElementById('overview-health-feed');
    if (!stat || !card || !feed) return;

    if (!h || h.status === 'unknown') {
      stat.textContent = '—';
      card.classList.remove('info', 'warn', 'danger');
      const msg = (h && h.reason && h.reason !== 'collecting probes')
        ? h.reason
        : 'Collecting probe data...';
      feed.innerHTML = `<li class="feed-empty">${esc(msg)}</li>`;
      return;
    }

    const status = String(h.status || 'unknown').toLowerCase();
    const score = Number(h.score || 0);
    const metrics = h.metrics || {};
    const loss = Number(metrics.loss_pct || 0).toFixed(1);
    const rtt = Number(metrics.avg_rtt_ms || 0).toFixed(1);
    const jitter = Number(metrics.jitter_ms || 0).toFixed(1);
    const routerProbe = h.router_probe || {};
    const routerLabel = routerProbe.target || 'router';
    const routerState = routerProbe.last_ok === false ? 'DOWN' : (routerProbe.last_ok === true ? 'UP' : 'UNKNOWN');
    const routerRtt = routerProbe.last_rtt_ms == null ? '—' : `${Number(routerProbe.last_rtt_ms).toFixed(1)} ms`;
    const deviceProbes = h.device_probes || {};
    const devTotal = Number(deviceProbes.total || 0);
    const devUp = Number(deviceProbes.up || 0);
    const devDown = Number(deviceProbes.down || 0);
    const devRows = Array.isArray(deviceProbes.rows) ? deviceProbes.rows : [];

    stat.textContent = `${score.toFixed(0)} (${status.toUpperCase()})`;
    card.classList.remove('info', 'warn', 'danger');
    if (status === 'good') card.classList.add('info');
    else if (status === 'degraded') card.classList.add('warn');
    else if (status === 'critical') card.classList.add('danger');

    const lines = [
      `Router ${routerLabel}: ${routerState} (${routerRtt})`,
      `Health metrics (router only): Loss ${loss}% | Avg RTT ${rtt} ms | Jitter ${jitter} ms`,
      `Device baseline: ${devUp}/${devTotal} up, ${devDown} down`,
      ...devRows.slice(0, 20).map(t => {
        const ok = t.last_ok === true;
        const lbl = ok ? 'UP' : 'DOWN';
        const rt = t.last_rtt_ms == null ? '—' : `${Number(t.last_rtt_ms).toFixed(1)} ms`;
        const name = t.device_name || t.alias || t.hostname || t.ip || t.target || 'unknown';
        const ip = t.ip || t.target || '—';
        return `${name} (${ip}): ${lbl} (${rt})`;
      }),
    ];
    feed.innerHTML = lines.map((line, idx) => {
      const sevCls = line.includes('DOWN') ? 'sev-high' : 'sev-low';
      return `
      <li class="feed-item">
        <span class="feed-sev ${sevCls}">${line.includes('DOWN') ? 'DOWN' : (idx <= 2 ? 'INFO' : 'UP')}</span>
        <div class="feed-body">
          <div class="feed-msg">${esc(line)}</div>
        </div>
      </li>`;
    }).join('');
  }

  function renderHealthTab() {
    const h = S.networkHealth;
    const summary = document.getElementById('health-summary-feed');
    const tbody = document.getElementById('health-probes-tbody');
    if (!summary || !tbody) return;

    if (!h || h.status === 'unknown') {
      const msg = (h && h.reason) ? h.reason : 'Collecting probe data...';
      summary.innerHTML = `<li class="feed-empty">${esc(msg)}</li>`;
      tbody.innerHTML = '<tr class="empty-row"><td colspan="6">No probe data yet</td></tr>';
      return;
    }

    const metrics = h.metrics || {};
    const routerProbe = h.router_probe || {};
    const deviceProbes = h.device_probes || {};
    const devRows = Array.isArray(deviceProbes.rows) ? deviceProbes.rows : [];
    const status = String(h.status || 'unknown').toUpperCase();
    const score = Number(h.score || 0).toFixed(0);
    const routerState = routerProbe.last_ok === false ? 'DOWN' : (routerProbe.last_ok === true ? 'UP' : 'UNKNOWN');
    const routerRtt = routerProbe.last_rtt_ms == null ? '—' : `${Number(routerProbe.last_rtt_ms).toFixed(1)} ms`;

    const lines = [
      `Health: ${status} (Score ${score})`,
      `Router: ${routerProbe.target || 'router'} is ${routerState} (${routerRtt})`,
      `Router-only metrics: Loss ${Number(metrics.loss_pct || 0).toFixed(1)}% | Avg RTT ${Number(metrics.avg_rtt_ms || 0).toFixed(1)} ms | Jitter ${Number(metrics.jitter_ms || 0).toFixed(1)} ms`,
      `Device availability: ${Number(deviceProbes.up || 0)}/${Number(deviceProbes.total || 0)} up, ${Number(deviceProbes.down || 0)} down`,
    ];
    summary.innerHTML = lines.map((line) => `
      <li class="feed-item">
        <span class="feed-sev ${line.includes('DOWN') ? 'sev-high' : 'sev-low'}">${line.includes('DOWN') ? 'DOWN' : 'INFO'}</span>
        <div class="feed-body"><div class="feed-msg">${esc(line)}</div></div>
      </li>`).join('');

    if (!devRows.length) {
      tbody.innerHTML = '<tr class="empty-row"><td colspan="6">No discovered devices to probe yet</td></tr>';
      return;
    }

    tbody.innerHTML = devRows.map((d) => {
      const up = d.last_ok === true;
      const rtt = d.last_rtt_ms == null ? '—' : `${Number(d.last_rtt_ms).toFixed(1)} ms`;
      const name = d.device_name || d.alias || d.hostname || d.ip || d.target || 'Unknown';
      const ip = d.ip || d.target || '—';
      return `
      <tr>
        <td>${esc(name)}</td>
        <td><code>${esc(d.mac || '—')}</code></td>
        <td><code>${esc(ip)}</code></td>
        <td>${up ? '<span class="pill pill-low">Up</span>' : '<span class="pill pill-high">Down</span>'}</td>
        <td class="text-muted text-sm">${esc(rtt)}</td>
        <td><button class="btn btn-ghost btn-mini" data-health-ping="${esc(ip)}">Ping</button></td>
      </tr>`;
    }).join('');

    tbody.querySelectorAll('[data-health-ping]').forEach((btn) => {
      btn.addEventListener('click', async () => {
        const ip = btn.getAttribute('data-health-ping');
        if (!ip || ip === '—') return;
        const prev = btn.textContent;
        btn.disabled = true;
        btn.textContent = 'Pinging...';
        try {
          const r = await apiFetch('POST', '/api/network/ping', { ip });
          const row = r?.row || {};
          const ok = row.last_ok === true;
          const rttText = row.last_rtt_ms == null ? 'timeout' : `${Number(row.last_rtt_ms).toFixed(1)} ms`;
          toast(`${ip} ${ok ? 'UP' : 'DOWN'} (${rttText})`, ok ? 'ok' : 'err');
          await fetchNetworkHealth();
        } catch (e) {
          toast('Ping failed: ' + e.message, 'err');
        } finally {
          btn.disabled = false;
          btn.textContent = prev;
        }
      });
    });
  }

  function renderFirewallLoggingStatus(fw) {
    const el = document.getElementById('firewall-log-status');
    if (!el) return;
    if (!fw) {
      el.textContent = 'Firewall log status unavailable';
      el.className = 'status-muted';
      return;
    }
    if (fw.enabled && fw.exists && fw.readable) {
      el.textContent = `Logging active (${fw.path})`;
      el.className = 'status-ok';
      return;
    }
    const reason = fw.reason || 'not available';
    el.textContent = `Logging unavailable: ${reason}`;
    if (reason === 'disabled in config' || reason === 'windows-only') {
      el.className = 'status-warn';
      return;
    }
    el.className = 'status-err';
  }

  async function fetchEvents() {
    try {
      S.events = await apiFetch('GET', '/api/events?limit=40');
      renderBwList();
    } catch (_) {}
  }

  function renderBwList() {
    const byNic = {};
    S.events.forEach(e => { byNic[e.interface] = e; });
    const vals = Object.values(byNic).map(e => e.bytes_sent_per_sec + e.bytes_recv_per_sec);
    const maxBps = Math.max(...vals, 1);
    const el = document.getElementById('bw-list');
    el.innerHTML = '';
    Object.entries(byNic).forEach(([nic, e]) => {
      const total = e.bytes_sent_per_sec + e.bytes_recv_per_sec;
      const pct = Math.min((total / maxBps) * 100, 100).toFixed(1);
      const hot = total > 2e6;
      el.innerHTML += `
        <li class="bw-item">
          <div class="bw-nic">${esc(nic)}</div>
          <div class="bw-bar-wrap"><div class="bw-bar${hot ? ' hot' : ''}" style="width:${pct}%"></div></div>
          <div class="bw-nums"><span>↑ ${fmt_bytes(e.bytes_sent_per_sec)}</span><span>↓ ${fmt_bytes(e.bytes_recv_per_sec)}</span></div>
        </li>`;
    });
    if (!el.children.length) el.innerHTML = '<li class="feed-empty">No traffic data yet</li>';
  }

  /* ═══════════════════════ Devices ══════════════════════════ */
  async function fetchDevices() {
    try { S.devices = await apiFetch('GET', '/api/devices'); renderDevices(); } catch (_) {}
  }

  async function fetchAgents() {
    try {
      S.agents = await apiFetch('GET', '/api/agents');
      renderAgents();
    } catch (_) {}
  }

  async function fetchAgentEvents() {
    try {
      S.agentEvents = await apiFetch('GET', '/api/agents/events?limit=500');
      renderAgentEvents();
      renderOverviewAgentsFeed();
    } catch (_) {}
  }

  function formatAgentEventSource(ev) {
    const type = String(ev.event_type || 'event');
    if (type === 'windows_event') {
      return `${ev.channel || 'Windows'} · ${ev.event_id || '—'}`;
    }
    if (type === 'connection_snapshot') {
      return `${ev.local_ip || '—'}:${ev.local_port || 0} → ${ev.remote_ip || '—'}:${ev.remote_port || 0}`;
    }
    if (type === 'host_identity') {
      return `${ev.os || 'host'} · ${((ev.local_ips || []).join(', ')) || 'no IPs'}`;
    }
    return type;
  }

  function formatAgentEventDetails(ev) {
    const type = String(ev.event_type || 'event');
    if (type === 'windows_event') {
      return `${ev.provider || 'provider'} · ${ev.level || 'level'} · ${String(ev.message || '').slice(0, 180) || 'No message'}`;
    }
    if (type === 'connection_snapshot') {
      const pid = ev.pid == null ? '—' : String(ev.pid);
      return `Status ${ev.status || 'unknown'} · PID ${pid}`;
    }
    if (type === 'host_identity') {
      return `FQDN ${ev.fqdn || '—'} · MAC ${(ev.mac_addresses || []).join(', ') || '—'}`;
    }
    return JSON.stringify(ev).slice(0, 180);
  }

  function renderOverviewAgentsFeed() {
    const feed = document.getElementById('overview-agents-feed');
    if (!feed) return;
    const rows = [...S.agentEvents].reverse().slice(0, 10);
    if (!rows.length) {
      feed.innerHTML = '<li class="feed-empty">No agent telemetry yet</li>';
      return;
    }
    feed.innerHTML = rows.map((row) => {
      const ev = row.event || {};
      const sev = String(ev.event_type || '') === 'windows_event' ? 'sev-medium' : 'sev-low';
      return `
      <li class="feed-item">
        <span class="feed-sev ${sev}">${esc(ev.event_type || 'event')}</span>
        <div class="feed-body">
          <div class="feed-msg">${esc(row.hostname || row.agent_id || 'agent')} · ${esc(formatAgentEventSource(ev))}</div>
          <div class="feed-time">${fmt_dt(row.received_at)} · ${esc(formatAgentEventDetails(ev))}</div>
        </div>
      </li>`;
    }).join('');
  }

  function renderAgents() {
    const tbody = document.getElementById('agents-tbody');
    if (!tbody) return;
    const q = String(document.getElementById('agent-search')?.value || '').toLowerCase();
    const statusF = String(document.getElementById('agent-status-filter')?.value || '').toLowerCase();
    const rows = S.agents.filter((a) => {
      const hay = [a.hostname, a.os, a.agent_version, (a.local_ips || []).join(','), a.fqdn].join(' ').toLowerCase();
      return (!statusF || String(a.status || '').toLowerCase() === statusF) && (!q || hay.includes(q));
    });
    if (!rows.length) {
      tbody.innerHTML = '<tr class="empty-row"><td colspan="9">No agents registered</td></tr>';
      return;
    }
    tbody.innerHTML = rows.map((a) => `
      <tr>
        <td>${String(a.status || '') === 'online' ? '<span class="pill pill-low">Online</span>' : '<span class="pill pill-medium">Stale</span>'}</td>
        <td>${esc(a.hostname || '—')}</td>
        <td><code>${esc((a.local_ips || []).join(', ') || '—')}</code></td>
        <td>${esc(a.os || '—')}</td>
        <td>${esc(a.agent_version || '—')}</td>
        <td>${esc(a.queue_depth ?? 0)}</td>
        <td>${esc(a.event_count ?? 0)}</td>
        <td class="text-muted text-sm">${fmt_dt(a.last_upload_at)}</td>
        <td class="text-muted text-sm">${fmt_dt(a.last_seen)}</td>
      </tr>`).join('');
  }

  function renderAgentEvents() {
    const tbody = document.getElementById('agent-events-tbody');
    if (!tbody) return;
    const q = String(document.getElementById('agent-event-search')?.value || '').toLowerCase();
    const typeF = String(document.getElementById('agent-event-type-filter')?.value || '').toLowerCase();
    const rows = [...S.agentEvents].reverse().filter((row) => {
      const ev = row.event || {};
      const eventType = String(ev.event_type || '').toLowerCase();
      const hay = [
        row.hostname,
        row.agent_id,
        ev.channel,
        ev.message,
        ev.local_ip,
        ev.remote_ip,
        ev.os,
        ev.fqdn,
      ].join(' ').toLowerCase();
      return (!typeF || eventType === typeF) && (!q || hay.includes(q));
    }).slice(0, 300);
    if (!rows.length) {
      tbody.innerHTML = '<tr class="empty-row"><td colspan="6">No endpoint telemetry found</td></tr>';
      return;
    }
    tbody.innerHTML = rows.map((row) => {
      const ev = row.event || {};
      return `
      <tr>
        <td class="text-muted text-sm">${fmt_dt(row.received_at)}</td>
        <td><code>${esc(row.hostname || row.agent_id || 'agent')}</code></td>
        <td>${esc(ev.event_type || 'event')}</td>
        <td>${esc(formatAgentEventSource(ev))}</td>
        <td>${esc(formatAgentEventDetails(ev))}</td>
        <td>
          <button class="icon-btn" title="Analyze with AI"
            data-ai-item="${esc(JSON.stringify(row))}" data-ai-type="event">🤖</button>
        </td>
      </tr>`;
    }).join('');
    tbody.querySelectorAll('[data-ai-item]').forEach((btn) => {
      btn.addEventListener('click', () => sendToAI([JSON.parse(btn.dataset.aiItem)], btn.dataset.aiType));
    });
  }

  async function fetchBluetooth() {
    try {
      S.bluetooth = await apiFetch('GET', '/api/bluetooth?limit=200');
      renderBluetooth();
      renderOverviewBluetoothFeed();
      const since = Date.now() - (24 * 60 * 60 * 1000);
      const recentCount = S.bluetooth.filter(b => {
        const t = Date.parse(b.timestamp || '');
        return Number.isFinite(t) && t >= since;
      }).length;
      const statEl = document.getElementById('stat-bt');
      if (statEl) statEl.textContent = String(recentCount);
    } catch (_) {}
  }

  function renderOverviewBluetoothFeed() {
    const feed = document.getElementById('overview-bt-feed');
    if (!feed) return;
    const rows = [...S.bluetooth]
      .filter(b => !isNoisyBluetoothRow(b))
      .reverse()
      .slice(0, 10);
    if (!rows.length) {
      feed.innerHTML = '<li class="feed-empty">No Bluetooth events yet</li>';
      return;
    }
    feed.innerHTML = rows.map(b => `
      <li class="feed-item">
        <span class="feed-sev ${b.connected ? 'sev-low' : 'sev-medium'}">${b.connected ? 'CONNECTED' : 'DISCONNECTED'}</span>
        <div class="feed-body">
          <div class="feed-msg">${esc(b.name || 'Bluetooth device')} ${b.connected ? 'connected' : 'disconnected'}</div>
          <div class="feed-time">${fmt_dt(b.timestamp)} · ${esc(b.address || b.kind || 'bluetooth')}</div>
        </div>
      </li>`).join('');
  }

  function renderBluetooth() {
    const tbody = document.getElementById('bluetooth-tbody');
    if (!tbody) return;
    const rows = [...S.bluetooth]
      .filter(b => !isNoisyBluetoothRow(b))
      .reverse()
      .slice(0, 200);
    if (!rows.length) {
      tbody.innerHTML = '<tr class="empty-row"><td colspan="7">No bluetooth events yet</td></tr>';
      return;
    }
    tbody.innerHTML = rows.map(b => `
      <tr>
        <td class="text-muted text-sm">${fmt_dt(b.timestamp)}</td>
        <td>${esc(b.name || 'Bluetooth device')}</td>
        <td><code>${esc(b.address || '—')}</code></td>
        <td>${b.connected ? '<span class="pill pill-low">Connected</span>' : '<span class="pill pill-medium">Disconnected</span>'}</td>
        <td class="text-muted text-sm">${esc(b.kind || 'bluetooth')}</td>
        <td class="text-muted text-sm">${esc(b.source || '')}</td>
        <td>
          <button class="icon-btn" title="Analyze with AI"
            data-ai-item="${esc(JSON.stringify(b))}" data-ai-type="device">🤖</button>
        </td>
      </tr>`).join('');
    tbody.querySelectorAll('[data-ai-item]').forEach(btn => {
      btn.addEventListener('click', () => sendToAI([JSON.parse(btn.dataset.aiItem)], btn.dataset.aiType));
    });
  }

  function renderDevices() {
    const q = (document.getElementById('device-search')?.value ?? '').toLowerCase();
    const tbody = document.getElementById('device-tbody');
    const rows = S.devices.filter(d =>
      !q || d.ip.includes(q) ||
      (d.alias || '').toLowerCase().includes(q) ||
      (d.hostname || '').toLowerCase().includes(q) ||
      (d.mac || '').includes(q)
    );
    if (!rows.length) {
      tbody.innerHTML = '<tr class="empty-row"><td colspan="6">No devices found</td></tr>';
      return;
    }
    tbody.innerHTML = rows.map(d => `
      <tr>
        <td><code>${esc(d.ip)}</code></td>
        <td>
          <div class="alias-cell">
            ${d.alias
              ? `<span class="alias-name">${esc(d.alias)}</span>`
              : `<span class="text-muted">—</span>`}
            <button class="alias-btn" title="Edit name"
              data-ip="${esc(d.ip)}" data-alias="${esc(d.alias || '')}">✎</button>
          </div>
        </td>
        <td><code class="text-muted">${esc(d.mac || '—')}</code></td>
        <td>${esc(d.hostname || '—')}</td>
        <td class="text-muted text-sm">${fmt_dt(d.last_seen)}</td>
        <td>
          <button class="icon-btn" title="Analyze with AI"
            data-ai-item="${esc(JSON.stringify(d))}" data-ai-type="device">🤖</button>
        </td>
      </tr>`).join('');

    tbody.querySelectorAll('.alias-btn[data-ip]').forEach(b =>
      b.addEventListener('click', () => openAliasModal(b.dataset.ip, b.dataset.alias))
    );
    tbody.querySelectorAll('[data-ai-item]').forEach(b =>
      b.addEventListener('click', () =>
        sendToAI([JSON.parse(b.dataset.aiItem)], b.dataset.aiType)
      )
    );
  }

  /* ═══════════════════════ Alerts ═══════════════════════════ */
  async function fetchAlerts() {
    try {
      S.alerts = await apiFetch('GET', '/api/alerts?limit=300');
      renderAlerts();
      renderOverviewFeed();
      fetchIncidents();
    } catch (_) {}
  }

  async function fetchIncidents() {
    try {
      S.incidents = await apiFetch('GET', '/api/incidents?limit=200');
      if (!isIncidentEditorActive()) {
        renderIncidents();
      }
      renderOverviewIncidentsFeed();
    } catch (_) {}
  }

  function isIncidentEditorActive() {
    const active = document.activeElement;
    if (!active) return false;
    const inIncidentsView = !!active.closest('#view-incidents');
    if (!inIncidentsView) return false;
    return active.matches('[data-incident-owner], [data-incident-notes], [data-incident-sla], [data-incident-due], [data-incident-reopen]');
  }

  function setIncidentTicketTab(tab) {
    S.incidentTicketTab = tab === 'closed' ? 'closed' : 'open';
    const openBtn = document.getElementById('incident-tab-open');
    const closedBtn = document.getElementById('incident-tab-closed');
    openBtn?.classList.toggle('active', S.incidentTicketTab === 'open');
    closedBtn?.classList.toggle('active', S.incidentTicketTab === 'closed');

    const statusFilter = document.getElementById('incident-status-filter');
    if (statusFilter) {
      if (S.incidentTicketTab === 'closed') {
        statusFilter.value = 'closed';
      } else if (String(statusFilter.value || '').toLowerCase() === 'closed') {
        statusFilter.value = '';
      }
    }
    renderIncidents();
  }

  async function fetchHostRisk() {
    try {
      S.hostRisk = await apiFetch('GET', '/api/risk/hosts?limit=300');
      renderHostRisk();
    } catch (_) {}
  }

  async function fetchAttackChains() {
    try {
      S.attackChains = await apiFetch('GET', '/api/incidents/chains?window_seconds=3600');
      renderAttackChains();
    } catch (_) {}
  }

  async function fetchSavedViews() {
    try {
      S.savedViews = await apiFetch('GET', '/api/views/saved');
      renderSavedViewOptions();
    } catch (_) {}
  }

  function renderSavedViewOptions() {
    const scopeEl = document.getElementById('saved-view-scope');
    const selectEl = document.getElementById('saved-view-select');
    if (!scopeEl || !selectEl) return;
    const scope = String(scopeEl.value || 'alerts');
    const rows = Array.isArray(S.savedViews) ? S.savedViews : [];
    const scoped = rows.filter((r) => String((r.filters || {}).scope || '') === scope);
    if (!scoped.length) {
      selectEl.innerHTML = '<option value="">No saved views</option>';
      return;
    }
    selectEl.innerHTML = scoped
      .sort((a, b) => String(b.updated_at || '').localeCompare(String(a.updated_at || '')))
      .map((r) => `<option value="${esc(r.name || '')}">${esc(r.name || '')}</option>`)
      .join('');
  }

  function getFilterSnapshot(scope) {
    if (scope === 'alerts') {
      return {
        severity: document.getElementById('alert-severity-filter')?.value || '',
        query: document.getElementById('alert-search')?.value || '',
      };
    }
    if (scope === 'incidents') {
      return {
        status: document.getElementById('incident-status-filter')?.value || '',
        query: document.getElementById('incident-search')?.value || '',
        ticket_tab: S.incidentTicketTab || 'open',
      };
    }
    if (scope === 'traffic') {
      return {
        status: document.getElementById('traffic-status-filter')?.value || '',
        query: document.getElementById('traffic-search')?.value || '',
      };
    }
    return {};
  }

  function applyFilterSnapshot(scope, criteria) {
    const c = criteria || {};
    if (scope === 'alerts') {
      const sev = document.getElementById('alert-severity-filter');
      const q = document.getElementById('alert-search');
      if (sev) sev.value = String(c.severity || '');
      if (q) q.value = String(c.query || '');
      renderAlerts();
      return;
    }
    if (scope === 'incidents') {
      const status = document.getElementById('incident-status-filter');
      const q = document.getElementById('incident-search');
      if (status) status.value = String(c.status || '');
      if (q) q.value = String(c.query || '');
      setIncidentTicketTab(String(c.ticket_tab || 'open').toLowerCase() === 'closed' ? 'closed' : 'open');
      renderIncidents();
      return;
    }
    if (scope === 'traffic') {
      const status = document.getElementById('traffic-status-filter');
      const q = document.getElementById('traffic-search');
      if (status) status.value = String(c.status || '');
      if (q) q.value = String(c.query || '');
      renderConnections();
    }
  }

  async function saveCurrentView() {
    const scopeEl = document.getElementById('saved-view-scope');
    const nameEl = document.getElementById('saved-view-name');
    if (!scopeEl || !nameEl) return;
    const scope = String(scopeEl.value || 'alerts');
    const name = String(nameEl.value || '').trim();
    if (!name) {
      toast('Enter a name for the saved view', 'info');
      return;
    }
    try {
      await apiFetch('POST', '/api/views/saved', {
        name,
        filters: {
          scope,
          criteria: getFilterSnapshot(scope),
        },
      });
      toast('Saved view created', 'ok');
      await fetchSavedViews();
      const select = document.getElementById('saved-view-select');
      if (select) select.value = name;
    } catch (e) {
      toast('Failed to save view: ' + e.message, 'err');
    }
  }

  async function applySelectedView() {
    const selectEl = document.getElementById('saved-view-select');
    if (!selectEl) return;
    const name = String(selectEl.value || '');
    if (!name) {
      toast('Select a saved view to apply', 'info');
      return;
    }
    const view = (S.savedViews || []).find((r) => String(r.name || '') === name);
    if (!view) {
      toast('Saved view not found', 'err');
      return;
    }
    const scope = String((view.filters || {}).scope || 'alerts');
    const criteria = (view.filters || {}).criteria || {};
    switchView(scope);
    applyFilterSnapshot(scope, criteria);
    toast(`Applied saved view: ${name}`, 'ok');
  }

  async function deleteSelectedView() {
    const selectEl = document.getElementById('saved-view-select');
    if (!selectEl) return;
    const name = String(selectEl.value || '');
    if (!name) {
      toast('Select a saved view to delete', 'info');
      return;
    }
    try {
      await apiFetch('DELETE', `/api/views/saved/${encodeURIComponent(name)}`);
      toast('Saved view deleted', 'ok');
      await fetchSavedViews();
    } catch (e) {
      toast('Failed to delete view: ' + e.message, 'err');
    }
  }

  function renderAlerts() {
    const tbody = document.getElementById('alerts-tbody');
    const sevF = document.getElementById('alert-severity-filter')?.value ?? '';
    const q    = (document.getElementById('alert-search')?.value ?? '').toLowerCase();
    const rows = S.alerts.filter(a =>
      (!sevF || a.severity === sevF) &&
      (!q || (a.message || '').toLowerCase().includes(q) ||
             (a.rule    || '').toLowerCase().includes(q) ||
             (a.interface || '').toLowerCase().includes(q))
    );
    if (!rows.length) {
      tbody.innerHTML = '<tr class="empty-row"><td colspan="7">No alerts</td></tr>';
      return;
    }
    tbody.innerHTML = rows.map(a => `
      <tr>
        <td class="text-muted text-sm" style="white-space:nowrap">${fmt_dt(a.timestamp)}</td>
        <td>${sev_pill(a.severity)}</td>
        <td class="text-muted text-sm">${esc(a.rule)}</td>
        <td>${esc(a.message)}</td>
        <td><code class="text-muted">${esc(a.interface)}</code></td>
        <td>${parseFloat(a.observed_value || 0).toFixed(1)}</td>
        <td>
          <button class="icon-btn" title="Analyze with AI"
            data-ai-item="${esc(JSON.stringify(a))}" data-ai-type="alert">🤖</button>
          <button class="icon-btn" title="Mark expected / suppress"
            data-expected-item="${esc(JSON.stringify(a))}">✓</button>
        </td>
      </tr>`).join('');

    tbody.querySelectorAll('[data-ai-item]').forEach(b =>
      b.addEventListener('click', () =>
        sendToAI([JSON.parse(b.dataset.aiItem)], b.dataset.aiType)
      )
    );
    tbody.querySelectorAll('[data-expected-item]').forEach(b =>
      b.addEventListener('click', async () => {
        const a = JSON.parse(b.dataset.expectedItem);
        try {
          await apiFetch('POST', '/api/alerts/mark-expected', {
            rule: a.rule,
            interface: a.interface || '',
            contains: '',
            reason: 'Marked expected from alert table',
          });
          toast('Added suppression rule for expected alert', 'ok');
        } catch (e) {
          toast('Failed to mark expected: ' + e.message, 'err');
        }
      })
    );
  }

  function renderOverviewFeed() {
    const feed = document.getElementById('overview-alerts-feed');
    const recent = S.alerts.slice(0, 10);
    if (!recent.length) { feed.innerHTML = '<li class="feed-empty">No alerts yet</li>'; return; }
    feed.innerHTML = recent.map(a => `
      <li class="feed-item">
        <span class="feed-sev sev-${esc(a.severity.toLowerCase())}">${esc(a.severity)}</span>
        <div class="feed-body">
          <div class="feed-msg">${esc(a.message)}</div>
          <div class="feed-time">${fmt_dt(a.timestamp)} · ${esc(a.rule)}</div>
        </div>
        <button class="icon-btn" title="Analyze with AI"
          data-ai-item="${esc(JSON.stringify(a))}" data-ai-type="alert">🤖</button>
      </li>`).join('');
    feed.querySelectorAll('[data-ai-item]').forEach(b =>
      b.addEventListener('click', () =>
        sendToAI([JSON.parse(b.dataset.aiItem)], b.dataset.aiType)
      )
    );
  }

  function renderOverviewIncidentsFeed() {
    const feed = document.getElementById('overview-incidents-feed');
    if (!feed) return;
    const rows = [...S.incidents].slice(0, 10);
    if (!rows.length) {
      feed.innerHTML = '<li class="feed-empty">No active correlated incidents</li>';
      return;
    }
    feed.innerHTML = rows.map(i => {
      const sev = String(i.severity || 'low').toLowerCase();
      const sevCls = sev === 'high' ? 'sev-high' : sev === 'medium' ? 'sev-medium' : 'sev-low';
      return `
      <li class="feed-item">
        <span class="feed-sev ${sevCls}">${esc(sev.toUpperCase())}</span>
        <div class="feed-body">
          <div class="feed-msg">${esc(i.family || 'general')} incident for ${esc(i.actor || 'unknown')} (${esc(i.alert_count || 0)} alerts, score ${esc(i.score || 0)})</div>
          <div class="feed-time">${fmt_dt(i.last_seen)} · rules: ${esc((i.related_rules || []).slice(0, 3).join(', ') || '—')}</div>
        </div>
        <button class="icon-btn" title="Analyze incident with AI"
          data-ai-item="${esc(JSON.stringify(i))}" data-ai-type="incident">🤖</button>
      </li>`;
    }).join('');
    feed.querySelectorAll('[data-ai-item]').forEach(b =>
      b.addEventListener('click', () =>
        sendToAI([JSON.parse(b.dataset.aiItem)], b.dataset.aiType)
      )
    );
  }

  function renderIncidents() {
    const tbody = document.getElementById('incidents-tbody');
    if (!tbody) return;
    const statusF = String(document.getElementById('incident-status-filter')?.value || '').toLowerCase();
    const q = String(document.getElementById('incident-search')?.value || '').toLowerCase();
    const rows = (Array.isArray(S.incidents) ? S.incidents : [])
      .filter((i) => {
        const st = String(i.status || 'open').toLowerCase();
        return S.incidentTicketTab === 'closed' ? st === 'closed' : st !== 'closed';
      })
      .filter((i) => !statusF || String(i.status || 'open').toLowerCase() === statusF)
      .filter((i) => {
        if (!q) return true;
        return String(i.actor || '').toLowerCase().includes(q)
          || String(i.family || '').toLowerCase().includes(q)
          || String((i.related_rules || []).join(',')).toLowerCase().includes(q)
          || String(i.incident_key || '').toLowerCase().includes(q);
      })
      .slice(0, 200);
    if (!rows.length) {
      const emptyText = S.incidentTicketTab === 'closed'
        ? 'No closed correlated incidents'
        : 'No open correlated incidents';
      tbody.innerHTML = `<tr class="empty-row"><td colspan="14">${emptyText}</td></tr>`;
      return;
    }
    tbody.innerHTML = rows.map(i => {
      const sev = String(i.severity || 'low').toLowerCase();
      const pill = sev === 'high' ? 'pill-high' : sev === 'medium' ? 'pill-medium' : 'pill-low';
      const triage = String(i.status || 'open').toLowerCase();
      const triagePill = triage === 'closed' ? 'pill-low' : triage === 'acknowledged' ? 'pill-medium' : 'pill-high';
      return `
      <tr>
        <td><span class="pill ${pill}">${esc(sev)}</span></td>
        <td><span class="pill ${triagePill}">${esc(triage)}</span></td>
        <td>${esc(i.family || 'general')}</td>
        <td><code>${esc(i.actor || 'unknown')}</code></td>
        <td>
          <input class="search-box incident-input incident-input-owner" data-incident-owner="${esc(i.incident_key)}" value="${esc(i.owner || '')}" placeholder="owner" />
        </td>
        <td>${esc(i.alert_count ?? 0)}</td>
        <td>${esc(i.score ?? 0)}</td>
        <td class="text-muted text-sm">${esc((i.related_rules || []).join(', ') || '—')}</td>
        <td>
          <input class="search-box incident-input incident-input-sla" data-incident-sla="${esc(i.incident_key)}" value="${esc(i.sla_hours ?? 24)}" placeholder="24" />
        </td>
        <td>
          <input class="search-box incident-input incident-input-due" data-incident-due="${esc(i.incident_key)}" value="${esc(i.due_at || '')}" placeholder="2026-04-03T12:00:00Z" />
        </td>
        <td>
          <input class="search-box incident-input incident-input-reopen" data-incident-reopen="${esc(i.incident_key)}" value="${esc(i.reopen_reason || '')}" placeholder="reason if reopening" />
        </td>
        <td>
          <input class="search-box incident-input incident-input-notes" data-incident-notes="${esc(i.incident_key)}" value="${esc(i.notes || '')}" placeholder="notes" />
        </td>
        <td class="text-muted text-sm">${fmt_dt(i.last_seen)}</td>
        <td class="incident-actions-cell">
          <button class="btn btn-ghost btn-mini" data-ai-item="${esc(JSON.stringify(i))}" data-ai-type="incident">AI</button>
          <button class="btn btn-ghost btn-mini" data-incident-action="ack" data-incident-key="${esc(i.incident_key)}">Ack</button>
          <button class="btn btn-ghost btn-mini" data-incident-action="open" data-incident-key="${esc(i.incident_key)}">Open</button>
          <button class="btn btn-ghost btn-mini" data-incident-action="close" data-incident-key="${esc(i.incident_key)}">Close</button>
          <button class="btn btn-ghost btn-mini" data-incident-action="save" data-incident-key="${esc(i.incident_key)}">Save</button>
          <button class="btn btn-ghost btn-mini" data-incident-timeline="${esc(i.incident_key)}">Timeline</button>
        </td>
      </tr>`;
    }).join('');

    tbody.querySelectorAll('[data-ai-item]').forEach(b =>
      b.addEventListener('click', () =>
        sendToAI([JSON.parse(b.dataset.aiItem)], b.dataset.aiType)
      )
    );

    tbody.querySelectorAll('[data-incident-action]').forEach(btn => {
      btn.addEventListener('click', async () => {
        const key = btn.getAttribute('data-incident-key');
        const action = btn.getAttribute('data-incident-action');
        if (!key || !action) return;
        const ownerEl = tbody.querySelector(`[data-incident-owner="${CSS.escape(key)}"]`);
        const notesEl = tbody.querySelector(`[data-incident-notes="${CSS.escape(key)}"]`);
        const slaEl = tbody.querySelector(`[data-incident-sla="${CSS.escape(key)}"]`);
        const dueEl = tbody.querySelector(`[data-incident-due="${CSS.escape(key)}"]`);
        const reopenEl = tbody.querySelector(`[data-incident-reopen="${CSS.escape(key)}"]`);
        const owner = ownerEl ? ownerEl.value.trim() : '';
        const notes = notesEl ? notesEl.value.trim() : '';
        const dueAt = dueEl ? dueEl.value.trim() : '';
        const reopenReason = reopenEl ? reopenEl.value.trim() : '';
        const slaHours = slaEl ? parseFloat(slaEl.value || '24') : 24;
        const status = action === 'ack' ? 'acknowledged' : action === 'close' ? 'closed' : action === 'open' ? 'open' : null;
        const prev = btn.textContent;
        btn.disabled = true;
        btn.textContent = 'Saving...';
        try {
          await updateIncidentTriage({ incident_key: key, status, owner, notes, sla_hours: slaHours, due_at: dueAt, reopen_reason: reopenReason });
          toast(`Incident ${action === 'save' ? 'updated' : action}`, 'ok');
          await fetchIncidents();
        } catch (e) {
          toast('Incident update failed: ' + e.message, 'err');
        } finally {
          btn.disabled = false;
          btn.textContent = prev;
        }
      });
    });

    tbody.querySelectorAll('[data-incident-timeline]').forEach(btn => {
      btn.addEventListener('click', async () => {
        const key = btn.getAttribute('data-incident-timeline');
        if (!key) return;
        await fetchIncidentTimeline(key);
      });
    });
  }

  async function fetchIncidentTimeline(incidentKey) {
    const title = document.getElementById('incident-timeline-title');
    const feed = document.getElementById('incident-timeline-feed');
    if (!title || !feed) return;
    title.textContent = `Incident Timeline: ${incidentKey}`;
    feed.innerHTML = '<li class="feed-empty">Loading timeline...</li>';
    try {
      const rows = await apiFetch('GET', `/api/incidents/${encodeURIComponent(incidentKey)}/timeline?limit=200`);
      if (!Array.isArray(rows) || !rows.length) {
        feed.innerHTML = '<li class="feed-empty">No timeline events for this incident.</li>';
        return;
      }
      feed.innerHTML = rows.map((r) => `
        <li class="feed-item">
          <span class="feed-sev ${String(r.to_status || '').toLowerCase() === 'closed' ? 'sev-low' : 'sev-medium'}">${esc(String(r.to_status || 'open').toUpperCase())}</span>
          <div class="feed-body">
            <div class="feed-msg">${esc(r.from_status || 'open')} → ${esc(r.to_status || 'open')} · owner: ${esc(r.owner || '—')}</div>
            <div class="feed-time">${fmt_dt(r.timestamp)} · notes: ${esc(r.notes || '—')} · reopen: ${esc(r.reopen_reason || '—')}</div>
          </div>
        </li>`).join('');
    } catch (e) {
      feed.innerHTML = `<li class="feed-empty">Timeline unavailable: ${esc(e.message)}</li>`;
    }
  }

  function renderHostRisk() {
    const tbody = document.getElementById('risk-tbody');
    if (!tbody) return;
    const rows = Array.isArray(S.hostRisk) ? S.hostRisk.slice(0, 300) : [];
    if (!rows.length) {
      tbody.innerHTML = '<tr class="empty-row"><td colspan="8">No host risk scores available</td></tr>';
      return;
    }
    tbody.innerHTML = rows.map((r) => `
      <tr>
        <td><code>${esc(r.host || '—')}</code></td>
        <td>${esc((Number(r.score || 0)).toFixed(2))}</td>
        <td>${esc(r.alerts ?? 0)}</td>
        <td>${esc(r.high ?? 0)}</td>
        <td>${esc(r.medium ?? 0)}</td>
        <td>${esc(r.firewall_blocks ?? 0)}</td>
        <td>${esc((Number(r.health_penalty || 0)).toFixed(2))}</td>
        <td>
          <button class="btn btn-ghost btn-mini" data-risk-incidents="${esc(r.host || '')}">Incidents</button>
          <button class="btn btn-ghost btn-mini" data-risk-traffic="${esc(r.host || '')}">Traffic</button>
        </td>
      </tr>`).join('');

    tbody.querySelectorAll('[data-risk-incidents]').forEach((btn) => {
      btn.addEventListener('click', () => {
        const host = btn.getAttribute('data-risk-incidents') || '';
        switchView('incidents');
        const q = document.getElementById('incident-search');
        if (q) q.value = host;
        renderIncidents();
      });
    });
    tbody.querySelectorAll('[data-risk-traffic]').forEach((btn) => {
      btn.addEventListener('click', () => {
        const host = btn.getAttribute('data-risk-traffic') || '';
        switchView('traffic');
        const q = document.getElementById('traffic-search');
        if (q) q.value = host;
        renderConnections();
      });
    });
  }

  function renderAttackChains() {
    const tbody = document.getElementById('chains-tbody');
    if (!tbody) return;
    const rows = Array.isArray(S.attackChains) ? S.attackChains.slice(0, 300) : [];
    if (!rows.length) {
      tbody.innerHTML = '<tr class="empty-row"><td colspan="7">No attack chains detected</td></tr>';
      return;
    }
    tbody.innerHTML = rows.map((r) => {
      const conf = String(r.confidence || 'medium').toLowerCase();
      const confPill = conf === 'high' ? 'pill-high' : 'pill-medium';
      return `
      <tr>
        <td><code>${esc(r.actor || 'unknown')}</code></td>
        <td>${esc((r.stages || []).join(' -> ') || '—')}</td>
        <td>${esc(r.alert_count ?? 0)}</td>
        <td><span class="pill ${confPill}">${esc(conf)}</span></td>
        <td class="text-muted text-sm">${fmt_dt(r.first_seen)}</td>
        <td class="text-muted text-sm">${fmt_dt(r.last_seen)}</td>
        <td>
          <button class="btn btn-ghost btn-mini" data-chain-incidents="${esc(r.actor || '')}">Incidents</button>
          <button class="btn btn-ghost btn-mini" data-chain-alerts="${esc(r.actor || '')}">Alerts</button>
        </td>
      </tr>`;
    }).join('');

    tbody.querySelectorAll('[data-chain-incidents]').forEach((btn) => {
      btn.addEventListener('click', () => {
        const actor = btn.getAttribute('data-chain-incidents') || '';
        switchView('incidents');
        const q = document.getElementById('incident-search');
        if (q) q.value = actor;
        renderIncidents();
      });
    });
    tbody.querySelectorAll('[data-chain-alerts]').forEach((btn) => {
      btn.addEventListener('click', () => {
        const actor = btn.getAttribute('data-chain-alerts') || '';
        switchView('alerts');
        const q = document.getElementById('alert-search');
        if (q) q.value = actor;
        renderAlerts();
      });
    });
  }

  async function updateIncidentTriage(payload) {
    return apiFetch('POST', '/api/incidents/triage', payload);
  }

  async function fetchFirewallBlocks() {
    try {
      S.firewallBlocks = await apiFetch('GET', '/api/firewall/blocked?limit=300');
      renderFirewallBlocks();
      renderOverviewFirewallFeed();
    } catch (_) {}
  }

  function renderOverviewFirewallFeed() {
    const feed = document.getElementById('overview-firewall-feed');
    if (!feed) return;
    const rows = [...S.firewallBlocks].reverse().slice(0, 10);
    if (!rows.length) {
      feed.innerHTML = '<li class="feed-empty">No firewall blocks yet</li>';
      return;
    }
    feed.innerHTML = rows.map(r => `
      <li class="feed-item">
        <span class="feed-sev sev-medium">BLOCKED</span>
        <div class="feed-body">
          <div class="feed-msg">${esc((r.protocol || 'IP').toUpperCase())} ${esc(r.src_ip || '—')}${r.src_port ? ':' + esc(r.src_port) : ''} -> ${esc(r.dst_ip || '—')}${r.dst_port ? ':' + esc(r.dst_port) : ''}</div>
          <div class="feed-time">${fmt_dt(r.timestamp)} · ${esc(r.direction || 'unknown')}</div>
        </div>
      </li>`).join('');
  }

  function renderFirewallBlocks() {
    const tbody = document.getElementById('firewall-tbody');
    if (!tbody) return;
    const rows = [...S.firewallBlocks].reverse().slice(0, 300);
    if (!rows.length) {
      tbody.innerHTML = '<tr class="empty-row"><td colspan="7">No blocked firewall events yet. Enable Windows Firewall logging for dropped packets to populate this view.</td></tr>';
      return;
    }
    tbody.innerHTML = rows.map(r => `
      <tr>
        <td class="text-muted text-sm" style="white-space:nowrap">${fmt_dt(r.timestamp)}</td>
        <td><span class="pill pill-medium">${esc(r.action || 'DROP')}</span></td>
        <td><code>${esc((r.protocol || 'IP').toUpperCase())}</code></td>
        <td><code>${esc(r.src_ip || '—')}${r.src_port ? ':' + esc(r.src_port) : ''}</code></td>
        <td><code>${esc(r.dst_ip || '—')}${r.dst_port ? ':' + esc(r.dst_port) : ''}</code></td>
        <td class="text-muted text-sm">${esc(r.direction || 'unknown')}</td>
        <td class="text-muted text-sm">${esc(r.interface || '—')}</td>
      </tr>`).join('');
  }

  /* ═══════════════════════ Connections ══════════════════════ */
  async function fetchConnections() {
    try { S.connections = await apiFetch('GET', '/api/connections?limit=150'); renderConnections(); }
    catch (_) {}
  }

  async function fetchPackets() {
    if (S.packetsPaused) return;
    try {
      const incoming = await apiFetch('GET', '/api/packets?limit=500');
      const packetRows = Array.isArray(incoming) ? incoming : [];
      const merged = new Map();
      [...S.packets, ...packetRows].forEach((p) => {
        merged.set(packetIdentity(p), p);
      });
      S.packets = Array.from(merged.values()).slice(-2000);
      renderPackets();
      fetchPacketAnalytics();
    } catch (_) {}
  }

  function packetIdentity(p) {
    if (!p || typeof p !== 'object') return '';
    return [
      String(p.frame_number ?? ''),
      String(p.timestamp ?? ''),
      String(p.src_ip ?? ''),
      String(p.src_port ?? ''),
      String(p.dst_ip ?? ''),
      String(p.dst_port ?? ''),
      String(p.protocol ?? ''),
    ].join('|');
  }

  async function fetchPacketAnalytics() {
    try {
      const [flows, conversations] = await Promise.all([
        apiFetch('GET', '/api/packets/flows?limit=50'),
        apiFetch('GET', '/api/packets/conversations?limit=50'),
      ]);
      S.packetFlows = Array.isArray(flows) ? flows : [];
      S.packetConversations = Array.isArray(conversations) ? conversations : [];
      renderPacketFlows();
      renderPacketConversations();
    } catch (_) {}
  }

  function togglePacketsPause() {
    S.packetsPaused = !S.packetsPaused;
    const btn = document.getElementById('packets-pause-btn');
    if (btn) btn.textContent = S.packetsPaused ? 'Resume' : 'Pause';
    if (!S.packetsPaused) fetchPackets();
  }

  function clearPacketsView() {
    S.packets = [];
    S.packetFlows = [];
    S.packetConversations = [];
    S.selectedPacketKey = '';
    S.selectedPacket = null;
    renderPackets();
    renderPacketFlows();
    renderPacketConversations();
    toast('Packet table cleared (view only)', 'info');
  }

  function togglePacketAnalyticsCard(cardId, buttonId) {
    const card = document.getElementById(cardId);
    const btn = document.getElementById(buttonId);
    if (!card || !btn) return;
    const expanded = card.classList.toggle('is-expanded');
    btn.textContent = expanded ? 'Collapse' : 'Expand';
  }

  async function decodeSelectedPacketFrame() {
    if (!S.selectedPacket || !S.selectedPacket.frame_number) {
      toast('Select a packet row with a frame number first', 'info');
      return;
    }
    const out = document.getElementById('packet-detail-decode');
    if (out) out.textContent = 'Decoding with TShark...';
    try {
      const r = await apiFetch('GET', `/api/packets/decode?frame_number=${encodeURIComponent(S.selectedPacket.frame_number)}`);
      if (out) out.textContent = r.decode || 'No decode output';
      toast(`Decoded frame ${S.selectedPacket.frame_number}`, 'ok');
    } catch (e) {
      if (out) out.textContent = 'Decode failed: ' + e.message;
      toast('Decode failed: ' + e.message, 'err');
    }
  }

  async function exportPackets() {
    try {
      const r = await apiFetch('GET', '/api/packets/export?limit=5000');
      const blob = new Blob([JSON.stringify(r.rows || [], null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      const ts = new Date().toISOString().replace(/[:.]/g, '-');
      a.href = url;
      a.download = `siem-packets-${ts}.json`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      toast(`Exported ${(r.count || 0)} packets`, 'ok');
    } catch (e) {
      toast('Packet export failed: ' + e.message, 'err');
    }
  }

  function renderPackets() {
    const tbody = document.getElementById('packets-tbody');
    if (!tbody) return;
    const q = (document.getElementById('packets-search')?.value || '').toLowerCase();
    const protocolFilter = document.getElementById('packets-protocol-filter')?.value || '';
    const directionFilter = document.getElementById('packets-direction-filter')?.value || '';
    const rows = [...S.packets]
      .filter(p => !protocolFilter || String(p.protocol || '').toUpperCase() === protocolFilter)
      .filter(p => !directionFilter || String(p.direction || '').toLowerCase() === directionFilter)
      .filter(p => {
        if (!q) return true;
        const src = `${p.src_ip || ''}:${p.src_port || ''}`.toLowerCase();
        const dst = `${p.dst_ip || ''}:${p.dst_port || ''}`.toLowerCase();
        const proto = String(p.protocol || '').toLowerCase();
        const appProto = String(p.app_protocol || '').toLowerCase();
        const dnsQuery = String(p.dns_query || '').toLowerCase();
        const dnsAnswers = String(p.dns_answers || '').toLowerCase();
        const tlsSni = String(p.tls_sni || '').toLowerCase();
        const httpHost = String(p.http_host || '').toLowerCase();
        const httpMethod = String(p.http_method || '').toLowerCase();
        const httpPath = String(p.http_path || '').toLowerCase();
        return src.includes(q)
          || dst.includes(q)
          || proto.includes(q)
          || appProto.includes(q)
          || dnsQuery.includes(q)
          || dnsAnswers.includes(q)
          || tlsSni.includes(q)
          || httpHost.includes(q)
          || httpMethod.includes(q)
          || httpPath.includes(q);
      })
      .reverse()
      .slice(0, 500);
    if (!rows.length) {
      tbody.innerHTML = '<tr class="empty-row"><td colspan="9">No packet metadata captured yet. Use pcap mode to populate this view.</td></tr>';
      renderPacketDetails(null);
      return;
    }
    tbody.innerHTML = rows.map((p) => {
      const key = packetIdentity(p);
      const selected = key === S.selectedPacketKey ? ' packet-row-selected' : '';
      return `
      <tr class="${selected}" data-packet-key="${esc(key)}">
        <td class="text-muted text-sm" style="white-space:nowrap">${fmt_dt(p.timestamp)}</td>
        <td>${p.direction === 'inbound' ? '<span class="pill pill-low">IN</span>' : p.direction === 'outbound' ? '<span class="pill pill-medium">OUT</span>' : '<span class="pill">UNK</span>'}</td>
        <td><code>${esc(p.protocol || 'IP')}</code></td>
        <td>${p.app_protocol ? `<span class="pill pill-low">${esc(p.app_protocol)}</span>` : '—'}</td>
        <td><code>${esc(p.src_ip || '')}${p.src_port ? ':' + esc(p.src_port) : ''}</code></td>
        <td><code>${esc(p.dst_ip || '')}${p.dst_port ? ':' + esc(p.dst_port) : ''}</code></td>
        <td><code>${esc(p.tcp_flags || '—')}</code></td>
        <td class="text-muted">${esc(p.length ?? 0)}</td>
        <td class="text-muted text-sm">${esc(p.interface || 'pcap')}</td>
      </tr>`;
    }).join('');

    tbody.querySelectorAll('tr[data-packet-key]').forEach((tr) => {
      tr.addEventListener('click', () => {
        const key = tr.getAttribute('data-packet-key') || '';
        const p = rows.find((row) => packetIdentity(row) === key);
        if (!p) return;
        S.selectedPacketKey = key;
        S.selectedPacket = p;
        renderPackets();
        renderPacketDetails(p);
      });
    });

    if (!rows.some((p) => packetIdentity(p) === S.selectedPacketKey)) {
      S.selectedPacketKey = '';
      S.selectedPacket = rows[0] || null;
      renderPacketDetails(rows[0]);
      return;
    }

    const selected = rows.find((p) => packetIdentity(p) === S.selectedPacketKey) || S.selectedPacket;
    renderPacketDetails(selected || rows[0] || null);
  }

  function renderPacketDetails(p) {
    const meta = document.getElementById('packet-detail-meta');
    const payload = document.getElementById('packet-detail-payload');
    if (!meta || !payload) return;
    if (!p) {
      meta.textContent = 'Click a packet row to inspect details.';
      payload.textContent = 'No payload preview available.';
      const decode = document.getElementById('packet-detail-decode');
      if (decode) decode.textContent = 'No decode requested.';
      return;
    }
    const detailParts = [
      `Protocol: ${p.protocol || 'IP'}`,
      `App: ${p.app_protocol || '—'}`,
      `Direction: ${p.direction || 'unknown'}`,
      `Source: ${(p.src_ip || '') + (p.src_port ? ':' + p.src_port : '')}`,
      `Destination: ${(p.dst_ip || '') + (p.dst_port ? ':' + p.dst_port : '')}`,
      `Length: ${p.length || 0} bytes`,
      `Flags: ${p.tcp_flags || '—'}`,
      `Seq/Ack: ${p.tcp_seq ?? '—'} / ${p.tcp_ack ?? '—'}`,
      `Payload bytes: ${p.payload_len || 0}`,
      `Interface: ${p.interface || 'pcap'}`,
    ];
    if (p.dns_query) detailParts.push(`DNS query: ${p.dns_query}`);
    if (p.dns_answers) detailParts.push(`DNS answers: ${p.dns_answers}`);
    if (p.dns_rcode) detailParts.push(`DNS rcode: ${p.dns_rcode}`);
    if (p.dns_txn_rtt_ms != null) detailParts.push(`DNS txn RTT: ${p.dns_txn_rtt_ms} ms`);
    if (p.tls_sni) detailParts.push(`TLS SNI: ${p.tls_sni}`);
    if (p.tls_fingerprint) detailParts.push(`TLS fingerprint: ${p.tls_fingerprint}`);
    if (p.frame_number != null) detailParts.push(`Frame: ${p.frame_number}`);
    if (p.http_host) detailParts.push(`HTTP host: ${p.http_host}`);
    if (p.http_method || p.http_path) detailParts.push(`HTTP request: ${(p.http_method || '').trim()} ${(p.http_path || '').trim()}`.trim());
    meta.textContent = detailParts.join(' | ');
    payload.textContent = p.payload_preview_hex || '(No payload preview)';
  }

  function renderPacketFlows() {
    const tbody = document.getElementById('packet-flows-tbody');
    if (!tbody) return;
    const rows = Array.isArray(S.packetFlows) ? S.packetFlows.slice(0, 50) : [];
    if (!rows.length) {
      tbody.innerHTML = '<tr class="empty-row"><td colspan="4">No flow analytics yet</td></tr>';
      return;
    }
    tbody.innerHTML = rows.map(r => `
      <tr>
        <td><code>${esc(r.flow_key || '—')}</code></td>
        <td class="text-muted">${esc(r.packet_count ?? 0)}</td>
        <td class="text-muted">${esc(r.byte_count ?? 0)}</td>
        <td class="text-muted text-sm">${esc((r.app_protocols || []).join(', ') || '—')}</td>
      </tr>`).join('');
  }

  function renderPacketConversations() {
    const tbody = document.getElementById('packet-conversations-tbody');
    if (!tbody) return;
    const rows = Array.isArray(S.packetConversations) ? S.packetConversations.slice(0, 50) : [];
    if (!rows.length) {
      tbody.innerHTML = '<tr class="empty-row"><td colspan="4">No conversation analytics yet</td></tr>';
      return;
    }
    tbody.innerHTML = rows.map(r => `
      <tr>
        <td><code>${esc(r.conversation_key || '—')}</code></td>
        <td class="text-muted">${esc(r.packet_count ?? 0)}</td>
        <td class="text-muted">${esc(r.byte_count ?? 0)}</td>
        <td class="text-muted text-sm">${esc((r.app_protocols || []).join(', ') || '—')}</td>
      </tr>`).join('');
  }

  function renderConnections() {
    const tbody = document.getElementById('traffic-tbody');
    const q = String(document.getElementById('traffic-search')?.value || '').toLowerCase();
    const stateF = String(document.getElementById('traffic-status-filter')?.value || '').toLowerCase();
    const rows = [...S.connections]
      .reverse()
      .filter((c) => {
        if (!stateF) return true;
        const established = String(c.status || '').toUpperCase() === 'ESTABLISHED';
        return stateF === 'established' ? established : !established;
      })
      .filter((c) => {
        if (!q) return true;
        const local = `${c.local_ip || ''}:${c.local_port || ''}`.toLowerCase();
        const remote = `${c.remote_ip || ''}:${c.remote_port || ''}`.toLowerCase();
        return String(c.process_name || '').toLowerCase().includes(q)
          || local.includes(q)
          || remote.includes(q)
          || String(c.status || '').toLowerCase().includes(q)
          || String(c.family || '').toLowerCase().includes(q);
      })
      .slice(0, 150);
    if (!rows.length) {
      tbody.innerHTML = '<tr class="empty-row"><td colspan="7">No connections captured yet</td></tr>';
      return;
    }
    tbody.innerHTML = rows.map(c => `
      <tr>
        <td><strong>${esc(c.process_name || '—')}</strong></td>
        <td><code>${esc(c.local_ip)}:${esc(c.local_port)}</code></td>
        <td><code>${c.remote_ip ? esc(c.remote_ip) + ':' + esc(c.remote_port) : '—'}</code></td>
        <td><span class="pill ${c.status === 'ESTABLISHED' ? 'pill-low' : 'pill-medium'}">${esc(c.status || '—')}</span></td>
        <td class="text-muted text-sm">${esc(c.family)}</td>
        <td class="text-muted">${c.pid ?? '—'}</td>
        <td>
          <button class="icon-btn" title="Analyze with AI"
            data-ai-item="${esc(JSON.stringify(c))}" data-ai-type="event">🤖</button>
        </td>
      </tr>`).join('');
    tbody.querySelectorAll('[data-ai-item]').forEach(b =>
      b.addEventListener('click', () =>
        sendToAI([JSON.parse(b.dataset.aiItem)], b.dataset.aiType)
      )
    );
  }

  /* ═══════════════════════ Settings ═════════════════════════ */
  async function fetchSettings() {
    try {
      S.settings = await apiFetch('GET', '/api/settings');
      const f = S.settings;
      document.getElementById('set-events-hours').value = f.events_retention_hours ?? 24;
      document.getElementById('set-alerts-hours').value = f.alerts_retention_hours ?? 72;
      document.getElementById('set-archive-days').value = f.archive_retention_days ?? 90;
      const keyEl    = document.getElementById('ai-key-status');
      keyEl.textContent = f.ai_key_configured ? '✓ API key is set' : '✗ Not configured';
      keyEl.className = f.ai_key_configured ? 'status-ok' : 'status-muted';
      loadDetectionControls();
    } catch (_) {}
  }

  async function loadDetectionControls() {
    const ta = document.getElementById('detector-controls-json');
    if (!ta) return;
    try {
      const c = await apiFetch('GET', '/api/detections/controls');
      ta.value = JSON.stringify(c, null, 2);
    } catch (e) {
      ta.value = '{\n  "error": "' + String(e.message || 'failed') + '"\n}';
    }
  }

  async function saveDetectionControls() {
    const ta = document.getElementById('detector-controls-json');
    if (!ta) return;
    try {
      const payload = JSON.parse(ta.value || '{}');
      await apiFetch('POST', '/api/detections/controls', payload);
      toast('Detection controls saved', 'ok');
    } catch (e) {
      toast('Controls save failed: ' + e.message, 'err');
    }
  }

  async function saveSettings() {
    const body = {
      events_retention_hours: parseFloat(document.getElementById('set-events-hours').value),
      alerts_retention_hours: parseFloat(document.getElementById('set-alerts-hours').value),
      archive_retention_days: parseInt(document.getElementById('set-archive-days').value || '90', 10),
    };
    const key = (document.getElementById('set-ai-key').value || '').trim();
    if (key) body.openai_api_key = key;
    try {
      await apiFetch('POST', '/api/settings', body);
      toast('Settings saved', 'ok');
      if (key) document.getElementById('set-ai-key').value = '';
      fetchSettings();
    } catch (e) { toast('Save failed: ' + e.message, 'err'); }
  }

  async function pruneNow() {
    try {
      const r = await apiFetch('POST', '/api/logs/prune');
      const lines = Object.entries(r.removed).map(([f, n]) => `${f}: ${n} archived`).join(', ');
      toast('Archived old logs — ' + lines, 'ok');
    } catch (e) { toast('Prune failed: ' + e.message, 'err'); }
  }

  async function clearArchiveNow() {
    try {
      const r = await apiFetch('POST', '/api/logs/archive/clear');
      const removed = r.removed || {};
      const files = Number(removed.files || 0);
      const lines = Number(removed.lines || 0);
      const bytes = Number(removed.bytes || 0);
      const mb = (bytes / (1024 * 1024)).toFixed(2);
      toast(`Cleared archive: ${files} files, ${lines} lines, ${mb} MB`, 'ok');
    } catch (e) {
      toast('Archive clear failed: ' + e.message, 'err');
    }
  }

  /* ═══════════════════════ Alias Modal ══════════════════════ */
  function openAliasModal(ip, alias) {
    document.getElementById('modal-ip-label').textContent = 'IP: ' + ip;
    document.getElementById('modal-alias-input').value = alias || '';
    document.getElementById('alias-modal').dataset.ip = ip;
    document.getElementById('alias-modal').classList.remove('hidden');
    document.getElementById('modal-alias-input').focus();
  }

  function closeAliasModal() {
    document.getElementById('alias-modal').classList.add('hidden');
  }

  async function saveAlias() {
    const ip    = document.getElementById('alias-modal').dataset.ip;
    const alias = document.getElementById('modal-alias-input').value.trim();
    const enc   = encodeURIComponent(ip.replace(/:/g, '__colon__'));
    try {
      await apiFetch('PUT', `/api/devices/${enc}/alias`, { alias });
      toast('Name saved', 'ok');
      closeAliasModal();
      fetchDevices();
    } catch (e) { toast('Failed: ' + e.message, 'err'); }
  }

  async function clearAlias() {
    const ip  = document.getElementById('alias-modal').dataset.ip;
    const enc = encodeURIComponent(ip.replace(/:/g, '__colon__'));
    try {
      await apiFetch('DELETE', `/api/devices/${enc}/alias`);
      toast('Name cleared', 'ok');
      closeAliasModal();
      fetchDevices();
    } catch (e) { toast('Failed: ' + e.message, 'err'); }
  }

  /* ═══════════════════════ Subnet Scan ══════════════════════ */
  async function scanSubnet() {
    const btn    = document.getElementById('btn-scan');
    const banner = document.getElementById('scan-status');
    btn.disabled = true; btn.textContent = '⟳ Scanning…';
    banner.classList.remove('hidden');
    try {
      const r = await apiFetch('POST', '/api/scan');
      toast(`Scan done — ${r.new_devices} new device(s)`, 'ok');
      fetchDevices();
    } catch (e) { toast('Scan failed: ' + e.message, 'err'); }
    finally {
      btn.disabled = false; btn.textContent = '⟳ Scan Subnet';
      banner.classList.add('hidden');
    }
  }

  /* ═══════════════════════ SSE Live Alerts ══════════════════ */
  function initSSE() {
    const es = new EventSource('/api/stream/alerts');
    es.onmessage = ({ data }) => {
      const a = JSON.parse(data);
      S.alerts.unshift(a);
      renderOverviewFeed();
      const cardId = a.severity === 'high' ? 'stat-card-high' : 'stat-card-med';
      const card = document.getElementById(cardId);
      card?.classList.add('flicker');
      setTimeout(() => card?.classList.remove('flicker'), 500);
      if (shouldShowHighAlertPopup(a)) {
        toast(`[${a.severity.toUpperCase()}] ${a.message}`, 'err');
      }
      if (document.getElementById('view-alerts')?.classList.contains('active')) renderAlerts();
    };
    es.onopen  = () => { setDot('ok', 'Engine running'); };
    es.onerror = () => { setDot('err', 'Connection lost'); };
  }

  function setDot(cls, label) {
    document.getElementById('status-dot').className = `dot dot-${cls}`;
    document.getElementById('status-label').textContent = label;
  }

  function shouldShowHighAlertPopup(alert) {
    const alertsViewActive = !!document.getElementById('view-alerts')?.classList.contains('active');
    if (!alertsViewActive) return false;
    const severityFilter = String(document.getElementById('alert-severity-filter')?.value || '').toLowerCase();
    if (severityFilter !== 'high') return false;
    return String(alert?.severity || '').toLowerCase() === 'high';
  }

  function fmtAgentLabel(agentType) {
    const labels = {
      alert_triage: 'Alert Triage',
      incident_commander: 'Incident Commander',
      traffic_forensics: 'Traffic Forensics',
      device_risk: 'Device Risk',
      network_health_reliability: 'Health Reliability',
      soc_copilot: 'SOC Copilot',
    };
    return labels[String(agentType || '').trim()] || 'SOC Copilot';
  }

  function setAiAgentBadge(agentType) {
    const badge = document.getElementById('ai-agent-badge');
    if (!badge) return;
    badge.textContent = `Agent: ${fmtAgentLabel(agentType)}`;
  }

  /* ═══════════════════════ AI Analyzer ══════════════════════ */
  function sendToAI(items, type) {
    const agentMap = {
      alert: 'alert_triage',
      event: 'traffic_forensics',
      device: 'device_risk',
      incident: 'incident_commander',
      health: 'network_health_reliability',
      general: 'soc_copilot',
    };
    S.aiContext = { type, items, agentType: agentMap[type] || 'soc_copilot' };
    switchView('ai');
    setAiAgentBadge(S.aiContext.agentType);
    const info = document.getElementById('ai-context-info');
    const typeLabel = { alert: 'alert', event: 'connection', device: 'device', incident: 'incident', health: 'health signal' }[type] ?? type;
    info.textContent = `📎 Context loaded: ${items.length} ${typeLabel}(s) using ${S.aiContext.agentType}`;
    info.classList.remove('hidden');
    document.getElementById('ai-input').focus();
  }

  async function aiSend() {
    const inputEl = document.getElementById('ai-input');
    const msg = inputEl.value.trim();
    if (!msg) return;
    inputEl.value = '';

    S.aiMessages.push({ role: 'user', content: msg });
    renderAIChat();
    document.getElementById('ai-send-btn').disabled = true;

    const body = { message: msg, history: S.aiMessages.slice(-12), agent_type: 'soc_copilot' };
    if (S.aiContext) {
      const { type, items, agentType } = S.aiContext;
      body.agent_type = agentType || 'soc_copilot';
      if (type === 'alert')  body.context_alerts      = items;
      if (type === 'event')  body.context_connections = items;
      if (type === 'device') body.context_devices     = items;
      if (type === 'incident') body.context_incidents = items;
      if (type === 'health') body.context_health = items;
      // Clear context after first use
      S.aiContext = null;
      document.getElementById('ai-context-info').classList.add('hidden');
    }

    // Show typing indicator
    const chat = document.getElementById('ai-chat');
    const typing = document.createElement('div');
    typing.className = 'ai-msg ai-msg-assistant';
    typing.innerHTML = '<div class="ai-msg-label">⬡ SIEM AI</div><div class="ai-typing-dots"><span></span><span></span><span></span></div>';
    chat.appendChild(typing);
    chat.scrollTop = chat.scrollHeight;

    try {
      const r = await apiFetch('POST', '/api/ai/analyze', body);
      typing.remove();
      setAiAgentBadge(r.agent_type || body.agent_type || 'soc_copilot');
      S.aiMessages.push({ role: 'assistant', content: r.reply });
      renderAIChat();
    } catch (e) {
      typing.remove();
      const isKeyIssue = /api.key|openai_api_key|authentication|401|configure/i.test(e.message);
      const msg = isKeyIssue
        ? '⚠️ OpenAI API key issue: ' + e.message + '\n\nGo to **Settings & Logs** → paste your key → Save.'
        : '⚠️ AI request failed: ' + e.message;
      S.aiMessages.push({ role: 'assistant', content: msg });
      renderAIChat();
    } finally {
      document.getElementById('ai-send-btn').disabled = false;
      document.getElementById('ai-input').focus();
    }
  }

  function renderAIChat() {
    const chat  = document.getElementById('ai-chat');
    const empty = document.getElementById('ai-chat-empty');
    if (S.aiMessages.length) empty?.classList.add('hidden');
    chat.innerHTML = S.aiMessages.map(m => `
      <div class="ai-msg ai-msg-${esc(m.role)}">
        <div class="ai-msg-label">${m.role === 'user' ? 'You' : '⬡ SIEM AI'}</div>
        <div class="ai-msg-body">${esc(m.content).replace(/\n/g, '<br/>')}</div>
      </div>`).join('');
    chat.scrollTop = chat.scrollHeight;
  }

  /* ═══════════════════════ Init ═════════════════════════════ */
  function init() {
    initNav();
    setIncidentTicketTab('open');

    // Initial data
    fetchStats();
    fetchSystemStatus();
    fetchEvents();
    fetchAgents();
    fetchAgentEvents();
    fetchBluetooth();
    fetchAlerts();
    fetchIncidents();
    fetchSavedViews();
    fetchHostRisk();
    fetchAttackChains();
    fetchFirewallBlocks();
    fetchNetworkHealth();
    fetchSetupWizard();

    // Polling
    setInterval(() => { fetchStats(); fetchEvents(); fetchSystemStatus(); }, 5000);
    setInterval(() => {
      fetchAlerts();
      fetchIncidents();
      fetchAgents();
      fetchAgentEvents();
      fetchBluetooth();
      fetchFirewallBlocks();
      fetchNetworkHealth();
      if (document.getElementById('view-risk')?.classList.contains('active'))      fetchHostRisk();
      if (document.getElementById('view-chains')?.classList.contains('active'))    fetchAttackChains();
      if (document.getElementById('view-devices')?.classList.contains('active'))   fetchDevices();
      if (document.getElementById('view-agents')?.classList.contains('active'))    { fetchAgents(); fetchAgentEvents(); }
      if (document.getElementById('view-bluetooth')?.classList.contains('active')) fetchBluetooth();
      if (document.getElementById('view-firewall')?.classList.contains('active'))  fetchFirewallBlocks();
      if (document.getElementById('view-traffic')?.classList.contains('active'))   fetchConnections();
      if (document.getElementById('view-packets')?.classList.contains('active'))   fetchPackets();
    }, 10000);

    // SSE
    initSSE();

    // Device search
    document.getElementById('device-search')?.addEventListener('input', renderDevices);
    document.getElementById('agent-search')?.addEventListener('input', renderAgents);
    document.getElementById('agent-status-filter')?.addEventListener('change', renderAgents);
    document.getElementById('agent-event-search')?.addEventListener('input', renderAgentEvents);
    document.getElementById('agent-event-type-filter')?.addEventListener('change', renderAgentEvents);
    document.getElementById('agent-refresh-btn')?.addEventListener('click', () => { fetchAgents(); fetchAgentEvents(); });
    document.getElementById('btn-scan')?.addEventListener('click', scanSubnet);
    document.getElementById('packets-search')?.addEventListener('input', renderPackets);
    document.getElementById('packets-protocol-filter')?.addEventListener('change', renderPackets);
    document.getElementById('packets-direction-filter')?.addEventListener('change', renderPackets);
    document.getElementById('packets-pause-btn')?.addEventListener('click', togglePacketsPause);
    document.getElementById('packets-clear-btn')?.addEventListener('click', clearPacketsView);
    document.getElementById('packets-export-btn')?.addEventListener('click', exportPackets);
    document.getElementById('packet-decode-btn')?.addEventListener('click', decodeSelectedPacketFrame);
    document.getElementById('packet-flows-toggle-btn')?.addEventListener('click', () => {
      togglePacketAnalyticsCard('packet-flows-card', 'packet-flows-toggle-btn');
    });
    document.getElementById('packet-conversations-toggle-btn')?.addEventListener('click', () => {
      togglePacketAnalyticsCard('packet-conversations-card', 'packet-conversations-toggle-btn');
    });

    // Alert filters
    document.getElementById('alert-severity-filter')?.addEventListener('change', renderAlerts);
    document.getElementById('alert-search')?.addEventListener('input', renderAlerts);
    document.getElementById('incident-status-filter')?.addEventListener('change', () => {
      const status = String(document.getElementById('incident-status-filter')?.value || '').toLowerCase();
      if (status === 'closed') {
        setIncidentTicketTab('closed');
      } else if (S.incidentTicketTab === 'closed') {
        setIncidentTicketTab('open');
      } else {
        renderIncidents();
      }
    });
    document.getElementById('incident-search')?.addEventListener('input', renderIncidents);
    document.getElementById('incident-tab-open')?.addEventListener('click', () => setIncidentTicketTab('open'));
    document.getElementById('incident-tab-closed')?.addEventListener('click', () => setIncidentTicketTab('closed'));
    document.getElementById('traffic-status-filter')?.addEventListener('change', renderConnections);
    document.getElementById('traffic-search')?.addEventListener('input', renderConnections);

    // Saved views
    document.getElementById('saved-view-scope')?.addEventListener('change', renderSavedViewOptions);
    document.getElementById('saved-view-save-btn')?.addEventListener('click', saveCurrentView);
    document.getElementById('saved-view-apply-btn')?.addEventListener('click', applySelectedView);
    document.getElementById('saved-view-delete-btn')?.addEventListener('click', deleteSelectedView);

    // Risk and chain views
    document.getElementById('risk-refresh-btn')?.addEventListener('click', fetchHostRisk);
    document.getElementById('chains-refresh-btn')?.addEventListener('click', fetchAttackChains);

    // Alias modal
    document.getElementById('modal-close')?.addEventListener('click', closeAliasModal);
    document.getElementById('modal-save')?.addEventListener('click', saveAlias);
    document.getElementById('modal-clear')?.addEventListener('click', clearAlias);
    document.getElementById('alias-modal')?.addEventListener('click', e => {
      if (e.target === document.getElementById('alias-modal')) closeAliasModal();
    });
    document.getElementById('modal-alias-input')?.addEventListener('keydown', e => {
      if (e.key === 'Enter') saveAlias();
    });

    // Settings — retention save
    document.getElementById('settings-save-btn')?.addEventListener('click', saveSettings);
    document.getElementById('settings-prune-btn')?.addEventListener('click', pruneNow);
    document.getElementById('settings-clear-archive-btn')?.addEventListener('click', clearArchiveNow);
    document.getElementById('detector-controls-load-btn')?.addEventListener('click', loadDetectionControls);
    document.getElementById('detector-controls-save-btn')?.addEventListener('click', saveDetectionControls);
    document.getElementById('setup-refresh-btn')?.addEventListener('click', fetchSetupWizard);
    // Settings — API key save (separate button, same underlying function)
    document.getElementById('settings-ai-save-btn')?.addEventListener('click', saveSettings);

    // AI panel
    document.getElementById('ai-send-btn')?.addEventListener('click', aiSend);
    document.getElementById('ai-input')?.addEventListener('keydown', e => {
      if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); aiSend(); }
    });
    document.getElementById('ai-clear-btn')?.addEventListener('click', () => {
      S.aiMessages = []; S.aiContext = null;
      document.getElementById('ai-chat').innerHTML = '';
      document.getElementById('ai-chat-empty').classList.remove('hidden');
      document.getElementById('ai-context-info').classList.add('hidden');
      setAiAgentBadge('soc_copilot');
    });
    // Quick-analyze buttons on AI view
    document.getElementById('ai-quick-alerts')?.addEventListener('click', () => {
      sendToAI(S.alerts.slice(0, 20), 'alert');
      document.getElementById('ai-input').value = 'Analyze these recent alerts and explain what is happening on my network.';
    });
    document.getElementById('ai-quick-traffic')?.addEventListener('click', () => {
      sendToAI([...S.connections].reverse().slice(0, 30), 'event');
      document.getElementById('ai-input').value = 'Analyze this network traffic and identify any suspicious patterns.';
    });
  }

  document.addEventListener('DOMContentLoaded', init);
})();
