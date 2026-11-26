'use strict';

const app = document.getElementById('app');
let me = null;
let sse = null;
let pollTimer = null;
let peersCache = [];
let currentPeer = null;
let currentRange = '24h';
let clientFilter = { q: '', state: '' };
let lastTick = null;

// ---- helpers -----------------------------------------------------------

const esc = (value) => String(value ?? '').replace(/[&<>"']/g, (c) => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
}[c]));

const num = (value) => Number(value || 0).toLocaleString();

function fmtBytes(bytes) {
  const n = Number(bytes || 0);
  if (n < 1024) return `${n} B`;
  const units = ['KiB', 'MiB', 'GiB', 'TiB', 'PiB'];
  let value = n / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit++; }
  return `${value.toFixed(value >= 100 ? 0 : value >= 10 ? 1 : 2)} ${units[unit]}`;
}

function fmtDuration(seconds) {
  const s = Math.max(0, Number(seconds || 0));
  if (s < 60) return `${s} 秒`;
  if (s < 3600) return `${Math.floor(s / 60)} 分钟`;
  if (s < 86400) return `${Math.floor(s / 3600)} 小时 ${Math.floor((s % 3600) / 60)} 分`;
  return `${Math.floor(s / 86400)} 天 ${Math.floor((s % 86400) / 3600)} 小时`;
}

function fmtTime(value) {
  if (!value) return '—';
  const date = typeof value === 'number' ? new Date(value * 1000) : new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString('zh-CN', { hour12: false });
}

const canAdmin = () => me && me.role === 'admin';

function clearPoll() {
  if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
}

function stateBadge(state) {
  const labels = { online: '在线', offline: '离线', disabled: '禁用', abnormal: '异常' };
  return `<span class="badge ${esc(state)}">${labels[state] || esc(state)}</span>`;
}

function toast(message, kind = 'ok') {
  const el = document.createElement('div');
  el.className = 'toast';
  el.textContent = message;
  if (kind === 'error') el.style.color = 'var(--danger)';
  document.body.appendChild(el);
  setTimeout(() => el.remove(), 3200);
}

class ApiError extends Error {
  constructor(message, status, data) {
    super(message);
    this.status = status;
    this.data = data || {};
  }
}

async function api(path, options = {}) {
  const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
  const method = (options.method || 'GET').toUpperCase();
  if (method !== 'GET' && me && me.csrf_token) {
    headers['X-CSRF-Token'] = me.csrf_token;
  }
  const response = await fetch(path, {
    credentials: 'same-origin',
    ...options,
    method,
    headers,
  });
  let data = null;
  const text = await response.text();
  if (text) {
    try { data = JSON.parse(text); } catch { data = { error: text }; }
  }
  if (response.status === 401) {
    me = null;
    renderLogin();
    throw new ApiError('登录已过期', 401, data || {});
  }
  if (!response.ok) {
    throw new ApiError((data && data.error) || response.statusText || '请求失败', response.status, data || {});
  }
  return data;
}

// ---- layout ------------------------------------------------------------

function shell(active, title, body) {
  const nav = [
    ['dash', '#/', '总览'],
    ['clients', '#/clients', '客户端'],
    ['settings', '#/settings', '系统设置'],
    ['audit', '#/audit', '审计日志'],
  ].map(([key, href, label]) =>
    `<a href="${href}" class="${active === key ? 'active' : ''}">${label}</a>`).join('');
  return `<div class="shell">
    <aside class="sidebar">
      <div class="brand">RustVPN Admin</div>
      <nav class="nav">${nav}</nav>
      <div class="foot">
        ${esc(me?.user || '')} · ${esc(me?.role || '')}
        <div style="margin-top:8px"><button data-action="logout">退出登录</button></div>
      </div>
    </aside>
    <main class="main">
      <div class="header"><h2>${esc(title)}</h2><div class="muted small" id="live-status"></div></div>
      <div id="page">${body}</div>
    </main>
  </div>`;
}

// ---- login -------------------------------------------------------------

function renderLogin() {
  clearPoll();
  if (sse) { sse.close(); sse = null; }
  app.innerHTML = `<div class="login-wrap">
    <form class="login" id="login-form">
      <h1>RustVPN</h1>
      <p>管理端登录</p>
      <div class="field"><label>用户名</label>
        <input name="username" autocomplete="username" required autofocus></div>
      <div class="field"><label>口令</label>
        <input name="password" type="password" autocomplete="current-password" required></div>
      <div class="error" id="login-error"></div>
      <button class="primary" type="submit">登录</button>
    </form>
  </div>`;
  document.getElementById('login-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const error = document.getElementById('login-error');
    error.textContent = '';
    const button = form.querySelector('button');
    button.disabled = true;
    try {
      const data = await api('/api/login', {
        method: 'POST',
        body: JSON.stringify({
          username: form.username.value,
          password: form.password.value,
        }),
      });
      me = data;
      connectSse();
      if (!location.hash) location.hash = '#/';
      await route();
    } catch (err) {
      error.textContent = err.message;
    } finally {
      button.disabled = false;
    }
  });
}

async function logout() {
  try { await api('/api/logout', { method: 'POST' }); } catch { /* ignore */ }
  me = null;
  lastTick = null;
  if (sse) { sse.close(); sse = null; }
  renderLogin();
}

// ---- SSE ---------------------------------------------------------------

function connectSse() {
  if (!window.EventSource) return;
  if (sse) sse.close();
  sse = new EventSource('/api/events');
  sse.addEventListener('tick', (event) => {
    try {
      lastTick = JSON.parse(event.data);
      updateLive();
    } catch { /* ignore malformed frame */ }
  });
}

function updateLive() {
  if (!lastTick) return;
  document.querySelectorAll('[data-live]').forEach((el) => {
    const key = el.dataset.live;
    if (key === 'online') el.textContent = lastTick.online;
    if (key === 'rate-in') el.textContent = `${fmtBytes(lastTick.rate_in_bps)}/s`;
    if (key === 'rate-out') el.textContent = `${fmtBytes(lastTick.rate_out_bps)}/s`;
  });
  const sessions = new Map((lastTick.sessions || []).map((s) => [s.peer_id, s]));
  document.querySelectorAll('tr[data-peer]').forEach((row) => {
    const rate = row.querySelector('[data-peer-rate]');
    const session = sessions.get(row.dataset.peer);
    if (rate) {
      rate.textContent = session
        ? `↓ ${fmtBytes(session.rate_in_bps)}/s · ↑ ${fmtBytes(session.rate_out_bps)}/s`
        : '—';
    }
  });
  const status = document.getElementById('live-status');
  if (status) status.textContent = `在线 ${lastTick.online} · ↓ ${fmtBytes(lastTick.rate_in_bps)}/s · ↑ ${fmtBytes(lastTick.rate_out_bps)}/s`;
}

// ---- routing -----------------------------------------------------------

window.addEventListener('hashchange', () => { route(); });

async function route() {
  clearPoll();
  if (!me) {
    try { me = await api('/api/me'); } catch { renderLogin(); return; }
    connectSse();
  }
  const hash = location.hash.replace(/^#/, '') || '/';
  const parts = hash.split('/').filter(Boolean);
  try {
    if (parts[0] === 'clients') await renderClients();
    else if (parts[0] === 'peer' && parts[1]) await renderPeer(parts[1]);
    else if (parts[0] === 'settings') await renderSettings();
    else if (parts[0] === 'audit') await renderAudit();
    else await renderDashboard();
    updateLive();
  } catch (err) {
    if (err.status === 401) return;
    app.innerHTML = shell('dash', '出错了', `<div class="panel"><div class="error">${esc(err.message)}</div></div>`);
  }
}

// ---- dashboard ---------------------------------------------------------

async function renderDashboard() {
  app.innerHTML = `<div class="muted" style="padding:24px">加载中…</div>`;
  const [list, status, events] = await Promise.all([
    api('/api/peers'),
    api('/api/system/status'),
    api('/api/system/events'),
  ]);
  const top = [...list.peers]
    .sort((a, b) => (b.rate_in_bps + b.rate_out_bps) - (a.rate_in_bps + a.rate_out_bps))
    .slice(0, 8);
  const eventRows = (events.events || []).slice().reverse().slice(0, 12).map((event) => `
    <tr>
      <td class="small muted">${fmtTime(event.ts)}</td>
      <td>${esc(event.kind)}</td>
      <td>${esc(event.peer || '—')}</td>
      <td class="small">${esc(event.addr || '')}</td>
      <td class="small muted">${esc(event.detail || '')}</td>
    </tr>`).join('');
  const configOk = !status.config.last_error;
  const serverOnline = status.server_online !== false;
  app.innerHTML = shell('dash', '总览', `
    <div class="cards">
      <div class="card"><div class="label">在线 / 配置</div>
        <div class="value"><span data-live="online">${list.summary.online}</span> / ${list.summary.configured}</div>
        <div class="sub">禁用 ${list.summary.disabled} · 生成 ${status.config.generation}</div></div>
      <div class="card"><div class="label">当前下行（服务器 → 客户端）</div>
        <div class="value" data-live="rate-out">${fmtBytes(list.summary.rate_out_bps)}/s</div>
        <div class="sub">上行 <span data-live="rate-in">${fmtBytes(list.summary.rate_in_bps)}/s</span></div></div>
      <div class="card"><div class="label">今日载荷流量</div>
        <div class="value">${fmtBytes(list.summary.today_payload_in + list.summary.today_payload_out)}</div>
        <div class="sub">入 ${fmtBytes(list.summary.today_payload_in)} · 出 ${fmtBytes(list.summary.today_payload_out)}</div></div>
      <div class="card"><div class="label">服务状态</div>
        <div class="value" style="color:${serverOnline && configOk ? 'var(--ok)' : 'var(--danger)'}">${!serverOnline ? '服务端离线' : configOk ? '正常' : '配置错误'}</div>
        <div class="sub">${!serverOnline ? '控制 socket 不可达' : `运行 ${fmtDuration(status.uptime_seconds)} · ${esc(status.bind)}`}</div></div>
    </div>
    <div class="panel">
      <h3>Top 客户端</h3>
      <table>
        <thead><tr><th>名称</th><th>状态</th><th>地址</th><th class="num">实时速率</th><th class="num">累计</th></tr></thead>
        <tbody>
          ${top.length ? top.map((peer) => `
            <tr data-peer="${esc(peer.id)}">
              <td><a href="#/peer/${esc(peer.id)}">${esc(peer.name)}</a>
                <div class="small muted">${esc(peer.mode)} · MTU ${peer.mtu}</div></td>
              <td>${stateBadge(peer.state)}</td>
              <td class="small">${esc(peer.addr || '—')}</td>
              <td class="num" data-peer-rate>${peer.state === 'online'
                ? `↓ ${fmtBytes(peer.rate_in_bps)}/s · ↑ ${fmtBytes(peer.rate_out_bps)}/s` : '—'}</td>
              <td class="num">${fmtBytes(peer.lifetime.payload_in + peer.lifetime.payload_out)}</td>
            </tr>`).join('') : '<tr><td colspan="5" class="muted">还没有客户端</td></tr>'}
        </tbody>
      </table>
    </div>
    <div class="panel">
      <h3>最近事件</h3>
      <table><thead><tr><th>时间</th><th>类型</th><th>客户端</th><th>地址</th><th>详情</th></tr></thead>
        <tbody>${eventRows || '<tr><td colspan="5" class="muted">暂无事件</td></tr>'}</tbody>
      </table>
    </div>
  `);
  pollTimer = setInterval(async () => {
    try {
      const events = await api('/api/system/events');
      const rows = (events.events || []).slice().reverse().slice(0, 12).map((event) => `
        <tr><td class="small muted">${fmtTime(event.ts)}</td><td>${esc(event.kind)}</td>
        <td>${esc(event.peer || '—')}</td><td class="small">${esc(event.addr || '')}</td>
        <td class="small muted">${esc(event.detail || '')}</td></tr>`).join('');
      const table = document.querySelector('#page .panel:last-child tbody');
      if (table) table.innerHTML = rows || '<tr><td colspan="5" class="muted">暂无事件</td></tr>';
    } catch { /* ignore */ }
  }, 10000);
}

// ---- clients -----------------------------------------------------------

async function renderClients() {
  app.innerHTML = `<div class="muted" style="padding:24px">加载中…</div>`;
  const data = await api('/api/peers');
  peersCache = data.peers;
  app.innerHTML = shell('clients', '客户端', `
    <div class="panel">
      <div class="toolbar">
        <input id="client-q" placeholder="搜索名称 / 地址 / id" value="${esc(clientFilter.q)}">
        <select id="client-state">
          <option value="">全部状态</option>
          <option value="online">在线</option>
          <option value="offline">离线</option>
          <option value="disabled">禁用</option>
          <option value="abnormal">异常</option>
        </select>
        <button data-action="refresh-clients">刷新</button>
        ${canAdmin() ? '<button class="primary" data-action="add-peer">新增客户端</button>' : ''}
      </div>
      <div id="client-summary" class="muted small" style="margin-bottom:10px"></div>
      <div id="client-table"></div>
    </div>
  `);
  const stateSelect = document.getElementById('client-state');
  stateSelect.value = clientFilter.state;
  document.getElementById('client-q').addEventListener('input', (event) => {
    clientFilter.q = event.target.value;
    drawClientTable(data.summary);
  });
  stateSelect.addEventListener('change', (event) => {
    clientFilter.state = event.target.value;
    drawClientTable(data.summary);
  });
  drawClientTable(data.summary);
  pollTimer = setInterval(async () => {
    try {
      const fresh = await api('/api/peers');
      peersCache = fresh.peers;
      drawClientTable(fresh.summary);
    } catch { /* ignore */ }
  }, 10000);
}

function drawClientTable(summary) {
  const summaryEl = document.getElementById('client-summary');
  if (summaryEl && summary) {
    summaryEl.textContent = `在线 ${summary.online} · 已配置 ${summary.configured} · 禁用 ${summary.disabled} · 下行 ${fmtBytes(summary.rate_out_bps)}/s · 上行 ${fmtBytes(summary.rate_in_bps)}/s`;
  }
  const table = document.getElementById('client-table');
  if (!table) return;
  const query = clientFilter.q.trim().toLowerCase();
  const rows = peersCache.filter((peer) => {
    if (clientFilter.state && peer.state !== clientFilter.state) return false;
    if (!query) return true;
    return `${peer.name} ${peer.id} ${peer.addr || ''}`.toLowerCase().includes(query);
  });
  table.innerHTML = `<table>
    <thead><tr>
      <th>名称</th><th>状态</th><th>地址 / 协议</th><th class="num">实时速率</th>
      <th class="num">本月用量</th><th class="num">累计</th><th>最后活跃</th><th>操作</th>
    </tr></thead>
    <tbody>
      ${rows.length ? rows.map((peer) => `
        <tr data-peer="${esc(peer.id)}">
          <td><a href="#/peer/${esc(peer.id)}">${esc(peer.name)}</a>
            <div class="small muted">${esc(peer.mode)} · MTU ${peer.mtu}${peer.notes ? ` · ${esc(peer.notes)}` : ''}</div></td>
          <td>${stateBadge(peer.state)}</td>
          <td class="small">${esc(peer.addr || '—')}<div class="muted">${esc(peer.proto || '')}</div></td>
          <td class="num" data-peer-rate>${peer.state === 'online'
            ? `↓ ${fmtBytes(peer.rate_in_bps)}/s · ↑ ${fmtBytes(peer.rate_out_bps)}/s` : '—'}</td>
          <td class="num">${fmtBytes(peer.month_usage)}${peer.quota_bytes_month
            ? `<div class="small muted">/ ${fmtBytes(peer.quota_bytes_month)}</div>` : ''}</td>
          <td class="num">${fmtBytes(peer.lifetime.payload_in + peer.lifetime.payload_out)}</td>
          <td class="small">${fmtTime(peer.last_ping)}</td>
          <td class="small" style="white-space:nowrap">
            <a href="#/peer/${esc(peer.id)}">详情</a>
            ${canAdmin() && peer.state === 'online' ? `<button data-action="kick" data-id="${esc(peer.id)}" data-name="${esc(peer.name)}">断开</button>` : ''}
            ${canAdmin() && peer.enabled ? `<button data-action="disable" data-id="${esc(peer.id)}" data-name="${esc(peer.name)}">禁用</button>` : ''}
            ${canAdmin() && !peer.enabled ? `<button data-action="enable" data-id="${esc(peer.id)}" data-name="${esc(peer.name)}">启用</button>` : ''}
            ${canAdmin() ? `<button data-action="rotate" data-id="${esc(peer.id)}" data-name="${esc(peer.name)}">轮换</button>` : ''}
          </td>
        </tr>`).join('') : '<tr><td colspan="8" class="muted">没有匹配的客户端</td></tr>'}
    </tbody>
  </table>`;
}

// ---- peer detail -------------------------------------------------------

async function renderPeer(id) {
  app.innerHTML = `<div class="muted" style="padding:24px">加载中…</div>`;
  const [peer, traffic] = await Promise.all([
    api(`/api/peers/${id}`),
    api(`/api/peers/${id}/traffic?range=${currentRange}`),
  ]);
  currentPeer = peer;
  app.innerHTML = shell('clients', `客户端 · ${peer.name}`, `
    <div class="panel">
      <div class="header" style="margin-bottom:12px">
        <div><h3 style="margin:0">${esc(peer.name)} ${stateBadge(peer.state)}</h3>
          <div class="muted small">${esc(peer.id)}</div></div>
        <div style="display:flex;gap:8px;flex-wrap:wrap">
          ${canAdmin() && peer.state === 'online' ? `<button data-action="kick" data-id="${esc(peer.id)}" data-name="${esc(peer.name)}">断开</button>` : ''}
          ${canAdmin() && peer.enabled ? `<button data-action="disable" data-id="${esc(peer.id)}" data-name="${esc(peer.name)}">禁用</button>` : ''}
          ${canAdmin() && !peer.enabled ? `<button data-action="enable" data-id="${esc(peer.id)}" data-name="${esc(peer.name)}">启用</button>` : ''}
          ${canAdmin() ? `<button data-action="edit-peer" data-id="${esc(peer.id)}">编辑</button>` : ''}
          ${canAdmin() ? `<button class="danger" data-action="delete-peer" data-id="${esc(peer.id)}" data-name="${esc(peer.name)}">删除</button>` : ''}
        </div>
      </div>
      <div class="kv">
        <div class="k">状态</div><div>${stateBadge(peer.state)}</div>
        <div class="k">配置</div><div>${esc(peer.mode)} · MTU ${peer.mtu} · TAP ${esc(peer.iface || '—')}</div>
        <div class="k">超时 / 时间同步</div><div>${peer.timeout}s / ${peer.timesync}s</div>
        <div class="k">CPR</div><div>${peer.cpr || 0}</div>
        <div class="k">up / down</div><div class="small">${esc(peer.up || '—')}<br>${esc(peer.down || '—')}</div>
        <div class="k">备注</div><div>${esc(peer.notes || '—')}</div>
        <div class="k">本月用量</div><div>${fmtBytes(peer.month_usage)}${peer.quota_bytes_month ? ` / ${fmtBytes(peer.quota_bytes_month)}` : ''}</div>
        <div class="k">累计载荷</div><div>入 ${fmtBytes(peer.lifetime.payload_in)} · 出 ${fmtBytes(peer.lifetime.payload_out)}</div>
      </div>
    </div>

    <div class="panel">
      <h3>当前会话</h3>
      ${peer.state === 'online' ? `<div class="kv">
        <div class="k">地址</div><div>${esc(peer.addr)} (${esc(peer.proto)})</div>
        <div class="k">建立时间</div><div>${fmtTime(peer.established)}</div>
        <div class="k">在线时长</div><div>${fmtDuration(peer.uptime_seconds)}</div>
        <div class="k">最后收包</div><div>${fmtTime(peer.last_ping)}</div>
        <div class="k">实时速率</div><div>↓ ${fmtBytes(peer.rate_in_bps)}/s · ↑ ${fmtBytes(peer.rate_out_bps)}/s</div>
        <div class="k">线路 / 载荷</div><div>${fmtBytes(peer.session.bytes_in)} / ${fmtBytes(peer.session.payload_in)} 入 ·
          ${fmtBytes(peer.session.bytes_out)} / ${fmtBytes(peer.session.payload_out)} 出</div>
        <div class="k">异常计数</div><div>unauth ${peer.session.unauth} · dup ${peer.session.dup}</div>
      </div>` : '<div class="muted">当前无活跃会话</div>'}
    </div>

    <div class="panel">
      <div style="display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap">
        <h3 style="margin:0">流量</h3>
        <div class="tabs" style="margin:0;border:0">
          ${['1h', '24h', '7d', '30d'].map((range) =>
            `<button data-range="${range}" class="${range === currentRange ? 'active' : ''}">${range}</button>`).join('')}
        </div>
      </div>
      <canvas class="chart" id="traffic-chart"></canvas>
      <div class="legend">
        <span><i class="swatch" style="background:#2563eb"></i>入（服务器接收）</span>
        <span><i class="swatch" style="background:#16a34a"></i>出（服务器发送）</span>
        <span id="traffic-total" class="muted"></span>
      </div>
    </div>

    <div class="panel">
      <h3>会话历史</h3>
      <div id="session-history" class="muted small">加载中…</div>
    </div>
  `);
  const chart = document.getElementById('traffic-chart');
  drawTrafficChart(chart, traffic);
  document.querySelectorAll('[data-range]').forEach((button) => {
    button.addEventListener('click', async () => {
      currentRange = button.dataset.range;
      document.querySelectorAll('[data-range]').forEach((b) => b.classList.toggle('active', b === button));
      try {
        const fresh = await api(`/api/peers/${id}/traffic?range=${currentRange}`);
        drawTrafficChart(chart, fresh);
      } catch (err) { toast(err.message, 'error'); }
    });
  });
  loadSessionHistory(id);
}

async function loadSessionHistory(id) {
  try {
    const data = await api(`/api/peers/${id}/sessions?limit=50`);
    const el = document.getElementById('session-history');
    if (!el) return;
    const rows = (data.sessions || []).map((session) => `
      <tr>
        <td class="small">${fmtTime(session.started_at)}</td>
        <td class="small">${session.ended_at ? fmtTime(session.ended_at) : '<span class="badge online">进行中</span>'}</td>
        <td class="small">${esc(session.end_reason || '—')}</td>
        <td class="small">${esc(session.addr || '—')} (${esc(session.proto)})</td>
        <td class="num">${fmtBytes(session.counters.payload_in)} / ${fmtBytes(session.counters.payload_out)}</td>
      </tr>`).join('');
    el.className = '';
    el.innerHTML = `<table><thead><tr><th>开始</th><th>结束</th><th>原因</th><th>地址</th><th class="num">载荷 入 / 出</th></tr></thead>
      <tbody>${rows || '<tr><td colspan="5" class="muted">暂无会话记录</td></tr>'}</tbody></table>`;
  } catch (err) {
    const el = document.getElementById('session-history');
    if (el) el.innerHTML = `<span class="error">${esc(err.message)}</span>`;
  }
}

function drawTrafficChart(canvas, data) {
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const dpr = window.devicePixelRatio || 1;
  const width = canvas.clientWidth || 800;
  const height = canvas.clientHeight || 260;
  canvas.width = Math.round(width * dpr);
  canvas.height = Math.round(height * dpr);
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, width, height);

  const series = data.series || [];
  const totalEl = document.getElementById('traffic-total');
  if (totalEl) {
    totalEl.textContent = `区间：入 ${fmtBytes(data.totals?.payload_in || 0)} · 出 ${fmtBytes(data.totals?.payload_out || 0)}`;
  }
  if (!series.length) {
    ctx.fillStyle = '#888';
    ctx.font = '14px system-ui';
    ctx.fillText('该时间范围内没有采样数据', 16, 32);
    return;
  }

  const pad = { left: 56, right: 16, top: 16, bottom: 26 };
  const plotW = width - pad.left - pad.right;
  const plotH = height - pad.top - pad.bottom;
  const points = series.map((point) => ({
    x: point.ts,
    a: point.payload_in || 0,
    b: point.payload_out || 0,
  }));
  const minX = Math.min(...points.map((p) => p.x));
  const maxX = Math.max(...points.map((p) => p.x));
  const maxY = Math.max(1, ...points.map((p) => Math.max(p.a, p.b)));
  const xOf = (x) => pad.left + (maxX === minX ? plotW / 2 : ((x - minX) / (maxX - minX)) * plotW);
  const yOf = (y) => pad.top + plotH - (y / maxY) * plotH;

  ctx.strokeStyle = 'rgba(128,128,128,.18)';
  ctx.lineWidth = 1;
  ctx.fillStyle = '#888';
  ctx.font = '11px system-ui';
  for (let i = 0; i <= 4; i++) {
    const y = pad.top + (plotH / 4) * i;
    ctx.beginPath();
    ctx.moveTo(pad.left, y);
    ctx.lineTo(width - pad.right, y);
    ctx.stroke();
    const value = maxY * (1 - i / 4);
    ctx.fillText(fmtBytes(value), 4, y + 4);
  }
  ctx.fillText(fmtTime(minX), pad.left, height - 8);
  const endLabel = fmtTime(maxX);
  ctx.fillText(endLabel, width - pad.right - ctx.measureText(endLabel).width, height - 8);

  const line = (key, color) => {
    ctx.beginPath();
    points.forEach((point, index) => {
      const x = xOf(point.x);
      const y = yOf(point[key]);
      if (index === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.strokeStyle = color;
    ctx.lineWidth = 2;
    ctx.stroke();
  };
  line('a', '#2563eb');
  line('b', '#16a34a');
}

// ---- settings ---------------------------------------------------------

async function renderSettings() {
  app.innerHTML = `<div class="muted" style="padding:24px">加载中…</div>`;
  const [config, backups] = await Promise.all([
    api('/api/system/config'),
    api('/api/system/backups'),
  ]);
  configEtag = config.etag;
  const backupRows = (backups.backups || []).map((backup) => `
    <tr><td class="small">${esc(backup.name)}</td><td class="num">${fmtBytes(backup.size)}</td>
      <td class="small">${fmtTime(backup.modified)}</td>
      <td>${canAdmin() ? `<button data-action="restore-backup" data-name="${esc(backup.name)}">恢复</button>` : ''}</td></tr>`).join('');
  app.innerHTML = shell('settings', '系统设置', `
    <div class="panel">
      <h3>配置状态</h3>
      <div class="kv">
        <div class="k">peers.yaml</div><div class="small">${esc(config.config_status.path)}</div>
        <div class="k">禁用配置</div><div class="small">${esc(config.config_status.disabled_path)}</div>
        <div class="k">generation</div><div>${config.generation}</div>
        <div class="k">ETag</div><div class="small" style="word-break:break-all">${esc(config.etag)}</div>
        <div class="k">上次加载</div><div>${fmtTime(config.config_status.last_loaded_at)}</div>
        <div class="k">错误</div><div class="${config.config_status.last_error ? 'error' : 'muted'}">${esc(config.config_status.last_error || '无')}</div>
      </div>
      ${(config.warnings || []).length ? `<div class="error">${config.warnings.map(esc).join('<br>')}</div>` : ''}
    </div>
    <div class="panel">
      <h3>peers.yaml（启用）</h3>
      <textarea id="config-enabled" spellcheck="false">${esc(config.enabled_yaml)}</textarea>
    </div>
    <div class="panel">
      <h3>peers.disabled.yaml（禁用）</h3>
      <textarea id="config-disabled" spellcheck="false">${esc(config.disabled_yaml)}</textarea>
    </div>
    <div class="panel">
      <div class="toolbar">
        ${canAdmin() ? '<button data-action="preview-config">预览变更</button>' : ''}
        ${canAdmin() ? '<button class="primary" data-action="apply-config">应用配置</button>' : ''}
        <button data-action="reload-config">从磁盘重新加载</button>
      </div>
      <div id="config-preview" class="muted small"></div>
    </div>
    <div class="panel">
      <h3>备份</h3>
      <table><thead><tr><th>文件</th><th class="num">大小</th><th>时间</th><th>操作</th></tr></thead>
        <tbody>${backupRows || '<tr><td colspan="4" class="muted">暂无备份</td></tr>'}</tbody></table>
    </div>
  `);
  document.querySelector('[data-action="preview-config"]')?.addEventListener('click', previewConfig);
  document.querySelector('[data-action="apply-config"]')?.addEventListener('click', applyConfig);
  document.querySelector('[data-action="reload-config"]')?.addEventListener('click', () => { route(); });
}

async function previewConfig() {
  const enabled_yaml = document.getElementById('config-enabled').value;
  const disabled_yaml = document.getElementById('config-disabled').value;
  const target = document.getElementById('config-preview');
  try {
    const report = await api('/api/system/config/preview', {
      method: 'POST',
      body: JSON.stringify({ enabled_yaml, disabled_yaml }),
    });
    target.innerHTML = `<div class="kv">
      <div class="k">有效</div><div>${report.valid ? '<span class="badge online">是</span>' : '<span class="badge abnormal">否</span>'}</div>
      <div class="k">新增</div><div>${esc((report.added || []).join(', ') || '—')}</div>
      <div class="k">删除</div><div>${esc((report.removed || []).join(', ') || '—')}</div>
      <div class="k">变更</div><div>${esc((report.changed || []).join(', ') || '—')}</div>
      <div class="k">将吊销会话</div><div>${esc((report.revoked || []).join(', ') || '—')}</div>
      <div class="k">警告</div><div>${esc((report.warnings || []).join('; ') || '—')}</div>
      <div class="k">错误</div><div class="${report.errors?.length ? 'error' : ''}">${esc((report.errors || []).join('; ') || '—')}</div>
    </div>`;
  } catch (err) {
    target.innerHTML = `<span class="error">${esc(err.message)}</span>`;
  }
}

async function applyConfig() {
  const enabled_yaml = document.getElementById('config-enabled').value;
  const disabled_yaml = document.getElementById('config-disabled').value;
  const comment = window.prompt('变更说明（写入审计）', 'manual edit');
  if (comment === null) return;
  if (!window.confirm('应用配置会立即重载并吊销受影响会话，继续？')) return;
  try {
    const report = await api('/api/system/config', {
      method: 'PUT',
      body: JSON.stringify({
        enabled_yaml,
        disabled_yaml,
        expected_etag: currentConfigEtag(),
        comment,
      }),
    });
    toast(`配置已应用，generation ${report.generation}`);
    await route();
  } catch (err) {
    if (err.status === 409) {
      toast(`配置已在磁盘变化，请重新加载。当前 etag: ${err.data.current_etag || ''}`, 'error');
    } else {
      toast(err.message, 'error');
    }
  }
}

let configEtag = '';
function currentConfigEtag() { return configEtag; }

// ---- audit -------------------------------------------------------------

async function renderAudit() {
  app.innerHTML = `<div class="muted" style="padding:24px">加载中…</div>`;
  const data = await api('/api/audit?limit=200');
  const rows = (data.audit || []).map((row) => `
    <tr>
      <td class="small muted">${fmtTime(row.ts)}</td>
      <td>${esc(row.user)}</td>
      <td class="small">${esc(row.ip)}</td>
      <td>${esc(row.action)}</td>
      <td class="small">${esc(row.target)}</td>
      <td class="small muted" style="max-width:420px;word-break:break-all">${esc(row.detail)}</td>
      <td>${esc(row.result)}</td>
    </tr>`).join('');
  app.innerHTML = shell('audit', '审计日志', `
    <div class="panel">
      <table><thead><tr><th>时间</th><th>用户</th><th>来源</th><th>动作</th><th>对象</th><th>详情</th><th>结果</th></tr></thead>
        <tbody>${rows || '<tr><td colspan="7" class="muted">暂无记录</td></tr>'}</tbody></table>
    </div>
  `);
}

// ---- peer actions ------------------------------------------------------

async function addPeer() {
  const html = `<h3>新增客户端</h3>
    <form id="peer-add-form">
      <div class="row">
        <div class="field"><label>名称</label><input name="name" required autofocus placeholder="alice"></div>
        <div class="field"><label>接口名</label><input name="iface" value="rsvpn1"></div>
      </div>
      <div class="row">
        <div class="field"><label>MTU</label><input name="mtu" type="number" value="1515"></div>
        <div class="field"><label>timeout（秒）</label><input name="timeout" type="number" value="60"></div>
        <div class="field"><label>CPR（KiB/s）</label><input name="cpr" type="number" value="0"></div>
        <div class="field"><label>timesync（秒）</label><input name="timesync" type="number" value="0"></div>
      </div>
      <div class="row">
        <div class="field"><label><input type="checkbox" name="noise" style="width:auto"> noise</label></div>
        <div class="field"><label><input type="checkbox" name="encless" style="width:auto"> encless（TCP）</label></div>
        <div class="field"><label>月配额（GiB，0=不限）</label><input name="quota_gib" type="number" value="0" step="0.1"></div>
      </div>
      <div class="row">
        <div class="field"><label>up 脚本（可选）</label><input name="up" placeholder="/etc/rustvpn/up.sh"></div>
        <div class="field"><label>down 脚本（可选）</label><input name="down" placeholder="/etc/rustvpn/down.sh"></div>
      </div>
      <div class="field"><label>备注</label><input name="notes"></div>
      <div class="field"><label><input type="checkbox" name="generate" style="width:auto" checked> 自动生成口令</label></div>
      <div class="field"><label>口令（不自动生成时必填，至少 12 位）</label><input name="password" type="password"></div>
      <div class="field"><label>或导入长格式 verifier（可选，填了则忽略口令）</label>
        <textarea name="import_verifier" style="min-height:70px"></textarea></div>
      <div class="error" id="peer-add-error"></div>
      <div class="modal-actions">
        <button type="button" data-close>取消</button>
        <button class="primary" type="submit">创建</button>
      </div>
    </form>`;
  showModal(html);
  const form = document.getElementById('peer-add-form');
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const error = document.getElementById('peer-add-error');
    error.textContent = '';
    const quotaGiB = Number(form.quota_gib.value || 0);
    const importVerifier = form.import_verifier.value.trim();
    const payload = {
      name: form.name.value.trim(),
      iface: form.iface.value.trim(),
      mtu: Number(form.mtu.value || 1515),
      timeout: Number(form.timeout.value || 60),
      cpr: Number(form.cpr.value || 0),
      timesync: Number(form.timesync.value || 0),
      noise: form.noise.checked,
      encless: form.encless.checked,
      notes: form.notes.value.trim() || null,
      quota_bytes_month: quotaGiB > 0 ? Math.round(quotaGiB * 1024 * 1024 * 1024) : null,
      generate_password: form.generate.checked,
      password: form.generate.checked ? null : (form.password.value || null),
      up: form.up.value.trim(),
      down: form.down.value.trim(),
    };
    if (importVerifier) payload.import_long_verifier = importVerifier;
    try {
      const result = await api('/api/peers', { method: 'POST', body: JSON.stringify(payload) });
      closeModal();
      showCredential(result, '客户端已创建');
      await route();
    } catch (err) {
      error.textContent = err.message;
    }
  });
}

async function editPeer(id) {
  const peer = currentPeer && currentPeer.id === id ? currentPeer : await api(`/api/peers/${id}`);
  const html = `<h3>编辑客户端 · ${esc(peer.name)}</h3>
    <form id="peer-edit-form">
      <div class="row">
        <div class="field"><label>名称</label><input name="name" value="${esc(peer.name)}" required></div>
        <div class="field"><label>接口名</label><input name="iface" value="${esc(peer.iface)}"></div>
      </div>
      <div class="row">
        <div class="field"><label>MTU</label><input name="mtu" type="number" value="${peer.mtu}"></div>
        <div class="field"><label>timeout（秒）</label><input name="timeout" type="number" value="${peer.timeout}"></div>
        <div class="field"><label>CPR（KiB/s）</label><input name="cpr" type="number" value="${peer.cpr}"></div>
        <div class="field"><label>timesync（秒）</label><input name="timesync" type="number" value="${peer.timesync}"></div>
      </div>
      <div class="row">
        <div class="field"><label><input type="checkbox" name="noise" style="width:auto" ${peer.noise ? 'checked' : ''}> noise</label></div>
        <div class="field"><label><input type="checkbox" name="encless" style="width:auto" ${peer.encless ? 'checked' : ''}> encless</label></div>
        <div class="field"><label>月配额（GiB，0=不限）</label>
          <input name="quota_gib" type="number" step="0.1" value="${peer.quota_bytes_month ? (peer.quota_bytes_month / 1073741824).toFixed(2) : 0}"></div>
      </div>
      <div class="row">
        <div class="field"><label>up 脚本</label><input name="up" value="${esc(peer.up)}"></div>
        <div class="field"><label>down 脚本</label><input name="down" value="${esc(peer.down)}"></div>
      </div>
      <div class="field"><label>备注</label><input name="notes" value="${esc(peer.notes || '')}"></div>
      <div class="error" id="peer-edit-error"></div>
      <div class="modal-actions"><button type="button" data-close>取消</button>
        <button class="primary" type="submit">保存</button></div>
    </form>`;
  showModal(html);
  const form = document.getElementById('peer-edit-form');
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const error = document.getElementById('peer-edit-error');
    error.textContent = '';
    const quotaGiB = Number(form.quota_gib.value || 0);
    const payload = {
      name: form.name.value.trim(),
      iface: form.iface.value.trim(),
      mtu: Number(form.mtu.value || 1515),
      timeout: Number(form.timeout.value || 60),
      cpr: Number(form.cpr.value || 0),
      timesync: Number(form.timesync.value || 0),
      noise: form.noise.checked,
      encless: form.encless.checked,
      notes: form.notes.value.trim(),
      quota_bytes_month: quotaGiB > 0 ? Math.round(quotaGiB * 1073741824) : 0,
      up: form.up.value.trim(),
      down: form.down.value.trim(),
    };
    try {
      await api(`/api/peers/${id}`, { method: 'PATCH', body: JSON.stringify(payload) });
      closeModal();
      toast('已保存');
      await route();
    } catch (err) {
      error.textContent = err.message;
    }
  });
}

async function rotatePeer(id, name) {
  const html = `<h3>轮换凭据 · ${esc(name)}</h3>
    <p class="muted small">服务端会生成新的公钥并吊销当前会话；身份 id 保持不变，因此历史流量仍归到该客户端。</p>
    <form id="rotate-form">
      <div class="field"><label><input type="checkbox" name="generate" style="width:auto" checked> 自动生成新口令</label></div>
      <div class="field"><label>新口令（不自动生成时填写，至少 12 位）</label><input name="password" type="password"></div>
      <div class="error" id="rotate-error"></div>
      <div class="modal-actions"><button type="button" data-close>取消</button>
        <button class="primary" type="submit">轮换</button></div>
    </form>`;
  showModal(html);
  const form = document.getElementById('rotate-form');
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const error = document.getElementById('rotate-error');
    error.textContent = '';
    try {
      const result = await api(`/api/peers/${id}/rotate`, {
        method: 'POST',
        body: JSON.stringify({
          generate_password: form.generate.checked,
          password: form.generate.checked ? null : (form.password.value || null),
        }),
      });
      closeModal();
      showCredential(result, '凭据已轮换');
      await route();
    } catch (err) {
      error.textContent = err.message;
    }
  });
}

async function kickPeer(id, name) {
  if (!window.confirm(`立即断开 ${name} 的当前会话？客户端会自动重连。`)) return;
  const reason = window.prompt('断开原因（写入审计）', 'admin_kick');
  if (reason === null) return;
  try {
    await api(`/api/peers/${id}/kick`, { method: 'POST', body: JSON.stringify({ reason }) });
    toast('已断开');
    await route();
  } catch (err) {
    toast(err.message, 'error');
  }
}

async function setEnabled(id, name, enabled) {
  const action = enabled ? '启用' : '禁用';
  if (!window.confirm(`${action} ${name}？${enabled ? '' : '当前会话会被立即吊销。'}`)) return;
  try {
    await api(`/api/peers/${id}/${enabled ? 'enable' : 'disable'}`, { method: 'POST', body: '{}' });
    toast(`已${action}`);
    await route();
  } catch (err) {
    toast(err.message, 'error');
  }
}

async function deletePeer(id, name) {
  if (!window.confirm(`删除 ${name}？这会从配置中移除并吊销会话。`)) return;
  const purge = window.confirm('同时删除该客户端的历史流量与审计元数据？\n选择“取消”则保留历史。');
  try {
    await api(`/api/peers/${id}?purge_history=${purge ? 'true' : 'false'}`, { method: 'DELETE' });
    toast('已删除');
    location.hash = '#/clients';
  } catch (err) {
    toast(err.message, 'error');
  }
}

async function restoreBackup(name) {
  if (!window.confirm(`恢复备份 ${name}？`)) return;
  try {
    await api('/api/system/backups/restore', { method: 'POST', body: JSON.stringify({ name, comment: 'restore backup' }) });
    toast('已恢复并重载');
    await route();
  } catch (err) {
    toast(err.message, 'error');
  }
}

// ---- modal -------------------------------------------------------------

let modalRoot = null;

function showModal(html) {
  closeModal();
  modalRoot = document.createElement('div');
  modalRoot.className = 'modal-backdrop';
  modalRoot.innerHTML = `<div class="modal">${html}</div>`;
  document.body.appendChild(modalRoot);
  modalRoot.addEventListener('click', (event) => {
    if (event.target === modalRoot) closeModal();
  });
  modalRoot.querySelectorAll('[data-close]').forEach((button) => {
    button.addEventListener('click', closeModal);
  });
}

function closeModal() {
  if (modalRoot) { modalRoot.remove(); modalRoot = null; }
}

function showCredential(data, title) {
  const password = data.password ? `<div class="field"><label>口令（只显示一次）</label><div class="secret">${esc(data.password)}</div></div>` : '';
  showModal(`<h3>${esc(title)}</h3>
    <p class="muted small">关闭后无法再次查看口令。请立即复制并交给客户端使用者。</p>
    <div class="field"><label>客户端名称</label><div class="secret">${esc(data.name)}</div></div>
    ${password}
    <div class="field"><label>短格式 verifier</label><div class="secret">${esc(data.short_verifier)}</div></div>
    <div class="field"><label>client.env</label><div class="secret">${esc(data.client_env)}</div></div>
    <div class="field"><label>客户端命令示例</label><div class="secret">${esc(data.client_command)}</div></div>
    <div class="modal-actions"><button class="primary" data-close>我已保存</button></div>`);
}

// ---- event delegation --------------------------------------------------

document.addEventListener('click', async (event) => {
  const target = event.target.closest('[data-action]');
  if (!target) return;
  const action = target.dataset.action;
  const id = target.dataset.id;
  const name = target.dataset.name;
  try {
    if (action === 'logout') await logout();
    else if (action === 'refresh-clients') await route();
    else if (action === 'add-peer') await addPeer();
    else if (action === 'kick') await kickPeer(id, name);
    else if (action === 'disable') await setEnabled(id, name, false);
    else if (action === 'enable') await setEnabled(id, name, true);
    else if (action === 'rotate') await rotatePeer(id, name);
    else if (action === 'edit-peer') await editPeer(id);
    else if (action === 'delete-peer') await deletePeer(id, name);
    else if (action === 'restore-backup') await restoreBackup(target.dataset.name);
  } catch (err) {
    toast(err.message, 'error');
  }
});

document.addEventListener('keydown', (event) => {
  if (event.key === 'Escape') closeModal();
});

// ---- boot --------------------------------------------------------------

route();