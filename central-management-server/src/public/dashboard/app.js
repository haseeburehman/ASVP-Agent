import { applicationMetrics, describeCheck, latestCollectorState } from './posture-data.js';

const $ = (id) => document.getElementById(id);
const escapeHtml = (value) => String(value ?? '').replace(/[&<>"']/g, (character) => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
})[character]);
const formatTime = (value) => value ? new Date(value).toLocaleString() : 'Never';
const relativeTime = (value) => {
  if (!value) return 'never';
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(value).getTime()) / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
};
const jsonBlock = (value, className = '') => `<pre class="json ${className}"><code>${escapeHtml(JSON.stringify(value, null, 2))}</code></pre>`;
const statusLabels = { online: 'Online', stale: 'Stale', 'never-connected': 'Never connected', deregistered: 'Deregistered' };
const statusIcon = { online: '●', stale: '!', 'never-connected': '○', deregistered: '×' };
const eventPageSize = 25;
const routineTypes = new Set(['heartbeat', 'poll']);
const meaningfulTypes = new Set(['register', 'task-created', 'result', 'result-received', 'deregister', 'deregistered', 'status-transition']);

let socket;
let reconnectTimer;
let fallbackTimer;
let fleetAgents = [];
let detailData = null;
const liveEventsByAgent = new Map();
let selectedAgentId = location.pathname.match(/^\/fleet\/agents\/(.+)$/)?.[1] ?? null;
const viewState = {
  tab: 'overview', eventLimit: eventPageSize, routineTypesVisible: new Set(),
  eventTypes: new Set(['register', 'task-created', 'result', 'result-received', 'deregister', 'deregistered', 'status-transition', 'other']),
};

async function api(url, options) {
  const response = await fetch(url, { ...options, headers: { 'content-type': 'application/json', ...(options?.headers ?? {}) } });
  if (response.status === 401) {
    $('dashboard').hidden = true;
    $('login').hidden = false;
    throw new Error('Authentication required');
  }
  if (!response.ok) throw new Error((await response.json()).error ?? response.statusText);
  return response.status === 204 ? null : response.json();
}

function statusBadge(status) {
  return `<span class="status-badge ${escapeHtml(status)}"><i>${statusIcon[status] ?? '•'}</i>${escapeHtml(statusLabels[status] ?? status)}</span>`;
}

function renderSummary(agents) {
  const count = (state) => agents.filter((agent) => agent.status === state).length;
  const values = {
    online: count('online'), stale: count('stale'),
    'never-connected': count('never-connected'), deregistered: count('deregistered'),
  };
  const total = agents.length || 1;
  const onlineEnd = values.online / total * 360;
  const staleEnd = onlineEnd + values.stale / total * 360;
  const neverEnd = staleEnd + values['never-connected'] / total * 360;
  const chart = `conic-gradient(var(--online) 0deg ${onlineEnd}deg,var(--stale) ${onlineEnd}deg ${staleEnd}deg,var(--never) ${staleEnd}deg ${neverEnd}deg,var(--deregistered) ${neverEnd}deg 360deg)`;
  $('summary').innerHTML = `<article class="panel health-overview"><div class="donut" style="--chart:${chart}"><div><strong>${agents.length}</strong><span>Total</span></div></div><div><p class="eyebrow">Current coverage</p><h3>${values.online} of ${agents.length} endpoints online</h3><p>Live endpoint availability across the managed fleet.</p></div></article>${Object.entries(values).map(([state, value]) => `<article class="panel metric ${state}"><div class="metric-icon">${statusIcon[state]}</div><div><span>${statusLabels[state]}</span><strong>${value}</strong><small>${agents.length ? Math.round(value / agents.length * 100) : 0}% of fleet</small></div></article>`).join('')}`;
}

const statusOrder = { stale: 0, 'never-connected': 1, online: 2, deregistered: 3 };
function renderFleetTable() {
  const query = $('agent-search').value.trim().toLowerCase();
  const sort = $('agent-sort').value;
  const filtered = fleetAgents.filter((agent) => `${agent.hostname} ${agent.id} ${agent.platform} ${agent.architecture}`.toLowerCase().includes(query));
  filtered.sort((a, b) => {
    if (sort === 'hostname') return (a.hostname ?? '').localeCompare(b.hostname ?? '');
    if (sort === 'heartbeat') return new Date(b.last_heartbeat_at ?? 0) - new Date(a.last_heartbeat_at ?? 0);
    return (statusOrder[a.status] ?? 9) - (statusOrder[b.status] ?? 9) || (a.hostname ?? '').localeCompare(b.hostname ?? '');
  });
  $('agent-count').textContent = `${filtered.length} of ${fleetAgents.length} endpoints`;
  $('fleet-empty').hidden = filtered.length > 0;
  $('agents').innerHTML = filtered.map((agent) => `<tr data-id="${escapeHtml(agent.id)}" tabindex="0"><td><div class="endpoint"><span class="endpoint-avatar">${escapeHtml((agent.hostname || '?').slice(0, 1).toUpperCase())}</span><div><strong>${escapeHtml(agent.hostname || 'Unknown')}</strong><small>Managed endpoint</small></div></div></td><td>${escapeHtml([agent.platform, agent.architecture].filter(Boolean).join(' / ') || 'Unknown')}</td><td><code class="agent-id">${escapeHtml(agent.id)}</code></td><td>${statusBadge(agent.status)}</td><td><span title="${escapeHtml(formatTime(agent.last_heartbeat_at))}">${escapeHtml(relativeTime(agent.last_heartbeat_at))}</span></td><td><span title="${escapeHtml(formatTime(agent.last_poll_at))}">${escapeHtml(relativeTime(agent.last_poll_at))}</span></td></tr>`).join('');
  document.querySelectorAll('#agents tr').forEach((row) => {
    const open = () => loadDetail(row.dataset.id);
    row.onclick = open;
    row.onkeydown = (event) => { if (event.key === 'Enter' || event.key === ' ') open(); };
  });
}

async function loadFleet() {
  const data = await api('/api/dashboard/fleet');
  $('login').hidden = true;
  $('dashboard').hidden = false;
  $('threshold').textContent = `Online requires a heartbeat within ${data.onlineThresholdMs / 1000}s.`;
  $('updated').textContent = `Updated ${new Date(data.generatedAt).toLocaleTimeString()}`;
  fleetAgents = data.agents;
  renderSummary(fleetAgents);
  renderFleetTable();
}

const postureIcons = { os: '▣', apps: '◇', users: '♙', antivirus: '◆', compliance: '⬡' };
function postureCard(key, title, status, body, raw) {
  return `<article class="posture-card state-${escapeHtml(status)}"><div class="posture-heading"><span class="posture-icon">${postureIcons[key]}</span><div><p class="eyebrow">${escapeHtml(status)}</p><h3>${escapeHtml(title)}</h3></div><span class="posture-state">${escapeHtml(status)}</span></div><div class="posture-body">${body}</div><details class="raw-toggle"><summary>View raw JSON</summary>${jsonBlock(raw)}</details></article>`;
}

function postureBody(entry, content = '') {
  const error = entry.error ? `<p class="inline-error"><strong>Error:</strong> ${escapeHtml(typeof entry.error === 'string' ? entry.error : JSON.stringify(entry.error))}</p>` : '';
  if (entry.result) return error + (content || '<p>No posture data was returned.</p>');
  if (entry.state === 'pending') return '<p>Waiting for baseline result.</p>';
  if (entry.state === 'failed') return error || '<p>The baseline task failed before returning a result.</p>';
  if (entry.state === 'missing') return '<p>The baseline task completed without a result.</p>';
  return '<p>No baseline task has been scheduled.</p>';
}

function renderPosture(results, tasks) {
  const osEntry = latestCollectorState(results, tasks, 'os-info');
  const appsEntry = latestCollectorState(results, tasks, 'apps');
  const usersEntry = latestCollectorState(results, tasks, 'users-groups');
  const antivirusEntry = latestCollectorState(results, tasks, 'antivirus-status');
  const complianceEntry = latestCollectorState(results, tasks, 'compliance-checks');
  const os = osEntry.payload; const apps = appsEntry.payload; const users = usersEntry.payload;
  const antivirus = antivirusEntry.payload; const compliance = complianceEntry.payload;
  const appMetrics = applicationMetrics(apps);
  const userItems = users?.users?.items ?? []; const groups = users?.groups?.items ?? [];
  const privileged = groups.filter((group) => /^(administrators|admin|wheel|sudo)$/i.test(group.name));
  const patchItems = os?.patches?.items;
  const accountStatusWarning = users?.users?.accountStatus && users.users.accountStatus !== 'available'
    ? `<p class="inline-error"><strong>Account status: ${escapeHtml(users.users.accountStatus)}</strong> — ${escapeHtml(users.users.reason ?? 'Lock and password-expiry state could not be collected.')}</p>`
    : '';
  return [
    postureCard('os', 'Operating system & patches', osEntry.state, postureBody(osEntry, os ? `<dl><dt>OS</dt><dd>${escapeHtml(os.prettyName)}</dd><dt>Version</dt><dd>${escapeHtml(os.version)}</dd><dt>Architecture</dt><dd>${escapeHtml(os.architecture)}</dd><dt>Recent patches</dt><dd>${Array.isArray(patchItems) ? patchItems.length : 'Undetermined'}</dd></dl>` : ''), osEntry.result ?? osEntry.task),
    postureCard('apps', 'Applications', appsEntry.state, postureBody(appsEntry, apps ? `<p class="large-stat"><strong>${escapeHtml(appMetrics.totalDetected)}</strong> applications reported</p>${appMetrics.truncated ? `<p>${escapeHtml(appMetrics.shown)} shown, ${escapeHtml(appMetrics.truncated)} truncated.</p>` : ''}` : ''), appsEntry.result ?? appsEntry.task),
    postureCard('users', 'Users & privileged groups', usersEntry.state, postureBody(usersEntry, users ? `<p><strong>${userItems.length}</strong> local users · <strong>${groups.length}</strong> groups</p>${accountStatusWarning}${privileged.map((group) => `<p><b>${escapeHtml(group.name)}:</b> ${escapeHtml((group.members ?? []).map((member) => typeof member === 'string' ? member : member.name).join(', ') || 'No explicit members')}</p>`).join('') || '<p>No standard privileged group was reported.</p>'}` : ''), usersEntry.result ?? usersEntry.task),
    postureCard('antivirus', 'Antivirus / endpoint protection', antivirusEntry.state, postureBody(antivirusEntry, antivirus ? `<p>${escapeHtml(antivirus.reason ?? 'Status reported successfully.')}</p><ul>${(antivirus.products ?? []).map((product) => `<li>${escapeHtml(product.name)} — ${product.enabled === true ? 'enabled' : product.enabled === false ? 'disabled' : 'state unknown'}</li>`).join('')}</ul>` : ''), antivirusEntry.result ?? antivirusEntry.task),
    postureCard('compliance', 'Firewall & compliance', complianceEntry.state, postureBody(complianceEntry, compliance ? `<dl><dt>Firewall</dt><dd>${escapeHtml(describeCheck(compliance.firewall, (active) => active === true ? 'active' : active === false ? 'inactive' : null))}</dd><dt>SSH root login</dt><dd>${escapeHtml(describeCheck(compliance.ssh?.permitRootLogin))}</dd><dt>SSH password auth</dt><dd>${escapeHtml(describeCheck(compliance.ssh?.passwordAuthentication))}</dd><dt>UAC</dt><dd>${escapeHtml(describeCheck(compliance.uac, (value) => value?.name ?? value?.level ?? value))}</dd></dl>` : ''), complianceEntry.result ?? complianceEntry.task),
  ].join('');
}

function eventCategory(event) {
  if (routineTypes.has(event.event_type)) return event.event_type;
  return meaningfulTypes.has(event.event_type) ? event.event_type : 'other';
}

function eventCard(event) {
  const category = eventCategory(event);
  return `<article class="event-card type-${escapeHtml(category)}"><div class="event-node"></div><div class="event-content"><div class="event-heading"><strong>${escapeHtml(event.event_type)}</strong><time title="${escapeHtml(formatTime(event.created_at))}">${escapeHtml(relativeTime(event.created_at))}</time></div>${jsonBlock(event.details, 'event-json')}</div></article>`;
}

function renderActivity() {
  const events = detailData.events ?? [];
  const hourAgo = Date.now() - 3600000;
  const recentRoutine = events.filter((event) => routineTypes.has(event.event_type) && new Date(event.created_at).getTime() >= hourAgo);
  const heartbeats = recentRoutine.filter((event) => event.event_type === 'heartbeat');
  const polls = recentRoutine.filter((event) => event.event_type === 'poll');
  const emptyPolls = polls.filter((event) => Number(event.details?.taskCount ?? 0) === 0);
  const lastHeartbeat = heartbeats[0]?.created_at ?? detailData.agent.last_heartbeat_at;
  const filtered = events.filter((event) => {
    const category = eventCategory(event);
    if (routineTypes.has(category)) return viewState.routineTypesVisible.has(category);
    return viewState.eventTypes.has(category);
  });
  const visible = filtered.slice(0, viewState.eventLimit);
  const remaining = Math.max(0, filtered.length - visible.length);
  const routineSummary = `<details class="routine-summary"><summary><span class="summary-icon">↻</span><span><strong>${heartbeats.length} heartbeats, ${emptyPolls.length} empty polls in the last hour</strong><small>Last heartbeat ${escapeHtml(relativeTime(lastHeartbeat))} · expand to inspect raw routine activity</small></span></summary>${recentRoutine.length ? `<div class="routine-list">${recentRoutine.slice(0, 50).map(eventCard).join('')}${recentRoutine.length > 50 ? '<p>Showing the latest 50 routine events from this hour.</p>' : ''}</div>` : '<p>No routine activity in the last hour.</p>'}</details>`;
  return `<div class="activity-toolbar"><div class="filter-group" role="group" aria-label="Event filters"><label><input type="checkbox" data-event-filter="heartbeat" ${viewState.routineTypesVisible.has('heartbeat') ? 'checked' : ''}> Heartbeats</label><label><input type="checkbox" data-event-filter="poll" ${viewState.routineTypesVisible.has('poll') ? 'checked' : ''}> Polls</label><label><input type="checkbox" data-event-filter="result" ${viewState.eventTypes.has('result') ? 'checked' : ''}> Results</label><label><input type="checkbox" data-event-filter="task-created" ${viewState.eventTypes.has('task-created') ? 'checked' : ''}> Tasks</label><label><input type="checkbox" data-event-filter="register" ${viewState.eventTypes.has('register') ? 'checked' : ''}> Registration</label><label><input type="checkbox" data-event-filter="other" ${viewState.eventTypes.has('other') ? 'checked' : ''}> Other</label></div><span>${filtered.length} matching events</span></div>${routineSummary}<div class="timeline">${visible.map(eventCard).join('') || '<div class="empty">No events match the selected filters.</div>'}</div>${remaining ? `<button id="load-more-events" class="secondary load-more">Show older activity (${remaining})</button>` : ''}`;
}

function overviewPanel() {
  const agent = detailData.agent;
  return `<div class="overview-grid"><article class="panel overview-card"><p class="eyebrow">Identity</p><h3>Registration</h3><dl><dt>Agent ID</dt><dd><code>${escapeHtml(agent.id)}</code></dd><dt>Platform</dt><dd>${escapeHtml([agent.platform, agent.architecture].filter(Boolean).join(' / ') || 'Unknown')}</dd><dt>Agent version</dt><dd>${escapeHtml(agent.agent_version || 'Unknown')}</dd><dt>Registered</dt><dd>${escapeHtml(formatTime(agent.registered_at))}</dd></dl></article><article class="panel overview-card"><p class="eyebrow">Connectivity</p><h3>Current presence</h3><div class="presence-status">${statusBadge(agent.status)}</div><dl><dt>Last heartbeat</dt><dd>${escapeHtml(formatTime(agent.last_heartbeat_at))}</dd><dt>Last poll</dt><dd>${escapeHtml(formatTime(agent.last_poll_at))}</dd><dt>Deregistered</dt><dd>${escapeHtml(formatTime(agent.deregistered_at))}</dd></dl></article><article class="panel overview-card overview-wide"><p class="eyebrow">Latest activity</p><h3>Recent meaningful events</h3>${(detailData.events ?? []).filter((event) => !routineTypes.has(event.event_type)).slice(0, 5).map((event) => `<div class="compact-event"><strong>${escapeHtml(event.event_type)}</strong><span>${escapeHtml(relativeTime(event.created_at))}</span></div>`).join('') || '<p>No meaningful events yet.</p>'}</article></div>`;
}

function resultsPanel() {
  return `<div class="results-list">${detailData.results.map((result) => `<details class="result-row"><summary><span><strong>${escapeHtml(result.collector)}</strong><small>${escapeHtml(formatTime(result.received_at))}</small></span><span class="result-status ${escapeHtml(result.status)}">${escapeHtml(result.status)}</span></summary>${jsonBlock(result.data)}</details>`).join('') || '<div class="empty">No results have been received.</div>'}</div>`;
}

function rawPanel() {
  return `<div class="raw-grid"><details open><summary>Agent record</summary>${jsonBlock(detailData.agent)}</details><details><summary>Tasks (${detailData.tasks.length})</summary>${jsonBlock(detailData.tasks)}</details><details><summary>Results (${detailData.results.length})</summary>${jsonBlock(detailData.results)}</details><details><summary>Events (${detailData.events.length})</summary>${jsonBlock(detailData.events)}</details></div>`;
}

function renderDetail() {
  if (!detailData) return;
  const agent = detailData.agent;
  $('fleet-view').hidden = true;
  $('detail').hidden = false;
  const content = viewState.tab === 'overview' ? overviewPanel()
    : viewState.tab === 'posture' ? `<div class="posture-grid">${renderPosture(detailData.results, detailData.tasks)}</div>`
      : viewState.tab === 'activity' ? renderActivity()
        : viewState.tab === 'results' ? resultsPanel() : rawPanel();
  $('detail').innerHTML = `<button id="back-to-fleet" class="back-button">← Back to fleet</button><section class="detail-hero panel"><div class="endpoint-avatar large">${escapeHtml((agent.hostname || '?').slice(0, 1).toUpperCase())}</div><div><p class="eyebrow">Managed endpoint</p><h2>${escapeHtml(agent.hostname || agent.id)}</h2><p><code>${escapeHtml(agent.id)}</code> · Agent ${escapeHtml(agent.agent_version || 'version unknown')}</p></div>${statusBadge(agent.status)}</section><nav class="detail-tabs" aria-label="Agent detail"><button data-tab="overview" class="${viewState.tab === 'overview' ? 'active' : ''}">Overview</button><button data-tab="posture" class="${viewState.tab === 'posture' ? 'active' : ''}">Security posture</button><button data-tab="activity" class="${viewState.tab === 'activity' ? 'active' : ''}">Activity log</button><button data-tab="results" class="${viewState.tab === 'results' ? 'active' : ''}">Results</button><button data-tab="raw" class="${viewState.tab === 'raw' ? 'active' : ''}">Raw data</button></nav><section class="tab-content">${content}</section>`;
  $('back-to-fleet').onclick = showFleet;
  document.querySelectorAll('[data-tab]').forEach((button) => { button.onclick = () => { viewState.tab = button.dataset.tab; renderDetail(); }; });
  $('load-more-events')?.addEventListener('click', () => { viewState.eventLimit += eventPageSize; renderDetail(); });
  document.querySelectorAll('[data-event-filter]').forEach((input) => {
    input.onchange = () => {
      const type = input.dataset.eventFilter;
      if (type === 'heartbeat' || type === 'poll') {
        if (input.checked) viewState.routineTypesVisible.add(type);
        else viewState.routineTypesVisible.delete(type);
      }
      else {
        const related = type === 'result' ? ['result', 'result-received'] : type === 'register' ? ['register', 'deregister', 'deregistered'] : [type];
        related.forEach((value) => input.checked ? viewState.eventTypes.add(value) : viewState.eventTypes.delete(value));
      }
      viewState.eventLimit = eventPageSize;
      renderDetail();
    };
  });
}

async function loadDetail(id, { preserveState = false } = {}) {
  selectedAgentId = decodeURIComponent(id);
  if (!preserveState) { viewState.tab = 'overview'; viewState.eventLimit = eventPageSize; }
  detailData = await api(`/api/dashboard/agents/${encodeURIComponent(selectedAgentId)}`);
  const liveEvents = liveEventsByAgent.get(selectedAgentId) ?? [];
  if (liveEvents.length) detailData.events = [...liveEvents, ...detailData.events].slice(0, 200);
  history.replaceState({}, '', `/fleet/agents/${encodeURIComponent(selectedAgentId)}`);
  renderDetail();
}

function showFleet() {
  selectedAgentId = null; detailData = null;
  history.replaceState({}, '', '/fleet');
  $('detail').hidden = true; $('fleet-view').hidden = false;
}

async function refreshFromPush() {
  await loadFleet().catch(() => {});
  if (selectedAgentId) await loadDetail(selectedAgentId, { preserveState: true }).catch(() => {});
}

function connectLive() {
  clearTimeout(reconnectTimer);
  const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
  socket = new WebSocket(`${protocol}//${location.host}/api/dashboard/live`);
  socket.onopen = () => {
    $('live-state').innerHTML = '<i></i>Live'; $('live-state').className = 'live connected';
    clearInterval(fallbackTimer); fallbackTimer = null;
  };
  socket.onmessage = (event) => {
    const message = JSON.parse(event.data);
    if (message.type === 'status-transition' && message.agentId) {
      const events = liveEventsByAgent.get(message.agentId) ?? [];
      events.unshift({ event_type: 'status-transition', created_at: message.occurredAt ?? new Date().toISOString(), details: { from: message.from, to: message.to } });
      liveEventsByAgent.set(message.agentId, events.slice(0, 25));
    }
    if (['agent-registered', 'heartbeat', 'status-transition', 'result-received'].includes(message.type)) refreshFromPush();
  };
  socket.onclose = () => {
    $('live-state').innerHTML = '<i></i>Reconnecting'; $('live-state').className = 'live disconnected';
    if (!fallbackTimer) fallbackTimer = setInterval(refreshFromPush, 15000);
    reconnectTimer = setTimeout(connectLive, 3000);
  };
}

$('agent-search').oninput = renderFleetTable;
$('agent-sort').onchange = renderFleetTable;
$('login-form').onsubmit = async (event) => {
  event.preventDefault(); $('login-error').textContent = '';
  try {
    await api('/api/dashboard/session', { method: 'POST', body: JSON.stringify({ token: $('token').value }) });
    $('token').value = ''; await loadFleet(); connectLive();
  } catch (error) { $('login-error').textContent = error.message; }
};
$('logout').onclick = async () => { socket?.close(); await api('/api/dashboard/session', { method: 'DELETE' }); location.href = '/login'; };

loadFleet().then(() => { connectLive(); if (selectedAgentId) loadDetail(selectedAgentId).catch(() => {}); }).catch(() => {});
