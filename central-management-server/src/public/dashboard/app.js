import { applicationMetrics, describeCheck, latestCollectorState } from './posture-data.js';

const $ = (id) => document.getElementById(id);
const formatTime = (value) => value ? new Date(value).toLocaleString() : 'Never';
const escapeHtml = (value) => String(value ?? '').replace(/[&<>"']/g, (character) => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
})[character]);
let socket;
let reconnectTimer;
let fallbackTimer;
let selectedAgentId = location.pathname.match(/^\/fleet\/agents\/(.+)$/)?.[1] ?? null;

async function api(url, options) {
  const response = await fetch(url, {
    ...options,
    headers: { 'content-type': 'application/json', ...(options?.headers ?? {}) },
  });
  if (response.status === 401) {
    $('dashboard').hidden = true;
    $('login').hidden = false;
    throw new Error('Authentication required');
  }
  if (!response.ok) throw new Error((await response.json()).error ?? response.statusText);
  return response.status === 204 ? null : response.json();
}

function renderSummary(agents) {
  const count = (state) => agents.filter((agent) => agent.status === state).length;
  $('summary').innerHTML = [
    ['Total', agents.length, ''], ['Online', count('online'), 'online'],
    ['Stale', count('stale'), 'stale'], ['Never connected', count('never-connected'), 'never-connected'],
    ['Deregistered', count('deregistered'), 'deregistered'],
  ].map(([label, value, className]) => `<div class="card metric ${className}"><span>${label}</span><strong>${value}</strong></div>`).join('');
}

async function loadFleet() {
  const data = await api('/api/dashboard/fleet');
  $('login').hidden = true;
  $('dashboard').hidden = false;
  $('threshold').textContent = `Online means a heartbeat within ${data.onlineThresholdMs / 1000}s (2 × the expected ${data.expectedHeartbeatIntervalMs / 1000}s interval).`;
  $('updated').textContent = `Updated ${new Date(data.generatedAt).toLocaleTimeString()} `;
  renderSummary(data.agents);
  $('agents').innerHTML = data.agents.map((agent) => `<tr data-id="${escapeHtml(agent.id)}"><td>${escapeHtml(agent.hostname || 'Unknown')}</td><td>${escapeHtml([agent.platform, agent.architecture].filter(Boolean).join(' / ') || 'Unknown')}</td><td><code>${escapeHtml(agent.id)}</code></td><td class="badge ${agent.status}">${escapeHtml(agent.status)}</td><td>${formatTime(agent.last_heartbeat_at)}</td><td>${formatTime(agent.last_poll_at)}</td></tr>`).join('');
  document.querySelectorAll('#agents tr').forEach((row) => { row.onclick = () => loadDetail(row.dataset.id); });
}

function postureCard(title, status, body, raw) {
  return `<article class="posture-card"><div class="posture-heading"><h3>${escapeHtml(title)}</h3><span>${escapeHtml(status)}</span></div>${body}<details><summary>Raw JSON</summary><pre>${escapeHtml(JSON.stringify(raw, null, 2))}</pre></details></article>`;
}

function postureBody(entry, content = '') {
  const error = entry.error ? `<p><strong>Error:</strong> ${escapeHtml(typeof entry.error === 'string' ? entry.error : JSON.stringify(entry.error))}</p>` : '';
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
  const os = osEntry.payload;
  const apps = appsEntry.payload;
  const users = usersEntry.payload;
  const antivirus = antivirusEntry.payload;
  const compliance = complianceEntry.payload;
  const appMetrics = applicationMetrics(apps);
  const userItems = users?.users?.items ?? [];
  const groups = users?.groups?.items ?? [];
  const privileged = groups.filter((group) => /^(administrators|admin|wheel|sudo)$/i.test(group.name));
  const patchItems = os?.patches?.items;
  return [
    postureCard('Operating system & patches', osEntry.state, postureBody(osEntry, os
      ? `<dl><dt>OS</dt><dd>${escapeHtml(os.prettyName)}</dd><dt>Version</dt><dd>${escapeHtml(os.version)}</dd><dt>Architecture</dt><dd>${escapeHtml(os.architecture)}</dd><dt>Recent patches</dt><dd>${Array.isArray(patchItems) ? patchItems.length : 'Undetermined'}</dd></dl>` : ''), osEntry.result ?? osEntry.task),
    postureCard('Applications', appsEntry.state, postureBody(appsEntry, apps
      ? `<p><strong>${escapeHtml(appMetrics.totalDetected)}</strong> applications reported${appMetrics.truncated ? ` (${escapeHtml(appMetrics.shown)} shown, ${escapeHtml(appMetrics.truncated)} truncated)` : ''}.</p>` : ''), appsEntry.result ?? appsEntry.task),
    postureCard('Users & privileged groups', usersEntry.state, postureBody(usersEntry, users
      ? `<p><strong>${userItems.length}</strong> local users and <strong>${groups.length}</strong> groups.</p>${privileged.map((group) => `<p><b>${escapeHtml(group.name)}:</b> ${escapeHtml((group.members ?? []).map((member) => typeof member === 'string' ? member : member.name).join(', ') || 'No explicit members')}</p>`).join('') || '<p>No standard privileged group was reported.</p>'}` : ''), usersEntry.result ?? usersEntry.task),
    postureCard('Antivirus / endpoint protection', antivirusEntry.state, postureBody(antivirusEntry, antivirus
      ? `<p>${escapeHtml(antivirus.reason ?? 'Status reported successfully.')}</p><ul>${(antivirus.products ?? []).map((product) => `<li>${escapeHtml(product.name)} — ${product.enabled === true ? 'enabled' : product.enabled === false ? 'disabled' : 'state unknown'}</li>`).join('')}</ul>` : ''), antivirusEntry.result ?? antivirusEntry.task),
    postureCard('Firewall & compliance', complianceEntry.state, postureBody(complianceEntry, compliance
      ? `<dl><dt>Firewall</dt><dd>${escapeHtml(describeCheck(compliance.firewall, (active) => active === true ? 'active' : active === false ? 'inactive' : null))}</dd><dt>SSH root login</dt><dd>${escapeHtml(describeCheck(compliance.ssh?.permitRootLogin))}</dd><dt>SSH password auth</dt><dd>${escapeHtml(describeCheck(compliance.ssh?.passwordAuthentication))}</dd><dt>UAC</dt><dd>${escapeHtml(describeCheck(compliance.uac, (value) => value?.name ?? value?.level ?? value))}</dd></dl>` : ''), complianceEntry.result ?? complianceEntry.task),
  ].join('');
}

async function loadDetail(id) {
  selectedAgentId = decodeURIComponent(id);
  const detail = await api(`/api/dashboard/agents/${encodeURIComponent(selectedAgentId)}`);
  history.replaceState({}, '', `/fleet/agents/${encodeURIComponent(selectedAgentId)}`);
  $('detail').hidden = false;
  $('detail').innerHTML = `<h2>${escapeHtml(detail.agent.hostname || detail.agent.id)}</h2><h3>Security posture</h3><div class="posture-grid">${renderPosture(detail.results, detail.tasks)}</div><div class="grid"><div><h3>Registration</h3><pre>${escapeHtml(JSON.stringify(detail.agent, null, 2))}</pre><h3>Recent events</h3>${detail.events.map((event) => `<div class="event"><strong>${escapeHtml(event.event_type)}</strong> · ${formatTime(event.created_at)}<pre>${escapeHtml(JSON.stringify(event.details, null, 2))}</pre></div>`).join('') || '<p>No events</p>'}</div><div><h3>Tasks (${detail.tasks.length})</h3><pre>${escapeHtml(JSON.stringify(detail.tasks, null, 2))}</pre><h3>Results (${detail.results.length})</h3>${detail.results.map((result) => `<details><summary>${escapeHtml(result.collector)} · ${escapeHtml(result.status)} · ${formatTime(result.received_at)}</summary><pre>${escapeHtml(JSON.stringify(result.data, null, 2))}</pre></details>`).join('') || '<p>No results</p>'}</div></div>`;
  const versionBadge = document.createElement('small');
  versionBadge.textContent = ` Agent ${detail.agent.agent_version || 'version unknown'}`;
  $('detail').querySelector('h2')?.append(versionBadge);
}

function refreshFromPush() {
  loadFleet().catch(() => {});
  if (selectedAgentId) loadDetail(selectedAgentId).catch(() => {});
}

function connectLive() {
  clearTimeout(reconnectTimer);
  const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
  socket = new WebSocket(`${protocol}//${location.host}/api/dashboard/live`);
  socket.onopen = () => {
    $('live-state').textContent = 'Live';
    $('live-state').className = 'live online';
    clearInterval(fallbackTimer);
  };
  socket.onmessage = (event) => {
    const message = JSON.parse(event.data);
    if (['agent-registered', 'heartbeat', 'status-transition', 'result-received'].includes(message.type)) refreshFromPush();
  };
  socket.onclose = () => {
    $('live-state').textContent = 'Reconnecting';
    $('live-state').className = 'live never-connected';
    if (!fallbackTimer) fallbackTimer = setInterval(refreshFromPush, 15000);
    reconnectTimer = setTimeout(connectLive, 3000);
  };
}

$('login-form').onsubmit = async (event) => {
  event.preventDefault();
  $('login-error').textContent = '';
  try {
    await api('/api/dashboard/session', { method: 'POST', body: JSON.stringify({ token: $('token').value }) });
    $('token').value = '';
    await loadFleet();
    connectLive();
  } catch (error) { $('login-error').textContent = error.message; }
};
$('logout').onclick = async () => { socket?.close(); await api('/api/dashboard/session', { method: 'DELETE' }); location.href = '/login'; };

loadFleet().then(() => {
  connectLive();
  if (selectedAgentId) loadDetail(selectedAgentId).catch(() => {});
}).catch(() => {});
