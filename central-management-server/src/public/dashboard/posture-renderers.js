const escapeHtml = (value) => String(value ?? '').replace(/[&<>"']/g, (character) => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
})[character]);

const text = (value, fallback = 'Unknown') => escapeHtml(value == null || value === '' ? fallback : value);
const valueOf = (field) => field?.value;

export function formatBytes(value) {
  const bytes = Number(value);
  if (!Number.isFinite(bytes) || bytes < 0) return 'Unknown';
  if (bytes === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const amount = bytes / (1024 ** index);
  return `${amount >= 10 || index === 0 ? amount.toFixed(0) : amount.toFixed(1)} ${units[index]}`;
}

export function availabilityMessage(payload) {
  const status = payload?.status ?? payload?.reasonCode;
  const reason = payload?.reason;
  if (status === 'insufficient_privilege' || payload?.insufficientPrivilege) {
    return `<div class="availability-state privilege"><strong>Requires elevated privileges</strong><span>${text(reason, 'Some fields could not be inspected with the agent account.')}</span></div>`;
  }
  if (status === 'unavailable' || payload?.available === false) {
    return `<div class="availability-state"><strong>Not available on this platform</strong><span>${text(reason, 'This collector did not return platform data.')}</span></div>`;
  }
  return '';
}

export function badge(label, tone = 'unknown', title = '') {
  return `<span class="security-pill ${escapeHtml(tone)}"${title ? ` title="${escapeHtml(title)}"` : ''}>${escapeHtml(label)}</span>`;
}

function empty(message) { return `<div class="readable-empty">${escapeHtml(message)}</div>`; }
function summaryStats(items) { return `<div class="posture-stats">${items.map(([value, label]) => `<div><strong>${text(value)}</strong><span>${escapeHtml(label)}</span></div>`).join('')}</div>`; }

export function renderDiskSecurity(data) {
  const unavailable = availabilityMessage(data);
  if (!data || unavailable && !(data.volumes?.length)) return unavailable || empty('No volume data was returned.');
  const volumes = data.volumes ?? [];
  const encrypted = volumes.filter((volume) => volume.encryption?.status === 'encrypted').length;
  return `${unavailable}${summaryStats([[volumes.length, 'volumes'], [encrypted, 'encrypted']])}<div class="volume-list">${volumes.map((volume) => {
    const used = Number.isFinite(Number(volume.usedPercent)) ? Math.max(0, Math.min(100, Number(volume.usedPercent))) : null;
    const encryption = volume.encryption?.status;
    const encryptionBadge = encryption === 'encrypted' ? badge('Encrypted', 'pass') : encryption === 'not_encrypted' ? badge('Not Encrypted', 'danger') : badge('Unknown', 'unknown', volume.encryption?.reason);
    return `<section class="volume-card"><div class="card-row"><strong>${text(volume.mount, volume.filesystem || 'Volume')}</strong>${encryptionBadge}</div><div class="capacity-label"><span>${used == null ? 'Usage unknown' : `${used.toFixed(1)}% used`}</span><span>${formatBytes(volume.usedBytes)} / ${formatBytes(volume.capacityBytes)}</span></div><div class="capacity-bar" role="meter" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${used ?? 0}"><i style="width:${used ?? 0}%"></i></div><div class="muted-row"><span>${text(volume.type, 'Filesystem type unknown')}</span><span title="${volume.readOnly === true ? 'Read-only volume' : volume.readOnly === false ? 'Writable volume' : 'Read-only state unknown'}">${volume.readOnly === true ? '🔒 Read-only' : volume.readOnly === false ? '✎ Writable' : '○ Access unknown'}</span></div></section>`;
  }).join('') || empty('No volumes were reported.')}</div>`;
}

function fieldValue(section, selector, fallback = 'Unknown') {
  return section?.status === 'available' ? selector(section.value ?? {}) ?? fallback : fallback;
}
export function renderHardwareInfo(data) {
  if (!data) return empty('No hardware data was returned.');
  const cpu = fieldValue(data.cpu, (value) => [value.manufacturer, value.brand].filter(Boolean).join(' '));
  const cores = fieldValue(data.cpu, (value) => value.physicalCores ?? value.cores);
  const ram = fieldValue(data.memory, (value) => formatBytes(value.totalBytes));
  const system = data.system?.value ?? {};
  const bios = data.bios?.value ?? {};
  const disks = data.disks?.value?.items ?? [];
  const virtual = data.virtualization?.value;
  return `${summaryStats([[cores, 'physical cores'], [ram, 'memory'], [disks.length, 'disks']])}<section class="asset-card"><div class="card-row"><div><span class="meta-label">Processor</span><strong>${text(cpu)}</strong></div>${virtual ? badge(virtual.isVirtual ? `Virtual machine${virtual.hypervisorVendor ? ` · ${virtual.hypervisorVendor}` : ''}` : 'Physical host', virtual.isVirtual ? 'warn' : 'pass') : badge('Virtualization unknown', 'unknown')}</div><dl><dt>System</dt><dd>${text([system.manufacturer, system.model].filter(Boolean).join(' '))}</dd><dt>Serial</dt><dd>${text(system.serialNumber)}</dd><dt>BIOS</dt><dd>${text([bios.vendor, bios.version].filter(Boolean).join(' '))}</dd><dt>Disks</dt><dd>${disks.map((disk) => `${text([disk.vendor, disk.model].filter(Boolean).join(' '))} (${formatBytes(disk.sizeBytes)})`).join('<br>') || 'Unknown'}</dd></dl></section>`;
}

const linuxExpectations = {
  'kernel.kptr_restrict': (value) => Number(value) >= 1,
  'kernel.dmesg_restrict': (value) => Number(value) === 1,
  'kernel.yama.ptrace_scope': (value) => Number(value) >= 1,
  'net.ipv4.conf.all.accept_source_route': (value) => Number(value) === 0,
  'net.ipv4.conf.all.accept_redirects': (value) => Number(value) === 0,
  'kernel.randomize_va_space': (value) => Number(value) === 2,
};
export function renderKernelHardening(data) {
  const fields = Object.entries(data?.sysctls ?? {}).map(([name, field]) => {
    const available = field?.status === 'available';
    const passed = available && linuxExpectations[name]?.(field.value);
    const tone = !available ? 'unknown' : passed ? 'pass' : 'warn';
    const icon = !available ? '?' : passed ? '✓' : '!';
    return `<div class="check-row"><span class="check-icon ${tone}">${icon}</span><div><strong>${escapeHtml(name)}</strong><small>${text(field?.reason ?? field?.source, 'Reported setting')}</small></div><code>${text(field?.value, 'Unknown')}</code></div>`;
  });
  const mitigation = data?.processMitigations;
  if (mitigation?.status === 'available') fields.push(`<div class="check-row"><span class="check-icon pass">✓</span><div><strong>Windows system process mitigations</strong><small>${text(mitigation.source)}</small></div>${badge('Reported', 'pass')}</div>`);
  else if (data?.platform === 'win32') fields.push(`<div class="check-row"><span class="check-icon unknown">?</span><div><strong>Windows system process mitigations</strong><small>${text(mitigation?.reason)}</small></div>${badge('Unknown', 'unknown')}</div>`);
  return `${availabilityMessage(data)}<div class="check-list">${fields.join('') || empty('No hardening checks were reported.')}</div>`;
}

function table(headers, rows, className = '') {
  return `<div class="posture-table-wrap"><table class="posture-table ${className}"><thead><tr>${headers.map(([key, label]) => `<th data-sort-key="${key}" tabindex="0">${escapeHtml(label)} <span>↕</span></th>`).join('')}</tr></thead><tbody>${rows.join('')}</tbody></table></div>`;
}
export function renderServices(data) {
  if (!data?.services) return availabilityMessage(data) || empty('No services were reported.');
  const services = data.services ?? [];
  const rows = services.map((service) => `<tr data-search="${escapeHtml(`${service.name} ${service.displayName} ${service.status} ${service.startupType} ${service.runningUser}`.toLowerCase())}" data-status="${text(service.status, '').toLowerCase()}"><td><strong>${text(service.displayName ?? service.name)}</strong><small>${text(service.name)}</small></td><td>${badge(service.status ?? 'Unknown', service.status === 'running' ? 'pass' : 'unknown')}</td><td>${text(service.startupType)}</td><td>${text(service.runningUser)}</td></tr>`);
  return `${summaryStats([[data.summary?.totalDetected ?? services.length, 'services detected'], [services.filter((item) => item.status === 'running').length, 'running shown']])}<div class="posture-tools"><input type="search" data-table-search placeholder="Filter services" aria-label="Filter services"><select data-table-status aria-label="Filter service status"><option value="">All statuses</option>${[...new Set(services.map((item) => item.status).filter(Boolean))].map((status) => `<option value="${escapeHtml(status.toLowerCase())}">${escapeHtml(status)}</option>`).join('')}</select></div>${table([['name','Service'],['status','Status'],['startup','Startup type'],['account','Running account']], rows, 'interactive-table')}`;
}

export function renderProcessSummary(data) {
  if (!data?.processes) return availabilityMessage(data) || empty('No processes were reported.');
  const processes = data.processes ?? [];
  const rows = processes.map((process) => `<tr data-search="${escapeHtml(`${process.name} ${process.pid} ${process.user}`.toLowerCase())}"><td><strong>${text(process.name)}</strong></td><td>${text(process.pid)}</td><td>${text(process.user)}</td><td>${process.memory?.percent == null ? 'Unknown' : `${escapeHtml(Number(process.memory.percent).toFixed(1))}%`}</td><td>${process.binarySha256 ? `<span class="hash-indicator" title="SHA-256: ${escapeHtml(process.binarySha256)}">#</span>` : '<span class="hash-indicator unavailable" title="Binary hash not captured">—</span>'}</td></tr>`);
  return `${summaryStats([[data.summary?.totalDetected ?? processes.length, 'processes detected'], [processes.filter((item) => item.binarySha256).length, 'binary hashes captured']])}<div class="posture-tools"><input type="search" data-table-search placeholder="Filter processes" aria-label="Filter processes"></div>${table([['name','Process'],['pid','PID'],['owner','Owner'],['memory','Memory'],['hash','SHA-256']], rows, 'interactive-table')}`;
}

export function renderFilePermissions(data) {
  const checks = [...(data?.paths ?? []), ...(data?.privilegedExecutables ?? [])];
  return `${availabilityMessage(data)}${summaryStats([[checks.length, 'paths checked'], [checks.filter((item) => item.overlyPermissive === true).length, 'warnings']])}<div class="check-list">${checks.map((item) => {
    const unavailable = ['unavailable', 'insufficient_privilege', 'not_present'].includes(item.status);
    const tone = unavailable ? 'unknown' : item.overlyPermissive ? 'danger' : 'pass';
    return `<div class="check-row"><span class="check-icon ${tone}">${unavailable ? '?' : item.overlyPermissive ? '!' : '✓'}</span><div><strong>${text(item.path)}</strong><small>${text(item.mode ? `Mode ${item.mode}${item.worldWritable ? ' · world-writable' : ''}` : item.aclSummary || item.reason, 'Permission metadata reported')}</small></div>${item.overlyPermissive === true ? badge('Overly Permissive', 'danger') : unavailable ? badge(item.status.replaceAll('_', ' '), 'unknown') : badge('Acceptable', 'pass')}</div>`;
  }).join('') || empty('No paths were checked.')}</div>`;
}

export function renderCredentialExposure(data) {
  const configured = (data?.metadata?.scanPaths?.length ?? 0) > 0;
  if (!configured) return `<div class="availability-state"><strong>Not configured</strong><span>${text(data?.reason, 'No credential exposure scan paths are configured.')}</span></div>`;
  const findings = data?.findings ?? [];
  return `${availabilityMessage(data)}${summaryStats([[data?.summary?.filesScanned ?? 0, 'files scanned'], [findings.length, 'findings']])}${findings.length ? `<div class="finding-list">${findings.map((finding) => `<div class="finding-item"><span class="check-icon danger">!</span><div><strong>${text(finding.filePath)}</strong><small>${text(finding.rule)}</small></div>${badge(finding.confidence ?? 'unknown', finding.confidence === 'high' ? 'danger' : 'warn')}</div>`).join('')}</div>` : empty('No credential exposure findings were reported.')}`;
}

export function renderNetworkConfig(data) {
  if (!data) return empty('No network configuration was returned.');
  const interfaces = data.interfaces ?? [];
  return `${summaryStats([[interfaces.length, 'interfaces'], [(data.dnsServers ?? []).length, 'DNS servers']])}<div class="interface-list">${interfaces.map((item) => `<section class="interface-card"><div class="card-row"><strong>${text(item.name)}</strong>${item.default ? badge('Default', 'pass') : ''}</div><dl><dt>Addresses</dt><dd>${(item.addresses ?? []).map((address) => `${text(address.family)} ${text(address.address)}`).join('<br>') || 'None reported'}</dd><dt>MAC</dt><dd>${(item.macs ?? []).map(text).join(', ') || 'Unknown'}</dd><dt>Gateway</dt><dd>${item.default ? text(data.defaultGateway) : '—'}</dd><dt>DNS</dt><dd>${(data.dnsServers ?? []).map(text).join(', ') || 'None reported'}</dd></dl></section>`).join('') || empty('No interfaces were reported.')}</div>`;
}

export function renderContainers(data) {
  if (data?.available === false) return availabilityMessage(data);
  const containers = data?.containers ?? [];
  return `${summaryStats([[data?.summary?.totalRunning ?? containers.length, 'running containers'], [containers.filter((item) => valueOf(item.privileged) === true).length, 'privileged']])}<div class="container-list">${containers.map((item) => {
    const ports = valueOf(item.exposedPorts);
    const age = valueOf(item.imageAge);
    const broad = valueOf(item.broadCapabilities);
    return `<section class="container-card"><div class="card-row"><div><strong>${text(item.imageName)}</strong><small>${text(item.containerId)?.slice(0, 12)}</small></div>${valueOf(item.privileged) === true ? badge('Privileged', 'danger') : valueOf(item.privileged) === false ? badge('Not privileged', 'pass') : badge('Privilege unknown', 'unknown')}</div><div class="pill-row">${valueOf(item.mainProcessRunsAsRoot) === true ? badge('Runs as root', 'danger') : valueOf(item.mainProcessRunsAsRoot) === false ? badge('Non-root', 'pass') : badge('User unknown', 'unknown')}${broad?.hasCapAddAll ? badge('CAP_ADD ALL', 'danger') : broad ? badge('Capabilities bounded', 'pass') : badge('Capabilities unknown', 'unknown')}</div><dl><dt>Exposed ports</dt><dd>${Array.isArray(ports) && ports.length ? ports.map((port) => `${text(port.hostIp, '*')}:${text(port.hostPort)} → ${text(port.containerPort)}`).join('<br>') : 'None published'}</dd><dt>Image age</dt><dd>${age ? `${text(age.ageDays)} days · ${text(age.createdAt)}` : text(item.imageAge?.reason)}</dd></dl></section>`;
  }).join('') || empty(data?.reason || 'No running containers were reported.')}</div>`;
}

export function renderScaDeps(data) {
  const configured = (data?.metadata?.traversal?.scanPaths?.length ?? 0) > 0;
  if (!configured) return `<div class="availability-state"><strong>Not configured</strong><span>${text(data?.reason, 'No dependency scan paths are configured.')}</span></div>`;
  const dependencies = data?.dependencies ?? [];
  const rows = dependencies.map((dependency) => `<tr data-search="${escapeHtml(`${dependency.name} ${dependency.version} ${dependency.ecosystem}`.toLowerCase())}"><td><strong>${text(dependency.name)}</strong></td><td>${text(dependency.version)}</td><td>${badge(dependency.ecosystem ?? 'unknown', 'unknown')}</td></tr>`);
  return `${summaryStats([[dependencies.length, 'dependencies'], [data?.summary?.manifestsProcessed ?? 0, 'manifests processed']])}<div class="posture-tools"><input type="search" data-table-search placeholder="Filter dependencies" aria-label="Filter dependencies"></div>${table([['name','Dependency'],['version','Version'],['ecosystem','Ecosystem']], rows, 'interactive-table')}`;
}

export function renderMissingPatches(data) {
  if (!data) return `<div class="availability-state"><strong>Missing-patch data unavailable in this dashboard session</strong><span>The existing missing-patches endpoint requires an admin bearer token, while this dashboard intentionally retains only an HttpOnly session cookie. No token is stored in browser JavaScript.</span></div><p class="inference-note">advisory-based inference; not vendor confirmation</p>`;
  const patches = data.patches ?? [];
  return `<p class="inference-note">advisory-based inference; not vendor confirmation</p>${summaryStats([[patches.length, 'missing advisories'], [(data.feedCache ?? []).filter((feed) => feed.lastError).length, 'feed errors']])}<div class="patch-list">${patches.map((patch) => `<article class="patch-item"><div class="card-row"><strong>${text(patch.advisoryId)}</strong>${badge(patch.severity ?? 'unknown', /critical|high/i.test(patch.severity ?? '') ? 'danger' : /medium|moderate/i.test(patch.severity ?? '') ? 'warn' : 'unknown')}</div><h4>${text(patch.title, 'Untitled advisory')}</h4><div class="pill-row">${badge(`${patch.confidence ?? 'unknown'} confidence`, patch.confidence === 'high' ? 'pass' : 'warn')}<span>${text(patch.source)}</span><time>${text(patch.publishedDate)}</time></div></article>`).join('') || empty('Current: no known missing patches were inferred from cached advisories.')}</div><section class="freshness-section"><h3>Data freshness</h3><div class="freshness-grid">${(data.feedCache ?? []).map((feed) => `<div><div class="card-row"><strong>${text(feed.feedName)}</strong>${feed.lastError ? badge('Refresh failed', 'danger') : badge('Current cache', 'pass')}</div><small>Fetched ${text(feed.fetchedAt, 'Never')} · ${text(feed.advisoryCount, '0')} advisories</small>${feed.lastError ? `<p class="inline-error">${text(feed.lastError)}</p>` : ''}</div>`).join('') || empty('No feed-cache status was returned.')}</div></section><details class="raw-toggle"><summary>View raw JSON</summary><pre class="json"><code>${escapeHtml(JSON.stringify(data, null, 2))}</code></pre></details>`;
}
