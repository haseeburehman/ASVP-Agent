import assert from 'node:assert/strict';
import test from 'node:test';
import {
  formatBytes, renderContainers, renderCredentialExposure, renderDiskSecurity,
  renderFilePermissions, renderMissingPatches, renderProcessSummary, renderScaDeps, renderServices,
} from '../src/public/dashboard/posture-renderers.js';

test('formats capacities and renders disk encryption and usage clearly', () => {
  assert.equal(formatBytes(16 * 1024 ** 3), '16 GB');
  const html = renderDiskSecurity({ status: 'available', volumes: [{ mount: '/', capacityBytes: 1000, usedBytes: 500, usedPercent: 50, readOnly: false, encryption: { status: 'encrypted' } }] });
  assert.match(html, /Encrypted/);
  assert.match(html, /50\.0% used/);
  assert.match(html, /capacity-bar/);
});

test('file permissions respect the collector sticky-bit decision', () => {
  const html = renderFilePermissions({ status: 'available', paths: [{ path: '/tmp', mode: '1777', worldWritable: true, overlyPermissive: false, status: 'available' }] });
  assert.doesNotMatch(html, /Overly Permissive/);
  assert.match(html, /Acceptable/);
});

test('credential exposure renders metadata but never content or secret values', () => {
  const html = renderCredentialExposure({ metadata: { scanPaths: ['/srv/app'] }, summary: { filesScanned: 1 }, findings: [{ filePath: '.env', rule: 'sensitive-key-name', confidence: 'high', value: 'top-secret', content: 'PASSWORD=top-secret' }] });
  assert.match(html, /sensitive-key-name/);
  assert.doesNotMatch(html, /top-secret|PASSWORD=/);
});

test('unconfigured SCA has an explicit state', () => {
  const html = renderScaDeps({ metadata: { traversal: { scanPaths: [] } }, reason: 'No scanPaths are configured', dependencies: [] });
  assert.match(html, /Not configured/);
  assert.doesNotMatch(html, /<table/);
});

test('services and processes render required table columns without command lines', () => {
  const services = renderServices({ services: [{ name: 'sshd', displayName: 'OpenSSH', status: 'running', startupType: 'automatic', runningUser: 'root' }], summary: { totalDetected: 1 } });
  assert.match(services, /Service/); assert.match(services, /Startup type/); assert.match(services, /Running account/); assert.match(services, /data-table-search/);
  const processes = renderProcessSummary({ processes: [{ name: 'node', pid: 42, user: 'agent', memory: { percent: 1.2 }, binarySha256: 'abc123' }], summary: { totalDetected: 1 } });
  assert.match(processes, /Owner/); assert.match(processes, /Memory/); assert.match(processes, /SHA-256: abc123/);
  assert.doesNotMatch(processes, /Command line|Arguments/);
});

test('container renderer highlights privileged, root, broad capabilities, ports, and age', () => {
  const html = renderContainers({ available: true, summary: { totalRunning: 1 }, containers: [{ containerId: 'abcdef123456789', imageName: 'nginx:latest', privileged: { value: true }, mainProcessRunsAsRoot: { value: true }, exposedPorts: { value: [{ hostIp: '0.0.0.0', hostPort: '8080', containerPort: '80/tcp' }] }, imageAge: { value: { ageDays: 30, createdAt: '2026-06-01' } }, broadCapabilities: { value: { hasCapAddAll: true, capAdd: ['ALL'] } } }] });
  for (const expected of ['Privileged', 'Runs as root', 'CAP_ADD ALL', '8080', '30 days']) assert.match(html, new RegExp(expected));
});

test('missing patches renders inference disclaimer and visible feed staleness', () => {
  const html = renderMissingPatches({ patches: [{ advisoryId: 'USN-1234-1', severity: 'high', title: 'Kernel update', confidence: 'low', source: 'ubuntu', publishedDate: '2026-07-01' }], feedCache: [{ feedName: 'ubuntu', fetchedAt: '2026-07-01', advisoryCount: 10, lastError: 'timeout' }] });
  assert.match(html, /advisory-based inference; not vendor confirmation/);
  assert.match(html, /USN-1234-1/);
  assert.match(html, /Refresh failed/);
  assert.match(html, /timeout/);
  assert.match(html, /View raw JSON/);
});
