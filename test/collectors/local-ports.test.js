import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { createLocalPortsCollector } from '../../src/collectors/local-ports/index.js';
import { CollectorRegistry } from '../../src/core/collector-registry.js';

test('local-ports reports only local listening bindings from the OS connection table', async () => {
  const collector = createLocalPortsCollector({
    connectionProvider: async () => [
      { state: 'ESTABLISHED', localAddress: '10.0.0.5', localPort: '51000', protocol: 'tcp', process: 'client', pid: 1 },
      { state: 'LISTEN', localAddress: '0.0.0.0', localPort: '443', protocol: 'TCP', process: 'server', pid: '42' },
      { state: 'listen', localAddress: '127.0.0.1', localPort: 80, protocol: 'tcp', process: '', pid: null },
      { state: 'LISTEN', localAddress: '::1', localPort: 3000, protocol: 'tcp6', process: 'local', pid: 7 },
    ],
  });

  const result = await collector.run({ targets: ['192.0.2.1'], ports: [22] });

  assert.equal(result.bindings.length, 3);
  assert.deepEqual(result.bindings.map(({ address, port }) => ({ address, port })), [
    { address: '127.0.0.1', port: 80 },
    { address: '0.0.0.0', port: 443 },
    { address: '::1', port: 3000 },
  ]);
  assert.equal(result.bindings[0].scope, 'loopback-only');
  assert.equal(result.bindings[0].externallyReachable, false);
  assert.equal(result.bindings[1].scope, 'all-interfaces');
  assert.equal(result.bindings[1].externallyReachable, true);
  assert.equal(result.reason, null);
});

test('local-ports is registered while remote scanners remain structurally unavailable', async () => {
  const registry = new CollectorRegistry();
  assert.equal((await registry.get('local-ports')).name, 'local-ports');
  assert.equal(registry.has('network-scan'), false);
  assert.equal(registry.has('tls-checks'), false);
  await assert.rejects(registry.get('network-scan'), /not registered or implemented/);
  await assert.rejects(registry.get('tls-checks'), /not registered or implemented/);
});

test('local-ports source has no outbound or subprocess primitives', async () => {
  const source = await readFile(new URL('../../src/collectors/local-ports/index.js', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /node:(?:net|tls|http|https|child_process)/);
  assert.doesNotMatch(source, /\.connect\s*\(|\b(?:spawn|exec|nmap|masscan)\b/i);
  assert.doesNotMatch(source, /allowedCidrs|approvedTargets|targetParams/);
});
