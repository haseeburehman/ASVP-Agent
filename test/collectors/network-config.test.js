import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { createNetworkConfigCollector } from '../../src/collectors/network-config/index.js';

test('network-config normalizes local interfaces, DNS servers, and the default gateway', async () => {
  const collector = createNetworkConfigCollector({
    interfaceProvider: async () => [
      {
        iface: 'Ethernet',
        ip4: ' 192.168.10.4 ',
        ip6: 'fe80::20c:29ff:fe9c:409',
        mac: '00:0C:29:9C:04:09',
        default: true,
      },
      {
        iface: 'Ethernet',
        ip4: '192.168.10.4',
        ip6: '',
        mac: '00:0c:29:9c:04:09',
      },
      {
        ifaceName: 'Loopback',
        ip4: ['127.0.0.1', '127.0.0.1'],
        ip6: '::1',
        mac: '',
      },
      { iface: '   ', ip4: '203.0.113.10', mac: 'aa:bb:cc:dd:ee:ff' },
    ],
    gatewayProvider: async () => ' 192.168.10.1 ',
    dnsProvider: () => ['1.1.1.1', ' 2001:4860:4860::8888 ', '1.1.1.1', ''],
  });

  const result = await collector.run({ targets: ['198.51.100.1'] });

  assert.deepEqual(result, {
    interfaces: [
      {
        name: 'Ethernet',
        addresses: [
          { address: '192.168.10.4', family: 'IPv4' },
          { address: 'fe80::20c:29ff:fe9c:409', family: 'IPv6' },
        ],
        macs: ['00:0c:29:9c:04:09'],
        default: true,
      },
      {
        name: 'Loopback',
        addresses: [
          { address: '127.0.0.1', family: 'IPv4' },
          { address: '::1', family: 'IPv6' },
        ],
        macs: [],
        default: false,
      },
    ],
    dnsServers: ['1.1.1.1', '2001:4860:4860::8888'],
    defaultGateway: '192.168.10.1',
    summary: { maxItems: 100, totalDetected: 2, returnedItems: 2, truncated: 0 },
  });
});

test('network-config returns empty normalized values when local configuration is absent', async () => {
  const collector = createNetworkConfigCollector({
    interfaceProvider: async () => undefined,
    gatewayProvider: async () => undefined,
    dnsProvider: () => [],
  });

  assert.deepEqual(await collector.run(), {
    interfaces: [],
    dnsServers: [],
    defaultGateway: null,
    summary: { maxItems: 100, totalDetected: 0, returnedItems: 0, truncated: 0 },
  });
});

test('network-config caps local interface output', async () => {
  const collector = createNetworkConfigCollector({
    interfaceProvider: async () => [
      { iface: 'a', ip4: '10.0.0.1' },
      { iface: 'b', ip4: '10.0.0.2' },
    ],
    gatewayProvider: async () => null,
    dnsProvider: () => [],
  });
  const result = await collector.run({}, { collectorConfig: { maxItems: 1 } });
  assert.equal(result.interfaces.length, 1);
  assert.deepEqual(result.summary, { maxItems: 1, totalDetected: 2, returnedItems: 1, truncated: 1 });
});

test('network-config rejects promptly when collection is aborted', async () => {
  const controller = new AbortController();
  const collector = createNetworkConfigCollector({
    interfaceProvider: () => new Promise(() => {}),
    gatewayProvider: () => new Promise(() => {}),
    dnsProvider: () => assert.fail('DNS provider must not run after abort'),
  });

  const collection = collector.run({}, { signal: controller.signal });
  controller.abort();

  await assert.rejects(collection, (error) => (
    error.name === 'AbortError' && error.code === 'ABORT_ERR'
  ));
});

test('network-config rejects an already-aborted signal before invoking providers', async () => {
  const controller = new AbortController();
  controller.abort();
  let invoked = false;
  const collector = createNetworkConfigCollector({
    interfaceProvider: () => { invoked = true; return []; },
    gatewayProvider: () => { invoked = true; return null; },
    dnsProvider: () => { invoked = true; return []; },
  });

  await assert.rejects(collector.run({}, { signal: controller.signal }), { name: 'AbortError', code: 'ABORT_ERR' });
  assert.equal(invoked, false);
});

test('network-config source uses no outbound, remote lookup, or subprocess primitives', async () => {
  const source = await readFile(new URL('../../src/collectors/network-config/index.js', import.meta.url), 'utf8');

  assert.doesNotMatch(source, /node:(?:net|http|https|tls|child_process)/);
  assert.doesNotMatch(source, /\b(?:fetch|WebSocket|XMLHttpRequest|spawn|exec|execFile|fork|ping|nmap|masscan)\b/i);
  assert.doesNotMatch(source, /\.connect\s*\(|\b(?:dns|resolver)\.(?:lookup|resolve(?:4|6|Any|Cname|Mx|Naptr|Ns|Ptr|Soa|Srv|Txt)?)\s*\(/i);
});
