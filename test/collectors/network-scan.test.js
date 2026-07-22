import assert from 'node:assert/strict';
import net from 'node:net';
import test from 'node:test';
import { authorizeNetworkScan } from '../../src/collectors/network-scan/authorization.js';
import {
  ACTIVE_PROBES,
  COMMON_TCP_PORTS,
  createNetworkScanCollector,
  detectLocalPortBindings,
  scanAuthorizedPlan,
  scanTcpPort,
} from '../../src/collectors/network-scan/index.js';

async function listen(handler = () => {}, host = '127.0.0.1') {
  const server = net.createServer(handler);
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, host, resolve);
  });
  return server;
}

async function close(server) {
  if (!server.listening) return;
  await new Promise((resolve) => server.close(resolve));
}

function portOf(server) {
  return server.address().port;
}

function planFor(targets, ports, overrides = {}) {
  return authorizeNetworkScan({
    config: {
      allowedCidrs: ['127.0.0.0/16'],
      maxCidrSize: 16,
      maxConcurrentTargets: 5,
      maxPortsPerHost: 1000,
      perHostDelayMs: 0,
      perPortTimeoutMs: 200,
      maxScanOperationsPerTask: 100000,
      ...overrides,
    },
    taskParams: { targets, ports },
  });
}

test('real loopback TCP scan detects an open port and excludes a closed port', async (t) => {
  const openServer = await listen((socket) => socket.end());
  const temporary = await listen();
  const closedPort = portOf(temporary);
  await close(temporary);
  t.after(() => close(openServer));

  const plan = planFor(['127.0.0.1'], [portOf(openServer), closedPort]);
  const [host] = await scanAuthorizedPlan(plan, {
    bannerTimeoutMs: 50,
    maxBannerBytes: 1024,
    maxConcurrentPortsPerHost: 2,
  });

  assert.equal(host.status, 'up');
  assert.equal(host.scannedPortCount, 2);
  assert.equal(host.respondedPortCount, 1);
  assert.deepEqual(host.openPorts.map((item) => item.port), [portOf(openServer)]);
  assert.ok(!host.openPorts.some((item) => item.port === closedPort));
});

test('passive banner capture escapes control bytes and respects the banner timeout', async (t) => {
  const bannerServer = await listen((socket) => socket.write(Buffer.from('SSH-2.0-test\r\n\x01')));
  const silentServer = await listen(() => {});
  t.after(() => Promise.all([close(bannerServer), close(silentServer)]));

  const bannerResult = await scanTcpPort('127.0.0.1', portOf(bannerServer), {
    perPortTimeoutMs: 200,
    bannerTimeoutMs: 100,
    maxBannerBytes: 1024,
  });
  const silentResult = await scanTcpPort('127.0.0.1', portOf(silentServer), {
    perPortTimeoutMs: 200,
    bannerTimeoutMs: 40,
    maxBannerBytes: 1024,
  });

  assert.equal(bannerResult.status, 'open');
  assert.equal(bannerResult.probeUsed, false);
  assert.equal(bannerResult.banner.data, 'SSH-2.0-test\\r\\n\\x01');
  assert.equal(silentResult.status, 'open');
  assert.equal(silentResult.banner, null);
});

test('HTTP active probe sends only the reviewed HEAD payload and captures the response', async (t) => {
  let received = Buffer.alloc(0);
  const server = await listen((socket) => {
    socket.on('data', (chunk) => {
      received = Buffer.concat([received, chunk]);
      socket.end('HTTP/1.0 200 OK\r\nServer: fixture\r\n\r\n');
    });
  });
  t.after(() => close(server));

  const result = await scanTcpPort('127.0.0.1', portOf(server), {
    perPortTimeoutMs: 200,
    bannerTimeoutMs: 200,
    maxBannerBytes: 1024,
    activeProbes: { [portOf(server)]: ACTIVE_PROBES[8080] },
  });

  assert.equal(received.toString('ascii'), 'HEAD / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n');
  assert.equal(result.probeUsed, true);
  assert.match(result.banner.data, /^HTTP\/1\.0 200 OK/);
});

test('authorization denial prevents the scanner callback from being invoked', async () => {
  let scanCalls = 0;
  const collector = createNetworkScanCollector({
    scanPlan: async () => { scanCalls += 1; return []; },
    connectionProvider: async () => [],
  });

  const result = await collector.run({ targets: ['127.0.0.2'], ports: [80] }, {
    collectorConfig: {
      allowedCidrs: ['127.0.0.1/32'],
      maxCidrSize: 16,
    },
  });

  assert.equal(scanCalls, 0);
  assert.equal(result.hosts.length, 0);
  assert.equal(result.authorization.authorized, false);
  assert.equal(result.authorization.deniedTargets[0].target, '127.0.0.2');
});

test('mixed authorization passes only approved targets to the scanner', async () => {
  let receivedPlan;
  const collector = createNetworkScanCollector({
    scanPlan: async (plan) => { receivedPlan = plan; return []; },
    connectionProvider: async () => [],
  });

  const result = await collector.run({ targets: ['127.0.0.1', '127.0.0.2'], ports: [80] }, {
    collectorConfig: {
      allowedCidrs: ['127.0.0.1/32'],
      maxCidrSize: 16,
      maxScanOperationsPerTask: 10,
    },
  });

  assert.deepEqual(receivedPlan.approvedTargets.map((item) => item.target), ['127.0.0.1']);
  assert.deepEqual(result.authorization.deniedTargets.map((item) => item.target), ['127.0.0.2']);
});

test('host and per-host port concurrency limits are respected with real sockets', async (t) => {
  const servers = await Promise.all(Array.from({ length: 4 }, () => listen(() => {})));
  t.after(() => Promise.all(servers.map(close)));

  let activeHosts = 0;
  let maxActiveHosts = 0;
  let activePorts = 0;
  let maxActivePorts = 0;
  const hooks = {
    onHostScanStart() {
      activeHosts += 1;
      maxActiveHosts = Math.max(maxActiveHosts, activeHosts);
    },
    onHostScanEnd() { activeHosts -= 1; },
    onPortScanStart() {
      activePorts += 1;
      maxActivePorts = Math.max(maxActivePorts, activePorts);
    },
    onPortScanEnd() { activePorts -= 1; },
  };
  const hostPlan = planFor(
    ['127.0.0.1', '127.0.0.1', '127.0.0.1'],
    [portOf(servers[0])],
    { maxConcurrentTargets: 2 },
  );
  await scanAuthorizedPlan(hostPlan, {
    bannerTimeoutMs: 80,
    maxBannerBytes: 128,
    maxConcurrentPortsPerHost: 2,
    hooks,
  });
  assert.ok(maxActiveHosts <= 2);
  assert.ok(maxActiveHosts >= 2);

  activePorts = 0;
  maxActivePorts = 0;
  const portPlan = planFor(['127.0.0.1'], servers.map(portOf));
  await scanAuthorizedPlan(portPlan, {
    bannerTimeoutMs: 80,
    maxBannerBytes: 128,
    maxConcurrentPortsPerHost: 2,
    hooks,
  });
  assert.ok(maxActivePorts <= 2);
  assert.ok(maxActivePorts >= 2);
});

test('abort stops an in-progress loopback scan without waiting for banner timeout', async (t) => {
  const server = await listen(() => {});
  t.after(() => close(server));
  const controller = new AbortController();
  const plan = planFor(['127.0.0.1'], [portOf(server)]);
  const startedAt = Date.now();
  const scanning = scanAuthorizedPlan(plan, {
    signal: controller.signal,
    bannerTimeoutMs: 5000,
    maxBannerBytes: 128,
    maxConcurrentPortsPerHost: 1,
  });
  setTimeout(() => controller.abort(), 50);

  await assert.rejects(scanning, (error) => error.name === 'AbortError');
  assert.ok(Date.now() - startedAt < 1000);
});

test('local binding detection identifies a real loopback listener and classifies wildcard binding when available', async (t) => {
  const loopback = await listen();
  const wildcard = await listen(() => {}, '0.0.0.0');
  t.after(() => Promise.all([close(loopback), close(wildcard)]));

  const result = await detectLocalPortBindings();

  assert.equal(result.reason, null);
  const loopbackBinding = result.bindings.find((item) => item.port === portOf(loopback));
  assert.ok(loopbackBinding);
  assert.equal(loopbackBinding.scope, 'loopback-only');
  assert.equal(loopbackBinding.externallyReachable, false);

  const wildcardBinding = result.bindings.find((item) => item.port === portOf(wildcard));
  if (wildcardBinding) {
    assert.equal(wildcardBinding.scope, 'all-interfaces');
    assert.equal(wildcardBinding.externallyReachable, true);
  }
});

test('reviewed common port list and active probes remain explicit and bounded', () => {
  assert.deepEqual(COMMON_TCP_PORTS, [
    21, 22, 23, 25, 53, 80, 110, 111, 135,
    139, 143, 443, 445, 993, 995, 1433, 1521,
    2049, 2375, 3000, 3306, 3389, 5432, 6379,
    8000, 8080, 8443,
  ]);
  assert.deepEqual(Object.keys(ACTIVE_PROBES).map(Number), [80, 3000, 8000, 8080]);
  for (const payload of Object.values(ACTIVE_PROBES)) {
    assert.equal(payload.toString('ascii'), 'HEAD / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n');
  }
});
