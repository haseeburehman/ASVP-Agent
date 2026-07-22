import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { X509Certificate } from 'node:crypto';
import tls from 'node:tls';
import test from 'node:test';
import {
  createTlsChecksCollector,
  DEFAULT_TLS_PORTS,
  parseNmapHeartbleedXml,
  TLS_VERSIONS,
} from '../../src/collectors/tls-checks/index.js';

const fixtureDirectory = new URL('../fixtures/tls/', import.meta.url);

async function fixture(name) {
  return readFile(new URL(name, fixtureDirectory), 'utf8');
}

async function listenTls(certificateName = 'test-invalid-cert.pem') {
  const server = tls.createServer({
    key: await fixture('test-invalid-key.pem'),
    cert: await fixture(certificateName),
    minVersion: 'TLSv1.2',
    maxVersion: 'TLSv1.3',
  });
  server.on('tlsClientError', () => {});
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  return server;
}

async function close(server) {
  if (!server.listening) return;
  await new Promise((resolve) => server.close(resolve));
}

function collectorConfig(overrides = {}) {
  return {
    allowedCidrs: ['127.0.0.1/32'],
    maxCidrSize: 16,
    maxConcurrentTargets: 2,
    maxPortsPerHost: 10,
    perHostDelayMs: 0,
    perHandshakeTimeoutMs: 1000,
    nmapTimeoutMs: 1000,
    expiryWarningDays: 30,
    maxScanOperationsPerTask: 100,
    ...overrides,
  };
}

function nmapUnavailable() {
  const error = new Error('spawn nmap ENOENT');
  error.code = 'ENOENT';
  throw error;
}

test('real loopback TLS server reports versions, negotiated ciphers, certificate, and nmap unavailable', async (t) => {
  const server = await listenTls();
  t.after(() => close(server));
  const port = server.address().port;
  const collector = createTlsChecksCollector({ runCommand: async () => nmapUnavailable() });

  const result = await collector.run({ targets: ['127.0.0.1'], ports: [port] }, {
    collectorConfig: collectorConfig(),
  });

  assert.equal(result.authorization.authorized, true);
  assert.equal(result.endpoints.length, 1);
  const endpoint = result.endpoints[0];
  assert.equal(endpoint.target, '127.0.0.1');
  assert.equal(endpoint.port, port);
  assert.equal(endpoint.reachable, true);
  assert.equal(endpoint.versions.find((item) => item.version === 'TLS 1.2').status, 'supported');
  assert.equal(endpoint.versions.find((item) => item.version === 'TLS 1.3').status, 'supported');
  assert.ok(endpoint.versions.every((item) => ['supported', 'not-supported', 'client-limitation'].includes(item.status)));
  assert.ok(endpoint.weakCiphers.defaultNegotiatedCiphers.length >= 2);
  assert.ok(endpoint.weakCiphers.defaultNegotiatedCiphers.every((item) => typeof item.cipher.name === 'string'));
  assert.equal(endpoint.certificate.status, 'valid');
  assert.equal(endpoint.certificate.subject.CN, 'test.invalid');
  assert.equal(endpoint.heartbleed.status, 'not-assessed');
  assert.match(endpoint.heartbleed.reason, /nmap is unavailable/);
});

test('certificate expiry uses controlled clocks for expired and expiring-soon real certificates', async (t) => {
  for (const [certificateName, offsetDays, expectedStatus] of [
    ['test-invalid-expired-cert.pem', 1, 'expired'],
    ['test-invalid-soon-cert.pem', -5, 'expiring-soon'],
  ]) {
    const pem = await fixture(certificateName);
    const validTo = new Date(new X509Certificate(pem).validTo);
    const server = await listenTls(certificateName);
    t.after(() => close(server));
    const collector = createTlsChecksCollector({
      runCommand: async () => nmapUnavailable(),
      now: () => new Date(validTo.getTime() + offsetDays * 86400000),
    });
    const result = await collector.run({ targets: ['127.0.0.1'], ports: [server.address().port] }, {
      collectorConfig: collectorConfig(),
    });
    assert.equal(result.endpoints[0].certificate.status, expectedStatus);
  }
});

test('authorization denial prevents both TLS handshakes and nmap invocation', async () => {
  let handshakeCalls = 0;
  let commandCalls = 0;
  const collector = createTlsChecksCollector({
    handshake: async () => { handshakeCalls += 1; throw new Error('must not run'); },
    runCommand: async () => { commandCalls += 1; throw new Error('must not run'); },
  });

  const result = await collector.run({ targets: ['127.0.0.2'], ports: [443] }, {
    collectorConfig: collectorConfig(),
  });

  assert.equal(result.authorization.authorized, false);
  assert.equal(handshakeCalls, 0);
  assert.equal(commandCalls, 0);
  assert.deepEqual(result.endpoints, []);
});

test('local context failure is classified as client-limitation without attempting that handshake', async () => {
  const handshakeVersions = [];
  const fakeTls = {
    createSecureContext({ minVersion }) {
      if (minVersion === 'TLSv1') {
        const error = new Error('legacy protocol disabled for this runtime');
        error.code = 'ERR_SSL_NO_PROTOCOLS_AVAILABLE';
        throw error;
      }
      return { minVersion };
    },
    getCiphers() { return []; },
  };
  const collector = createTlsChecksCollector({
    tlsApi: fakeTls,
    runCommand: async () => nmapUnavailable(),
    handshake: async (_target, _port, options) => {
      handshakeVersions.push(options.minVersion);
      throw new Error('target rejected handshake');
    },
  });

  const result = await collector.run({ targets: ['127.0.0.1'], ports: [443] }, {
    collectorConfig: collectorConfig(),
  });

  const tls10 = result.endpoints[0].versions.find((item) => item.version === 'TLS 1.0');
  assert.equal(tls10.status, 'client-limitation');
  assert.equal(tls10.supportedByTarget, null);
  assert.ok(!handshakeVersions.includes('TLSv1'));
});

test('nmap parser distinguishes vulnerable, not-vulnerable, and inconclusive output', () => {
  const xml = (summary) => `<?xml version="1.0"?><nmaprun><host><ports><port protocol="tcp" portid="443"><script id="ssl-heartbleed" output="${summary}"/></port></ports></host></nmaprun>`;

  assert.equal(parseNmapHeartbleedXml(xml('State: VULNERABLE')).status, 'vulnerable');
  assert.equal(parseNmapHeartbleedXml(xml('State: NOT VULNERABLE')).status, 'not-vulnerable');
  assert.equal(parseNmapHeartbleedXml(xml('could not identify protocol')).status, 'inconclusive');
  assert.equal(parseNmapHeartbleedXml('<nmaprun/>').status, 'inconclusive');
});

test('nmap is invoked with the exact fixed argument layout for an approved endpoint', async () => {
  const calls = [];
  const notVulnerableXml = '<?xml version="1.0"?><nmaprun><host><ports><port protocol="tcp" portid="443"><script id="ssl-heartbleed" output="NOT VULNERABLE"/></port></ports></host></nmaprun>';
  const collector = createTlsChecksCollector({
    runCommand: async (command, args) => {
      calls.push([command, args]);
      if (args[0] === '--version') return 'Nmap version 7.95';
      return notVulnerableXml;
    },
    handshake: async () => { throw new Error('target protocol not supported'); },
  });

  const result = await collector.run({ targets: ['127.0.0.1'], ports: [443] }, {
    collectorConfig: collectorConfig(),
  });

  assert.deepEqual(calls[0], ['nmap', ['--version']]);
  assert.deepEqual(calls[1], ['nmap', ['-p', '443', '--script', 'ssl-heartbleed', '127.0.0.1', '-oX', '-']]);
  assert.equal(result.endpoints[0].heartbleed.status, 'not-vulnerable');
});

test('TLS task operation cap refuses work before nmap or handshakes', async () => {
  let calls = 0;
  const collector = createTlsChecksCollector({
    runCommand: async () => { calls += 1; throw new Error('must not run'); },
    handshake: async () => { calls += 1; throw new Error('must not run'); },
  });

  const result = await collector.run({ targets: ['127.0.0.1'], ports: [443, 8443] }, {
    collectorConfig: collectorConfig({ maxScanOperationsPerTask: 5 }),
  });

  assert.equal(result.authorization.authorized, false);
  assert.equal(result.authorization.code, 'tls-operation-limit-exceeded');
  assert.equal(calls, 0);
});

test('TLS constants remain explicit', () => {
  assert.deepEqual(DEFAULT_TLS_PORTS, [443, 8443]);
  assert.deepEqual(TLS_VERSIONS.map((item) => item.nodeName), ['TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3']);
});
