import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { WebSocket } from 'ws';
import { runManualScan } from '../../src/cli/commands.js';
import { DashboardServer } from '../../src/dashboard/server.js';

const logger = { info() {}, warn() {}, error() {}, debug() {}, flush() {} };

function testConfig(directory) {
  return {
    server: {
      mode: 'mock', url: 'mock://dashboard-test', registrationPath: '/register', heartbeatPath: '/heartbeat',
      tasksPath: '/tasks', resultsPath: '/results', requestTimeoutMs: 1000,
    },
    agent: { heartbeatIntervalMs: 60000, pollIntervalMs: 60000, logLevel: 'silent' },
    dashboard: { enabled: false, port: 0, bindAddress: '127.0.0.1' },
    storage: {
      identityPath: path.join(directory, 'identity.json'), statusPath: path.join(directory, 'status.json'),
      queueDir: path.join(directory, 'queue'), maxQueueSizeBytes: 1_000_000, maxQueueItems: 100, maxItemAgeMs: 60_000,
    },
    retry: { initialDelayMs: 100, maximumDelayMs: 1000 },
    collectors: {
      upload: { intervalMs: 60000, uploadConcurrency: 1, maxPayloadWarningBytes: 1_000_000 },
      'os-info': { timeoutMs: 25000, concurrency: 1, patchCheckTimeoutMs: 15000 },
      'network-scan': {
        allowedCidrs: [], maxCidrSize: 16, allowWideRanges: false, timeoutMs: 1000, concurrency: 1,
        maxConcurrentTargets: 1, maxConcurrentPortsPerHost: 1, maxPortsPerHost: 10,
        perHostDelayMs: 0, perPortTimeoutMs: 50, bannerTimeoutMs: 50, maxBannerBytes: 128,
        maxScanOperationsPerTask: 10,
      },
      'tls-checks': {
        allowedCidrs: [], maxCidrSize: 16, allowWideRanges: false, timeoutMs: 1000, concurrency: 1,
        maxConcurrentTargets: 1, maxPortsPerHost: 10, perHostDelayMs: 0, perHandshakeTimeoutMs: 50,
        nmapTimeoutMs: 50, expiryWarningDays: 30, maxScanOperationsPerTask: 10,
      },
      'sca-deps': { timeoutMs: 1000, concurrency: 1, scanPaths: [], maxDepth: 1, maxManifests: 1 },
    },
  };
}

async function withDashboard(callback) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'asvp-dashboard-'));
  const dashboard = new DashboardServer({
    config: testConfig(directory), logger, version: 'test', token: 'test-dashboard-token', cwd: directory,
  });
  try {
    await dashboard.start({ startAgent: false });
    await callback(dashboard);
  } finally {
    await dashboard.stop();
    await rm(directory, { recursive: true, force: true });
  }
}

function receiveOne(socket) {
  return new Promise((resolve, reject) => {
    socket.once('message', (data) => resolve(JSON.parse(data.toString())));
    socket.once('error', reject);
  });
}

test('dashboard is disabled in the default configuration and is not part of AgentLifecycle startup', async () => {
  const { loadConfig } = await import('../../src/config/loader.js');
  const config = await loadConfig({ env: {}, loadDotEnv: false });
  assert.equal(config.dashboard.enabled, false);
  const lifecycleSource = await import('node:fs/promises').then(({ readFile }) => readFile(new URL('../../src/agent/lifecycle.js', import.meta.url), 'utf8'));
  assert.doesNotMatch(lifecycleSource, /DashboardServer|dashboard\/server/);
});

test('HTTP page and WebSocket both require the local dashboard token', async () => {
  await withDashboard(async (dashboard) => {
    const base = `http://127.0.0.1:${dashboard.port}`;
    assert.equal((await fetch(`${base}/`)).status, 401);
    const page = await fetch(`${base}/?token=test-dashboard-token`);
    assert.equal(page.status, 200);
    assert.match(await page.text(), /ASVP Agent Console/);

    const rejectedStatus = await new Promise((resolve, reject) => {
      const socket = new WebSocket(`ws://127.0.0.1:${dashboard.port}/ws`);
      socket.once('unexpected-response', (_request, response) => resolve(response.statusCode));
      socket.once('error', reject);
    });
    assert.equal(rejectedStatus, 401);

    const socket = new WebSocket(`ws://127.0.0.1:${dashboard.port}/ws?token=test-dashboard-token`);
    const first = await receiveOne(socket);
    assert.equal(first.type, 'snapshot');
    socket.close();
  });
});

test('WebSocket scan command uses the same normalized manual-scan pipeline as the CLI service', async () => {
  await withDashboard(async (dashboard) => {
    const direct = await runManualScan({
      collectorName: 'os-info', queue: false, config: dashboard.config, logger, cwd: dashboard.cwd,
    });
    const socket = new WebSocket(`ws://127.0.0.1:${dashboard.port}/ws?token=test-dashboard-token`);
    await receiveOne(socket);
    const responsePromise = new Promise((resolve, reject) => {
      socket.on('message', (raw) => {
        const message = JSON.parse(raw.toString());
        if (message.type === 'command-result') resolve(message);
      });
      socket.once('error', reject);
    });
    socket.send(JSON.stringify({ type: 'command', id: 'scan-1', command: 'scan os-info --no-queue' }));
    const response = await responsePromise;
    assert.equal(response.ok, true);
    assert.equal(response.output.collector, direct.result.collector);
    assert.equal(response.output.status, direct.result.status);
    assert.deepEqual(Object.keys(response.output), Object.keys(direct.result));
    assert.equal(typeof response.output.data.prettyName, 'string');
    socket.close();
  });
});

test('dashboard saves the loopback HTTP server URL without confusing it with the status label', async () => {
  await withDashboard(async (dashboard) => {
    dashboard.config.dashboard.port = 4180;
    const saved = await dashboard.saveConfig({
      server: { mode: 'http', url: '  http://127.0.0.1:8080  ' },
      networkScanAllowedCidrs: [],
      scaDepsScanPaths: [],
    });
    assert.equal(saved.config.server.mode, 'http');
    assert.equal(saved.config.server.url, 'http://127.0.0.1:8080');
    const html = await import('node:fs/promises').then(({ readFile }) => readFile(new URL('../../src/dashboard/public/index.html', import.meta.url), 'utf8'));
    assert.equal((html.match(/id="serverUrl"/g) ?? []).length, 1);
    assert.equal((html.match(/id="connectedServerUrl"/g) ?? []).length, 1);
  });
});

test('mock mode disables central task creation with a clear reason', async () => {
  await withDashboard(async (dashboard) => {
    const snapshot = dashboard.snapshot();
    assert.equal(snapshot.agentVersion, 'test');
        assert.equal(snapshot.taskCreation.enabled, false);
    assert.equal(snapshot.taskCreation.reason, 'Task creation requires a real connected server');
    await assert.rejects(
      dashboard.createTask({ collectorName: 'os-info' }),
      /Task creation requires a real connected server/,
    );
  });
});

test('one-shot connection test reports success and unreachable states', async () => {
  await withDashboard(async (dashboard) => {
    dashboard.config.server.mode = 'http';
    dashboard.config.server.url = 'http://127.0.0.1:8080';
    dashboard.lifecycle = {
      getHealth: () => ({ state: 'running', agentId: 'agent-1', lastHeartbeatAt: new Date().toISOString(), lastHeartbeatError: null, lastPollAt: new Date().toISOString(), lastPollError: null }),
      testConnection: async () => ({ ok: true, testedAt: new Date().toISOString(), latencyMs: 4 }),
      stop: async () => {},
    };
    const success = await dashboard.testConnection();
    assert.equal(success.ok, true);
    assert.equal(success.serverUrl, 'http://127.0.0.1:8080');
    assert.equal(dashboard.snapshot().serverConnectionState, 'connected');

    dashboard.lifecycle = {
      getHealth: () => ({ state: 'running', agentId: 'agent-1', lastHeartbeatAt: null, lastHeartbeatError: 'fetch failed', lastPollAt: null, lastPollError: 'fetch failed' }),
      testConnection: async () => { throw new Error('fetch failed'); },
      stop: async () => {},
    };
    await assert.rejects(dashboard.testConnection(), /fetch failed/);
    assert.equal(dashboard.snapshot().serverConnectionState, 'unreachable');
  });
});

test('dashboard and CLI manual paths deny the same unauthorized network target before scanning', async () => {
  await withDashboard(async (dashboard) => {
    let directError;
    try {
      await runManualScan({
        collectorName: 'network-scan', targets: ['192.0.2.10'], ports: [443], queue: false,
        config: dashboard.config, logger, cwd: dashboard.cwd,
      });
    } catch (error) {
      directError = error;
    }
    await assert.rejects(
      dashboard.executeOperatorCommand('scan network-scan --target 192.0.2.10 --ports 443', new AbortController().signal),
      (error) => error.code === 'AUTHORIZATION_DENIED' && error.message === directError.message,
    );
  });
});
