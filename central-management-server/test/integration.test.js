import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { AgentLifecycle } from '../../src/agent/lifecycle.js';
import { DashboardServer } from '../../src/dashboard/server.js';
import { CredentialStore } from '../../src/security/credentials.js';
import { createApp } from '../src/app.js';
import { createDatabase } from '../src/database.js';

const logger = { info() {}, warn() {}, error() {}, debug() {}, flush() {} };

function listen(app) {
  return new Promise((resolve, reject) => {
    const server = app.listen(0, '127.0.0.1', () => resolve(server));
    server.once('error', reject);
  });
}

async function waitFor(readValue, { timeoutMs = 25000, intervalMs = 100 } = {}) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const value = readValue();
    if (value) return value;
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
  throw new Error(`Condition was not met within ${timeoutMs}ms`);
}

test('real AgentLifecycle registers, heartbeats, polls, runs os-info, and uploads readable data', { timeout: 35000 }, async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'asvp-server-integration-'));
  const database = createDatabase({ filename: ':memory:' });
  const events = [];
  const adminToken = 'integration-admin-token';
  const app = createApp({ database, adminToken, baselineCollectors: [], logger: { info: (event) => events.push(event), warn() {}, error() {} } });
  const server = await listen(app);
  let lifecycle;
  try {
    const port = server.address().port;
    const config = {
      server: {
        mode: 'http', url: `http://127.0.0.1:${port}`, registrationPath: '/api/agents/register',
        heartbeatPath: '/api/agents/heartbeat', tasksPath: '/api/agents/tasks/poll',
        resultsPath: '/api/agents/results', adminToken, requestTimeoutMs: 5000,
      },
      agent: { heartbeatIntervalMs: 150, pollIntervalMs: 150, logLevel: 'silent' },
      dashboard: { enabled: false, port: 4180, bindAddress: '127.0.0.1' },
      storage: {
        identityPath: path.join(directory, 'identity.json'), statusPath: path.join(directory, 'status.json'),
        queueDir: path.join(directory, 'queue'), maxQueueSizeBytes: 10_000_000, maxQueueItems: 100,
        maxItemAgeMs: 60_000,
      },
      retry: { initialDelayMs: 100, maximumDelayMs: 500 },
      collectors: {
        upload: { intervalMs: 150, uploadConcurrency: 1, maxPayloadWarningBytes: 1_000_000 },
        'os-info': { timeoutMs: 15000, concurrency: 1 },
      },
    };
    const credentialStore = await new CredentialStore({
      identityPath: config.storage.identityPath, keychain: null, logger, cwd: directory,
    }).initialize();
    lifecycle = new AgentLifecycle({ config, version: '0.1.0', logger, credentialStore, cwd: directory });
    await lifecycle.start();

    const dashboard = new DashboardServer({ config, logger, version: '0.1.0', cwd: directory });
    dashboard.lifecycle = lifecycle;
    const { taskId } = await dashboard.createTask({ collectorName: 'os-info' });

    const stored = await waitFor(() => database.prepare('SELECT * FROM results WHERE task_id = ?').get(taskId));
    const result = JSON.parse(stored.raw_data);
    assert.equal(result.taskId, taskId);
    assert.equal(result.collector, 'os-info');
    assert.equal(result.status, 'success');
    assert.equal(typeof result.data.prettyName, 'string');
    assert.equal(database.prepare('SELECT status FROM tasks WHERE id = ?').get(taskId).status, 'completed');
    const agent = database.prepare('SELECT * FROM agents WHERE id = ?').get(stored.agent_id);
    assert.equal(agent.status, 'online');
    assert.ok(agent.last_heartbeat_at);
    assert.ok(events.some((event) => event.event === 'register'));
    assert.ok(events.some((event) => event.event === 'heartbeat'));
    assert.ok(events.some((event) => event.event === 'poll' && event.taskCount === 1));
    assert.ok(events.some((event) => event.event === 'result' && event.taskId === taskId));
  } finally {
    await lifecycle?.stop();
    await new Promise((resolve) => server.close(resolve));
    database.close();
    await rm(directory, { recursive: true, force: true });
  }
});
