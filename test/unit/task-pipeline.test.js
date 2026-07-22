import assert from 'node:assert/strict';
import test from 'node:test';
import { CollectorRegistry, CollectorNotImplementedError } from '../../src/core/collector-registry.js';
import { TaskRunner } from '../../src/core/task-runner.js';
import { ApiClient, MockManagementTransport } from '../../src/transport/api-client.js';

const silentLogger = {
  info() {},
  warn() {},
  debug() {},
  error() {},
};

function createApiConfig() {
  return {
    server: {
      mode: 'mock',
      url: 'mock://test',
      registrationPath: '/register',
      heartbeatPath: '/heartbeat',
      tasksPath: '/tasks',
      requestTimeoutMs: 1000,
    },
  };
}

test('collector registry finds implemented collectors and reports unknown or unimplemented collectors', async () => {
  const registry = new CollectorRegistry();

  assert.equal(registry.has('noop'), true);
  assert.equal(registry.has('does-not-exist'), false);
  assert.equal((await registry.get('noop')).name, 'noop');
  assert.equal((await registry.get('network-scan')).name, 'network-scan');
  await assert.rejects(registry.get('tls-checks'), (error) => {
    assert.ok(error instanceof CollectorNotImplementedError);
    assert.match(error.message, /allowlisted but not implemented/);
    return true;
  });
  await assert.rejects(registry.get('does-not-exist'), /not registered or implemented/);
});

test('task runner enforces the configured collector timeout', async () => {
  const collector = {
    name: 'hung',
    version: '1.0.0',
    async run() {
      return new Promise(() => {});
    },
  };
  const registry = {
    getDefinition: () => ({ implemented: true, timeoutMs: 20, concurrency: 1 }),
    async get() { return collector; },
  };
  const handedOff = [];
  const runner = new TaskRunner({
    registry,
    logger: silentLogger,
    onResult: async (result) => handedOff.push(result),
  });

  const result = await runner.run({ taskId: 'timeout-1', collectorName: 'hung', params: {} });

  assert.equal(result.status, 'timeout');
  assert.equal(result.error.code, 'COLLECTOR_TIMEOUT');
  assert.match(result.error.message, /20ms timeout/);
  assert.deepEqual(handedOff, [result]);
});

test('task runner converts an unknown collector into a failed result', async () => {
  const handedOff = [];
  const runner = new TaskRunner({
    registry: new CollectorRegistry(),
    logger: silentLogger,
    onResult: async (result) => handedOff.push(result),
  });

  const result = await runner.run({ taskId: 'unknown-1', collectorName: 'unknown-plugin' });

  assert.equal(result.taskId, 'unknown-1');
  assert.equal(result.collector, 'unknown-plugin');
  assert.equal(result.status, 'failed');
  assert.equal(result.error.code, 'COLLECTOR_NOT_IMPLEMENTED');
  assert.match(result.error.message, /not registered or implemented/);
  assert.deepEqual(handedOff, [result]);
});

test('mock transport runs noop and safely refuses the default network scan end-to-end', async () => {
  const apiClient = new ApiClient({
    config: createApiConfig(),
    transport: new MockManagementTransport(),
  });
  const identity = { agentId: 'test-agent', authToken: 'test-token' };
  const tasks = await apiClient.pollTasks(identity);
  const handedOff = [];
  const runner = new TaskRunner({
    registry: new CollectorRegistry(),
    logger: silentLogger,
    onResult: async (result) => handedOff.push(result),
  });

  const results = await runner.runAll(tasks);
  const noop = results.find((result) => result.collector === 'noop');
  const networkScan = results.find((result) => result.collector === 'network-scan');

  assert.equal(tasks.length, 2);
  assert.equal(noop.status, 'success');
  assert.equal(noop.data.message, 'No-op collector completed');
  assert.equal(noop.data.echo.source, 'mock-management-transport');
  assert.equal(networkScan.status, 'success');
  assert.equal(networkScan.error, null);
  assert.equal(networkScan.data.authorization.authorized, false);
  assert.equal(networkScan.data.authorization.code, 'allowlist-not-configured');
  assert.deepEqual(networkScan.data.hosts, []);
  assert.equal(handedOff.length, 2);
  assert.deepEqual(await apiClient.pollTasks(identity), []);
});
