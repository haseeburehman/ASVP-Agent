import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { parsePorts, runManualScan } from '../../src/cli/commands.js';
import { ResultStore } from '../../src/storage/result-store.js';

const logger = { info() {}, warn() {}, error() {}, debug() {} };

function config(queueDir, collectorOverrides = {}) {
  return {
    storage: {
      queueDir,
      maxQueueSizeBytes: 1_000_000,
      maxQueueItems: 100,
      maxItemAgeMs: 60_000,
    },
    collectors: {
      'os-info': { timeoutMs: 1000, concurrency: 1 },
      'network-scan': {
        allowedCidrs: ['127.0.0.1/32'],
        maxCidrSize: 16,
        allowWideRanges: false,
        maxConcurrentTargets: 1,
        maxConcurrentPortsPerHost: 1,
        maxPortsPerHost: 10,
        perHostDelayMs: 0,
        perPortTimeoutMs: 50,
        maxScanOperationsPerTask: 10,
        ...collectorOverrides,
      },
    },
  };
}

function registryFor(name, collector, getSpy = () => {}) {
  return {
    has(value) { return value === name; },
    getDefinition(value) {
      return value === name ? { implemented: true, timeoutMs: 1000, concurrency: 1 } : null;
    },
    async get(value) {
      getSpy(value);
      if (value !== name) throw new Error('unknown collector');
      return collector;
    },
  };
}

test('manual scan refuses unauthorized targets before collector loading or execution', async () => {
  let getCalls = 0;
  let runCalls = 0;
  const registry = registryFor('network-scan', {
    name: 'network-scan',
    version: 'test',
    async run() { runCalls += 1; return {}; },
  }, () => { getCalls += 1; });

  await assert.rejects(
    runManualScan({
      collectorName: 'network-scan',
      targets: ['192.0.2.10'],
      ports: [443],
      queue: false,
      config: config('unused'),
      logger,
      registry,
    }),
    /authorization denied: not in allowedCidrs/,
  );
  assert.equal(getCalls, 0);
  assert.equal(runCalls, 0);
});

test('manual os-info scan runs without a target through TaskRunner', async () => {
  const registry = registryFor('os-info', {
    name: 'os-info',
    version: 'test',
    async run(params) {
      assert.deepEqual(params, {});
      return { prettyName: 'Test OS', version: '1.0' };
    },
  });
  const { result, task } = await runManualScan({
    collectorName: 'os-info',
    queue: false,
    config: config('unused'),
    logger,
    registry,
    taskId: 'manual-test-os',
  });

  assert.equal(result.status, 'success');
  assert.equal(result.collector, 'os-info');
  assert.equal(task.taskId, 'manual-test-os');
  assert.deepEqual(result.data, { prettyName: 'Test OS', version: '1.0' });
});

test('manual scan durably queues its normalized result by default', async () => {
  const temporaryDirectory = await mkdtemp(path.join(os.tmpdir(), 'asvp-manual-scan-'));
  try {
    const queueDir = path.join(temporaryDirectory, 'queue');
    const runtimeConfig = config(queueDir);
    const store = new ResultStore({
      ...runtimeConfig.storage,
      logger,
    });
    const registry = registryFor('os-info', {
      name: 'os-info',
      version: 'test',
      async run() { return { prettyName: 'Queued OS', version: '2.0' }; },
    });

    const { result, queued } = await runManualScan({
      collectorName: 'os-info',
      config: runtimeConfig,
      logger,
      registry,
      resultStore: store,
      taskId: 'manual-test-queue',
    });
    const pending = await store.listPending();

    assert.equal(queued.state, 'pending');
    assert.equal(pending.length, 1);
    assert.equal(pending[0].result.taskId, 'manual-test-queue');
    assert.deepEqual(pending[0].result, result);
  } finally {
    await rm(temporaryDirectory, { recursive: true, force: true });
  }
});

test('manual port parsing accepts comma-separated ports and rejects invalid values', () => {
  assert.deepEqual(parsePorts('22, 80,443'), [22, 80, 443]);
  assert.throws(() => parsePorts('22,not-a-port'), /Invalid TCP port/);
  assert.throws(() => parsePorts('0'), /Invalid TCP port/);
});
