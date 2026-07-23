import assert from 'node:assert/strict';
import { mkdtemp, rm, stat } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { AgentLifecycle } from '../../src/agent/lifecycle.js';
import { ResultStore } from '../../src/storage/result-store.js';

const silentLogger = {
  info() {},
  warn() {},
  debug() {},
  error() {},
  flush() {},
};

async function withTempDirectory(callback) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'asvp-queue-'));
  try {
    await callback(directory);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

function createStore(directory, overrides = {}) {
  return new ResultStore({
    queueDir: path.join(directory, 'queue'),
    maxQueueSizeBytes: 1024 * 1024,
    maxQueueItems: 100,
    maxItemAgeMs: 86400000,
    logger: silentLogger,
    ...overrides,
  });
}

function result(number = 1) {
  return {
    taskId: `task-${number}`,
    collector: 'noop',
    startedAt: '2026-01-01T00:00:00.000Z',
    finishedAt: '2026-01-01T00:00:00.001Z',
    status: 'success',
    data: { number },
    error: null,
  };
}

test('enqueue and delivery-state transitions round trip durably', async () => {
  await withTempDirectory(async (directory) => {
    const store = await createStore(directory).initialize();
    const first = await store.enqueue(result(1));
    const second = await store.enqueue(result(2));

    assert.equal(first.state, 'pending');
    assert.equal(first.attemptCount, 0);
    assert.deepEqual((await store.listPending()).map((item) => item.id), [first.id, second.id]);

    const inFlight = await store.markInFlight(first.id);
    assert.equal(inFlight.state, 'in-flight');
    assert.equal(inFlight.attemptCount, 1);
    assert.equal(typeof inFlight.lastAttemptAt, 'string');

    const delivered = await store.markDelivered(first.id);
    assert.equal(delivered.state, 'delivered');
    const failed = await store.markFailed(second.id, new Error('non-retryable result'));
    assert.equal(failed.state, 'failed-permanent');
    assert.equal(failed.lastError, 'non-retryable result');

    assert.deepEqual(await store.listPending(), []);
    const stats = await store.getStats();
    assert.equal(stats.deliveredCount, 1);
    assert.equal(stats.failedPermanentCount, 1);
    assert.equal(typeof stats.failedPermanentRetainUntil, 'string');
  });
});

test('startup recovery changes persisted in-flight items back to pending', async () => {
  await withTempDirectory(async (directory) => {
    const firstProcess = await createStore(directory).initialize();
    const queued = await firstProcess.enqueue(result());
    await firstProcess.markInFlight(queued.id);

    const restarted = await createStore(directory).initialize();
    const recovered = await restarted.requeueStaleInFlight();
    const pending = await restarted.listPending();

    assert.equal(recovered, 1);
    assert.equal(pending.length, 1);
    assert.equal(pending[0].id, queued.id);
    assert.equal(pending[0].state, 'pending');
    assert.equal(pending[0].attemptCount, 1);
    assert.match(pending[0].lastError, /Recovered an in-flight/);
  });
});

test('count cap evicts oldest items first and tracks eviction metrics', async () => {
  await withTempDirectory(async (directory) => {
    let tick = 0;
    const store = await createStore(directory, {
      maxQueueItems: 2,
      now: () => new Date(1700000000000 + tick++ * 1000),
    }).initialize();
    const oldest = await store.enqueue(result(1));
    const middle = await store.enqueue(result(2));
    const newest = await store.enqueue(result(3));
    const pendingIds = (await store.listPending()).map((item) => item.id);

    assert.ok(!pendingIds.includes(oldest.id));
    assert.ok(pendingIds.includes(middle.id));
    assert.ok(pendingIds.includes(newest.id));
    const stats = await store.getStats();
    assert.equal(stats.evictedCount, 1);
    assert.equal(typeof stats.lastEvictedAt, 'string');
  });
});

test('byte-size cap evicts oldest files independently of count cap', async () => {
  await withTempDirectory(async (directory) => {
    let tick = 0;
    const store = await createStore(directory, {
      now: () => new Date(1700000000000 + tick++ * 1000),
    }).initialize();
    const oldest = await store.enqueue({ ...result(1), data: { payload: 'a'.repeat(1000) } });
    const firstSize = (await store.getStats()).totalBytes;
    store.maxQueueSizeBytes = firstSize + Math.floor(firstSize / 2);
    const newest = await store.enqueue({ ...result(2), data: { payload: 'b'.repeat(1000) } });
    const pendingIds = (await store.listPending()).map((item) => item.id);

    assert.ok(!pendingIds.includes(oldest.id));
    assert.ok(pendingIds.includes(newest.id));
    assert.equal((await store.getStats()).evictedCount, 1);
  });
});

test('age limit evicts stale items while retaining newer results', async () => {
  await withTempDirectory(async (directory) => {
    let currentTime = 1700000000000;
    const store = await createStore(directory, {
      maxItemAgeMs: 1000,
      now: () => new Date(currentTime),
    }).initialize();
    const stale = await store.enqueue(result(1));
    currentTime += 2000;
    const fresh = await store.enqueue(result(2));
    const pendingIds = (await store.listPending()).map((item) => item.id);

    assert.ok(!pendingIds.includes(stale.id));
    assert.ok(pendingIds.includes(fresh.id));
    assert.equal((await store.getStats()).evictedCount, 1);
  });
});

test('failed-permanent retention visibility clears when age eviction removes the item', async () => {
  await withTempDirectory(async (directory) => {
    let currentTime = 1700000000000;
    const store = await createStore(directory, {
      maxItemAgeMs: 1000,
      now: () => new Date(currentTime),
    }).initialize();
    const queued = await store.enqueue(result(1));
    await store.markFailed(queued.id, 'permanent rejection');
    let stats = await store.getStats();
    assert.equal(stats.failedPermanentCount, 1);
    assert.equal(stats.failedPermanentRetainUntil, new Date(1700000001000).toISOString());
    currentTime += 2000;
    await store.enqueue(result(2));
    stats = await store.getStats();
    assert.equal(stats.failedPermanentCount, 0);
    assert.equal(stats.failedPermanentRetainUntil, null);
  });
});

test('concurrent enqueue calls are serialized without corruption or loss', async () => {
  await withTempDirectory(async (directory) => {
    const store = await createStore(directory).initialize();
    const queued = await Promise.all(Array.from({ length: 20 }, (_, index) => store.enqueue(result(index))));
    const pending = await store.listPending();

    assert.equal(new Set(queued.map((item) => item.id)).size, 20);
    assert.equal(pending.length, 20);
    assert.deepEqual(new Set(pending.map((item) => item.result.data.number)), new Set(Array.from({ length: 20 }, (_, index) => index)));
  });
});

test('queue directory and files use restrictive permissions where supported', async () => {
  await withTempDirectory(async (directory) => {
    const store = await createStore(directory).initialize();
    const item = await store.enqueue(result());
    if (process.platform !== 'win32') {
      const directoryMode = (await stat(store.queueDir)).mode & 0o777;
      const fileMode = (await stat(path.join(store.queueDir, `${item.id}.json`))).mode & 0o777;
      assert.equal(directoryMode, 0o700);
      assert.equal(fileMode, 0o600);
    } else {
      assert.ok((await stat(store.queueDir)).isDirectory());
      assert.ok((await stat(path.join(store.queueDir, `${item.id}.json`))).isFile());
    }
  });
});

test('lifecycle task pipeline durably queues a collector result as pending', async () => {
  await withTempDirectory(async (directory) => {
    let deliveredTasks = false;
    const config = {
      server: {
        mode: 'mock', registrationPath: '/register', heartbeatPath: '/heartbeat', tasksPath: '/tasks', resultsPath: '/results',
      },
      agent: { heartbeatIntervalMs: 60000, pollIntervalMs: 60000, logLevel: 'silent' },
      storage: {
        identityPath: path.join(directory, 'identity.json'),
        statusPath: path.join(directory, 'status.json'),
        queueDir: path.join(directory, 'queue'),
        maxQueueSizeBytes: 1024 * 1024,
        maxQueueItems: 100,
        maxItemAgeMs: 86400000,
      },
      retry: { initialDelayMs: 100, maximumDelayMs: 1000 },
      collectors: {
        upload: { intervalMs: 60000, uploadConcurrency: 1, maxPayloadWarningBytes: 1024 * 1024 },
        noop: { timeoutMs: 1000, concurrency: 1 },
      },
    };
    const credentialStore = {
      async initialize() { return this; },
      async loadIdentity() {
        return {
          agentId: 'integration-agent',
          authToken: 'integration-token',
          encryptionKey: Buffer.alloc(32, 7).toString('base64'),
        };
      },
    };
    const apiClient = {
      async sendHeartbeat() { return { accepted: true }; },
      async uploadResult() { throw new Error('offline during lifecycle queue test'); },
      async pollTasks() {
        if (deliveredTasks) return [];
        deliveredTasks = true;
        return [{ taskId: 'integration-task', collectorName: 'noop', params: { integration: true } }];
      },
    };
    const lifecycle = new AgentLifecycle({
      config,
      version: '0.1.0',
      logger: silentLogger,
      credentialStore,
      apiClient,
      cwd: directory,
    });

    await lifecycle.start();
    await new Promise((resolve) => setTimeout(resolve, 100));
    await lifecycle.stop();

    const pending = await lifecycle.resultStore.listPending();
    assert.equal(pending.length, 1);
    assert.equal(pending[0].state, 'pending');
    assert.equal(pending[0].result.taskId, 'integration-task');
    assert.equal(pending[0].result.collector, 'noop');
    assert.equal(lifecycle.getHealth().queueDepth, 1);
  });
});
