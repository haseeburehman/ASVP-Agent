import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { decrypt, generateEncryptionKey } from '../../src/security/crypto.js';
import { ResultStore } from '../../src/storage/result-store.js';
import { ApiClient, ManagementHttpError, MockManagementTransport } from '../../src/transport/api-client.js';
import { compressResult, decompressResult, ResultUploader } from '../../src/transport/result-uploader.js';

const logger = { info() {}, warn() {}, error() {}, debug() {} };

async function createHarness(uploadHandler) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'asvp-uploader-'));
  const resultStore = await new ResultStore({
    queueDir: path.join(directory, 'queue'),
    maxQueueSizeBytes: 10_000_000,
    maxQueueItems: 100,
    maxItemAgeMs: 60_000,
    logger,
  }).initialize();
  const transport = new MockManagementTransport({ tasks: [], uploadHandler });
  const apiClient = new ApiClient({
    config: {
      server: {
        mode: 'mock', url: 'mock://test', registrationPath: '/register', heartbeatPath: '/heartbeat',
        tasksPath: '/tasks', resultsPath: '/results', requestTimeoutMs: 1000,
      },
    },
    transport,
  });
  const identity = {
    agentId: 'upload-test-agent',
    authToken: 'upload-test-token',
    encryptionKey: generateEncryptionKey(),
  };
  const uploader = new ResultUploader({ resultStore, apiClient, identity, logger, uploadConcurrency: 2 });
  return {
    directory, resultStore, transport, identity, uploader,
    cleanup: () => rm(directory, { recursive: true, force: true }),
  };
}

test('gzip compression round trip reduces a realistic repetitive result', async () => {
  const result = { collector: 'apps', status: 'success', data: { applications: Array.from({ length: 100 }, (_, index) => ({ name: `application-${index % 5}`, version: '1.2.3', status: 'installed' })) } };
  const compressed = await compressResult(result);
  assert.ok(compressed.compressedSizeBytes < compressed.uncompressedSizeBytes);
  assert.deepEqual(await decompressResult(compressed.compressed), result);
});

test('uploader compresses, encrypts, uploads, and marks a queue item delivered', async () => {
  const harness = await createHarness();
  try {
    const original = { taskId: 'task-1', collector: 'os-info', status: 'success', data: { os: 'Test OS', repeated: 'x'.repeat(2000) } };
    const item = await harness.resultStore.enqueue(original);
    const summary = await harness.uploader.drain();

    assert.deepEqual(summary, { attempted: 1, delivered: 1, requeued: 0, failedPermanent: 0, interrupted: 0 });
    assert.equal((await harness.resultStore.getStats()).deliveredCount, 1);
    assert.equal(harness.transport.receivedUploads.length, 1);
    const wire = harness.transport.receivedUploads[0];
    const compressed = decrypt(wire.ciphertext, harness.identity.encryptionKey, wire.iv, wire.authTag);
    assert.deepEqual(await decompressResult(compressed), original);
    assert.equal(wire.queueItemId, item.id);
    assert.equal(wire.agentId, harness.identity.agentId);
    assert.equal(wire.contentEncoding, 'gzip');
    assert.equal(wire.encryption, 'aes-256-gcm');
    assert.ok(wire.compressedSizeBytes < wire.uncompressedSizeBytes);
  } finally {
    await harness.cleanup();
  }
});

test('transient upload failure returns an in-flight item to pending', async () => {
  const harness = await createHarness(async () => { throw new ManagementHttpError(503); });
  try {
    await harness.resultStore.enqueue({ collector: 'noop', status: 'success' });
    const summary = await harness.uploader.drain();
    assert.equal(summary.requeued, 1);
    const pending = await harness.resultStore.listPending();
    assert.equal(pending.length, 1);
    assert.match(pending[0].lastError, /HTTP 503/);
    assert.equal(pending[0].attemptCount, 1);
  } finally {
    await harness.cleanup();
  }
});

test('authentication failures remain retryable rather than discarding queued data', async () => {
  const harness = await createHarness(async () => { throw new ManagementHttpError(401); });
  try {
    await harness.resultStore.enqueue({ collector: 'apps', status: 'success' });
    const summary = await harness.uploader.drain();
    assert.equal(summary.requeued, 1);
    assert.equal((await harness.resultStore.getStats()).failedPermanentCount, 0);
  } finally {
    await harness.cleanup();
  }
});

test('permanent payload rejection marks an item failed-permanent', async () => {
  const harness = await createHarness(async () => { throw new ManagementHttpError(413); });
  try {
    await harness.resultStore.enqueue({ collector: 'apps', status: 'success' });
    const summary = await harness.uploader.drain();
    assert.equal(summary.failedPermanent, 1);
    const stats = await harness.resultStore.getStats();
    assert.equal(stats.failedPermanentCount, 1);
    assert.equal(stats.pendingCount, 0);
  } finally {
    await harness.cleanup();
  }
});

test('abort during upload leaves in-flight item recoverable on restart', async () => {
  let uploadStarted;
  const started = new Promise((resolve) => { uploadStarted = resolve; });
  const harness = await createHarness((_payload, _token, signal) => new Promise((_resolve, reject) => {
    uploadStarted();
    signal.addEventListener('abort', () => reject(new DOMException('Upload aborted', 'AbortError')), { once: true });
  }));
  try {
    await harness.resultStore.enqueue({ collector: 'containers', status: 'success' });
    const controller = new AbortController();
    const draining = harness.uploader.drain({ signal: controller.signal });
    await started;
    controller.abort();
    const summary = await draining;
    assert.equal(summary.interrupted, 1);
    assert.equal((await harness.resultStore.getStats()).inFlightCount, 1);
    assert.equal(await harness.resultStore.requeueStaleInFlight(), 1);
    assert.equal((await harness.resultStore.listPending()).length, 1);
  } finally {
    await harness.cleanup();
  }
});
