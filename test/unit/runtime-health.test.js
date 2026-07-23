import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { AgentRuntime } from '../../src/agent/runtime.js';

const logger = { info() {}, warn() {}, error() {}, debug() {} };
const emptyStats = {
  pendingCount: 0, inFlightCount: 0, deliveredCount: 0, failedPermanentCount: 0,
  failedPermanentRetainUntil: null, totalItems: 0, totalBytes: 0, evictedCount: 0, lastEvictedAt: null,
};

function summary(overrides = {}) {
  return { attempted: 1, delivered: 0, requeued: 1, authFailures: 1, failedPermanent: 0, interrupted: 0, ...overrides };
}

test('upload auth failures degrade health at threshold and a successful upload clears it', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'asvp-runtime-health-'));
  try {
    const statusPath = path.join(directory, 'status.json');
    const summaries = [summary(), summary(), summary(), summary({ delivered: 1, requeued: 0, authFailures: 0 })];
    const runtime = new AgentRuntime({
      config: {
        storage: { statusPath },
        collectors: { upload: { uploadConcurrency: 1, maxPayloadWarningBytes: 1000, authFailureThreshold: 3 } },
      },
      identity: { agentId: 'agent-health', authToken: 'token', encryptionKey: Buffer.alloc(32).toString('base64') },
      apiClient: {}, logger, version: 'test', cwd: directory,
      resultStore: { async getStats() { return emptyStats; } },
      resultUploader: { async drain() { return summaries.shift(); } },
    });

    await runtime.uploadResultsOnce();
    await runtime.uploadResultsOnce();
    assert.equal(runtime.getHealth().healthState, 'healthy');
    await runtime.uploadResultsOnce();
    let health = runtime.getHealth();
    assert.equal(health.healthState, 'authentication-degraded');
    assert.equal(health.consecutiveUploadAuthFailures, 3);
    let persisted = JSON.parse(await readFile(statusPath, 'utf8'));
    assert.equal(persisted.healthState, 'authentication-degraded');
    assert.equal(persisted.consecutiveUploadAuthFailures, 3);

    await runtime.uploadResultsOnce();
    health = runtime.getHealth();
    assert.equal(health.healthState, 'healthy');
    assert.equal(health.consecutiveUploadAuthFailures, 0);
    persisted = JSON.parse(await readFile(statusPath, 'utf8'));
    assert.equal(persisted.healthState, 'healthy');
    assert.equal(persisted.consecutiveUploadAuthFailures, 0);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
