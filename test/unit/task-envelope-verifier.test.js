import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { signTaskEnvelope } from '../../src/security/task-envelope.js';
import { TaskEnvelopeVerifier } from '../../src/task/envelope-verifier.js';

const now = Date.parse('2026-07-27T12:00:00.000Z');
const identity = {
  agentId: 'agent-verified',
  tenantId: 'tenant-verified',
  taskSigningKey: Buffer.alloc(32, 7).toString('base64'),
  taskSigningKeyId: 'task-key-1',
};

function envelope(overrides = {}) {
  const task = {
    taskId: 'task-1',
    collectorName: 'noop',
    params: { nested: { b: 2, a: 1 } },
    agentId: identity.agentId,
    tenantId: identity.tenantId,
    keyId: identity.taskSigningKeyId,
    issuedAt: new Date(now - 1_000).toISOString(),
    expiresAt: new Date(now + 60_000).toISOString(),
    nonce: 'nonce-1',
    sequence: 1,
    ...overrides,
  };
  task.signature = signTaskEnvelope(task, identity.taskSigningKey);
  return task;
}

async function withVerifier(callback, options = {}) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'asvp-task-verifier-'));
  const warnings = [];
  try {
    const verifier = new TaskEnvelopeVerifier({
      identity,
      ledgerPath: 'replay.json',
      cwd: directory,
      clock: () => now,
      logger: { warn(context) { warnings.push(context); } },
      ...options,
    });
    await callback({ verifier, directory, warnings });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

test('accepts valid signed task envelopes and persists replay claims', async () => {
  await withVerifier(async ({ verifier, directory, warnings }) => {
    const task = envelope();
    assert.deepEqual(await verifier.verifyAll([task]), [task]);
    const ledger = JSON.parse(await readFile(path.join(directory, 'replay.json'), 'utf8'));
    assert.deepEqual(ledger.entries, [{ keyId: 'task-key-1', nonce: 'nonce-1', sequence: 1, expiresAt: now + 60_000 }]);
    assert.deepEqual(warnings, []);
  });
});

test('filters invalid signatures, identity claims, timestamps, nonce, and sequence', async () => {
  await withVerifier(async ({ verifier, warnings }) => {
    const invalid = [
      { ...envelope({ nonce: 'bad-signature' }), signature: 'invalid' },
      envelope({ nonce: 'wrong-key', sequence: 2, keyId: 'other-key' }),
      envelope({ nonce: 'wrong-agent', sequence: 3, agentId: 'other-agent' }),
      envelope({ nonce: 'wrong-tenant', sequence: 9, tenantId: 'other-tenant' }),
      envelope({ nonce: 'future', sequence: 4, issuedAt: new Date(now + 31_000).toISOString() }),
      envelope({ nonce: 'expired', sequence: 5, issuedAt: new Date(now - 90_000).toISOString(), expiresAt: new Date(now - 31_000).toISOString() }),
      envelope({ nonce: '', sequence: 6 }),
      envelope({ nonce: 'bad-sequence', sequence: 0 }),
    ];
    assert.deepEqual(await verifier.verifyAll(invalid), []);
    assert.equal(warnings.length, invalid.length);
  });
});

test('rejects tampered and unsigned legacy tasks', async () => {
  await withVerifier(async ({ verifier, warnings }) => {
    const signed = envelope({ nonce: 'tampered', sequence: 7 });
    const tampered = { ...signed, params: { nested: { a: 999, b: 2 } } };
    const unsigned = { ...envelope({ nonce: 'unsigned', sequence: 8 }) };
    delete unsigned.signature;

    assert.deepEqual(await verifier.verifyAll([tampered, unsigned]), []);
    assert.equal(warnings.length, 2);
    assert.ok(warnings.every(({ reason }) => reason === 'task signature is invalid'));
  });
});

test('rejects replayed nonce or sequence after verifier restart', async () => {
  await withVerifier(async ({ verifier, directory }) => {
    assert.equal((await verifier.verifyAll([envelope()])).length, 1);
    const restarted = new TaskEnvelopeVerifier({ identity, ledgerPath: 'replay.json', cwd: directory, clock: () => now });
    assert.deepEqual(await restarted.verifyAll([
      envelope({ taskId: 'task-2', sequence: 2 }),
      envelope({ taskId: 'task-3', nonce: 'nonce-3' }),
    ]), []);
  });
});

test('bounds the persistent replay ledger', async () => {
  await withVerifier(async ({ verifier, directory }) => {
    const tasks = Array.from({ length: 4 }, (_, index) => envelope({
      taskId: `task-${index + 1}`,
      nonce: `nonce-${index + 1}`,
      sequence: index + 1,
    }));
    await verifier.verifyAll(tasks);
    const ledger = JSON.parse(await readFile(path.join(directory, 'replay.json'), 'utf8'));
    assert.equal(ledger.entries.length, 2);
    assert.deepEqual(ledger.entries.map(({ sequence }) => sequence), [3, 4]);
  }, { maxReplayEntries: 2 });
});
