import assert from 'node:assert/strict';
import { Writable } from 'node:stream';
import test from 'node:test';
import { createLogger } from '../../src/utils/logger.js';

test('redacts every secret-bearing identity and enrollment field', async () => {
  let output = '';
  const destination = new Writable({
    write(chunk, _encoding, callback) {
      output += chunk.toString();
      callback();
    },
  });
  const logger = createLogger({ destination });

  logger.info({
    authToken: 'top-level-auth-secret',
    encryptionKey: 'top-level-encryption-secret',
    taskSigningKey: 'top-level-signing-secret',
    enrollmentToken: 'top-level-enrollment-secret',
    machineFingerprint: 'top-level-fingerprint',
    identity: {
      agentId: 'agent-1',
      tenantId: 'tenant-1',
      authToken: 'auth-secret',
      encryptionKey: 'identity-encryption-secret',
      taskSigningKey: 'identity-signing-secret',
      taskSigningKeyId: 'key-id-v1',
      machineFingerprint: 'identity-fingerprint',
    },
    config: { server: { enrollmentToken: 'config-enrollment-secret' } },
  }, 'identity loaded');

  await new Promise((resolve) => destination.end(resolve));
  const entry = JSON.parse(output.trim());
  assert.equal(entry.authToken, '[REDACTED]');
  assert.equal(entry.encryptionKey, '[REDACTED]');
  assert.equal(entry.taskSigningKey, '[REDACTED]');
  assert.equal(entry.enrollmentToken, '[REDACTED]');
  assert.equal(entry.machineFingerprint, '[REDACTED]');
  assert.equal(entry.identity.authToken, '[REDACTED]');
  assert.equal(entry.identity.encryptionKey, '[REDACTED]');
  assert.equal(entry.identity.taskSigningKey, '[REDACTED]');
  assert.equal(entry.identity.machineFingerprint, '[REDACTED]');
  assert.equal(entry.config.server.enrollmentToken, '[REDACTED]');
  assert.equal(entry.identity.agentId, 'agent-1');
  assert.equal(entry.identity.tenantId, 'tenant-1');
  assert.equal(entry.identity.taskSigningKeyId, 'key-id-v1');
  for (const secret of ['top-level-auth-secret', 'top-level-encryption-secret', 'top-level-signing-secret', 'top-level-enrollment-secret', 'top-level-fingerprint', 'auth-secret', 'identity-encryption-secret', 'identity-signing-secret', 'identity-fingerprint', 'config-enrollment-secret']) {
    assert.equal(output.includes(secret), false);
  }
});
