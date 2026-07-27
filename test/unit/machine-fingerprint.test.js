import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { deriveMachineFingerprint } from '../../src/security/machine-fingerprint.js';
import { ApiClient, loadOrRegisterIdentity, ManagementHttpError } from '../../src/transport/api-client.js';

const components = [
  'system.uuid=machine-uuid',
  'system.serial=system-serial',
  'network.mac.0=00:11:22:33:44:55',
].join('\n');
const expectedFingerprint = createHash('sha256').update(components).digest('hex');

const fingerprintInputs = {
  system: async () => ({ uuid: 'MACHINE-UUID', serial: 'SYSTEM-SERIAL' }),

  networkInterfaces: {
    Ethernet: [{ internal: false, mac: '00:11:22:33:44:55' }],
    Loopback: [{ internal: true, mac: '00:00:00:00:00:00' }],
  },
};

test('hashes canonical hardware values without returning raw components', async () => {
  const fingerprint = await deriveMachineFingerprint(fingerprintInputs);
  assert.equal(fingerprint, expectedFingerprint);
  assert.match(fingerprint, /^[a-f0-9]{64}$/);
  assert.equal(fingerprint.includes('machine-uuid'), false);
});

test('re-derives and sends only the fingerprint on authenticated requests', async () => {
  const calls = [];
  let derivations = 0;
  const transport = {
    async register(_path, body) { calls.push(body); return {}; },
    async heartbeat(_path, body) { calls.push(body); return {}; },
    async pollTasks(_path, body) { calls.push(body); return []; },
    async uploadResult(_path, body) { calls.push(body); return {}; },
  };
  const config = { server: { mode: 'http', registrationPath: '/register', heartbeatPath: '/heartbeat', tasksPath: '/tasks', resultsPath: '/results' } };
  const apiClient = new ApiClient({ config, transport, fingerprintProvider: async () => { derivations += 1; return expectedFingerprint; } });
  const identity = { agentId: 'agent-1', authToken: 'token' };

  await apiClient.register({ hostname: 'host' });
  await apiClient.sendHeartbeat(identity, { agentId: identity.agentId, hostname: 'host' });
  await apiClient.pollTasks(identity);
  await apiClient.uploadResult(identity, { agentId: identity.agentId });

  assert.equal(derivations, 4);
  assert.ok(calls.every((body) => body.machineFingerprint === expectedFingerprint));
  assert.equal(JSON.stringify(calls).includes('machine-uuid'), false);
});

test('fingerprint mismatch does not trigger automatic continuity registration', async () => {
  let registrations = 0;
  await assert.rejects(
    loadOrRegisterIdentity({
      credentialStore: {
        async loadIdentity() {
          return {
            agentId: 'agent-1', tenantId: 'tenant-1', authToken: 'token', encryptionKey: 'key',
            taskSigningKey: 'task-key', taskSigningKeyId: 'key-id',
          };
        },
      },
      apiClient: { async register() { registrations += 1; } },
      validateExisting: async () => { throw new ManagementHttpError(403, 'mismatch', 'IDENTITY_FINGERPRINT_MISMATCH'); },
    }),
    (error) => error.code === 'IDENTITY_FINGERPRINT_MISMATCH',
  );
  assert.equal(registrations, 0);
});
