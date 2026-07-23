import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { CredentialStore } from '../../src/security/credentials.js';
import { loadOrRegisterIdentity } from '../../src/transport/api-client.js';

function createKeychainMock() {
  let value = null;
  return {
    async getPassword() { return value; },
    async setPassword(_service, _account, nextValue) { value = nextValue; },
    async deletePassword() { value = null; return true; },
  };
}

function createApiClientMock() {
  let calls = 0;
  return {
    get calls() { return calls; },
    async register() {
      calls += 1;
      return {
        agentId: `agent-${calls}`,
        authToken: `token-${calls}`,
        encryptionKey: Buffer.alloc(32, calls).toString('base64'),
      };
    },
  };
}

test('registers once, persists identity, and reuses it on subsequent runs', async () => {
  const store = await new CredentialStore({
    identityPath: 'unused.json',
    keychain: createKeychainMock(),
  }).initialize();
  const apiClient = createApiClientMock();

  const first = await loadOrRegisterIdentity({ credentialStore: store, apiClient });
  const second = await loadOrRegisterIdentity({ credentialStore: store, apiClient });

  assert.equal(first.registered, true);
  assert.equal(second.registered, false);
  assert.deepEqual(second.identity, first.identity);
  assert.equal(apiClient.calls, 1);
});

test('loads restricted-file identity when an available keychain returns no value', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'asvp-credential-fallback-'));
  const identityPath = path.join(directory, 'identity.json');
  const identity = {
    agentId: 'fallback-agent',
    authToken: 'fallback-token',
    encryptionKey: Buffer.alloc(32, 7).toString('base64'),
  };
  try {
    await writeFile(identityPath, JSON.stringify(identity));
    const store = await new CredentialStore({
      identityPath,
      keychain: { async getPassword() { return null; } },
    }).initialize();
    assert.deepEqual(await store.loadIdentity(), identity);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('forced registration replaces the persisted identity', async () => {
  const store = await new CredentialStore({
    identityPath: 'unused.json',
    keychain: createKeychainMock(),
  }).initialize();
  const apiClient = createApiClientMock();

  await loadOrRegisterIdentity({ credentialStore: store, apiClient });
  const replacement = await loadOrRegisterIdentity({ credentialStore: store, apiClient, force: true });
  const persisted = await store.loadIdentity();

  assert.equal(replacement.identity.agentId, 'agent-2');
  assert.deepEqual(persisted, replacement.identity);
  assert.equal(apiClient.calls, 2);
});

test('incomplete existing identity is sent as previousAgentId during migration registration', async () => {
  let registrationMetadata;
  let saved;
  const credentialStore = {
    async loadIdentity() { return { agentId: 'legacy-agent', authToken: 'legacy-token' }; },
    async saveIdentity(identity) { saved = identity; },
  };
  const replacement = {
    agentId: 'legacy-agent', authToken: 'rotated-token', encryptionKey: Buffer.alloc(32, 9).toString('base64'),
  };
  const result = await loadOrRegisterIdentity({
    credentialStore,
    apiClient: { async register(metadata) { registrationMetadata = metadata; return replacement; } },
    metadata: { hostname: 'migration-host' },
  });
  assert.deepEqual(registrationMetadata, { hostname: 'migration-host', previousAgentId: 'legacy-agent' });
  assert.deepEqual(saved, replacement);
  assert.equal(result.registered, true);
});

test('rejects incomplete registration responses without persisting them', async () => {
  const store = await new CredentialStore({
    identityPath: 'unused.json',
    keychain: createKeychainMock(),
  }).initialize();

  await assert.rejects(
    loadOrRegisterIdentity({
      credentialStore: store,
      apiClient: { async register() { return { agentId: 'missing-token' }; } },
    }),
    /did not include agentId, authToken, and encryptionKey/,
  );
  assert.equal(await store.loadIdentity(), null);
});
