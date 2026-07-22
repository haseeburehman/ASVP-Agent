import assert from 'node:assert/strict';
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
