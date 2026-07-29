import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { AgentLifecycle } from '../../src/agent/lifecycle.js';
import { CredentialStore } from '../../src/security/credentials.js';
import { loadOrRegisterIdentity, ManagementHttpError } from '../../src/transport/api-client.js';

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
        tenantId: 'tenant-1',
        authToken: `token-${calls}`,
        encryptionKey: Buffer.alloc(32, calls).toString('base64'),
        taskSigningKey: Buffer.alloc(32, calls + 10).toString('base64'),
        taskSigningKeyId: `task-key-${calls}`,
      };
    },
  };
}

test('integrity baseline uses a separate restricted 0600 file when keychain is unavailable', async (t) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'asvp-integrity-store-')); t.after(() => rm(directory, { recursive: true, force: true }));
  const store = await new CredentialStore({ identityPath: 'identity.json', keychain: null, logger: { warn() {} }, cwd: directory }).initialize();
  const baseline = { schemaVersion: 1, hashes: { binary: { sha256: 'a'.repeat(64) } } };
  await store.saveIntegrityBaseline(baseline);
  assert.deepEqual(await store.loadIntegrityBaseline(), baseline);
  const serialized = await readFile(path.join(directory, 'identity.json.integrity.json'), 'utf8');
  assert.equal(JSON.parse(serialized).hashes.binary.sha256, 'a'.repeat(64));
});

test('HTTP startup fails clearly before registration when the server URL is missing', async () => {
  const errors = [];
  let registerCalls = 0;
  const lifecycle = new AgentLifecycle({
    config: {
      server: { mode: 'http', url: 'https://management.example.invalid', enrollmentToken: null },
      agent: { logLevel: 'info' },
      storage: {},
    },
    version: '1.1.0',
    logger: { info() {}, warn() {}, debug() {}, error(context, message) { errors.push({ context, message }); } },
    credentialStore: {
      async initialize() {},
      async loadIdentity() { return null; },
    },
    apiClient: { async register() { registerCalls += 1; } },
    resultStore: {},
  });

  await assert.rejects(lifecycle.start(), /Agent management server URL is not configured/);
  assert.equal(registerCalls, 0);
  assert.deepEqual(errors, [{
    context: { reasonCode: 'SERVER_URL_NOT_CONFIGURED' },
    message: 'Agent management server URL is not configured - run the enroll command or provide a valid server URL before starting the service',
  }]);
});

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

test('packaged agents ignore stale account-scoped keychain identity when the shared identity file is absent', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'asvp-packaged-identity-'));
  const identityPath = path.join(directory, 'identity.json');
  const staleIdentity = {
    agentId: 'deleted-agent',
    authToken: 'deleted-token',
    encryptionKey: Buffer.alloc(32, 8).toString('base64'),
  };
  try {
    const store = await new CredentialStore({
      identityPath,
      preferIdentityFile: true,
      keychain: { async getPassword() { return JSON.stringify(staleIdentity); } },
    }).initialize();
    assert.equal(await store.loadIdentity(), null);
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

test('re-registers when the server rejects a persisted identity', async () => {
  const store = await new CredentialStore({
    identityPath: 'unused.json',
    keychain: createKeychainMock(),
  }).initialize();
  const apiClient = createApiClientMock();
  const first = await loadOrRegisterIdentity({ credentialStore: store, apiClient });

  const replacement = await loadOrRegisterIdentity({
    credentialStore: store,
    apiClient,
    validateExisting: async () => { throw new ManagementHttpError(401); },
  });

  assert.equal(replacement.registered, true);
  assert.notEqual(replacement.identity.agentId, first.identity.agentId);
  assert.deepEqual(await store.loadIdentity(), replacement.identity);
  assert.equal(apiClient.calls, 2);
});

test('keeps persisted identity when startup validation fails transiently', async () => {
  const store = await new CredentialStore({
    identityPath: 'unused.json',
    keychain: createKeychainMock(),
  }).initialize();
  const apiClient = createApiClientMock();
  const first = await loadOrRegisterIdentity({ credentialStore: store, apiClient });

  const reused = await loadOrRegisterIdentity({
    credentialStore: store,
    apiClient,
    validateExisting: async () => { throw new ManagementHttpError(503); },
  });

  assert.equal(reused.registered, false);
  assert.deepEqual(reused.identity, first.identity);
  assert.equal(reused.validationError.status, 503);
  assert.equal(apiClient.calls, 1);
});

test('incomplete existing identity is sent as previousAgentId during migration registration', async () => {
  let registrationMetadata;
  let saved;
  const credentialStore = {
    async loadIdentity() { return { agentId: 'legacy-agent', authToken: 'legacy-token' }; },
    async saveIdentity(identity) { saved = identity; },
  };
  const replacement = {
    agentId: 'legacy-agent',
    tenantId: 'tenant-migrated',
    authToken: 'rotated-token',
    encryptionKey: Buffer.alloc(32, 9).toString('base64'),
    taskSigningKey: Buffer.alloc(32, 10).toString('base64'),
    taskSigningKeyId: 'task-key-migrated',
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

test('re-registers a legacy identity missing task signing fields', async () => {
  let saved;
  let registerCalls = 0;
  const legacy = {
    agentId: 'legacy-agent',
    authToken: 'legacy-token',
    encryptionKey: Buffer.alloc(32, 4).toString('base64'),
  };
  const replacement = {
    ...legacy,
    tenantId: 'tenant-migrated',
    taskSigningKey: Buffer.alloc(32, 5).toString('base64'),
    taskSigningKeyId: 'task-key-new',
  };
  const result = await loadOrRegisterIdentity({
    credentialStore: {
      async loadIdentity() { return legacy; },
      async saveIdentity(identity) { saved = identity; },
    },
    apiClient: {
      async register(metadata) {
        registerCalls += 1;
        assert.equal(metadata.previousAgentId, legacy.agentId);
        return replacement;
      },
    },
    validateExisting: async () => assert.fail('legacy identity must not be validated for reuse'),
  });

  assert.equal(registerCalls, 1);
  assert.equal(result.registered, true);
  assert.deepEqual(saved, replacement);
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
    /did not include agentId, tenantId, authToken, encryptionKey, taskSigningKey, and taskSigningKeyId/,
  );
  assert.equal(await store.loadIdentity(), null);
});
