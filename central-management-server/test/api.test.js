import assert from 'node:assert/strict';
import { createCipheriv, randomBytes, randomUUID } from 'node:crypto';
import { promisify } from 'node:util';
import { gzip } from 'node:zlib';
import test from 'node:test';
import request from 'supertest';
import { createApp } from '../src/app.js';
import { createDatabase } from '../src/database.js';
import { hashToken } from '../src/crypto.js';
import { computeFleetStatus } from '../src/fleet-status.js';

const gzipAsync = promisify(gzip);
const logger = { info() {}, warn() {}, error() {} };

function setup(options = {}) {
  const database = createDatabase({ filename: ':memory:' });
  const adminToken = options.adminToken ?? 'test-admin-token';
  const app = createApp({ database, adminToken, logger, adminRateLimit: options.adminRateLimit, baselineCollectors: options.baselineCollectors ?? [] });
  return { database, api: request(app), adminToken };
}

function createAdminTask(api, adminToken, body) {
  return api.post('/api/admin/tasks').set('Authorization', `Bearer ${adminToken}`).send(body);
}

async function register(api) {
  const response = await api.post('/api/agents/register').send({
    hostname: 'test-host', platform: 'win32', architecture: 'x64', agentVersion: '1.0.0',
  }).expect(201);
  return response.body;
}

async function makeEnvelope(result, identity) {
  const plaintext = Buffer.from(JSON.stringify(result));
  const compressed = await gzipAsync(plaintext);
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', Buffer.from(identity.encryptionKey, 'base64'), iv);
  const ciphertext = Buffer.concat([cipher.update(compressed), cipher.final()]);
  return {
    schemaVersion: 1,
    queueItemId: randomUUID(),
    agentId: identity.agentId,
    enqueuedAt: new Date().toISOString(),
    contentEncoding: 'gzip',
    encryption: 'aes-256-gcm',
    iv: iv.toString('base64'),
    authTag: cipher.getAuthTag().toString('base64'),
    ciphertext: ciphertext.toString('base64'),
    uncompressedSizeBytes: plaintext.length,
    compressedSizeBytes: compressed.length,
  };
}

test('registration returns exact identity shape and stores only the token hash', async (t) => {
  const { database, api } = setup();
  t.after(() => database.close());
  const identity = await register(api);
  assert.deepEqual(Object.keys(identity).sort(), ['agentId', 'authToken', 'encryptionKey']);
  assert.equal(Buffer.from(identity.encryptionKey, 'base64').length, 32);
  const row = database.prepare('SELECT * FROM agents WHERE id = ?').get(identity.agentId);
  assert.equal(row.auth_token_hash, hashToken(identity.authToken));
  assert.notEqual(row.auth_token_hash, identity.authToken);
});

test('registration reuses a known previousAgentId and rotates credentials in one row', async (t) => {
  const { database, api } = setup();
  t.after(() => database.close());
  const first = await register(api);
  const before = database.prepare('SELECT * FROM agents WHERE id = ?').get(first.agentId);
  const second = await api.post('/api/agents/register')
    .set('Authorization', `Bearer ${first.authToken}`)
    .send({
      hostname: 'same-host', platform: 'win32', architecture: 'x64', previousAgentId: first.agentId,
    }).expect(201);
  assert.equal(second.body.agentId, first.agentId);
  assert.notEqual(second.body.authToken, first.authToken);
  assert.equal(database.prepare('SELECT COUNT(*) AS count FROM agents').get().count, 1);
  const after = database.prepare('SELECT * FROM agents WHERE id = ?').get(first.agentId);
  assert.equal(after.id, before.id);
  assert.equal(after.registered_at, before.registered_at);
  assert.notEqual(after.auth_token_hash, before.auth_token_hash);
  assert.notEqual(after.encryption_key, before.encryption_key);
  assert.equal(after.auth_token_hash, hashToken(second.body.authToken));
});

test('known previousAgentId with wrong prior credential cannot take over the existing row', async (t) => {
  const { database, api } = setup();
  t.after(() => database.close());
  const first = await register(api);
  const before = database.prepare('SELECT * FROM agents WHERE id = ?').get(first.agentId);
  const response = await api.post('/api/agents/register')
    .set('Authorization', 'Bearer wrong-previous-token')
    .send({ hostname: 'attacker-host', platform: 'win32', architecture: 'x64', previousAgentId: first.agentId })
    .expect(201);
  assert.notEqual(response.body.agentId, first.agentId);
  assert.equal(database.prepare('SELECT COUNT(*) AS count FROM agents').get().count, 2);
  const unchanged = database.prepare('SELECT * FROM agents WHERE id = ?').get(first.agentId);
  assert.deepEqual(unchanged, before);
});

test('registration falls back to a new agent when previousAgentId is unknown', async (t) => {
  const { database, api } = setup();
  t.after(() => database.close());
  const unknown = randomUUID();
  const response = await api.post('/api/agents/register').send({
    hostname: 'new-server-host', platform: 'win32', architecture: 'x64', previousAgentId: unknown,
  }).expect(201);
  assert.notEqual(response.body.agentId, unknown);
  assert.equal(database.prepare('SELECT COUNT(*) AS count FROM agents').get().count, 1);
});

test('deregister marks an authenticated agent as intentionally removed', async (t) => {
  const { database, api } = setup();
  t.after(() => database.close());
  const identity = await register(api);
  await api.post('/api/agents/deregister').send({ agentId: identity.agentId }).expect(401);
  const response = await api.post('/api/agents/deregister')
    .set('Authorization', `Bearer ${identity.authToken}`)
    .send({ agentId: identity.agentId }).expect(200);
  assert.equal(response.body.accepted, true);
  const row = database.prepare('SELECT status, deregistered_at FROM agents WHERE id = ?').get(identity.agentId);
  assert.equal(row.status, 'deregistered');
  assert.ok(row.deregistered_at);
    assert.equal(computeFleetStatus(row).state, 'deregistered');
});

test('heartbeat requires bearer auth, validates agentId, and updates presence', async (t) => {
  const { database, api } = setup();
  t.after(() => database.close());
  const identity = await register(api);
  const heartbeat = {
    agentId: identity.agentId,
    uptimeSeconds: 12,
    processUptimeSeconds: 20,
    hostname: 'heartbeat-host',
    lastSuccessfulHeartbeat: null,
    currentQueueSize: 3,
    agentVersion: '0.1.0',
  };
  await api.post('/api/agents/heartbeat').send(heartbeat).expect(401);
  const response = await api.post('/api/agents/heartbeat')
    .set('Authorization', `Bearer ${identity.authToken}`).send(heartbeat).expect(200);
  assert.equal(response.body.accepted, true);
  const row = database.prepare('SELECT * FROM agents WHERE id = ?').get(identity.agentId);
  assert.equal(row.hostname, 'heartbeat-host');
  assert.equal(row.status, 'online');
  assert.ok(row.last_heartbeat_at);
    assert.equal(row.agent_version, '0.1.0');
});

test('admin task creation rejects missing and wrong tokens without creating tasks', async (t) => {
  const { database, api } = setup();
  t.after(() => database.close());
  const body = { agentId: null, collectorName: 'os-info', params: {} };
  const missing = await api.post('/api/admin/tasks').send(body).expect(401);
  const wrong = await api.post('/api/admin/tasks').set('Authorization', 'Bearer wrong-token').send(body).expect(401);
  assert.deepEqual(missing.body, { error: 'Unauthorized' });
  assert.deepEqual(wrong.body, { error: 'Unauthorized' });
  assert.equal(database.prepare('SELECT COUNT(*) AS count FROM tasks').get().count, 0);
});

test('admin rate limit rejects rapid requests after the configured allowance', async (t) => {
  const { database, api, adminToken } = setup({ adminRateLimit: { maxRequests: 2, windowMs: 60000 } });
  t.after(() => database.close());
  const body = { agentId: null, collectorName: 'os-info', params: {} };
  await createAdminTask(api, adminToken, body).expect(201);
  await createAdminTask(api, adminToken, body).expect(201);
  await createAdminTask(api, adminToken, body).expect(429);
  assert.equal(database.prepare('SELECT COUNT(*) AS count FROM tasks').get().count, 2);
});

test('task creation and poll return exact task shape once', async (t) => {
  const { database, api, adminToken } = setup();
  t.after(() => database.close());
  const identity = await register(api);
  const created = await createAdminTask(api, adminToken, {
    agentId: identity.agentId, collectorName: 'os-info', params: { reason: 'contract-test' },
  }).expect(201);
  assert.deepEqual(Object.keys(created.body), ['taskId']);
  const first = await api.post('/api/agents/tasks/poll')
    .set('Authorization', `Bearer ${identity.authToken}`).send({ agentId: identity.agentId }).expect(200);
  assert.equal(first.body.length, 1);
  assert.deepEqual(first.body[0], {
    taskId: created.body.taskId,
    collectorName: 'os-info',
    params: { reason: 'contract-test' },
    scheduledAt: first.body[0].scheduledAt,
  });
  assert.ok(first.body[0].scheduledAt);
  const second = await api.post('/api/agents/tasks/poll')
    .set('Authorization', `Bearer ${identity.authToken}`).send({ agentId: identity.agentId }).expect(200);
  assert.deepEqual(second.body, []);
});

test('encrypted result endpoint decrypts, gunzips, stores, and exactly acknowledges', async (t) => {
  const { database, api, adminToken } = setup();
  t.after(() => database.close());
  const identity = await register(api);
  const task = await createAdminTask(api, adminToken, {
    agentId: identity.agentId, collectorName: 'os-info', params: {},
  }).expect(201);
  await api.post('/api/agents/tasks/poll')
    .set('Authorization', `Bearer ${identity.authToken}`).send({ agentId: identity.agentId }).expect(200);
  const normalized = {
    taskId: task.body.taskId,
    collector: 'os-info',
    startedAt: new Date().toISOString(),
    finishedAt: new Date().toISOString(),
    status: 'success',
    data: { prettyName: 'Test OS' },
    error: null,
  };
  const envelope = await makeEnvelope(normalized, identity);
  const response = await api.post('/api/agents/results')
    .set('Authorization', `Bearer ${identity.authToken}`).send(envelope).expect(200);
  assert.deepEqual(response.body, { accepted: true, queueItemId: envelope.queueItemId });
  const stored = database.prepare('SELECT * FROM results WHERE id = ?').get(envelope.queueItemId);
  assert.deepEqual(JSON.parse(stored.raw_data), normalized);
  assert.equal(database.prepare('SELECT status FROM tasks WHERE id = ?').get(task.body.taskId).status, 'completed');
});

test('invalid encrypted result is permanently rejected without storage', async (t) => {
  const { database, api } = setup();
  t.after(() => database.close());
  const identity = await register(api);
  const envelope = await makeEnvelope({ collector: 'noop', status: 'success' }, identity);
  envelope.ciphertext = Buffer.from('tampered').toString('base64');
  await api.post('/api/agents/results')
    .set('Authorization', `Bearer ${identity.authToken}`).send(envelope).expect(400);
  assert.equal(database.prepare('SELECT COUNT(*) AS count FROM results').get().count, 0);
});
