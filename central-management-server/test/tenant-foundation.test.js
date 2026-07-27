import assert from 'node:assert/strict';
import { createCipheriv, randomBytes, randomUUID } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import { gzip } from 'node:zlib';
import test from 'node:test';
import Database from 'better-sqlite3';
import request from 'supertest';
import { createApp } from '../src/app.js';
import { createDatabase, DEFAULT_TENANT_ID } from '../src/database.js';

const gzipAsync = promisify(gzip);
const logger = { info() {}, warn() {}, error() {} };

async function issueToken(api, tenantId) {
  return (await api.post('/api/admin/enrollment-tokens')
    .set('Authorization', 'Bearer admin')
    .send({ tenantId })
    .expect(201)).body.token;
}

async function register(api, tenantId, hostname) {
  const enrollmentToken = await issueToken(api, tenantId);
  const machineFingerprint = hostname === 'agent-a' ? 'a'.repeat(64) : 'b'.repeat(64);
  const identity = (await api.post('/api/agents/register')
    .send({ hostname, platform: 'linux', architecture: 'x64', enrollmentToken, machineFingerprint })
    .expect(201)).body;
  return { ...identity, machineFingerprint };
}

async function resultEnvelope(identity, result) {
  const plaintext = Buffer.from(JSON.stringify(result));
  const compressed = await gzipAsync(plaintext);
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', Buffer.from(identity.encryptionKey, 'base64'), iv);
  const ciphertext = Buffer.concat([cipher.update(compressed), cipher.final()]);
  return {
    schemaVersion: 1,
    queueItemId: randomUUID(),
    agentId: identity.agentId,
    machineFingerprint: identity.machineFingerprint,
    enqueuedAt: new Date().toISOString(),
    contentEncoding: 'gzip',
    encryption: 'aes-256-gcm',
    iv: iv.toString('base64'),
    authTag: cipher.getAuthTag().toString('base64'),
    ciphertext: ciphertext.toString('base64'),
  };
}

test('migration creates the deterministic default tenant and backfills legacy rows', async (t) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'asvp-tenant-migration-'));
  const filename = path.join(directory, 'legacy.sqlite');
  const legacy = new Database(filename);
  legacy.exec(`
    CREATE TABLE agents (id TEXT PRIMARY KEY, hostname TEXT, auth_token_hash TEXT NOT NULL UNIQUE, encryption_key TEXT NOT NULL, registered_at TEXT NOT NULL, last_heartbeat_at TEXT, status TEXT NOT NULL);
    CREATE TABLE tasks (id TEXT PRIMARY KEY, agent_id TEXT REFERENCES agents(id), collector_name TEXT NOT NULL, params TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL, dispatched_at TEXT);
    CREATE TABLE results (id TEXT PRIMARY KEY, agent_id TEXT NOT NULL REFERENCES agents(id), task_id TEXT REFERENCES tasks(id), collector TEXT NOT NULL, status TEXT NOT NULL, raw_data TEXT NOT NULL, received_at TEXT NOT NULL);
    CREATE TABLE enrollment_tokens (token_hash TEXT PRIMARY KEY, created_at TEXT NOT NULL, expires_at TEXT NOT NULL, max_uses INTEGER, use_count INTEGER NOT NULL DEFAULT 0);
    CREATE TABLE agent_events (id INTEGER PRIMARY KEY AUTOINCREMENT, agent_id TEXT REFERENCES agents(id), event_type TEXT NOT NULL, details TEXT NOT NULL, created_at TEXT NOT NULL);
    INSERT INTO agents VALUES ('agent-1', 'legacy', '${'a'.repeat(64)}', 'key', '2025-01-01T00:00:00.000Z', NULL, 'registered');
    INSERT INTO tasks VALUES ('task-1', 'agent-1', 'os-info', '{}', 'pending', '2025-01-01T00:00:00.000Z', NULL);
    INSERT INTO results VALUES ('result-1', 'agent-1', 'task-1', 'os-info', 'success', '{}', '2025-01-01T00:00:00.000Z');
    INSERT INTO enrollment_tokens VALUES ('${'b'.repeat(64)}', '2025-01-01T00:00:00.000Z', '2099-01-01T00:00:00.000Z', 1, 0);
    INSERT INTO agent_events (agent_id, event_type, details, created_at) VALUES ('agent-1', 'register', '{}', '2025-01-01T00:00:00.000Z');
  `);
  legacy.close();

  const database = createDatabase({ filename });
  t.after(async () => { database.close(); await rm(directory, { recursive: true, force: true }); });
  assert.deepEqual(database.prepare('SELECT id, name, status FROM tenants').get(), {
    id: DEFAULT_TENANT_ID, name: 'Default tenant', status: 'active',
  });
  for (const table of ['agents', 'tasks', 'results', 'enrollment_tokens', 'agent_events']) {
    assert.equal(database.prepare(`SELECT tenant_id FROM ${table}`).get().tenant_id, DEFAULT_TENANT_ID);
    assert.ok(database.prepare(`PRAGMA foreign_key_list(${table})`).all().some((foreignKey) => foreignKey.from === 'tenant_id' && foreignKey.table === 'tenants'));
  }
  assert.deepEqual(database.prepare('PRAGMA foreign_key_check').all(), []);
});

test('tenant-bound registration and authenticated data paths prevent cross-tenant task access', async (t) => {
  const database = createDatabase({ filename: ':memory:' });
  t.after(() => database.close());
  const tenantB = '11111111-1111-4111-8111-111111111111';
  database.prepare('INSERT INTO tenants (id, name, created_at, status) VALUES (?, ?, ?, ?)')
    .run(tenantB, 'Tenant B', new Date().toISOString(), 'active');
  const app = createApp({ database, adminToken: 'admin', taskSigningSecret: 'signing-secret', baselineCollectors: [], logger });
  const api = request(app);
  const agentA = await register(api, DEFAULT_TENANT_ID, 'agent-a');
  const agentB = await register(api, tenantB, 'agent-b');
  assert.equal(database.prepare('SELECT tenant_id FROM agents WHERE id = ?').get(agentB.agentId).tenant_id, tenantB);

  await api.post('/api/admin/tasks').set('Authorization', 'Bearer admin')
    .send({ agentId: agentA.agentId, tenantId: tenantB, collectorName: 'os-info', params: {} })
    .expect(400);
  const taskB = await api.post('/api/admin/tasks').set('Authorization', 'Bearer admin')
    .send({ tenantId: tenantB, collectorName: 'apps', params: {} })
    .expect(201);

  const pollA = await api.post('/api/agents/tasks/poll').set('Authorization', `Bearer ${agentA.authToken}`)
    .send({ agentId: agentA.agentId, machineFingerprint: agentA.machineFingerprint }).expect(200);
  assert.deepEqual(pollA.body, []);
  const pollB = await api.post('/api/agents/tasks/poll').set('Authorization', `Bearer ${agentB.authToken}`)
    .send({ agentId: agentB.agentId, machineFingerprint: agentB.machineFingerprint }).expect(200);
  assert.equal(pollB.body[0].taskId, taskB.body.taskId);
  assert.equal(pollB.body[0].tenantId, tenantB);

  const crossTenantResult = await resultEnvelope(agentA, { taskId: taskB.body.taskId, collector: 'apps', status: 'success', data: {} });
  await api.post('/api/agents/results').set('Authorization', `Bearer ${agentA.authToken}`).send(crossTenantResult).expect(200);
  const stored = database.prepare('SELECT tenant_id, task_id FROM results WHERE id = ?').get(crossTenantResult.queueItemId);
  assert.deepEqual(stored, { tenant_id: DEFAULT_TENANT_ID, task_id: null });
  assert.equal(database.prepare('SELECT status FROM tasks WHERE id = ?').get(taskB.body.taskId).status, 'dispatched');
});
