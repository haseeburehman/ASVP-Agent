import assert from 'node:assert/strict';
import test from 'node:test';
import request from 'supertest';
import { createApp } from '../src/app.js';
import { createDatabase, DEFAULT_TENANT_ID } from '../src/database.js';

const FINGERPRINT = '1'.repeat(64);
const OTHER_FINGERPRINT = '2'.repeat(64);

function setup() {
  const database = createDatabase({ filename: ':memory:' });
  const warnings = [];
  const logger = { info() {}, warn(entry) { warnings.push(entry); }, error() {} };
  const app = createApp({ database, adminToken: 'admin', taskSigningSecret: 'signing-secret', baselineCollectors: [], logger });
  return { database, api: request(app), warnings };
}

async function enrollmentToken(api) {
  return (await api.post('/api/admin/enrollment-tokens')
    .set('Authorization', 'Bearer admin')
    .send({ tenantId: DEFAULT_TENANT_ID })
    .expect(201)).body.token;
}

async function register(api, machineFingerprint = FINGERPRINT) {
  return (await api.post('/api/agents/register').send({
    hostname: 'bound-host',
    platform: 'linux',
    architecture: 'x64',
    machineFingerprint,
    enrollmentToken: await enrollmentToken(api),
  }).expect(201)).body;
}

function authenticated(api, identity, path, body) {
  return api.post(path).set('Authorization', `Bearer ${identity.authToken}`).send(body);
}

test('new registration requires and stores a SHA-256 machine fingerprint', async (t) => {
  const { database, api } = setup();
  t.after(() => database.close());
  const token = await enrollmentToken(api);
  await api.post('/api/agents/register').send({ hostname: 'host', enrollmentToken: token }).expect(400);
  await api.post('/api/agents/register').send({ hostname: 'host', machineFingerprint: 'not-sha256', enrollmentToken: token }).expect(400);

  const identity = await register(api);
  assert.equal(database.prepare('SELECT machine_fingerprint FROM agents WHERE id = ?').get(identity.agentId).machine_fingerprint, FINGERPRINT);
});

test('matching fingerprint is accepted after bearer authentication', async (t) => {
  const { database, api } = setup();
  t.after(() => database.close());
  const identity = await register(api);

  await authenticated(api, identity, '/api/agents/heartbeat', {
    agentId: identity.agentId,
    hostname: 'bound-host',
    machineFingerprint: FINGERPRINT,
  }).expect(200);
  await authenticated(api, identity, '/api/agents/tasks/poll', {
    agentId: identity.agentId,
    machineFingerprint: FINGERPRINT,
  }).expect(200);
});

test('fingerprint mismatch rejects protected routes and records safe security telemetry', async (t) => {
  const { database, api, warnings } = setup();
  t.after(() => database.close());
  const identity = await register(api);
  const routes = [
    ['/api/agents/heartbeat', { agentId: identity.agentId, hostname: 'bound-host' }],
    ['/api/agents/tasks/poll', { agentId: identity.agentId }],
    ['/api/agents/results', { agentId: identity.agentId }],
  ];

  for (const [path, body] of routes) {
    const response = await authenticated(api, identity, path, { ...body, machineFingerprint: OTHER_FINGERPRINT }).expect(403);
    assert.equal(response.body.code, 'IDENTITY_FINGERPRINT_MISMATCH');
  }

  const events = database.prepare("SELECT details FROM agent_events WHERE agent_id = ? AND event_type = 'identity-fingerprint-mismatch' ORDER BY id").all(identity.agentId);
  assert.equal(events.length, routes.length);
  assert.equal(warnings.length, routes.length);
  for (const record of [...events.map((row) => JSON.parse(row.details)), ...warnings]) {
    const serialized = JSON.stringify(record);
    assert.equal(serialized.includes(FINGERPRINT), false);
    assert.equal(serialized.includes(OTHER_FINGERPRINT), false);
  }
});

test('continuity registration preserves an existing fingerprint and rejects replacement', async (t) => {
  const { database, api } = setup();
  t.after(() => database.close());
  const identity = await register(api);

  const response = await api.post('/api/agents/register')
    .set('Authorization', `Bearer ${identity.authToken}`)
    .send({ previousAgentId: identity.agentId, hostname: 'bound-host', machineFingerprint: OTHER_FINGERPRINT })
    .expect(403);
  assert.equal(response.body.code, 'IDENTITY_FINGERPRINT_MISMATCH');
  const stored = database.prepare('SELECT machine_fingerprint, auth_token_hash FROM agents WHERE id = ?').get(identity.agentId);
  assert.equal(stored.machine_fingerprint, FINGERPRINT);

  await authenticated(api, identity, '/api/agents/heartbeat', {
    agentId: identity.agentId,
    hostname: 'bound-host',
    machineFingerprint: FINGERPRINT,
  }).expect(200);
});

test('authenticated continuity registration upgrades a null legacy fingerprint once', async (t) => {
  const { database, api } = setup();
  t.after(() => database.close());
  const identity = await register(api);
  database.prepare('UPDATE agents SET machine_fingerprint = NULL WHERE id = ?').run(identity.agentId);

  const continuity = await api.post('/api/agents/register')
    .set('Authorization', `Bearer ${identity.authToken}`)
    .send({ previousAgentId: identity.agentId, hostname: 'legacy-host', machineFingerprint: OTHER_FINGERPRINT })
    .expect(201);
  assert.equal(continuity.body.agentId, identity.agentId);
  assert.equal(database.prepare('SELECT machine_fingerprint FROM agents WHERE id = ?').get(identity.agentId).machine_fingerprint, OTHER_FINGERPRINT);

  await api.post('/api/agents/register')
    .set('Authorization', `Bearer ${continuity.body.authToken}`)
    .send({ previousAgentId: identity.agentId, machineFingerprint: FINGERPRINT })
    .expect(403);
  assert.equal(database.prepare('SELECT machine_fingerprint FROM agents WHERE id = ?').get(identity.agentId).machine_fingerprint, OTHER_FINGERPRINT);
});
