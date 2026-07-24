import assert from 'node:assert/strict';
import test from 'node:test';
import request from 'supertest';
import { createApp } from '../src/app.js';
import { createDatabase } from '../src/database.js';

const logger = { info() {}, warn() {}, error() {} };
function setup(options = {}) {
  const database = createDatabase({ filename: ':memory:' });
  let clock = new Date('2026-01-01T00:00:00.000Z');
  const app = createApp({ database, adminToken: 'admin-secret', logger, now: () => new Date(clock), rateNow: () => clock.getTime(), baselineCollectors: [], ...options });
  return { database, app, api: request(app), setTime(value) { clock = new Date(value); } };
}
async function token(api, body = {}) {
  return (await api.post('/api/admin/enrollment-tokens').set('Authorization', 'Bearer admin-secret').send(body).expect(201)).body;
}
function register(api, body = {}) {
  return api.post('/api/agents/register').send({ hostname: 'host', platform: 'linux', architecture: 'x64', ...body });
}

 test('enrollment tokens are hashed, limited, expiring, and optional by default', async (t) => {
  const optional = setup(); t.after(() => optional.database.close());
  await register(optional.api).expect(201);
  const required = setup({ requireEnrollmentToken: true }); t.after(() => required.database.close());
  await register(required.api).expect(403);
  await register(required.api, { enrollmentToken: 'wrong' }).expect(403);
  const issued = await token(required.api, { expiresInHours: 24, maxUses: 1 });
  assert.equal(required.database.prepare('SELECT token_hash FROM enrollment_tokens').get().token_hash.includes(issued.token), false);
  const identity = (await register(required.api, { enrollmentToken: issued.token }).expect(201)).body;
    await register(required.api, { enrollmentToken: issued.token }).expect(403);
    await required.api.post('/api/agents/register')
      .set('Authorization', `Bearer ${identity.authToken}`)
      .send({ hostname: 'host', platform: 'linux', architecture: 'x64', previousAgentId: identity.agentId })
      .expect(201);
  const expiring = await token(required.api, { expiresInHours: 1, maxUses: 2 });
  required.setTime('2026-01-01T02:00:00.000Z');
  await register(required.api, { enrollmentToken: expiring.token }).expect(403);
});

test('authenticated fleet computes independent states and flips overdue agents stale', async (t) => {
  const env = setup({ expectedHeartbeatIntervalMs: 30000 }); t.after(() => env.database.close());
  const first = (await register(env.api).expect(201)).body;
  const second = (await register(env.api, { hostname: 'never-host', platform: 'win32' }).expect(201)).body;
  await env.api.post('/api/agents/heartbeat').set('Authorization', `Bearer ${first.authToken}`).send({ agentId: first.agentId, hostname: 'online-host' }).expect(200);
  const agent = request.agent(env.app);
  await agent.post('/api/dashboard/session').send({ token: 'admin-secret' }).expect(200);
  let fleet = await agent.get('/api/dashboard/fleet').expect(200);
  assert.equal(fleet.body.agents.find((row) => row.id === first.agentId).status, 'online');
  assert.equal(fleet.body.agents.find((row) => row.id === second.agentId).status, 'never-connected');
  env.setTime('2026-01-01T00:01:01.000Z');
  fleet = await agent.get('/api/dashboard/fleet').expect(200);
  assert.equal(fleet.body.agents.find((row) => row.id === first.agentId).status, 'stale');
  assert.equal(fleet.body.onlineThresholdMs, 60000);
});

test('dashboard requires a session and detail data is isolated per agent', async (t) => {
  const env = setup(); t.after(() => env.database.close());
  const first = (await register(env.api, { hostname: 'one' }).expect(201)).body;
  const second = (await register(env.api, { hostname: 'two' }).expect(201)).body;
  await env.api.get('/fleet').expect(302).expect('Location', '/login');
    await env.api.get('/api/dashboard/fleet').expect(401);
    await env.api.post('/api/dashboard/session').send({ token: 'wrong' }).expect(401);
  const browser = request.agent(env.app);
  const login = await browser.post('/api/dashboard/session').send({ token: 'admin-secret' }).expect(200);
  assert.match(login.headers['set-cookie'][0], /^asvp_fleet_session=[A-Za-z0-9_-]{43}; HttpOnly; SameSite=Strict; Path=\/; Max-Age=28800$/);
    const httpsEnv = setup({ secureDashboardCookie: true });
    t.after(() => httpsEnv.database.close());
    const secureLogin = await httpsEnv.api.post('/api/dashboard/session').send({ token: 'admin-secret' }).expect(200);
    assert.match(secureLogin.headers['set-cookie'][0], /; Secure$/);
    await browser.get('/fleet').expect(200);
  await env.api.post('/api/admin/tasks').set('Authorization', 'Bearer admin-secret').send({ agentId: first.agentId, collectorName: 'os-info', params: { owner: 'one' } }).expect(201);
  await env.api.post('/api/admin/tasks').set('Authorization', 'Bearer admin-secret').send({ agentId: second.agentId, collectorName: 'noop', params: { owner: 'two' } }).expect(201);
  const detail = await browser.get(`/api/dashboard/agents/${first.agentId}`).expect(200);
  assert.equal(detail.body.agent.id, first.agentId);
  assert.ok(detail.body.tasks.every((task) => task.params.owner === 'one'));
  assert.ok(detail.body.events.every((event) => !JSON.stringify(event).includes(second.agentId)));
  assert.equal(JSON.stringify(detail.body).includes('auth_token_hash'), false);
  assert.equal(JSON.stringify(detail.body).includes('encryption_key'), false);
});
